package tools

import (
	"context"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// CheckTLSInput are the parameters of check_tls_endpoint.
type CheckTLSInput struct {
	Host     string `json:"host" jsonschema:"Host name (or host:port) to connect to, e.g. app.example.com"`
	Port     int    `json:"port,omitempty" jsonschema:"TCP port (default 443, or the port given in host)"`
	SNI      string `json:"sni,omitempty" jsonschema:"Server name to send (default: host). Use it to test a name against an IP address"`
	Instance string `json:"instance,omitempty" jsonschema:"Also look up the served certificate in this instance's certificate store (Traefik 3.7+); omit to check all instances"`
}

// rootCAs is overridable in tests.
var rootCAs *x509.CertPool

func (r *Registry) checkTLS(ctx context.Context, in CheckTLSInput) (*mcp.CallToolResult, error) {
	host := strings.TrimSpace(in.Host)
	if host == "" {
		return nil, errors.New("host is required")
	}
	host = strings.TrimPrefix(strings.TrimPrefix(host, "https://"), "http://")
	host, _, _ = strings.Cut(host, "/")
	port := in.Port
	if h, p, err := net.SplitHostPort(host); err == nil {
		host = h
		if port == 0 {
			if port, err = strconv.Atoi(p); err != nil {
				return nil, fmt.Errorf("invalid port %q in host", p)
			}
		}
	}
	host = strings.Trim(host, "[]")
	if port == 0 {
		port = 443
	}
	if port < 1 || port > 65535 {
		return nil, fmt.Errorf("invalid port %d", port)
	}
	sni := strings.TrimSpace(in.SNI)
	if sni == "" && net.ParseIP(host) == nil {
		sni = host
	}
	addr := net.JoinHostPort(host, strconv.Itoa(port))

	dctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	d := &tls.Dialer{
		NetDialer: &net.Dialer{Control: r.dialControl},
		Config: &tls.Config{
			ServerName:         sni,
			InsecureSkipVerify: true, //nolint:gosec // we verify manually below to report details
			NextProtos:         []string{"h2", "http/1.1"},
			MinVersion:         tls.VersionTLS10,
		},
	}
	conn, err := d.DialContext(dctx, "tcp", addr)
	if err != nil {
		hint := ""
		if strings.Contains(err.Error(), "unrecognized name") {
			hint = " (the server has no certificate for this SNI and rejects unknown names, e.g. Traefik tls option sniStrict=true)"
		}
		return nil, fmt.Errorf("TLS handshake with %s (SNI %q) failed: %w%s", addr, sni, err, hint)
	}
	defer conn.Close()
	state := conn.(*tls.Conn).ConnectionState()
	if len(state.PeerCertificates) == 0 {
		return nil, errors.New("server sent no certificate")
	}
	leaf := state.PeerCertificates[0]
	now := time.Now()
	fp := sha256.Sum256(leaf.Raw)
	fingerprint := hex.EncodeToString(fp[:])

	cert := map[string]any{
		"subject_cn":  leaf.Subject.CommonName,
		"sans":        certNames(leaf),
		"issuer":      strings.TrimSpace(strings.Join(leaf.Issuer.Organization, " ") + " " + leaf.Issuer.CommonName),
		"not_before":  leaf.NotBefore.UTC().Format(time.RFC3339),
		"not_after":   leaf.NotAfter.UTC().Format(time.RFC3339),
		"days_left":   daysUntil(leaf.NotAfter, now),
		"serial":      leaf.SerialNumber.String(),
		"fingerprint": fingerprint,
		"key":         keyDesc(leaf),
	}

	// Chain + hostname verification against the system roots.
	inter := x509.NewCertPool()
	for _, c := range state.PeerCertificates[1:] {
		inter.AddCert(c)
	}
	opts := x509.VerifyOptions{Roots: rootCAs, Intermediates: inter, CurrentTime: now}
	// Verify against the SNI, or for IP targets without SNI against the IP
	// itself (checked against the certificate's IP SANs).
	opts.DNSName = sni
	if opts.DNSName == "" {
		opts.DNSName = host
	}
	verified, verifyErr := true, ""
	if _, err := leaf.Verify(opts); err != nil {
		verified, verifyErr = false, err.Error()
	}

	out := map[string]any{
		"address":     addr,
		"sni":         sni,
		"tls_version": tls.VersionName(state.Version),
		"cipher":      tls.CipherSuiteName(state.CipherSuite),
		"alpn":        state.NegotiatedProtocol,
		"chain_len":   len(state.PeerCertificates),
		"verified":    verified,
		"certificate": cert,
	}
	if verifyErr != "" {
		out["verify_error"] = verifyErr
	}
	if leaf.Subject.CommonName == "TRAEFIK DEFAULT CERT" {
		out["traefik_default_cert"] = true
		out["hint"] = "Traefik served its self-signed default certificate: no router/certificate matches this SNI, or ACME has not obtained a certificate yet"
	}

	// Cross-reference with the Traefik certificate stores (3.7+).
	names := r.opts.Order
	if in.Instance != "" {
		_, n, err := r.instance(in.Instance)
		if err != nil {
			return nil, err
		}
		names = []string{n}
	}
	found := r.perInstance(ctx, names, func(ctx context.Context, _ string, inst Instance) any {
		certs, ok, err := fetchCertificates(ctx, inst.Client)
		if err != nil || !ok {
			return nil
		}
		// Only the exact certificate counts; serial numbers are public and only
		// unique per issuer.
		for _, c := range certs {
			if c.CertFingerprint != "" && normFingerprint(c.CertFingerprint) == fingerprint {
				return true
			}
		}
		return false
	})
	var stores []string
	for _, n := range names {
		if found[n] == true {
			stores = append(stores, n)
		}
	}
	if stores != nil {
		out["in_traefik_store"] = stores
	}
	return valueResult(out)
}

func normFingerprint(s string) string {
	return strings.ToLower(strings.NewReplacer(":", "", " ", "").Replace(s))
}

// blockedPrefixes are destinations check_tls_endpoint refuses unless the
// operator allows them via TLS_CHECK_ALLOW_CIDRS.
var blockedPrefixes = func() []netip.Prefix {
	var out []netip.Prefix
	for _, s := range []string{
		"0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12",
		"192.0.0.0/24", "192.168.0.0/16", "198.18.0.0/15", "224.0.0.0/3",
		"::/128", "::1/128", "fc00::/7", "fe80::/10", "ff00::/8", "64:ff9b:1::/48",
	} {
		out = append(out, netip.MustParsePrefix(s))
	}
	return out
}()

// destinationAllowed reports whether check_tls_endpoint may connect to ip.
func destinationAllowed(ip netip.Addr, allow []netip.Prefix) bool {
	ip = ip.Unmap()
	for _, p := range allow {
		if p.Contains(ip) {
			return true
		}
	}
	for _, p := range blockedPrefixes {
		if p.Contains(ip) {
			return false
		}
	}
	return true
}

// dialControl runs after DNS resolution, for every address actually dialed,
// so DNS names resolving to internal addresses are caught as well.
func (r *Registry) dialControl(_, address string, _ syscall.RawConn) error {
	ap, err := netip.ParseAddrPort(address)
	if err != nil {
		return fmt.Errorf("unexpected dial address %q", address)
	}
	if !destinationAllowed(ap.Addr(), r.opts.TLSCheckAllowCIDRs) {
		return fmt.Errorf("destination %s is an internal address (loopback, private, link-local, CGNAT, ...) and blocked by default; "+
			"the operator can allow it via TLS_CHECK_ALLOW_CIDRS", ap.Addr().Unmap())
	}
	return nil
}

func certNames(c *x509.Certificate) []string {
	out := append([]string{}, c.DNSNames...)
	for _, ip := range c.IPAddresses {
		out = append(out, ip.String())
	}
	return out
}

func keyDesc(c *x509.Certificate) string {
	switch k := c.PublicKey.(type) {
	case *rsa.PublicKey:
		return fmt.Sprintf("RSA %d", k.N.BitLen())
	case *ecdsa.PublicKey:
		return "ECDSA " + k.Curve.Params().Name
	default:
		return c.PublicKeyAlgorithm.String()
	}
}
