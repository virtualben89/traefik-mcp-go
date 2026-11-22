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
	"strconv"
	"strings"
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
			port, _ = strconv.Atoi(p)
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
		NetDialer: &net.Dialer{},
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
		"days_left":   int(leaf.NotAfter.Sub(now).Hours() / 24),
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
	if sni != "" {
		opts.DNSName = sni
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
		for _, c := range certs {
			if strings.EqualFold(c.CertFingerprint, fingerprint) || (c.SerialNumber != "" && c.SerialNumber == leaf.SerialNumber.String()) {
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
