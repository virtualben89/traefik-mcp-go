// Package config loads the server configuration from flags and environment variables.
package config

import (
	"errors"
	"flag"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// Instance describes one Traefik API endpoint.
type Instance struct {
	Name        string
	URL         string
	Timeout     time.Duration
	BearerToken string
	BasicUser   string
	BasicPass   string
	Headers     map[string]string
	InsecureTLS bool
	CAFile      string
}

// AuthMode returns a human readable description of the upstream auth.
func (i Instance) AuthMode() string {
	switch {
	case i.BearerToken != "":
		return "bearer"
	case i.BasicUser != "":
		return "basic"
	case len(i.Headers) > 0:
		return "headers"
	default:
		return "none"
	}
}

// Config holds the complete runtime configuration.
type Config struct {
	Instances       []Instance
	DefaultInstance string

	// MCP transport
	Transport          string // "stdio" or "http"
	HTTPAddr           string
	HTTPPath           string
	HTTPStateless      bool
	HTTPJSONResponse   bool
	HTTPEnableSSE      bool
	HTTPSessionTimeout time.Duration
	AuthTokens         []string
	AllowNoAuth        bool
	// AllowedHosts are extra Host header values (besides loopback names) accepted
	// by the MCP endpoints. Enforced always in no-auth mode, otherwise only when set.
	AllowedHosts []string

	// Behaviour
	ToolPrefix      string
	DefaultPerPage  int
	CertWarnDays    int
	TLSCheckEnabled bool
	// TLSCheckAllowCIDRs re-allows internal destinations (loopback, private,
	// link-local, ...) for check_tls_endpoint, which are blocked by default.
	TLSCheckAllowCIDRs []netip.Prefix

	LogLevel  string
	LogFormat string
}

// Instance returns the instance with the given name (empty = default).
func (c *Config) Instance(name string) (Instance, bool) {
	if name == "" {
		name = c.DefaultInstance
	}
	for _, i := range c.Instances {
		if i.Name == name {
			return i, true
		}
	}
	return Instance{}, false
}

// InstanceNames lists the configured instance names in order.
func (c *Config) InstanceNames() []string {
	out := make([]string, len(c.Instances))
	for i, in := range c.Instances {
		out[i] = in.Name
	}
	return out
}

func envOr(key, fallback string) string {
	if v, ok := os.LookupEnv(key); ok && v != "" {
		return v
	}
	return fallback
}

func envBool(key string, fallback bool) (bool, error) {
	v, ok := os.LookupEnv(key)
	if !ok || strings.TrimSpace(v) == "" {
		return fallback, nil
	}
	b, err := strconv.ParseBool(strings.TrimSpace(v))
	if err != nil {
		return false, fmt.Errorf("invalid boolean in %s: %q", key, v)
	}
	return b, nil
}

// boolEnv collects boolean environment values; the first invalid value is
// reported by Load, so an unrecognised spelling (e.g. "off") never silently
// falls back to a permissive default.
type boolEnv struct{ err error }

func (b *boolEnv) get(key string, fallback bool) bool {
	v, err := envBool(key, fallback)
	if err != nil && b.err == nil {
		b.err = fmt.Errorf("%w (use true or false)", err)
	}
	return v
}

// ParseCIDRs parses a comma/space separated list of CIDRs or single IPs.
func ParseCIDRs(s string) ([]netip.Prefix, error) {
	var out []netip.Prefix
	for _, t := range splitList(s) {
		if !strings.Contains(t, "/") {
			a, err := netip.ParseAddr(t)
			if err != nil {
				return nil, fmt.Errorf("invalid CIDR or IP %q", t)
			}
			a = a.Unmap()
			out = append(out, netip.PrefixFrom(a, a.BitLen()))
			continue
		}
		p, err := netip.ParsePrefix(t)
		if err != nil {
			return nil, fmt.Errorf("invalid CIDR %q", t)
		}
		out = append(out, p.Masked())
	}
	return out, nil
}

// secretFromEnv reads KEY or, if KEY_FILE is set, the trimmed file content.
func secretFromEnv(key string) (string, error) {
	if f := os.Getenv(key + "_FILE"); f != "" {
		b, err := os.ReadFile(f)
		if err != nil {
			return "", fmt.Errorf("reading %s_FILE: %w", key, err)
		}
		return strings.TrimSpace(string(b)), nil
	}
	return os.Getenv(key), nil
}

// ParseHeaders parses "Name: value" pairs separated by newlines or ";".
func ParseHeaders(s string) (map[string]string, error) {
	out := map[string]string{}
	s = strings.ReplaceAll(s, "\r", "")
	for _, part := range strings.FieldsFunc(s, func(r rune) bool { return r == '\n' || r == ';' }) {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		name, value, ok := strings.Cut(part, ":")
		if !ok {
			name, value, ok = strings.Cut(part, "=")
		}
		name = strings.TrimSpace(name)
		if !ok || name == "" {
			return nil, fmt.Errorf("invalid header %q, expected 'Name: value'", part)
		}
		out[name] = strings.TrimSpace(value)
	}
	return out, nil
}

func splitList(s string) []string {
	var out []string
	for _, t := range strings.FieldsFunc(s, func(r rune) bool { return r == ',' || r == '\n' || r == ' ' || r == ';' }) {
		if t = strings.TrimSpace(t); t != "" {
			out = append(out, t)
		}
	}
	return out
}

var nameRe = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,62}$`)

// EnvPrefix returns the environment variable prefix for an instance name,
// e.g. "vps-01" -> "TRAEFIK_VPS_01_".
func EnvPrefix(name string) string {
	return "TRAEFIK_" + strings.ToUpper(strings.ReplaceAll(name, "-", "_")) + "_"
}

// loadInstance reads one instance. prefix is "TRAEFIK_" for single-instance
// mode or "TRAEFIK_<NAME>_" for named instances; global values act as defaults.
func loadInstance(name, prefix string, defTimeout time.Duration, defInsecure bool, defCA string) (Instance, error) {
	in := Instance{Name: name}
	in.URL = os.Getenv(prefix + "URL")
	if in.URL == "" {
		return in, fmt.Errorf("instance %q: %sURL is required", name, prefix)
	}
	u, err := url.Parse(in.URL)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return in, fmt.Errorf("instance %q: %sURL must be an absolute http(s) URL", name, prefix)
	}
	if u.User != nil {
		// Credentials in the URL would be sent upstream and shown by list_instances.
		return in, fmt.Errorf("instance %q: %sURL must not contain credentials; use %sBASIC_USER and %sBASIC_PASSWORD", name, prefix, prefix, prefix)
	}
	in.URL = strings.TrimSuffix(strings.TrimRight(in.URL, "/"), "/api")

	in.Timeout = defTimeout
	if v := os.Getenv(prefix + "TIMEOUT"); v != "" {
		if in.Timeout, err = time.ParseDuration(v); err != nil {
			return in, fmt.Errorf("instance %q: invalid %sTIMEOUT: %w", name, prefix, err)
		}
	}
	if in.InsecureTLS, err = envBool(prefix+"INSECURE_SKIP_VERIFY", defInsecure); err != nil {
		return in, err
	}
	in.CAFile = envOr(prefix+"CA_FILE", defCA)

	if in.BearerToken, err = secretFromEnv(prefix + "BEARER_TOKEN"); err != nil {
		return in, err
	}
	in.BasicUser = os.Getenv(prefix + "BASIC_USER")
	if in.BasicPass, err = secretFromEnv(prefix + "BASIC_PASSWORD"); err != nil {
		return in, err
	}
	if in.BearerToken != "" && in.BasicUser != "" {
		return in, fmt.Errorf("instance %q: %sBEARER_TOKEN and %sBASIC_USER are mutually exclusive", name, prefix, prefix)
	}
	if in.BasicUser == "" && in.BasicPass != "" {
		return in, fmt.Errorf("instance %q: %sBASIC_PASSWORD set without %sBASIC_USER", name, prefix, prefix)
	}
	hdrs, err := secretFromEnv(prefix + "HEADERS")
	if err != nil {
		return in, err
	}
	if in.Headers, err = ParseHeaders(hdrs); err != nil {
		return in, fmt.Errorf("instance %q: %sHEADERS: %w", name, prefix, err)
	}
	return in, nil
}

// Load parses flags (args without program name) on top of environment defaults.
func Load(args []string) (*Config, error) {
	c := &Config{}
	fs := flag.NewFlagSet("traefik-mcp", flag.ContinueOnError)
	var be boolEnv

	traefikURL := fs.String("traefik-url", "", "Traefik API base URL for single-instance mode (overrides env TRAEFIK_URL)")
	timeout := fs.String("traefik-timeout", envOr("TRAEFIK_TIMEOUT", "15s"), "Default HTTP timeout for Traefik API requests (env TRAEFIK_TIMEOUT)")
	fs.StringVar(&c.DefaultInstance, "default-instance", envOr("TRAEFIK_DEFAULT_INSTANCE", ""), "Instance used when a tool call omits 'instance' (env TRAEFIK_DEFAULT_INSTANCE, default: first)")

	fs.StringVar(&c.Transport, "transport", envOr("MCP_TRANSPORT", "stdio"), "Transport: stdio or http (env MCP_TRANSPORT)")
	fs.StringVar(&c.HTTPAddr, "http-addr", envOr("MCP_HTTP_ADDR", ":8080"), "Listen address for http transport (env MCP_HTTP_ADDR)")
	fs.StringVar(&c.HTTPPath, "http-path", envOr("MCP_HTTP_PATH", "/mcp"), "Endpoint path for Streamable HTTP (env MCP_HTTP_PATH)")
	fs.BoolVar(&c.HTTPStateless, "http-stateless", be.get("MCP_HTTP_STATELESS", false), "Run Streamable HTTP in stateless mode (env MCP_HTTP_STATELESS)")
	fs.BoolVar(&c.HTTPJSONResponse, "http-json-response", be.get("MCP_HTTP_JSON_RESPONSE", false), "Answer with application/json instead of SSE streams (env MCP_HTTP_JSON_RESPONSE)")
	fs.BoolVar(&c.HTTPEnableSSE, "http-enable-sse", be.get("MCP_HTTP_ENABLE_SSE", true), "Also serve the legacy HTTP+SSE transport on /sse (env MCP_HTTP_ENABLE_SSE)")
	sessTimeout := fs.String("http-session-timeout", envOr("MCP_HTTP_SESSION_TIMEOUT", "30m"), "Idle timeout for HTTP sessions, 0 disables (env MCP_HTTP_SESSION_TIMEOUT)")
	fs.BoolVar(&c.AllowNoAuth, "allow-no-auth", be.get("MCP_ALLOW_NO_AUTH", false), "Allow http transport without bearer token (env MCP_ALLOW_NO_AUTH)")
	allowedHosts := fs.String("allowed-hosts", envOr("MCP_ALLOWED_HOSTS", ""), "Extra Host header values accepted by the MCP endpoints besides localhost; required for non-local access in no-auth mode (env MCP_ALLOWED_HOSTS)")

	fs.StringVar(&c.ToolPrefix, "tool-prefix", envOr("TOOL_PREFIX", ""), "Optional prefix for all tool names, e.g. traefik_ (env TOOL_PREFIX)")
	perPage := fs.String("default-per-page", envOr("DEFAULT_PER_PAGE", "100"), "Default page size for list tools (env DEFAULT_PER_PAGE)")
	warnDays := fs.String("cert-warn-days", envOr("CERT_WARN_DAYS", "21"), "health_report warns about certificates expiring within this many days (env CERT_WARN_DAYS)")
	fs.BoolVar(&c.TLSCheckEnabled, "tls-check", be.get("TLS_CHECK_ENABLED", true), "Expose check_tls_endpoint, which connects to public hosts (env TLS_CHECK_ENABLED)")
	tlsAllow := fs.String("tls-check-allow-cidrs", envOr("TLS_CHECK_ALLOW_CIDRS", ""), "CIDRs check_tls_endpoint may connect to although they are internal (loopback, private, link-local, CGNAT), e.g. 192.168.100.0/24 (env TLS_CHECK_ALLOW_CIDRS)")

	fs.StringVar(&c.LogLevel, "log-level", envOr("LOG_LEVEL", "info"), "debug, info, warn, error (env LOG_LEVEL)")
	fs.StringVar(&c.LogFormat, "log-format", envOr("LOG_FORMAT", "text"), "text or json (env LOG_FORMAT)")

	if err := fs.Parse(args); err != nil {
		return nil, err
	}
	if be.err != nil {
		return nil, be.err
	}
	var err error
	if c.TLSCheckAllowCIDRs, err = ParseCIDRs(*tlsAllow); err != nil {
		return nil, fmt.Errorf("TLS_CHECK_ALLOW_CIDRS: %w", err)
	}
	for _, h := range splitList(*allowedHosts) {
		h = strings.ToLower(h)
		if hh, _, err := net.SplitHostPort(h); err == nil {
			h = hh
		}
		c.AllowedHosts = append(c.AllowedHosts, strings.Trim(h, "[]"))
	}

	defTimeout, err := time.ParseDuration(*timeout)
	if err != nil || defTimeout <= 0 {
		return nil, fmt.Errorf("invalid TRAEFIK_TIMEOUT %q", *timeout)
	}
	if c.HTTPSessionTimeout, err = time.ParseDuration(*sessTimeout); err != nil || c.HTTPSessionTimeout < 0 {
		return nil, fmt.Errorf("invalid MCP_HTTP_SESSION_TIMEOUT %q (use a duration >= 0, 0 disables)", *sessTimeout)
	}
	if c.DefaultPerPage, err = strconv.Atoi(*perPage); err != nil || c.DefaultPerPage <= 0 {
		return nil, fmt.Errorf("invalid DEFAULT_PER_PAGE %q", *perPage)
	}
	if c.CertWarnDays, err = strconv.Atoi(*warnDays); err != nil || c.CertWarnDays <= 0 {
		return nil, fmt.Errorf("invalid CERT_WARN_DAYS %q", *warnDays)
	}
	defInsecure, err := envBool("TRAEFIK_INSECURE_SKIP_VERIFY", false)
	if err != nil {
		return nil, err
	}
	defCA := os.Getenv("TRAEFIK_CA_FILE")

	// Instances: either TRAEFIK_INSTANCES=a,b with TRAEFIK_A_URL ... or a single TRAEFIK_URL.
	if names := splitList(os.Getenv("TRAEFIK_INSTANCES")); len(names) > 0 {
		if *traefikURL != "" {
			return nil, errors.New("--traefik-url cannot be combined with TRAEFIK_INSTANCES")
		}
		seen := map[string]bool{}
		for _, n := range names {
			n = strings.ToLower(n)
			if !nameRe.MatchString(n) {
				return nil, fmt.Errorf("invalid instance name %q (allowed: a-z, 0-9, '-', '_')", n)
			}
			p := EnvPrefix(n)
			if seen[p] {
				return nil, fmt.Errorf("duplicate instance name %q", n)
			}
			seen[p] = true
			in, err := loadInstance(n, p, defTimeout, defInsecure, defCA)
			if err != nil {
				return nil, err
			}
			c.Instances = append(c.Instances, in)
		}
	} else {
		if *traefikURL != "" {
			if err := os.Setenv("TRAEFIK_URL", *traefikURL); err != nil {
				return nil, err
			}
		}
		if os.Getenv("TRAEFIK_URL") == "" {
			return nil, errors.New("configure TRAEFIK_URL (single instance) or TRAEFIK_INSTANCES with TRAEFIK_<NAME>_URL (multiple instances)")
		}
		name := strings.ToLower(envOr("TRAEFIK_INSTANCE_NAME", "default"))
		if !nameRe.MatchString(name) {
			return nil, fmt.Errorf("invalid TRAEFIK_INSTANCE_NAME %q", name)
		}
		in, err := loadInstance(name, "TRAEFIK_", defTimeout, defInsecure, defCA)
		if err != nil {
			return nil, err
		}
		c.Instances = []Instance{in}
	}

	tok, err := secretFromEnv("MCP_AUTH_TOKEN")
	if err != nil {
		return nil, err
	}
	c.AuthTokens = splitList(tok)

	return c, c.Validate()
}

// Validate checks the configuration for consistency.
func (c *Config) Validate() error {
	if len(c.Instances) == 0 {
		return errors.New("no Traefik instance configured")
	}
	c.DefaultInstance = strings.ToLower(c.DefaultInstance)
	if c.DefaultInstance == "" {
		c.DefaultInstance = c.Instances[0].Name
	}
	if _, ok := c.Instance(c.DefaultInstance); !ok {
		return fmt.Errorf("TRAEFIK_DEFAULT_INSTANCE %q is not a configured instance (%s)", c.DefaultInstance, strings.Join(c.InstanceNames(), ", "))
	}

	c.Transport = strings.ToLower(strings.TrimSpace(c.Transport))
	switch c.Transport {
	case "stdio":
	case "http", "streamable-http", "sse":
		c.Transport = "http"
		if !strings.HasPrefix(c.HTTPPath, "/") {
			c.HTTPPath = "/" + c.HTTPPath
		}
		if len(c.AuthTokens) == 0 && !c.AllowNoAuth {
			return errors.New("http transport requires MCP_AUTH_TOKEN (or set MCP_ALLOW_NO_AUTH=true to explicitly run without authentication)")
		}
		for _, t := range c.AuthTokens {
			if len(t) < 16 {
				return errors.New("MCP_AUTH_TOKEN values must be at least 16 characters long")
			}
		}
	default:
		return fmt.Errorf("unknown transport %q (use stdio or http)", c.Transport)
	}
	return nil
}
