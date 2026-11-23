package main

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/virtualben89/traefik-mcp-go/internal/config"
	"github.com/virtualben89/traefik-mcp-go/internal/tools"
)

const testToken = "test-token-0123456789abcdef"

type headerRT struct {
	token string
	next  http.RoundTripper
}

func (h headerRT) RoundTrip(r *http.Request) (*http.Response, error) {
	r = r.Clone(r.Context())
	if h.token != "" {
		r.Header.Set("Authorization", "Bearer "+h.token)
	}
	return h.next.RoundTrip(r)
}

func upstream(t *testing.T) *httptest.Server {
	t.Helper()
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/api/version":
			_, _ = io.WriteString(w, `{"Version":"3.7.0"}`)
		default:
			w.Header().Set("X-Next-Page", "1")
			_, _ = io.WriteString(w, `[]`)
		}
	}))
	t.Cleanup(ts.Close)
	return ts
}

func setup(t *testing.T, cfg *config.Config, urls map[string]string) *httptest.Server {
	t.Helper()
	if urls == nil {
		urls = map[string]string{"default": upstream(t).URL}
	}
	for name, u := range urls {
		cfg.Instances = append(cfg.Instances, config.Instance{Name: name, URL: u})
	}
	instances, err := buildInstances(cfg)
	if err != nil {
		t.Fatal(err)
	}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	server, _ := NewServer(instances, tools.Options{Order: cfg.InstanceNames()}, log)
	if cfg.HTTPPath == "" {
		cfg.HTTPPath = "/mcp"
	}
	ts := httptest.NewServer(buildHandler(cfg, server, instances, log))
	t.Cleanup(ts.Close)
	return ts
}

func connectHTTP(ctx context.Context, url, token string, sse bool) (*mcp.ClientSession, error) {
	hc := &http.Client{Transport: headerRT{token: token, next: http.DefaultTransport}, Timeout: 10 * time.Second}
	var tr mcp.Transport
	if sse {
		tr = &mcp.SSEClientTransport{Endpoint: url, HTTPClient: hc}
	} else {
		tr = &mcp.StreamableClientTransport{Endpoint: url, HTTPClient: hc}
	}
	return mcp.NewClient(&mcp.Implementation{Name: "t", Version: "0"}, nil).Connect(ctx, tr, nil)
}

func TestHTTPAuth(t *testing.T) {
	ts := setup(t, &config.Config{AuthTokens: []string{testToken}, HTTPEnableSSE: true}, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	for _, p := range []string{"/healthz", "/readyz"} {
		resp, err := http.Get(ts.URL + p)
		if err != nil || resp.StatusCode != http.StatusOK {
			t.Fatalf("%s: %v %v", p, err, resp)
		}
		resp.Body.Close()
	}

	for _, path := range []string{"/mcp", "/sse"} {
		for _, tok := range []string{"", "wrong-token-xxxxxxxxxxxx"} {
			req, _ := http.NewRequest(http.MethodPost, ts.URL+path, strings.NewReader(`{}`))
			if tok != "" {
				req.Header.Set("Authorization", "Bearer "+tok)
			}
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			resp.Body.Close()
			if resp.StatusCode != http.StatusUnauthorized {
				t.Errorf("%s token %q: got %d, want 401", path, tok, resp.StatusCode)
			}
		}
	}
	if _, err := connectHTTP(ctx, ts.URL+"/mcp", "", false); err == nil {
		t.Error("client without token connected")
	}

	for _, tc := range []struct {
		path string
		sse  bool
	}{{"/mcp", false}, {"/sse", true}} {
		cs, err := connectHTTP(ctx, ts.URL+tc.path, testToken, tc.sse)
		if err != nil {
			t.Fatalf("%s: connect: %v", tc.path, err)
		}
		res, err := cs.ListTools(ctx, nil)
		if err != nil || len(res.Tools) != 14 {
			t.Fatalf("%s: list tools: %v", tc.path, err)
		}
		cr, err := cs.CallTool(ctx, &mcp.CallToolParams{Name: "list_routers", Arguments: map[string]any{}})
		if err != nil || cr.IsError {
			t.Fatalf("%s: list_routers: %v %+v", tc.path, err, cr)
		}
		_ = cs.Close()
	}
}

func TestHTTPStatelessJSON(t *testing.T) {
	ts := setup(t, &config.Config{AuthTokens: []string{testToken}, HTTPStateless: true, HTTPJSONResponse: true}, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cs, err := connectHTTP(ctx, ts.URL+"/mcp", testToken, false)
	if err != nil {
		t.Fatal(err)
	}
	defer cs.Close()
	if _, err := cs.ListTools(ctx, nil); err != nil {
		t.Fatal(err)
	}
}

func TestReadyzDegraded(t *testing.T) {
	ts := setup(t, &config.Config{AllowNoAuth: true}, map[string]string{"up": upstream(t).URL, "down": "http://127.0.0.1:1"})
	resp, err := http.Get(ts.URL + "/readyz")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var body map[string]string
	_ = json.NewDecoder(resp.Body).Decode(&body)
	if resp.StatusCode != http.StatusServiceUnavailable || body["up"] != "ok" || body["down"] != "unreachable" {
		t.Errorf("readyz: %d %v", resp.StatusCode, body)
	}
}

// Regression (DNS rebinding): without bearer auth only loopback Host headers and
// MCP_ALLOWED_HOSTS reach the MCP endpoints, independent of the listener address.
func TestNoAuthHostGuard(t *testing.T) {
	ts := setup(t, &config.Config{AllowNoAuth: true, HTTPEnableSSE: true, AllowedHosts: []string{"traefik-mcp"}}, nil)
	initBody := `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"t","version":"1"}}}`
	post := func(path, host string, hdr map[string]string) int {
		req, _ := http.NewRequest(http.MethodPost, ts.URL+path, strings.NewReader(initBody))
		req.Host = host
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Accept", "application/json, text/event-stream")
		for k, v := range hdr {
			req.Header.Set(k, v)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}
	for host, want := range map[string]int{
		"attacker.example:8080": http.StatusForbidden,
		"192.168.1.5:8080":      http.StatusForbidden,
		"localhost:8080":        http.StatusOK,
		"127.0.0.1:8080":        http.StatusOK,
		"[::1]:8080":            http.StatusOK,
		"traefik-mcp:8080":      http.StatusOK,
	} {
		if got := post("/mcp", host, nil); got != want {
			t.Errorf("/mcp Host %s: got %d want %d", host, got, want)
		}
	}
	if got := post("/sse", "attacker.example", nil); got != http.StatusForbidden {
		t.Errorf("/sse foreign host: %d", got)
	}
	// Browser cross-origin request with an allowed Host (e.g. from another local page).
	if got := post("/mcp", "localhost:8080", map[string]string{"Sec-Fetch-Site": "cross-site", "Origin": "http://evil.example"}); got != http.StatusForbidden {
		t.Errorf("cross-origin browser request: %d", got)
	}
	// Health endpoints stay reachable for probes.
	req, _ := http.NewRequest(http.MethodGet, ts.URL+"/healthz", nil)
	req.Host = "attacker.example"
	if resp, err := http.DefaultClient.Do(req); err != nil || resp.StatusCode != http.StatusOK {
		t.Errorf("healthz: %v %v", err, resp)
	}
}

// Regression: invalid booleans, credentials in URLs and bad CIDRs fail startup.
func TestConfigStrict(t *testing.T) {
	clearEnv(t)
	t.Setenv("TRAEFIK_URL", "https://traefik.example.com")
	for _, k := range []string{"TLS_CHECK_ENABLED", "MCP_HTTP_ENABLE_SSE", "MCP_ALLOW_NO_AUTH", "MCP_HTTP_STATELESS"} {
		for _, v := range []string{"off", "no", "disabled"} {
			t.Setenv(k, v)
			if _, err := config.Load(nil); err == nil || !strings.Contains(err.Error(), k) {
				t.Errorf("%s=%s must fail: %v", k, v, err)
			}
		}
		t.Setenv(k, "")
	}
	t.Setenv("TLS_CHECK_ENABLED", "false")
	if cfg, err := config.Load(nil); err != nil || cfg.TLSCheckEnabled {
		t.Errorf("TLS_CHECK_ENABLED=false: %v %+v", err, cfg)
	}
	t.Setenv("TLS_CHECK_ENABLED", "")

	t.Setenv("TRAEFIK_URL", "https://user:s3cret@traefik.example.com")
	if _, err := config.Load(nil); err == nil || strings.Contains(err.Error(), "s3cret") || !strings.Contains(err.Error(), "credentials") {
		t.Errorf("userinfo URL: %v", err)
	}
	t.Setenv("TRAEFIK_URL", "https://traefik.example.com")

	t.Setenv("TLS_CHECK_ALLOW_CIDRS", "192.168.100.0/24, 10.0.0.5")
	if cfg, err := config.Load(nil); err != nil || len(cfg.TLSCheckAllowCIDRs) != 2 || cfg.TLSCheckAllowCIDRs[1].String() != "10.0.0.5/32" {
		t.Errorf("allow cidrs: %v %+v", err, cfg)
	}
	t.Setenv("TLS_CHECK_ALLOW_CIDRS", "not-a-cidr")
	if _, err := config.Load(nil); err == nil {
		t.Error("invalid CIDR must fail")
	}
	t.Setenv("TLS_CHECK_ALLOW_CIDRS", "")

	t.Setenv("MCP_HTTP_SESSION_TIMEOUT", "-5m")
	if _, err := config.Load(nil); err == nil {
		t.Error("negative session timeout must fail")
	}
	t.Setenv("MCP_HTTP_SESSION_TIMEOUT", "")

	t.Setenv("MCP_ALLOWED_HOSTS", "MCP.example.com:8443, traefik-mcp")
	if cfg, err := config.Load(nil); err != nil || strings.Join(cfg.AllowedHosts, ",") != "mcp.example.com,traefik-mcp" {
		t.Errorf("allowed hosts: %v %+v", err, cfg)
	}
}

func clearEnv(t *testing.T) {
	for _, k := range []string{"TRAEFIK_URL", "TRAEFIK_INSTANCES", "TRAEFIK_INSTANCE_NAME", "TRAEFIK_DEFAULT_INSTANCE",
		"TRAEFIK_BASIC_USER", "TRAEFIK_BASIC_PASSWORD", "TRAEFIK_BEARER_TOKEN", "MCP_TRANSPORT", "MCP_AUTH_TOKEN", "MCP_ALLOW_NO_AUTH",
		"TLS_CHECK_ENABLED", "TLS_CHECK_ALLOW_CIDRS", "MCP_HTTP_ENABLE_SSE", "MCP_HTTP_STATELESS", "MCP_HTTP_SESSION_TIMEOUT", "MCP_ALLOWED_HOSTS"} {
		t.Setenv(k, "")
	}
}

func TestConfigSingle(t *testing.T) {
	clearEnv(t)
	if _, err := config.Load(nil); err == nil {
		t.Error("missing URL must fail")
	}
	t.Setenv("TRAEFIK_URL", "https://traefik.example.com/api/")
	t.Setenv("TRAEFIK_BASIC_USER", "u")
	t.Setenv("TRAEFIK_BASIC_PASSWORD", "p")
	t.Setenv("MCP_TRANSPORT", "http")
	if _, err := config.Load(nil); err == nil || !strings.Contains(err.Error(), "MCP_AUTH_TOKEN") {
		t.Errorf("http without token must fail: %v", err)
	}
	t.Setenv("MCP_AUTH_TOKEN", "short")
	if _, err := config.Load(nil); err == nil {
		t.Error("short token must fail")
	}
	t.Setenv("MCP_AUTH_TOKEN", testToken+","+testToken+"2")
	cfg, err := config.Load(nil)
	if err != nil {
		t.Fatal(err)
	}
	in := cfg.Instances[0]
	if len(cfg.Instances) != 1 || in.Name != "default" || in.URL != "https://traefik.example.com" || in.AuthMode() != "basic" || len(cfg.AuthTokens) != 2 {
		t.Errorf("cfg: %+v", cfg)
	}
	t.Setenv("TRAEFIK_BEARER_TOKEN", "x")
	if _, err := config.Load(nil); err == nil {
		t.Error("bearer + basic must fail")
	}
	t.Setenv("TRAEFIK_BEARER_TOKEN", "")
	t.Setenv("MCP_TRANSPORT", "stdio")
	t.Setenv("MCP_AUTH_TOKEN", "")
	if _, err := config.Load(nil); err != nil {
		t.Errorf("stdio needs no token: %v", err)
	}
	if cfg, err := config.Load([]string{"--traefik-url", "http://other:8080"}); err != nil || cfg.Instances[0].URL != "http://other:8080" {
		t.Errorf("--traefik-url: %v %+v", err, cfg)
	}
}

func TestConfigMulti(t *testing.T) {
	clearEnv(t)
	t.Setenv("TRAEFIK_INSTANCES", "edge, lan-01")
	t.Setenv("TRAEFIK_EDGE_URL", "https://edge.example.com")
	t.Setenv("TRAEFIK_EDGE_BEARER_TOKEN", "tok")
	if _, err := config.Load(nil); err == nil || !strings.Contains(err.Error(), "TRAEFIK_LAN_01_URL") {
		t.Errorf("missing second URL must fail: %v", err)
	}
	t.Setenv("TRAEFIK_LAN_01_URL", "http://10.0.0.1:8080")
	t.Setenv("TRAEFIK_LAN_01_HEADERS", "X-Api-Key: abc; CF-Access-Client-Id: id")
	t.Setenv("TRAEFIK_DEFAULT_INSTANCE", "lan-01")
	cfg, err := config.Load(nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(cfg.InstanceNames(), ","); got != "edge,lan-01" || cfg.DefaultInstance != "lan-01" {
		t.Errorf("instances %s default %s", got, cfg.DefaultInstance)
	}
	lan, _ := cfg.Instance("")
	if lan.Headers["X-Api-Key"] != "abc" || lan.AuthMode() != "headers" {
		t.Errorf("lan: %+v", lan)
	}
	if e, _ := cfg.Instance("edge"); e.AuthMode() != "bearer" {
		t.Errorf("edge: %+v", e)
	}
	t.Setenv("TRAEFIK_DEFAULT_INSTANCE", "nope")
	if _, err := config.Load(nil); err == nil {
		t.Error("unknown default must fail")
	}
	t.Setenv("TRAEFIK_DEFAULT_INSTANCE", "")
	t.Setenv("TRAEFIK_INSTANCES", "Bad Name!")
	if _, err := config.Load(nil); err == nil {
		t.Error("invalid name must fail")
	}
}
