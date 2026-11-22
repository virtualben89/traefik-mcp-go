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

func clearEnv(t *testing.T) {
	for _, k := range []string{"TRAEFIK_URL", "TRAEFIK_INSTANCES", "TRAEFIK_INSTANCE_NAME", "TRAEFIK_DEFAULT_INSTANCE",
		"TRAEFIK_BASIC_USER", "TRAEFIK_BASIC_PASSWORD", "TRAEFIK_BEARER_TOKEN", "MCP_TRANSPORT", "MCP_AUTH_TOKEN", "MCP_ALLOW_NO_AUTH"} {
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
