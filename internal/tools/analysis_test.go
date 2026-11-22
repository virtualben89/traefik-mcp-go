package tools

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// fixtureTraefik serves static JSON per API path (lists are single-page).
func fixtureTraefik(t *testing.T, fx map[string]any) *httptest.Server {
	t.Helper()
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p, _ := url.PathUnescape(strings.TrimPrefix(r.URL.EscapedPath(), "/api"))
		v, ok := fx[p]
		if !ok {
			if p == "/version" {
				v = map[string]any{"Version": "3.7.0"}
			} else if strings.Count(p, "/") == 2 && !strings.HasPrefix(p, "/entrypoints/") {
				v = []any{} // empty list endpoint
			} else {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusNotFound)
				_, _ = io.WriteString(w, `{"message":"not found"}`)
				return
			}
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-Next-Page", "1")
		_ = json.NewEncoder(w).Encode(v)
	}))
	t.Cleanup(ts.Close)
	return ts
}

func day(n int) string {
	return time.Now().Add(time.Duration(n) * 24 * time.Hour).UTC().Format(time.RFC3339)
}

func homelabFixture() map[string]any {
	return map[string]any{
		"/entrypoints": []any{
			map[string]any{"name": "web", "address": ":80", "http": map[string]any{"middlewares": []any{"crowdsec@file"}}},
			map[string]any{"name": "redir", "address": ":8000", "http": map[string]any{"redirections": map[string]any{"entryPoint": map[string]any{"to": "websecure", "scheme": "https"}}}},
			map[string]any{"name": "websecure", "address": ":443"},
			map[string]any{"name": "dns", "address": ":53/udp"},
		},
		"/entrypoints/web": map[string]any{"name": "web", "address": ":80"},
		"/overview":        map[string]any{"http": map[string]any{"routers": map[string]any{"total": 5}}},
		"/http/routers": []any{
			map[string]any{"name": "api@internal", "provider": "internal", "status": "enabled", "rule": "PathPrefix(`/api`)", "priority": json.Number("9223372036854775806"), "using": []any{"traefik"}, "service": "api@internal", "tls": map[string]any{}},
			map[string]any{"name": "app@docker", "provider": "docker", "status": "enabled", "rule": "Host(`app.example.com`)", "using": []any{"websecure"}, "middlewares": []any{"sec"}, "service": "app", "tls": map[string]any{"certResolver": "le"}},
			map[string]any{"name": "app-api@docker", "provider": "docker", "status": "enabled", "rule": "Host(`app.example.com`) && PathPrefix(`/api`)", "using": []any{"websecure"}, "service": "api", "tls": map[string]any{}},
			map[string]any{"name": "app-debug@docker", "provider": "docker", "status": "enabled", "rule": "Host(`app.example.com`) && PathPrefix(`/api`) && Header(`X-Debug`, `1`)", "priority": 1000, "using": []any{"websecure"}, "service": "api", "tls": map[string]any{}},
			map[string]any{"name": "app-http@docker", "provider": "docker", "status": "enabled", "rule": "Host(`app.example.com`)", "using": []any{"web"}, "middlewares": []any{"to-https"}, "service": "app"},
			map[string]any{"name": "plain@docker", "provider": "docker", "status": "enabled", "rule": "Host(`plain.example.com`)", "using": []any{"web"}, "middlewares": []any{"rx"}, "service": "app"},
			map[string]any{"name": "ghost@docker", "provider": "docker", "status": "enabled", "rule": "Host(`web-myproject`)", "using": []any{"web", "websecure"}, "service": "app"},
			map[string]any{"name": "broken@file", "provider": "file", "status": "disabled", "rule": "Host(`broken.example.com`)", "using": []any{"websecure"}, "service": "missing", "tls": map[string]any{}, "error": []any{`the service "missing@file" does not exist`}},
		},
		"/tcp/routers": []any{
			map[string]any{"name": "mail@docker", "provider": "docker", "status": "enabled", "rule": "HostSNIRegexp(`^mail[.]example[.]de$`)", "using": []any{"websecure"}, "service": "mail", "tls": map[string]any{"passthrough": true}},
		},
		"/http/services": []any{
			map[string]any{"name": "app@docker", "provider": "docker", "status": "enabled", "type": "loadbalancer", "serverStatus": map[string]any{"http://10.0.0.1:80": "UP"}},
			map[string]any{"name": "api@docker", "provider": "docker", "status": "enabled", "type": "loadbalancer", "serverStatus": map[string]any{"http://10.0.0.2:80": "DOWN"}},
			map[string]any{"name": "half@docker", "provider": "docker", "status": "enabled", "type": "loadbalancer", "serverStatus": map[string]any{"http://10.0.0.3:80": "UP", "http://10.0.0.4:80": "DOWN"}},
		},
		"/http/services/app@docker": map[string]any{"name": "app@docker", "provider": "docker", "status": "enabled", "type": "loadbalancer",
			"loadBalancer": map[string]any{"servers": []any{map[string]any{"url": "http://10.0.0.1:80"}}}, "serverStatus": map[string]any{"http://10.0.0.1:80": "UP"}},
		"/http/services/api@docker": map[string]any{"name": "api@docker", "provider": "docker", "status": "enabled", "type": "weighted",
			"weighted": map[string]any{"services": []any{map[string]any{"name": "app"}}}},
		"/tcp/services/mail@docker": map[string]any{"name": "mail@docker", "provider": "docker", "status": "enabled", "type": "loadbalancer",
			"loadBalancer": map[string]any{"servers": []any{map[string]any{"address": "10.0.0.9:443"}}}},
		"/http/middlewares": []any{
			map[string]any{"name": "sec@docker", "provider": "docker", "status": "enabled", "type": "headers"},
			map[string]any{"name": "to-https@docker", "provider": "docker", "status": "enabled", "type": "redirectscheme"},
			map[string]any{"name": "rx@docker", "provider": "docker", "status": "enabled", "type": "redirectregex", "redirectRegex": map[string]any{"regex": "^http://www\\.(.*)", "replacement": "https://${1}"}},
			map[string]any{"name": "crowdsec@file", "provider": "file", "status": "warning", "type": "plugin", "error": []any{"plugin slow"}},
		},
		"/http/middlewares/sec@docker":    map[string]any{"name": "sec@docker", "status": "enabled", "type": "headers"},
		"/http/middlewares/crowdsec@file": map[string]any{"name": "crowdsec@file", "status": "enabled", "type": "plugin"},
		"/certificates": []any{
			map[string]any{"commonName": "old.example.com", "sans": []any{"old.example.com"}, "notAfter": day(-1), "certFingerprint": "aa"},
			map[string]any{"commonName": "soon.example.com", "sans": []any{"soon.example.com"}, "notAfter": day(5), "certFingerprint": "bb"},
			map[string]any{"commonName": "fine.example.com", "sans": []any{"fine.example.com", "www.fine.example.com"}, "notAfter": day(80), "certFingerprint": "cc"},
		},
	}
}

func analysisSession(t *testing.T, fx map[string]any, opts Options) (*ClientSessionWrapper, *httptest.Server) {
	t.Helper()
	srv := fixtureTraefik(t, fx)
	if opts.Order == nil {
		opts.Order = []string{"main"}
	}
	insts := map[string]Instance{}
	for _, n := range opts.Order {
		insts[n] = inst(t, n, srv.URL)
	}
	return &ClientSessionWrapper{t: t, cs: connect(t, opts, insts)}, srv
}

func TestHealthReport(t *testing.T) {
	s, _ := analysisSession(t, homelabFixture(), Options{})
	var out struct {
		Healthy   bool `json:"healthy"`
		Instances map[string]struct {
			Summary  map[string]int `json:"summary"`
			Findings []finding      `json:"findings"`
		} `json:"instances"`
	}
	s.decode("health_report", nil, &out)
	rep := out.Instances["main"]
	if out.Healthy {
		t.Error("report must be unhealthy")
	}
	byObj := map[string]finding{}
	for _, f := range rep.Findings {
		byObj[f.Category+"|"+f.Object] = f
	}
	for key, sev := range map[string]string{
		"http router|broken@file":       "error",
		"http service|api@docker":       "error",
		"http service|half@docker":      "warning",
		"http middleware|crowdsec@file": "warning",
		"certificate|old.example.com":   "error",
		"certificate|soon.example.com":  "warning",
		"ghost router|ghost@docker":     "warning",
		"plain http|plain@docker":       "info",
		"plain http|ghost@docker":       "info",
	} {
		f, ok := byObj[key]
		if !ok || f.Severity != sev {
			t.Errorf("%s: want %s, got %+v", key, sev, f)
		}
	}
	for _, key := range []string{"plain http|app-http@docker", "certificate|fine.example.com", "plain http|api@internal"} {
		if _, ok := byObj[key]; ok {
			t.Errorf("unexpected finding %s", key)
		}
	}
	if f := byObj["plain http|plain@docker"]; len(f.Details) != 1 || !strings.Contains(f.Details[0], "redirectRegex") {
		t.Errorf("redirectRegex detail missing: %+v", f)
	}
	if rep.Findings[0].Severity != "error" || rep.Findings[len(rep.Findings)-1].Severity != "info" {
		t.Error("findings not sorted by severity")
	}
	if rep.Summary["error"] != 3 {
		t.Errorf("summary: %v", rep.Summary)
	}

	// cert_warn_days widens the window, include_info=false drops info findings.
	s.decode("health_report", map[string]any{"cert_warn_days": 100, "include_info": false}, &out)
	rep = out.Instances["main"]
	for _, f := range rep.Findings {
		if f.Severity == "info" {
			t.Errorf("info finding with include_info=false: %+v", f)
		}
	}
	if rep.Summary["warning"] != 5 { // half, crowdsec, soon, fine, ghost
		t.Errorf("warn days 100: %v", rep.Summary)
	}
}

func TestHealthReportV2AndUnreachable(t *testing.T) {
	fx := homelabFixture()
	delete(fx, "/certificates")
	srv := fixtureTraefik(t, fx)
	cs := connect(t, Options{Order: []string{"v2", "down"}}, map[string]Instance{"v2": inst(t, "v2", srv.URL), "down": inst(t, "down", "http://127.0.0.1:1")})
	s := &ClientSessionWrapper{t: t, cs: cs}
	txt := s.ok("health_report", map[string]any{"all_instances": true})
	if !strings.Contains(txt, `"certificates":"not available (Traefik < 3.7)"`) {
		t.Errorf("v2 certificates note missing: %s", txt)
	}
	if !strings.Contains(txt, `"reachable":false`) {
		t.Errorf("unreachable instance not reported: %s", txt)
	}
}

func TestFindRoute(t *testing.T) {
	s, _ := analysisSession(t, homelabFixture(), Options{})
	type res struct {
		Result struct {
			Matched     string   `json:"matched"`
			EntryPoints []string `json:"entrypoints"`
			Route       struct {
				Router      string           `json:"router"`
				Middlewares []map[string]any `json:"middlewares"`
				Service     map[string]any   `json:"service"`
			} `json:"route"`
			Notes    []string         `json:"notes"`
			Redirect map[string]any   `json:"entrypoint_redirect"`
			Cands    []routeCandidate `json:"http_candidates"`
		} `json:"result"`
	}
	var r res
	// Priority: the more specific /api rule wins over the plain host rule;
	// the Header-based router has higher priority but cannot be evaluated.
	s.decode("find_route", map[string]any{"url": "https://app.example.com/api/x"}, &r)
	if r.Result.Matched != "http" || r.Result.Route.Router != "app-api@docker" {
		t.Fatalf("api route: %+v", r)
	}
	if len(r.Result.Notes) == 0 || !strings.Contains(strings.Join(r.Result.Notes, " "), "app-debug@docker") {
		t.Errorf("shadowing note missing: %v", r.Result.Notes)
	}
	if r.Result.Route.Service["type"] != "weighted" || r.Result.Route.Service["children"] == nil {
		t.Errorf("weighted children missing: %v", r.Result.Route.Service)
	}

	r = res{}
	s.decode("find_route", map[string]any{"url": "app.example.com/"}, &r)
	if r.Result.Route.Router != "app@docker" || len(r.Result.Route.Middlewares) != 1 {
		t.Errorf("host route: %+v", r.Result.Route)
	}
	if svc := r.Result.Route.Service; svc["serverStatus"] == nil || svc["servers"] == nil {
		t.Errorf("service chain: %v", svc)
	}

	// Plain HTTP on :80 -> router on web incl. entry point middleware first.
	r = res{}
	s.decode("find_route", map[string]any{"url": "http://app.example.com/"}, &r)
	if r.Result.Route.Router != "app-http@docker" || len(r.Result.Route.Middlewares) != 2 || r.Result.Route.Middlewares[0]["name"] != "crowdsec@file" {
		t.Errorf("http route: %+v", r.Result.Route)
	}

	// Traefik already merged the entry point middleware into the router: no duplicate.
	fx := homelabFixture()
	routers := fx["/http/routers"].([]any)
	routers[4].(map[string]any)["middlewares"] = []any{"crowdsec@file", "to-https"}
	s2, _ := analysisSession(t, fx, Options{})
	r = res{}
	s2.decode("find_route", map[string]any{"url": "http://app.example.com/"}, &r)
	if len(r.Result.Route.Middlewares) != 2 {
		t.Errorf("duplicate entry point middleware: %+v", r.Result.Route.Middlewares)
	}

	// TCP passthrough wins on the same entry point.
	r = res{}
	s.decode("find_route", map[string]any{"url": "https://mail.example.de"}, &r)
	if r.Result.Matched != "tcp" || r.Result.Route.Router != "mail@docker" {
		t.Errorf("tcp route: %+v", r)
	}

	// Entry point redirect.
	r = res{}
	s.decode("find_route", map[string]any{"url": "http://app.example.com:8000/"}, &r)
	if r.Result.Redirect == nil || r.Result.Redirect["to"] != "websecure" {
		t.Errorf("redirect: %+v", r)
	}

	// Unknown port -> all entry points + note; disabled router reported.
	r = res{}
	s.decode("find_route", map[string]any{"url": "https://broken.example.com:9443/"}, &r)
	notes := strings.Join(r.Result.Notes, " ")
	if r.Result.Matched != "none" || !strings.Contains(notes, "port 9443") || !strings.Contains(notes, "broken@file") {
		t.Errorf("broken: %+v", r)
	}

	if txt, isErr := call(t, s.cs, "find_route", map[string]any{"url": "ftp://x"}); !isErr {
		t.Errorf("ftp accepted: %s", txt)
	}
	if txt, isErr := call(t, s.cs, "find_route", map[string]any{"url": "https://x", "entrypoint": "nope"}); !isErr || !strings.Contains(txt, "nope") {
		t.Errorf("unknown entrypoint: %s", txt)
	}
}

func TestOverviewEntryPointsCertificates(t *testing.T) {
	s, _ := analysisSession(t, homelabFixture(), Options{})
	if txt := s.ok("get_overview", nil); !strings.Contains(txt, `"version":"3.7.0"`) || !strings.Contains(txt, `"total":5`) {
		t.Errorf("overview: %s", txt)
	}
	txt := s.ok("list_entrypoints", nil)
	for _, w := range []string{`"redirect":{"scheme":"https","to":"websecure"}`, `"protocol":"udp"`, `"port":443`, `"middlewares":["crowdsec@file"]`} {
		if !strings.Contains(txt, w) {
			t.Errorf("entrypoints missing %s: %s", w, txt)
		}
	}
	if txt := s.ok("get_entrypoint", map[string]any{"name": "web"}); !strings.Contains(txt, `":80"`) {
		t.Errorf("get_entrypoint: %s", txt)
	}
	if txt, isErr := call(t, s.cs, "get_entrypoint", map[string]any{"name": "nope"}); !isErr {
		t.Errorf("unknown entrypoint: %s", txt)
	}

	var certs struct {
		Count int              `json:"count"`
		Items []map[string]any `json:"items"`
	}
	s.decode("list_certificates", nil, &certs)
	if certs.Count != 3 || certs.Items[0]["common_name"] != "old.example.com" {
		t.Errorf("certificates not sorted by expiry: %+v", certs)
	}
	s.decode("list_certificates", map[string]any{"expiring_within_days": 30}, &certs)
	if certs.Count != 2 {
		t.Errorf("expiring filter: %+v", certs)
	}
	s.decode("list_certificates", map[string]any{"search": "www.fine"}, &certs)
	if certs.Count != 1 {
		t.Errorf("search: %+v", certs)
	}

	fx := homelabFixture()
	delete(fx, "/certificates")
	s2, _ := analysisSession(t, fx, Options{})
	if txt, isErr := call(t, s2.cs, "list_certificates", nil); !isErr || !strings.Contains(txt, "v3.7") {
		t.Errorf("v2 certificates: %s", txt)
	}
}

func TestCheckTLS(t *testing.T) {
	tlsSrv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {}))
	t.Cleanup(tlsSrv.Close)
	pool := x509.NewCertPool()
	pool.AddCert(tlsSrv.Certificate())
	rootCAs = pool
	t.Cleanup(func() { rootCAs = nil })

	fp := sha256.Sum256(tlsSrv.Certificate().Raw)
	fx := homelabFixture()
	fx["/certificates"] = []any{map[string]any{"commonName": "x", "notAfter": day(10), "certFingerprint": hex.EncodeToString(fp[:])}}
	s, _ := analysisSession(t, fx, Options{Order: []string{"a", "b"}})

	u, _ := url.Parse(tlsSrv.URL)
	var out map[string]any
	s.decode("check_tls_endpoint", map[string]any{"host": u.Host, "sni": "example.com"}, &out)
	if out["verified"] != true || out["tls_version"] == "" {
		t.Errorf("verified: %v", out)
	}
	if stores, _ := out["in_traefik_store"].([]any); len(stores) != 2 {
		t.Errorf("store cross-reference: %v", out["in_traefik_store"])
	}
	out = nil
	s.decode("check_tls_endpoint", map[string]any{"host": "https://" + u.Host + "/path", "sni": "wrong.test", "instance": "a"}, &out)
	if out["verified"] != false || out["verify_error"] == nil {
		t.Errorf("hostname mismatch not detected: %v", out)
	}
	if txt, isErr := call(t, s.cs, "check_tls_endpoint", map[string]any{"host": "127.0.0.1", "port": 1}); !isErr || !strings.Contains(txt, "handshake") {
		t.Errorf("closed port: %s", txt)
	}

	// Disabled via options.
	s3, _ := analysisSession(t, homelabFixture(), Options{DisableTLSCheck: true})
	if txt, isErr := call(t, s3.cs, "check_tls_endpoint", map[string]any{"host": "x"}); !isErr {
		t.Errorf("tool should be absent: %s", txt)
	}
}

// Every tool must survive "arguments": null without crashing the server.
func TestAllToolsNilArguments(t *testing.T) {
	s, _ := analysisSession(t, homelabFixture(), Options{})
	res, err := s.cs.ListTools(t.Context(), nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, tool := range res.Tools {
		_, _ = call(t, s.cs, tool.Name, nil)
	}
	s.ok("get_overview", nil) // server still alive
}

// ClientSessionWrapper adds assertion helpers around a client session.
type ClientSessionWrapper struct {
	t  *testing.T
	cs *mcp.ClientSession
}

func (s *ClientSessionWrapper) ok(tool string, args map[string]any) string {
	s.t.Helper()
	txt, isErr := call(s.t, s.cs, tool, args)
	if isErr {
		s.t.Fatalf("%s %v: %s", tool, args, txt)
	}
	return txt
}

func (s *ClientSessionWrapper) decode(tool string, args map[string]any, v any) {
	s.t.Helper()
	txt := s.ok(tool, args)
	if err := json.Unmarshal([]byte(txt), v); err != nil {
		s.t.Fatalf("%s: %v: %s", tool, err, txt)
	}
}
