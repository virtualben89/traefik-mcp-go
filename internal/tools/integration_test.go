//go:build integration

// Integration tests against a real Traefik started with testdata/traefik.
// Run: TRAEFIK_TEST_URL=http://localhost:8080 go test -tags integration ./internal/tools/
package tools

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"
)

func realSession(t *testing.T) *ClientSessionWrapper {
	t.Helper()
	u := os.Getenv("TRAEFIK_TEST_URL")
	if u == "" {
		t.Skip("TRAEFIK_TEST_URL not set")
	}
	cs := connect(t, Options{Order: []string{"it"}}, map[string]Instance{"it": inst(t, "it", u)})
	return &ClientSessionWrapper{t: t, cs: cs}
}

func TestIntegration(t *testing.T) {
	s := realSession(t)

	txt := s.ok("list_instances", nil)
	if !strings.Contains(txt, `"reachable":true`) {
		t.Fatalf("list_instances: %s", txt)
	}

	for _, tc := range []struct {
		tool  string
		args  map[string]any
		wants []string
	}{
		{"list_routers", nil, []string{`"whoami@file"`, `"whoami-secure@file"`, `"broken@file"`}},
		{"list_routers", map[string]any{"status": "disabled"}, []string{`"broken@file"`, `"count":1`}},
		{"list_routers", map[string]any{"middleware": "auth@file"}, []string{`"whoami-secure@file"`, `"count":1`}},
		{"list_routers", map[string]any{"middleware": "headers", "per_page": 1}, []string{`"count":1`, `"next_page":2`}},
		{"list_routers", map[string]any{"service": "whoami@file", "status": "enabled"}, []string{`"count":4`}},
		{"list_routers", map[string]any{"service": "whoami"}, []string{`"count":4`}},
		{"list_routers", map[string]any{"protocol": "tcp"}, []string{`"pg@file"`}},
		{"list_routers", map[string]any{"protocol": "udp"}, []string{`"dns@file"`}},
		{"list_services", map[string]any{"search": "whoami"}, []string{`"whoami@file"`, `"serverStatus"`}},
		{"list_services", map[string]any{"protocol": "tcp"}, []string{`"pg@file"`}},
		{"list_services", map[string]any{"protocol": "udp"}, []string{`"dns@file"`}},
		{"list_middlewares", nil, []string{`"headers@file"`, `"auth@file"`}},
		{"list_middlewares", map[string]any{"protocol": "tcp"}, []string{`"allowlist@file"`}},
		{"get_router", map[string]any{"name": "broken"}, []string{`"status":"disabled"`, `"error"`}},
		{"get_router", map[string]any{"name": "pg@file", "protocol": "tcp"}, []string{"HostSNI"}},
		{"get_router", map[string]any{"name": "dns", "protocol": "udp"}, []string{`"dns@file"`}},
		{"get_service", map[string]any{"name": "whoami"}, []string{`"usedBy"`, `"whoami-secure@file"`, "127.0.0.1:1"}},
		{"get_service", map[string]any{"name": "pg", "protocol": "tcp"}, []string{"127.0.0.1:5432"}},
		{"get_middleware", map[string]any{"name": "auth"}, []string{`"basicAuth"`}},
		{"get_middleware", map[string]any{"name": "allowlist", "protocol": "tcp"}, []string{"127.0.0.1/32"}},
	} {
		b, _ := json.Marshal(tc.args)
		txt := s.ok(tc.tool, tc.args)
		for _, w := range tc.wants {
			if !strings.Contains(txt, w) {
				t.Errorf("%s %s: missing %s in %s", tc.tool, b, w, txt)
			}
		}
	}

	// Pagination over real Traefik: 1 item per page.
	txt = s.ok("list_routers", map[string]any{"per_page": 1})
	if !strings.Contains(txt, `"next_page":2`) {
		t.Errorf("pagination: %s", txt)
	}
	txt = s.ok("list_routers", map[string]any{"per_page": 1, "page": 99})
	if !strings.Contains(txt, `"count":0`) {
		t.Errorf("beyond last page: %s", txt)
	}

	if txt, isErr := call(t, s.cs, "get_router", map[string]any{"name": "nope"}); !isErr || !strings.Contains(txt, "not found") {
		t.Errorf("not found: %s", txt)
	}
}

func TestIntegrationAnalysis(t *testing.T) {
	s := realSession(t)

	if txt := s.ok("get_overview", nil); !strings.Contains(txt, `"routers"`) {
		t.Errorf("overview: %s", txt)
	}
	txt := s.ok("list_entrypoints", nil)
	for _, w := range []string{`"name":"websecure"`, `"redirect":{"scheme":"https","to":"websecure"}`, `"protocol":"udp"`} {
		if !strings.Contains(txt, w) {
			t.Errorf("entrypoints missing %s: %s", w, txt)
		}
	}
	if txt := s.ok("get_entrypoint", map[string]any{"name": "redir"}); !strings.Contains(txt, "redirections") {
		t.Errorf("get_entrypoint: %s", txt)
	}

	// /api/certificates exists from v3.7 on.
	if txt, isErr := call(t, s.cs, "list_certificates", nil); isErr && !strings.Contains(txt, "v3.7") {
		t.Errorf("list_certificates: %s", txt)
	}

	// Health checks need a moment to mark the backend DOWN.
	var rep struct {
		Instances map[string]struct {
			Findings []finding `json:"findings"`
		} `json:"instances"`
	}
	want := map[string]string{
		"http router|broken@file": "error",
		"ghost router|ghost@file": "warning",
		"http service|down@file":  "error",
		"plain http|whoami@file":  "info",
	}
	var got map[string]string
	for range 20 {
		s.decode("health_report", nil, &rep)
		got = map[string]string{}
		for _, f := range rep.Instances["it"].Findings {
			got[f.Category+"|"+f.Object] = f.Severity
		}
		if got["http service|down@file"] != "" {
			break
		}
		time.Sleep(500 * time.Millisecond)
	}
	for k, sev := range want {
		if got[k] != sev {
			t.Errorf("health %s: want %s, got %q (all: %v)", k, sev, got[k], got)
		}
	}

	for _, tc := range []struct {
		args   map[string]any
		router string
	}{
		{map[string]any{"url": "https://secure.test:8443/"}, "secure@file"},
		{map[string]any{"url": "https://secure.test:8443/api/v1"}, "secure-api@file"},
		{map[string]any{"url": "http://whoami.test:8000/secure/x"}, "whoami-secure@file"},
		{map[string]any{"url": "http://whoami.test:8000/"}, "whoami@file"},
	} {
		txt := s.ok("find_route", tc.args)
		if !strings.Contains(txt, `"matched":"http"`) || !strings.Contains(txt, `"route":{"entrypoints"`) || !strings.Contains(txt, `"router":"`+tc.router+`"`) {
			t.Errorf("find_route %v: want %s, got %s", tc.args, tc.router, txt)
		}
	}
	if txt := s.ok("find_route", map[string]any{"url": "http://x.test:8001/"}); !strings.Contains(txt, `"entrypoint_redirect"`) {
		t.Errorf("redirect: %s", txt)
	}
	if txt := s.ok("find_route", map[string]any{"url": "https://db.test:9000/"}); !strings.Contains(txt, `"matched":"none"`) {
		// pg@file is a non-TLS HostSNI(*) router: it only catches plain TCP.
		t.Errorf("tls on tcp entrypoint: %s", txt)
	}
	if txt := s.ok("find_route", map[string]any{"url": "http://db.test:9000/"}); !strings.Contains(txt, `"matched":"tcp"`) || !strings.Contains(txt, "pg@file") {
		t.Errorf("plain tcp: %s", txt)
	}
}
