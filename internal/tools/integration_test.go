//go:build integration

// Integration tests against a real Traefik started with testdata/traefik.
// Run: TRAEFIK_TEST_URL=http://localhost:8080 go test -tags integration ./internal/tools/
package tools

import (
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

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
		{"list_routers", map[string]any{"service": "whoami@file", "status": "enabled"}, []string{`"count":2`}},
		{"list_routers", map[string]any{"service": "whoami"}, []string{`"count":2`}},
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
