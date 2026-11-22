package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/virtualben89/traefik-mcp-go/internal/traefik"
)

// fakeTraefik serves a tiny subset of the Traefik API with Traefik-like pagination.
func fakeTraefik(t *testing.T, name string, routers []map[string]any) *httptest.Server {
	t.Helper()
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.URL.Path == "/api/version":
			_, _ = io.WriteString(w, `{"Version":"3.7.0-`+name+`","Codename":"test","startDate":"2026-01-01T00:00:00Z"}`)
		case r.URL.Path == "/api/http/routers":
			q := r.URL.Query()
			var filtered []map[string]any
			for _, it := range routers {
				if s := q.Get("search"); s != "" && !strings.Contains(strings.ToLower(it["name"].(string)), strings.ToLower(s)) {
					continue
				}
				if s := q.Get("status"); s != "" && it["status"] != s {
					continue
				}
				filtered = append(filtered, it)
			}
			page, _ := strconv.Atoi(q.Get("page"))
			per, _ := strconv.Atoi(q.Get("per_page"))
			if page < 1 {
				page = 1
			}
			if per < 1 {
				per = 100
			}
			start := (page - 1) * per
			if start != 0 && start >= len(filtered) {
				w.WriteHeader(http.StatusBadRequest)
				_, _ = io.WriteString(w, `{"message":"invalid request: page"}`)
				return
			}
			end := min(start+per, len(filtered))
			next := 1
			if page*per < len(filtered) {
				next = page + 1
			}
			w.Header().Set("X-Next-Page", strconv.Itoa(next))
			out := filtered[start:end]
			if out == nil {
				out = []map[string]any{}
			}
			_ = json.NewEncoder(w).Encode(out)
		case strings.HasPrefix(r.URL.Path, "/api/http/routers/"):
			n := strings.TrimPrefix(r.URL.Path, "/api/http/routers/")
			for _, it := range routers {
				if it["name"] == n {
					_ = json.NewEncoder(w).Encode(it)
					return
				}
			}
			w.WriteHeader(http.StatusNotFound)
			_, _ = io.WriteString(w, `{"message":"router not found"}`)
		case r.URL.Path == "/api/tcp/middlewares":
			w.Header().Set("X-Next-Page", "1")
			_, _ = io.WriteString(w, `[{"name":"allow@file","type":"ipallowlist","status":"enabled"}]`)
		case strings.Count(r.URL.Path, "/") == 3: // other /api/<proto>/<kind> lists
			w.Header().Set("X-Next-Page", "1")
			_, _ = io.WriteString(w, `[]`)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(ts.Close)
	return ts
}

func router(name, status string) map[string]any {
	return map[string]any{"name": name, "status": status, "rule": "Host(`" + name + "`)", "service": "svc",
		"observability": map[string]any{"accessLogs": true}, "priorityStr": "1"}
}

func connect(t *testing.T, opts Options, instances map[string]Instance) *mcp.ClientSession {
	t.Helper()
	srv := mcp.NewServer(&mcp.Implementation{Name: "test", Version: "0"}, nil)
	Register(srv, instances, opts)
	ct, st := mcp.NewInMemoryTransports()
	ctx := context.Background()
	if _, err := srv.Connect(ctx, st, nil); err != nil {
		t.Fatal(err)
	}
	cs, err := mcp.NewClient(&mcp.Implementation{Name: "c", Version: "0"}, nil).Connect(ctx, ct, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cs.Close() })
	return cs
}

func inst(t *testing.T, name, url string) Instance {
	t.Helper()
	c, err := traefik.New(traefik.Options{Name: name, BaseURL: url})
	if err != nil {
		t.Fatal(err)
	}
	return Instance{Client: c, URL: c.BaseURL(), Auth: "none"}
}

func call(t *testing.T, cs *mcp.ClientSession, name string, args map[string]any) (string, bool) {
	t.Helper()
	res, err := cs.CallTool(context.Background(), &mcp.CallToolParams{Name: name, Arguments: args})
	if err != nil {
		return err.Error(), true
	}
	return res.Content[0].(*mcp.TextContent).Text, res.IsError
}

func setup(t *testing.T) *mcp.ClientSession {
	var rs []map[string]any
	for i := range 5 {
		rs = append(rs, router(fmt.Sprintf("app%d@docker", i), "enabled"))
	}
	rs = append(rs, router("dup@docker", "enabled"), router("dup@file", "warning"), router("solo@file", "disabled"))
	a := fakeTraefik(t, "a", rs)
	b := fakeTraefik(t, "b", nil)
	return connect(t, Options{Order: []string{"edge", "lan"}, DefaultPerPage: 100},
		map[string]Instance{"edge": inst(t, "edge", a.URL), "lan": inst(t, "lan", b.URL+"/api/")})
}

func TestSchemasPortable(t *testing.T) {
	cs := setup(t)
	res, err := cs.ListTools(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Tools) != 14 {
		t.Fatalf("got %d tools", len(res.Tools))
	}
	for _, tool := range res.Tools {
		b, _ := json.Marshal(tool.InputSchema)
		s := string(b)
		if strings.Contains(s, `"type":[`) || strings.Contains(s, `$ref`) || strings.Contains(s, `$defs`) {
			t.Errorf("%s: non-portable schema %s", tool.Name, s)
		}
		if tool.Annotations == nil || !tool.Annotations.ReadOnlyHint {
			t.Errorf("%s: missing readOnlyHint", tool.Name)
		}
		if tool.Name != "list_instances" && !strings.Contains(s, `"enum":["edge","lan"]`) {
			t.Errorf("%s: instance enum missing: %s", tool.Name, s)
		}
	}
}

func TestListInstances(t *testing.T) {
	cs := setup(t)
	txt, isErr := call(t, cs, "list_instances", nil)
	if isErr || !strings.Contains(txt, `"version":"3.7.0-a"`) || !strings.Contains(txt, `"version":"3.7.0-b"`) || !strings.Contains(txt, `"default":"edge"`) {
		t.Fatalf("list_instances: %s", txt)
	}
	txt, _ = call(t, cs, "list_instances", map[string]any{"probe": false})
	if strings.Contains(txt, "version") {
		t.Errorf("probe=false still probed: %s", txt)
	}
}

func TestListRoutersPagingAndSlim(t *testing.T) {
	cs := setup(t)
	txt, isErr := call(t, cs, "list_routers", map[string]any{"per_page": 3})
	if isErr {
		t.Fatal(txt)
	}
	var out struct {
		Count    int              `json:"count"`
		NextPage int              `json:"next_page"`
		Items    []map[string]any `json:"items"`
	}
	_ = json.Unmarshal([]byte(txt), &out)
	if out.Count != 3 || out.NextPage != 2 {
		t.Fatalf("page 1: %s", txt)
	}
	if _, ok := out.Items[0]["observability"]; ok {
		t.Error("observability not stripped")
	}
	txt, _ = call(t, cs, "list_routers", map[string]any{"per_page": 3, "page": 3, "full": true})
	out.NextPage = 0
	_ = json.Unmarshal([]byte(txt), &out)
	if out.Count != 2 || out.NextPage != 0 {
		t.Fatalf("last page: %s", txt)
	}
	if _, ok := out.Items[0]["observability"]; !ok {
		t.Error("full=true must keep observability")
	}
	txt, isErr = call(t, cs, "list_routers", map[string]any{"per_page": 3, "page": 9})
	if isErr || !strings.Contains(txt, `"count":0`) {
		t.Fatalf("beyond last page: %s", txt)
	}
	txt, _ = call(t, cs, "list_routers", map[string]any{"status": "warning"})
	if !strings.Contains(txt, `"count":1`) || !strings.Contains(txt, "dup@file") {
		t.Fatalf("status filter: %s", txt)
	}
	txt, _ = call(t, cs, "list_routers", map[string]any{"instance": "lan"})
	if !strings.Contains(txt, `"instance":"lan"`) || !strings.Contains(txt, `"items":[]`) {
		t.Fatalf("second instance: %s", txt)
	}
}

func TestGetRouterResolution(t *testing.T) {
	cs := setup(t)
	for _, tc := range []struct {
		name, want string
		err        bool
	}{
		{"solo", `"name":"solo@file"`, false},
		{"app3@docker", `"name":"app3@docker"`, false},
		{"dup", "ambiguous", true},
		{"missing", "not found", true},
		{"missing@docker", "not found", true},
	} {
		txt, isErr := call(t, cs, "get_router", map[string]any{"name": tc.name})
		if isErr != tc.err || !strings.Contains(txt, tc.want) {
			t.Errorf("%s: err=%v %s", tc.name, isErr, txt)
		}
	}
}

// Clients may send "arguments": null; this must never crash the server.
func TestNilArguments(t *testing.T) {
	cs := setup(t)
	for _, name := range []string{"list_instances", "list_routers", "list_services", "list_middlewares"} {
		if txt, isErr := call(t, cs, name, nil); isErr {
			t.Errorf("%s with nil args: %s", name, txt)
		}
	}
	if txt, isErr := call(t, cs, "get_router", nil); !isErr {
		t.Errorf("get_router without name: %s", txt)
	}
}

func TestValidation(t *testing.T) {
	cs := setup(t)
	if txt, isErr := call(t, cs, "list_routers", map[string]any{"instance": "nope"}); !isErr {
		t.Errorf("unknown instance accepted: %s", txt)
	}
	if txt, isErr := call(t, cs, "list_middlewares", map[string]any{"protocol": "udp"}); !isErr {
		t.Errorf("udp middlewares accepted: %s", txt)
	}
	if txt, isErr := call(t, cs, "list_middlewares", map[string]any{"protocol": "tcp"}); isErr || !strings.Contains(txt, "allow@file") {
		t.Errorf("tcp middlewares: %s", txt)
	}
	if txt, isErr := call(t, cs, "get_service", map[string]any{}); !isErr {
		t.Errorf("missing name accepted: %s", txt)
	}
}

func TestUpstreamAuth(t *testing.T) {
	var got http.Header
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.Header.Clone()
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"Version":"x"}`)
	}))
	defer up.Close()
	c, _ := traefik.New(traefik.Options{Name: "x", BaseURL: up.URL, BearerToken: "up-token", Headers: map[string]string{"X-Extra": "1"}})
	if _, err := c.Version(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got.Get("Authorization") != "Bearer up-token" || got.Get("X-Extra") != "1" {
		t.Errorf("headers: %v", got)
	}
	c, _ = traefik.New(traefik.Options{Name: "x", BaseURL: up.URL, BasicUser: "u", BasicPassword: "p"})
	_, _ = c.Version(context.Background())
	if u, p, ok := (&http.Request{Header: got}).BasicAuth(); !ok || u != "u" || p != "p" {
		t.Errorf("basic auth missing: %v", got)
	}
}

func TestUpstreamErrors(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/version" {
			w.Header().Set("Content-Type", "text/html")
			_, _ = io.WriteString(w, "<html>login</html>")
			return
		}
		http.Error(w, "401 Unauthorized", http.StatusUnauthorized)
	}))
	defer up.Close()
	c, _ := traefik.New(traefik.Options{Name: "x", BaseURL: up.URL})
	if _, err := c.Version(context.Background()); err == nil || !strings.Contains(err.Error(), "content type") {
		t.Errorf("html must be rejected: %v", err)
	}
	if _, err := c.Get(context.Background(), "/http/routers", nil); err == nil || !strings.Contains(err.Error(), "credentials") {
		t.Errorf("401 hint missing: %v", err)
	}
}
