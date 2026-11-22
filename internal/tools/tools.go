// Package tools registers the read-only Traefik MCP tools.
package tools

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/jsonschema-go/jsonschema"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/virtualben89/traefik-mcp-go/internal/traefik"
)

// Instance is a configured Traefik endpoint as seen by the tools.
type Instance struct {
	Client *traefik.Client
	URL    string
	Auth   string // bearer, basic, headers, none
}

// Options controls tool registration.
type Options struct {
	Prefix         string
	DefaultPerPage int
	// Default is the instance used when a call omits "instance".
	Default string
	// Order is the configured instance order (names).
	Order []string
}

// Registry adds tools to a server.
type Registry struct {
	srv       *mcp.Server
	instances map[string]Instance
	opts      Options
	names     []string
}

// Register adds all tools and returns their names.
func Register(srv *mcp.Server, instances map[string]Instance, opts Options) []string {
	if opts.DefaultPerPage <= 0 {
		opts.DefaultPerPage = 100
	}
	if opts.Default == "" && len(opts.Order) > 0 {
		opts.Default = opts.Order[0]
	}
	r := &Registry{srv: srv, instances: instances, opts: opts}
	r.registerAll()
	return r.names
}

func ptr[T any](v T) *T { return &v }

type toolDef struct {
	name        string
	title       string
	description string
	enums       map[string][]any // property name -> allowed values
}

// add registers a typed read-only tool.
func add[In any](r *Registry, d toolDef, h func(context.Context, In) (*mcp.CallToolResult, error)) {
	schema, err := jsonschema.For[In](nil)
	if err != nil {
		panic(fmt.Sprintf("schema for %s: %v", d.name, err))
	}
	sanitizeSchema(schema)
	for prop, vals := range d.enums {
		s, ok := schema.Properties[prop]
		if !ok {
			panic(fmt.Sprintf("tool %s: enum for unknown property %s", d.name, prop))
		}
		s.Enum = vals
	}
	// Deliberately no schema "default" values: go-sdk panics applying defaults
	// when a client sends "arguments": null. Defaults are applied in code.

	name := r.opts.Prefix + d.name
	tool := &mcp.Tool{
		Name:        name,
		Title:       d.title,
		Description: d.description,
		InputSchema: schema,
		Annotations: &mcp.ToolAnnotations{
			Title:          d.title,
			ReadOnlyHint:   true,
			IdempotentHint: true,
			OpenWorldHint:  ptr(false),
		},
	}
	mcp.AddTool(r.srv, tool, func(ctx context.Context, _ *mcp.CallToolRequest, in In) (*mcp.CallToolResult, any, error) {
		res, err := h(ctx, in)
		if err != nil {
			return errorResult(err), nil, nil
		}
		return res, nil, nil
	})
	r.names = append(r.names, name)
}

// sanitizeSchema makes generated schemas friendly to a wide range of clients
// (e.g. Gemini / OpenAI function calling reject `"type": ["null","string"]`).
func sanitizeSchema(s *jsonschema.Schema) {
	if s == nil {
		return
	}
	if len(s.Types) > 0 {
		var nonNull []string
		for _, t := range s.Types {
			if t != "null" {
				nonNull = append(nonNull, t)
			}
		}
		if len(nonNull) == 1 {
			s.Type = nonNull[0]
			s.Types = nil
		}
	}
	for _, p := range s.Properties {
		sanitizeSchema(p)
	}
	sanitizeSchema(s.Items)
}

func errorResult(err error) *mcp.CallToolResult {
	return &mcp.CallToolResult{
		IsError: true,
		Content: []mcp.Content{&mcp.TextContent{Text: err.Error()}},
	}
}

func valueResult(v any) (*mcp.CallToolResult, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: string(b)}}}, nil
}

// ---- inputs ----

// ListRoutersInput are the parameters of list_routers.
type ListRoutersInput struct {
	Instance   string `json:"instance,omitempty" jsonschema:"Traefik instance name (see list_instances); omit for the default instance"`
	Protocol   string `json:"protocol,omitempty" jsonschema:"Router protocol: http (default), tcp or udp"`
	Search     string `json:"search,omitempty" jsonschema:"Case-insensitive substring filter on name, rule, service, provider"`
	Status     string `json:"status,omitempty" jsonschema:"Only routers with this status"`
	Service    string `json:"service,omitempty" jsonschema:"Only routers pointing to this service (name or name@provider)"`
	Middleware string `json:"middleware,omitempty" jsonschema:"Only routers using this middleware (name or name@provider)"`
	Page       int    `json:"page,omitempty" jsonschema:"Page number starting at 1"`
	PerPage    int    `json:"per_page,omitempty" jsonschema:"Items per page"`
	Full       bool   `json:"full,omitempty" jsonschema:"Return the complete objects incl. observability settings"`
}

// ListServicesInput are the parameters of list_services.
type ListServicesInput struct {
	Instance string `json:"instance,omitempty" jsonschema:"Traefik instance name (see list_instances); omit for the default instance"`
	Protocol string `json:"protocol,omitempty" jsonschema:"Service protocol: http (default), tcp or udp"`
	Search   string `json:"search,omitempty" jsonschema:"Case-insensitive substring filter on name, type, provider"`
	Status   string `json:"status,omitempty" jsonschema:"Only services with this status"`
	Page     int    `json:"page,omitempty" jsonschema:"Page number starting at 1"`
	PerPage  int    `json:"per_page,omitempty" jsonschema:"Items per page"`
	Full     bool   `json:"full,omitempty" jsonschema:"Return the complete objects"`
}

// ListMiddlewaresInput are the parameters of list_middlewares.
type ListMiddlewaresInput struct {
	Instance string `json:"instance,omitempty" jsonschema:"Traefik instance name (see list_instances); omit for the default instance"`
	Protocol string `json:"protocol,omitempty" jsonschema:"Middleware protocol: http (default) or tcp (UDP has no middlewares)"`
	Search   string `json:"search,omitempty" jsonschema:"Case-insensitive substring filter on name, type, provider"`
	Status   string `json:"status,omitempty" jsonschema:"Only middlewares with this status"`
	Page     int    `json:"page,omitempty" jsonschema:"Page number starting at 1"`
	PerPage  int    `json:"per_page,omitempty" jsonschema:"Items per page"`
	Full     bool   `json:"full,omitempty" jsonschema:"Return the complete objects"`
}

// GetInput are the parameters of the get_* tools.
type GetInput struct {
	Instance string `json:"instance,omitempty" jsonschema:"Traefik instance name (see list_instances); omit for the default instance"`
	Protocol string `json:"protocol,omitempty" jsonschema:"Protocol: http (default), tcp or udp"`
	Name     string `json:"name" jsonschema:"Object name, ideally with provider suffix (e.g. whoami@docker). Without suffix it is resolved if unique."`
}

// ListInstancesInput are the parameters of list_instances.
type ListInstancesInput struct {
	Probe *bool `json:"probe,omitempty" jsonschema:"Query /api/version of every instance to report reachability and version (default true)"`
}

// ---- helpers ----

type kind struct {
	path   string // routers, services, middlewares
	single string // router, service, middleware
}

var (
	kRouters     = kind{"routers", "router"}
	kServices    = kind{"services", "service"}
	kMiddlewares = kind{"middlewares", "middleware"}
)

func (r *Registry) instance(name string) (Instance, string, error) {
	name = strings.ToLower(strings.TrimSpace(name))
	if name == "" {
		name = r.opts.Default
	}
	in, ok := r.instances[name]
	if !ok {
		return Instance{}, "", fmt.Errorf("unknown instance %q; configured: %s", name, strings.Join(r.opts.Order, ", "))
	}
	return in, name, nil
}

func protocol(p string, k kind) (string, error) {
	p = strings.ToLower(strings.TrimSpace(p))
	if p == "" {
		p = "http"
	}
	switch p {
	case "http", "tcp":
		return p, nil
	case "udp":
		if k == kMiddlewares {
			return "", errors.New("UDP has no middlewares; use protocol http or tcp")
		}
		return p, nil
	}
	return "", fmt.Errorf("invalid protocol %q (use http, tcp or udp)", p)
}

// noisyKeys are dropped from list items unless full=true.
var noisyKeys = []string{"observability", "priorityStr"}

func slim(items []map[string]any) {
	for _, it := range items {
		for _, k := range noisyKeys {
			delete(it, k)
		}
	}
}

type listParams struct {
	instance, protocol                      string
	search, status, serviceName, middleware string
	page, perPage                           int
	full                                    bool
}

func (r *Registry) list(ctx context.Context, k kind, p listParams) (*mcp.CallToolResult, error) {
	in, iname, err := r.instance(p.instance)
	if err != nil {
		return nil, err
	}
	proto, err := protocol(p.protocol, k)
	if err != nil {
		return nil, err
	}
	if p.page < 0 || p.perPage < 0 {
		return nil, errors.New("page and per_page must be positive")
	}
	if p.page == 0 {
		p.page = 1
	}
	if p.perPage == 0 {
		p.perPage = r.opts.DefaultPerPage
	}
	base := url.Values{}
	if p.search != "" {
		base.Set("search", p.search)
	}
	if p.status != "" {
		base.Set("status", strings.ToLower(p.status))
	}

	var (
		items    []map[string]any
		nextPage int
	)
	if p.serviceName != "" || p.middleware != "" {
		// Traefik v2 ignores serviceName/middlewareName, and v3 matches them
		// strictly. Fetch all matching routers and filter + paginate locally.
		all, err := fetchAll(ctx, in.Client, "/"+proto+"/"+k.path, base)
		if err != nil {
			return nil, err
		}
		for _, it := range all {
			if matchService(it, p.serviceName) && matchMiddleware(it, p.middleware) {
				items = append(items, it)
			}
		}
		start := (p.page - 1) * p.perPage
		if start >= len(items) {
			items = nil
		} else {
			end := min(start+p.perPage, len(items))
			if end < len(items) {
				nextPage = p.page + 1
			}
			items = items[start:end]
		}
	} else {
		q := url.Values{}
		for k, v := range base {
			q[k] = v
		}
		q.Set("page", strconv.Itoa(p.page))
		q.Set("per_page", strconv.Itoa(p.perPage))
		resp, err := in.Client.Get(ctx, "/"+proto+"/"+k.path, q)
		if err != nil {
			// Traefik answers 400 when page is beyond the last page.
			var ae *traefik.APIError
			if errors.As(err, &ae) && ae.Status == 400 && p.page > 1 {
				return valueResult(map[string]any{"instance": iname, "protocol": proto, "kind": k.path, "page": p.page, "per_page": p.perPage, "count": 0, "items": []any{}})
			}
			return nil, err
		}
		if err := json.Unmarshal(resp.Body, &items); err != nil {
			return nil, fmt.Errorf("decoding %s list: %w", k.path, err)
		}
		nextPage = resp.NextPage
	}
	if items == nil {
		items = []map[string]any{}
	}
	if !p.full {
		slim(items)
	}
	out := map[string]any{
		"instance": iname,
		"protocol": proto,
		"kind":     k.path,
		"page":     p.page,
		"per_page": p.perPage,
		"count":    len(items),
		"items":    items,
	}
	if nextPage > 0 {
		out["next_page"] = nextPage
	}
	return valueResult(out)
}

// fetchAll reads every page of a list endpoint.
func fetchAll(ctx context.Context, c *traefik.Client, path string, base url.Values) ([]map[string]any, error) {
	var all []map[string]any
	for page := 1; page <= 1000; page++ {
		q := url.Values{}
		for k, v := range base {
			q[k] = v
		}
		q.Set("page", strconv.Itoa(page))
		q.Set("per_page", "500")
		resp, err := c.Get(ctx, path, q)
		if err != nil {
			return nil, err
		}
		var items []map[string]any
		if err := json.Unmarshal(resp.Body, &items); err != nil {
			return nil, fmt.Errorf("decoding %s: %w", path, err)
		}
		all = append(all, items...)
		if resp.NextPage == 0 {
			break
		}
	}
	return all, nil
}

// sameName compares object references; the provider suffix is only compared
// when both sides carry one ("whoami" matches "whoami@docker").
func sameName(a, b string) bool {
	if strings.Contains(a, "@") && strings.Contains(b, "@") {
		return a == b
	}
	an, _, _ := strings.Cut(a, "@")
	bn, _, _ := strings.Cut(b, "@")
	return an == bn
}

func matchService(it map[string]any, want string) bool {
	if want == "" {
		return true
	}
	s, _ := it["service"].(string)
	return s != "" && sameName(s, want)
}

func matchMiddleware(it map[string]any, want string) bool {
	if want == "" {
		return true
	}
	mws, _ := it["middlewares"].([]any)
	for _, m := range mws {
		if s, ok := m.(string); ok && sameName(s, want) {
			return true
		}
	}
	return false
}

// resolveName turns "foo" into "foo@provider" when exactly one object matches.
func resolveName(ctx context.Context, c *traefik.Client, proto string, k kind, name string) (string, error) {
	if strings.Contains(name, "@") {
		return name, nil
	}
	var matches []string
	for page := 1; page <= 100; page++ {
		q := url.Values{"search": {name}, "page": {strconv.Itoa(page)}, "per_page": {"500"}}
		resp, err := c.Get(ctx, "/"+proto+"/"+k.path, q)
		if err != nil {
			return "", err
		}
		var items []struct {
			Name string `json:"name"`
		}
		if err := json.Unmarshal(resp.Body, &items); err != nil {
			return "", err
		}
		for _, it := range items {
			if before, _, _ := strings.Cut(it.Name, "@"); before == name {
				matches = append(matches, it.Name)
			}
		}
		if resp.NextPage == 0 {
			break
		}
	}
	switch len(matches) {
	case 0:
		return "", fmt.Errorf("%s %s %q not found on instance %s; use list_%s with search to find it", proto, k.single, name, c.Name(), k.path)
	case 1:
		return matches[0], nil
	default:
		return "", fmt.Errorf("%s %s %q is ambiguous on instance %s, specify one of: %s", proto, k.single, name, c.Name(), strings.Join(matches, ", "))
	}
}

func (r *Registry) get(ctx context.Context, k kind, in GetInput) (*mcp.CallToolResult, error) {
	inst, iname, err := r.instance(in.Instance)
	if err != nil {
		return nil, err
	}
	proto, err := protocol(in.Protocol, k)
	if err != nil {
		return nil, err
	}
	name := strings.TrimSpace(in.Name)
	if name == "" {
		return nil, errors.New("name is required")
	}
	full, err := resolveName(ctx, inst.Client, proto, k, name)
	if err != nil {
		return nil, err
	}
	resp, err := inst.Client.Get(ctx, "/"+proto+"/"+k.path+"/"+url.PathEscape(full), nil)
	if err != nil {
		if traefik.IsNotFound(err) {
			return nil, fmt.Errorf("%s %s %q not found on instance %s; use list_%s with search to find it", proto, k.single, full, iname, k.path)
		}
		return nil, err
	}
	var obj map[string]any
	if err := json.Unmarshal(resp.Body, &obj); err != nil {
		return nil, fmt.Errorf("decoding %s: %w", k.single, err)
	}
	return valueResult(map[string]any{"instance": iname, "protocol": proto, k.single: obj})
}

// ---- registration ----

func (r *Registry) registerAll() {
	instEnum := make([]any, len(r.opts.Order))
	for i, n := range r.opts.Order {
		instEnum[i] = n
	}
	all := []any{"http", "tcp", "udp"}
	noUDP := []any{"http", "tcp"}
	status := []any{"enabled", "disabled", "warning"}

	add(r, toolDef{
		name:  "list_instances",
		title: "List Traefik instances",
		description: "List the configured Traefik instances (name, API URL, auth mode, default flag). " +
			"With probe (default) also reports reachability and Traefik version of each instance.",
	}, func(ctx context.Context, in ListInstancesInput) (*mcp.CallToolResult, error) {
		probe := in.Probe == nil || *in.Probe
		out := make([]map[string]any, len(r.opts.Order))
		var wg sync.WaitGroup
		for i, name := range r.opts.Order {
			inst := r.instances[name]
			row := map[string]any{"name": name, "url": inst.URL, "auth": inst.Auth, "default": name == r.opts.Default}
			out[i] = row
			if !probe {
				continue
			}
			wg.Add(1)
			go func() {
				defer wg.Done()
				pctx, cancel := context.WithTimeout(ctx, 10*time.Second)
				defer cancel()
				v, err := inst.Client.Version(pctx)
				if err != nil {
					row["reachable"] = false
					row["error"] = err.Error()
					return
				}
				row["reachable"] = true
				row["version"] = v.Version
				row["start_date"] = v.StartDate
			}()
		}
		wg.Wait()
		return valueResult(map[string]any{"default": r.opts.Default, "instances": out})
	})

	add(r, toolDef{
		name:  "list_routers",
		title: "List routers",
		description: "List HTTP, TCP or UDP routers of a Traefik instance with rule, entryPoints, service, middlewares, TLS and status. " +
			"Filter by search text, status, service or middleware. Paginated: if next_page is present, call again with page=next_page.",
		enums: map[string][]any{"instance": instEnum, "protocol": all, "status": status},
	}, func(ctx context.Context, in ListRoutersInput) (*mcp.CallToolResult, error) {
		return r.list(ctx, kRouters, listParams{instance: in.Instance, protocol: in.Protocol, search: in.Search, status: in.Status,
			serviceName: in.Service, middleware: in.Middleware, page: in.Page, perPage: in.PerPage, full: in.Full})
	})

	add(r, toolDef{
		name:  "get_router",
		title: "Get router",
		description: "Get the full details of one router (rule, entryPoints, middlewares, service, TLS/certResolver, status, errors). " +
			"Name like 'whoami@docker'; a name without @provider is resolved when unique.",
		enums: map[string][]any{"instance": instEnum, "protocol": all},
	}, func(ctx context.Context, in GetInput) (*mcp.CallToolResult, error) {
		return r.get(ctx, kRouters, in)
	})

	add(r, toolDef{
		name:  "list_services",
		title: "List services",
		description: "List HTTP, TCP or UDP services of a Traefik instance with type, backend servers, serverStatus (UP/DOWN), usedBy and status. " +
			"Paginated: if next_page is present, call again with page=next_page.",
		enums: map[string][]any{"instance": instEnum, "protocol": all, "status": status},
	}, func(ctx context.Context, in ListServicesInput) (*mcp.CallToolResult, error) {
		return r.list(ctx, kServices, listParams{instance: in.Instance, protocol: in.Protocol, search: in.Search, status: in.Status,
			page: in.Page, perPage: in.PerPage, full: in.Full})
	})

	add(r, toolDef{
		name:  "get_service",
		title: "Get service",
		description: "Get the full details of one service incl. load balancer servers, health check, serverStatus (UP/DOWN) and the routers using it. " +
			"Name like 'whoami@docker'; a name without @provider is resolved when unique.",
		enums: map[string][]any{"instance": instEnum, "protocol": all},
	}, func(ctx context.Context, in GetInput) (*mcp.CallToolResult, error) {
		return r.get(ctx, kServices, in)
	})

	add(r, toolDef{
		name:  "list_middlewares",
		title: "List middlewares",
		description: "List HTTP or TCP middlewares of a Traefik instance with type, configuration, usedBy and status. " +
			"Paginated: if next_page is present, call again with page=next_page.",
		enums: map[string][]any{"instance": instEnum, "protocol": noUDP, "status": status},
	}, func(ctx context.Context, in ListMiddlewaresInput) (*mcp.CallToolResult, error) {
		return r.list(ctx, kMiddlewares, listParams{instance: in.Instance, protocol: in.Protocol, search: in.Search, status: in.Status,
			page: in.Page, perPage: in.PerPage, full: in.Full})
	})

	add(r, toolDef{
		name:  "get_middleware",
		title: "Get middleware",
		description: "Get the full configuration of one HTTP or TCP middleware and the routers using it. " +
			"Name like 'secHeaders@file'; a name without @provider is resolved when unique. " +
			"Note: secrets such as basicAuth users are returned as Traefik exposes them.",
		enums: map[string][]any{"instance": instEnum, "protocol": noUDP},
	}, func(ctx context.Context, in GetInput) (*mcp.CallToolResult, error) {
		return r.get(ctx, kMiddlewares, in)
	})
}
