package tools

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net"
	"net/url"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/virtualben89/traefik-mcp-go/internal/traefik"
)

// ---- typed views on API objects (only the fields the analysis needs) ----

type apiRouter struct {
	Name        string          `json:"name"`
	Provider    string          `json:"provider"`
	Status      string          `json:"status"`
	Rule        string          `json:"rule"`
	RuleSyntax  string          `json:"ruleSyntax"`
	Priority    int64           `json:"priority"`
	EntryPoints []string        `json:"entryPoints"`
	Using       []string        `json:"using"`
	Middlewares []string        `json:"middlewares"`
	Service     string          `json:"service"`
	TLS         json.RawMessage `json:"tls"`
	Error       []string        `json:"error"`
}

func (r apiRouter) hasTLS() bool {
	s := strings.TrimSpace(string(r.TLS))
	return s != "" && s != "null"
}

// entryPoints returns the effective entry points.
func (r apiRouter) entryPoints() []string {
	if len(r.Using) > 0 {
		return r.Using
	}
	return r.EntryPoints
}

// effPriority mirrors Traefik: without explicit priority the rule length is used.
func (r apiRouter) effPriority() int64 {
	if r.Priority != 0 {
		return r.Priority
	}
	return int64(len(r.Rule))
}

type apiService struct {
	Name         string            `json:"name"`
	Provider     string            `json:"provider"`
	Status       string            `json:"status"`
	Type         string            `json:"type"`
	ServerStatus map[string]string `json:"serverStatus"`
	UsedBy       []string          `json:"usedBy"`
	Error        []string          `json:"error"`
	Weighted     *struct {
		Services []struct {
			Name string `json:"name"`
		} `json:"services"`
	} `json:"weighted"`
	Failover *struct {
		Service  string `json:"service"`
		Fallback string `json:"fallback"`
	} `json:"failover"`
	Mirroring *struct {
		Service string `json:"service"`
	} `json:"mirroring"`
}

type apiMiddleware struct {
	RedirectScheme *struct {
		Scheme string `json:"scheme"`
	} `json:"redirectScheme"`
	RedirectRegex *struct {
		Regex       string `json:"regex"`
		Replacement string `json:"replacement"`
	} `json:"redirectRegex"`
	Name     string   `json:"name"`
	Provider string   `json:"provider"`
	Status   string   `json:"status"`
	Type     string   `json:"type"`
	UsedBy   []string `json:"usedBy"`
	Error    []string `json:"error"`
}

type apiEntryPoint struct {
	Name    string `json:"name"`
	Address string `json:"address"`
	HTTP    struct {
		Redirections *struct {
			EntryPoint *struct {
				To     string `json:"to"`
				Scheme string `json:"scheme"`
			} `json:"entryPoint"`
		} `json:"redirections"`
		Middlewares []string        `json:"middlewares"`
		TLS         json.RawMessage `json:"tls"`
	} `json:"http"`
	ForwardedHeaders *struct {
		Insecure   bool     `json:"insecure"`
		TrustedIPs []string `json:"trustedIPs"`
	} `json:"forwardedHeaders"`
	ProxyProtocol json.RawMessage `json:"proxyProtocol"`
	HTTP3         json.RawMessage `json:"http3"`
}

// port and protocol of the entry point address (":443", "0.0.0.0:53/udp").
func (e apiEntryPoint) portProto() (int, string) {
	addr, proto := e.Address, "tcp"
	if a, p, ok := strings.Cut(addr, "/"); ok {
		addr, proto = a, strings.ToLower(p)
	}
	_, ps, err := net.SplitHostPort(addr)
	if err != nil {
		return 0, proto
	}
	port, _ := strconv.Atoi(ps)
	return port, proto
}

func (e apiEntryPoint) redirect() (to, scheme string, ok bool) {
	if e.HTTP.Redirections == nil || e.HTTP.Redirections.EntryPoint == nil {
		return "", "", false
	}
	return e.HTTP.Redirections.EntryPoint.To, e.HTTP.Redirections.EntryPoint.Scheme, true
}

type apiCertificate struct {
	Name                 string   `json:"name"`
	SANs                 []string `json:"sans"`
	NotAfter             string   `json:"notAfter"`
	NotBefore            string   `json:"notBefore"`
	SerialNumber         string   `json:"serialNumber"`
	CommonName           string   `json:"commonName"`
	IssuerOrg            string   `json:"issuerOrg"`
	IssuerCN             string   `json:"issuerCN"`
	KeyType              string   `json:"keyType"`
	KeySize              int      `json:"keySize"`
	CertFingerprint      string   `json:"certFingerprint"`
	PublicKeyFingerprint string   `json:"publicKeyFingerprint"`
	Status               string   `json:"status"`
}

func (c apiCertificate) daysLeft(now time.Time) (int, bool) {
	t, err := time.Parse(time.RFC3339, c.NotAfter)
	if err != nil {
		return 0, false
	}
	return daysUntil(t, now), true
}

// daysUntil returns whole days until t, rounded down: a certificate that
// expired an hour ago yields -1, not 0.
func daysUntil(t, now time.Time) int {
	return int(math.Floor(t.Sub(now).Hours() / 24))
}

// fetchTyped reads all pages of a list endpoint into a typed slice.
func fetchTyped[T any](ctx context.Context, c *traefik.Client, path string) ([]T, error) {
	raw, err := fetchAll(ctx, c, path, url.Values{})
	if err != nil {
		return nil, err
	}
	b, err := json.Marshal(raw)
	if err != nil {
		return nil, err
	}
	var out []T
	if err := json.Unmarshal(b, &out); err != nil {
		return nil, fmt.Errorf("decoding %s: %w", path, err)
	}
	return out, nil
}

func getTyped[T any](ctx context.Context, c *traefik.Client, path string) (*T, error) {
	resp, err := c.Get(ctx, path, nil)
	if err != nil {
		return nil, err
	}
	var out T
	if err := json.Unmarshal(resp.Body, &out); err != nil {
		return nil, fmt.Errorf("decoding %s: %w", path, err)
	}
	return &out, nil
}

// fetchCertificates returns (nil, false, nil) when the instance has no
// certificates endpoint (Traefik < 3.7).
func fetchCertificates(ctx context.Context, c *traefik.Client) ([]apiCertificate, bool, error) {
	certs, err := fetchTyped[apiCertificate](ctx, c, "/certificates")
	if err != nil {
		if traefik.IsNotFound(err) {
			return nil, false, nil
		}
		return nil, false, err
	}
	return certs, true, nil
}

// qualify adds the provider of ref when name has none (Traefik semantics).
func qualify(name, provider string) string {
	if strings.Contains(name, "@") || provider == "" {
		return name
	}
	return name + "@" + provider
}

// targets resolves the instances for tools that accept all_instances.
func (r *Registry) targets(instance string, all bool) ([]string, error) {
	if all {
		return r.opts.Order, nil
	}
	_, name, err := r.instance(instance)
	if err != nil {
		return nil, err
	}
	return []string{name}, nil
}

// perInstance runs f concurrently for each instance and collects results by name.
func (r *Registry) perInstance(ctx context.Context, names []string, f func(context.Context, string, Instance) any) map[string]any {
	out := make(map[string]any, len(names))
	var mu sync.Mutex
	var wg sync.WaitGroup
	for _, n := range names {
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer recoverAs(func(err error) {
				mu.Lock()
				out[n] = map[string]any{"error": err.Error()}
				mu.Unlock()
			})
			v := f(ctx, n, r.instances[n])
			mu.Lock()
			out[n] = v
			mu.Unlock()
		}()
	}
	wg.Wait()
	return out
}

// ---- inputs ----

// InstanceInput selects an instance.
type InstanceInput struct {
	Instance string `json:"instance,omitempty" jsonschema:"Traefik instance name (see list_instances); omit for the default instance"`
}

// ListEntryPointsInput are the parameters of list_entrypoints.
type ListEntryPointsInput struct {
	Instance string `json:"instance,omitempty" jsonschema:"Traefik instance name (see list_instances); omit for the default instance"`
	Full     bool   `json:"full,omitempty" jsonschema:"Return the complete objects incl. transport and HTTP/2 settings"`
}

// GetEntryPointInput are the parameters of get_entrypoint.
type GetEntryPointInput struct {
	Instance string `json:"instance,omitempty" jsonschema:"Traefik instance name (see list_instances); omit for the default instance"`
	Name     string `json:"name" jsonschema:"Entry point name, e.g. websecure"`
}

// ListCertificatesInput are the parameters of list_certificates.
type ListCertificatesInput struct {
	Instance           string `json:"instance,omitempty" jsonschema:"Traefik instance name (see list_instances); omit for the default instance"`
	Search             string `json:"search,omitempty" jsonschema:"Case-insensitive substring filter on common name and SANs, e.g. a domain"`
	ExpiringWithinDays int    `json:"expiring_within_days,omitempty" jsonschema:"Only certificates that expire within this many days (expired ones included)"`
	Full               bool   `json:"full,omitempty" jsonschema:"Return the complete objects incl. serial number and public key fingerprint"`
}

// HealthReportInput are the parameters of health_report.
type HealthReportInput struct {
	Instance     string `json:"instance,omitempty" jsonschema:"Traefik instance name (see list_instances); omit for the default instance"`
	AllInstances bool   `json:"all_instances,omitempty" jsonschema:"Check every configured instance"`
	CertWarnDays int    `json:"cert_warn_days,omitempty" jsonschema:"Warn about certificates expiring within this many days (server default if omitted)"`
	IncludeInfo  *bool  `json:"include_info,omitempty" jsonschema:"Include informational findings such as plain-HTTP routers (default true)"`
}

// FindRouteInput are the parameters of find_route.
type FindRouteInput struct {
	URL          string `json:"url" jsonschema:"Request URL, e.g. https://app.example.com/api/x (scheme defaults to https)"`
	Method       string `json:"method,omitempty" jsonschema:"HTTP method (default GET)"`
	EntryPoint   string `json:"entrypoint,omitempty" jsonschema:"Entry point the request arrives on; derived from the URL port if omitted"`
	Instance     string `json:"instance,omitempty" jsonschema:"Traefik instance name (see list_instances); omit for the default instance"`
	AllInstances bool   `json:"all_instances,omitempty" jsonschema:"Evaluate the URL on every configured instance"`
}

// ---- get_overview ----

func (r *Registry) overview(ctx context.Context, in InstanceInput) (*mcp.CallToolResult, error) {
	inst, name, err := r.instance(in.Instance)
	if err != nil {
		return nil, err
	}
	resp, err := inst.Client.Get(ctx, "/overview", nil)
	if err != nil {
		return nil, err
	}
	var ov map[string]any
	if err := decodeExact(resp.Body, &ov); err != nil {
		return nil, fmt.Errorf("decoding overview: %w", err)
	}
	out := map[string]any{"instance": name, "overview": ov}
	if v, err := inst.Client.Version(ctx); err == nil {
		out["version"] = v.Version
		out["start_date"] = v.StartDate
	}
	return valueResult(out)
}

// ---- entry points ----

func slimEntryPoint(e map[string]any, typed apiEntryPoint) map[string]any {
	port, proto := typed.portProto()
	out := map[string]any{"name": typed.Name, "address": typed.Address, "port": port, "protocol": proto}
	if to, scheme, ok := typed.redirect(); ok {
		out["redirect"] = map[string]any{"to": to, "scheme": scheme}
	}
	if len(typed.HTTP.Middlewares) > 0 {
		out["middlewares"] = typed.HTTP.Middlewares
	}
	if s := strings.TrimSpace(string(typed.HTTP.TLS)); s != "" && s != "null" {
		out["tls"] = typed.HTTP.TLS
	}
	if fh := typed.ForwardedHeaders; fh != nil && (fh.Insecure || len(fh.TrustedIPs) > 0) {
		out["forwardedHeaders"] = fh
	}
	if s := strings.TrimSpace(string(typed.ProxyProtocol)); s != "" && s != "null" {
		out["proxyProtocol"] = typed.ProxyProtocol
	}
	if _, ok := e["http3"]; ok {
		out["http3"] = true
	}
	return out
}

func (r *Registry) listEntryPoints(ctx context.Context, in ListEntryPointsInput) (*mcp.CallToolResult, error) {
	inst, name, err := r.instance(in.Instance)
	if err != nil {
		return nil, err
	}
	raw, err := fetchAll(ctx, inst.Client, "/entrypoints", url.Values{})
	if err != nil {
		return nil, err
	}
	items := make([]map[string]any, 0, len(raw))
	for _, e := range raw {
		if in.Full {
			items = append(items, e)
			continue
		}
		b, _ := json.Marshal(e)
		var t apiEntryPoint
		_ = json.Unmarshal(b, &t)
		items = append(items, slimEntryPoint(e, t))
	}
	return valueResult(map[string]any{"instance": name, "count": len(items), "items": items})
}

func (r *Registry) getEntryPoint(ctx context.Context, in GetEntryPointInput) (*mcp.CallToolResult, error) {
	inst, name, err := r.instance(in.Instance)
	if err != nil {
		return nil, err
	}
	n := strings.TrimSpace(in.Name)
	if n == "" {
		return nil, errors.New("name is required")
	}
	resp, err := inst.Client.Get(ctx, "/entrypoints/"+url.PathEscape(n), nil)
	if err != nil {
		if traefik.IsNotFound(err) {
			return nil, fmt.Errorf("entry point %q not found on instance %s; use list_entrypoints", n, name)
		}
		return nil, err
	}
	var obj map[string]any
	if err := decodeExact(resp.Body, &obj); err != nil {
		return nil, err
	}
	return valueResult(map[string]any{"instance": name, "entrypoint": obj})
}

// ---- certificates ----

func (r *Registry) listCertificates(ctx context.Context, in ListCertificatesInput) (*mcp.CallToolResult, error) {
	inst, name, err := r.instance(in.Instance)
	if err != nil {
		return nil, err
	}
	if in.ExpiringWithinDays < 0 {
		return nil, errors.New("expiring_within_days must be positive")
	}
	certs, ok, err := fetchCertificates(ctx, inst.Client)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, fmt.Errorf("instance %s has no /api/certificates endpoint (requires Traefik v3.7 or newer); use check_tls_endpoint to inspect a served certificate", name)
	}
	now := time.Now()
	search := strings.ToLower(in.Search)
	type row struct {
		days int
		item map[string]any
	}
	var rows []row
	for _, c := range certs {
		if search != "" && !strings.Contains(strings.ToLower(c.CommonName+" "+strings.Join(c.SANs, " ")), search) {
			continue
		}
		days, okDays := c.daysLeft(now)
		if in.ExpiringWithinDays > 0 && (!okDays || days > in.ExpiringWithinDays) {
			continue
		}
		item := map[string]any{
			"common_name": c.CommonName,
			"sans":        c.SANs,
			"issuer":      strings.TrimSpace(c.IssuerOrg + " " + c.IssuerCN),
			"not_before":  c.NotBefore,
			"not_after":   c.NotAfter,
			"days_left":   days,
			"key":         strings.TrimSpace(fmt.Sprintf("%s %d", c.KeyType, c.KeySize)),
			"fingerprint": c.CertFingerprint,
			"status":      c.Status,
		}
		if in.Full {
			item["serial_number"] = c.SerialNumber
			item["public_key_fingerprint"] = c.PublicKeyFingerprint
		}
		rows = append(rows, row{days, item})
	}
	sort.SliceStable(rows, func(i, j int) bool { return rows[i].days < rows[j].days })
	items := make([]map[string]any, len(rows))
	for i, rw := range rows {
		items[i] = rw.item
	}
	return valueResult(map[string]any{"instance": name, "count": len(items), "total": len(certs), "items": items})
}

// ---- health_report ----

type finding struct {
	Severity string   `json:"severity"` // error, warning, info
	Category string   `json:"category"`
	Object   string   `json:"object,omitempty"`
	Message  string   `json:"message"`
	Details  []string `json:"details,omitempty"`
}

func (r *Registry) healthReport(ctx context.Context, in HealthReportInput) (*mcp.CallToolResult, error) {
	names, err := r.targets(in.Instance, in.AllInstances)
	if err != nil {
		return nil, err
	}
	warnDays := in.CertWarnDays
	if warnDays <= 0 {
		warnDays = r.opts.CertWarnDays
	}
	includeInfo := in.IncludeInfo == nil || *in.IncludeInfo
	reports := r.perInstance(ctx, names, func(ctx context.Context, name string, inst Instance) any {
		return instanceHealth(ctx, inst.Client, warnDays, includeInfo)
	})
	healthy := true
	for _, rep := range reports {
		if m, ok := rep.(map[string]any); ok && m["healthy"] != true {
			healthy = false
		}
	}
	return valueResult(map[string]any{"healthy": healthy, "cert_warn_days": warnDays, "instances": reports})
}

func statusFinding(kind, name, status string, errs []string) *finding {
	switch status {
	case "disabled":
		return &finding{Severity: "error", Category: kind, Object: name, Message: kind + " is disabled", Details: errs}
	case "warning":
		return &finding{Severity: "warning", Category: kind, Object: name, Message: kind + " has warnings", Details: errs}
	}
	return nil
}

func instanceHealth(ctx context.Context, c *traefik.Client, warnDays int, includeInfo bool) map[string]any {
	out := map[string]any{}
	v, err := c.Version(ctx)
	if err != nil {
		return map[string]any{"healthy": false, "reachable": false, "error": err.Error()}
	}
	out["reachable"] = true
	out["version"] = v.Version

	var (
		mu       sync.Mutex
		findings []finding
		fetchErr []string
		wg       sync.WaitGroup
	)
	addF := func(f finding) {
		mu.Lock()
		findings = append(findings, f)
		mu.Unlock()
	}
	addErr := func(e error) {
		mu.Lock()
		fetchErr = append(fetchErr, e.Error())
		mu.Unlock()
	}

	var (
		httpRouters []apiRouter
		entryPoints []apiEntryPoint
		httpMws     []apiMiddleware
	)
	for _, proto := range []string{"http", "tcp", "udp"} {
		wg.Add(2)
		go func() {
			defer wg.Done()
			defer recoverAs(addErr)
			routers, err := fetchTyped[apiRouter](ctx, c, "/"+proto+"/routers")
			if err != nil {
				addErr(err)
				return
			}
			if proto == "http" {
				mu.Lock()
				httpRouters = routers
				mu.Unlock()
			}
			for _, rt := range routers {
				if f := statusFinding(proto+" router", rt.Name, rt.Status, rt.Error); f != nil {
					addF(*f)
				}
				if host, ok := ghostHost(rt.Rule); ok && proto == "http" && rt.Provider != "internal" {
					addF(finding{Severity: "warning", Category: "ghost router", Object: rt.Name,
						Message: fmt.Sprintf("rule Host(`%s`) looks like the Docker provider default (no rule label set); it is attached to entry points %s", host, strings.Join(rt.entryPoints(), ", "))})
				}
			}
		}()
		go func() {
			defer wg.Done()
			defer recoverAs(addErr)
			services, err := fetchTyped[apiService](ctx, c, "/"+proto+"/services")
			if err != nil {
				addErr(err)
				return
			}
			for _, s := range services {
				if f := statusFinding(proto+" service", s.Name, s.Status, s.Error); f != nil {
					addF(*f)
				}
				var down, up []string
				for srv, st := range s.ServerStatus {
					if strings.EqualFold(st, "UP") {
						up = append(up, srv)
					} else {
						down = append(down, srv+" "+st)
					}
				}
				sort.Strings(down)
				switch {
				case len(down) > 0 && len(up) == 0:
					addF(finding{Severity: "error", Category: proto + " service", Object: s.Name, Message: "all backend servers are DOWN", Details: down})
				case len(down) > 0:
					addF(finding{Severity: "warning", Category: proto + " service", Object: s.Name, Message: fmt.Sprintf("%d of %d backend servers are DOWN", len(down), len(down)+len(up)), Details: down})
				}
			}
		}()
	}
	for _, proto := range []string{"http", "tcp"} {
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer recoverAs(addErr)
			mws, err := fetchTyped[apiMiddleware](ctx, c, "/"+proto+"/middlewares")
			if err != nil {
				addErr(err)
				return
			}
			if proto == "http" {
				mu.Lock()
				httpMws = mws
				mu.Unlock()
			}
			for _, m := range mws {
				if f := statusFinding(proto+" middleware", m.Name, m.Status, m.Error); f != nil {
					addF(*f)
				}
			}
		}()
	}
	wg.Add(2)
	go func() {
		defer wg.Done()
		defer recoverAs(addErr)
		eps, err := fetchTyped[apiEntryPoint](ctx, c, "/entrypoints")
		if err != nil {
			addErr(err)
			return
		}
		mu.Lock()
		entryPoints = eps
		mu.Unlock()
	}()
	go func() {
		defer wg.Done()
		defer recoverAs(addErr)
		certs, ok, err := fetchCertificates(ctx, c)
		if err != nil {
			addErr(err)
			return
		}
		if !ok {
			mu.Lock()
			out["certificates"] = "not available (Traefik < 3.7)"
			mu.Unlock()
			return
		}
		now := time.Now()
		for _, ct := range certs {
			obj := ct.CommonName
			if obj == "" && len(ct.SANs) > 0 {
				obj = ct.SANs[0]
			}
			days, okDays := ct.daysLeft(now)
			if !okDays {
				addF(finding{Severity: "warning", Category: "certificate", Object: obj,
					Message: fmt.Sprintf("cannot parse expiry date %q; check this certificate manually", ct.NotAfter), Details: ct.SANs})
				continue
			}
			switch {
			case days < 0:
				addF(finding{Severity: "error", Category: "certificate", Object: obj, Message: fmt.Sprintf("expired on %s", ct.NotAfter), Details: ct.SANs})
			case days <= warnDays:
				addF(finding{Severity: "warning", Category: "certificate", Object: obj, Message: fmt.Sprintf("expires in %d days (%s)", days, ct.NotAfter), Details: ct.SANs})
			}
		}
		mu.Lock()
		out["certificates"] = len(certs)
		mu.Unlock()
	}()
	wg.Wait()

	// Plain HTTP routers: no TLS, on entry points without redirect, and no
	// redirectScheme middleware on the router or the entry point.
	if includeInfo && entryPoints != nil {
		epByName := map[string]apiEntryPoint{}
		for _, e := range entryPoints {
			epByName[e.Name] = e
		}
		mwByName := map[string]apiMiddleware{}
		for _, m := range httpMws {
			mwByName[m.Name] = m
		}
		// Only a redirectScheme middleware that redirects to https counts.
		isRedirect := func(names []string, provider string) bool {
			for _, n := range names {
				m, ok := mwByName[qualify(n, provider)]
				if !ok || !strings.EqualFold(m.Type, "redirectscheme") {
					continue
				}
				if m.RedirectScheme == nil || m.RedirectScheme.Scheme == "" || strings.EqualFold(m.RedirectScheme.Scheme, "https") {
					return true
				}
			}
			return false
		}
		for _, rt := range httpRouters {
			if rt.hasTLS() || rt.Provider == "internal" || rt.Status != "enabled" {
				continue
			}
			if isRedirect(rt.Middlewares, rt.Provider) {
				continue
			}
			var plain []string
			for _, epn := range rt.entryPoints() {
				ep := epByName[epn]
				// Entry point with http.tls: every router on it is served with TLS.
				if t := strings.TrimSpace(string(ep.HTTP.TLS)); t != "" && t != "null" {
					continue
				}
				if _, scheme, ok := ep.redirect(); (ok && (scheme == "" || strings.EqualFold(scheme, "https"))) || isRedirect(ep.HTTP.Middlewares, "") {
					continue
				}
				plain = append(plain, epn)
			}
			if len(plain) > 0 {
				f := finding{Severity: "info", Category: "plain http", Object: rt.Name,
					Message: fmt.Sprintf("served without TLS and without HTTPS redirect on entry points %s (rule %s)", strings.Join(plain, ", "), rt.Rule)}
				// redirectRegex may redirect to https, but only if its regex matches.
				for _, n := range rt.Middlewares {
					if m, ok := mwByName[qualify(n, rt.Provider)]; ok && m.RedirectRegex != nil && strings.HasPrefix(strings.ToLower(m.RedirectRegex.Replacement), "https") {
						f.Details = append(f.Details, fmt.Sprintf("redirectRegex %s: %s -> %s (redirects only when the regex matches; verify with check_tls_endpoint or curl)", m.Name, m.RedirectRegex.Regex, m.RedirectRegex.Replacement))
					}
				}
				addF(f)
			}
		}
	}

	sevRank := map[string]int{"error": 0, "warning": 1, "info": 2}
	sort.SliceStable(findings, func(i, j int) bool {
		if sevRank[findings[i].Severity] != sevRank[findings[j].Severity] {
			return sevRank[findings[i].Severity] < sevRank[findings[j].Severity]
		}
		if findings[i].Category != findings[j].Category {
			return findings[i].Category < findings[j].Category
		}
		return findings[i].Object < findings[j].Object
	})
	counts := map[string]int{"error": 0, "warning": 0, "info": 0}
	for _, f := range findings {
		counts[f.Severity]++
	}
	if findings == nil {
		findings = []finding{}
	}
	out["summary"] = counts
	out["findings"] = findings
	if len(fetchErr) > 0 {
		sort.Strings(fetchErr)
		out["fetch_errors"] = fetchErr
	}
	out["healthy"] = counts["error"] == 0 && counts["warning"] == 0 && len(fetchErr) == 0
	return out
}

// ---- find_route ----

type routeCandidate struct {
	Router   string   `json:"router"`
	Priority int64    `json:"priority"`
	Rule     string   `json:"rule"`
	Match    string   `json:"match"`
	Unknown  []string `json:"cannot_evaluate,omitempty"`
}

func (r *Registry) findRoute(ctx context.Context, in FindRouteInput) (*mcp.CallToolResult, error) {
	raw := strings.TrimSpace(in.URL)
	if raw == "" {
		return nil, errors.New("url is required")
	}
	if !strings.Contains(raw, "://") {
		raw = "https://" + raw
	}
	u, err := url.Parse(raw)
	if err != nil || u.Hostname() == "" {
		return nil, fmt.Errorf("invalid url %q", in.URL)
	}
	scheme := strings.ToLower(u.Scheme)
	if scheme != "http" && scheme != "https" {
		return nil, fmt.Errorf("unsupported scheme %q (use http or https)", scheme)
	}
	port := 443
	if scheme == "http" {
		port = 80
	}
	if p := u.Port(); p != "" {
		port, _ = strconv.Atoi(p)
	}
	path := u.EscapedPath()
	if path == "" {
		path = "/"
	}
	req := requestInfo{host: strings.ToLower(strings.TrimSuffix(u.Hostname(), ".")), path: path, method: strings.ToUpper(in.Method), tls: scheme == "https"}
	if req.method == "" {
		req.method = "GET"
	}
	names, err := r.targets(in.Instance, in.AllInstances)
	if err != nil {
		return nil, err
	}
	results := r.perInstance(ctx, names, func(ctx context.Context, _ string, inst Instance) any {
		res, err := resolveRoute(ctx, inst.Client, req, port, strings.TrimSpace(in.EntryPoint))
		if err != nil {
			return map[string]any{"error": err.Error()}
		}
		return res
	})
	out := map[string]any{
		"request": map[string]any{"scheme": scheme, "host": req.host, "port": port, "path": req.path, "method": req.method},
	}
	if len(names) == 1 {
		if m, ok := results[names[0]].(map[string]any); ok && len(m) == 1 && m["error"] != nil {
			return nil, fmt.Errorf("%v", m["error"])
		}
		out["instance"] = names[0]
		out["result"] = results[names[0]]
	} else {
		out["instances"] = results
	}
	return valueResult(out)
}

func resolveRoute(ctx context.Context, c *traefik.Client, req requestInfo, port int, epName string) (map[string]any, error) {
	eps, err := fetchTyped[apiEntryPoint](ctx, c, "/entrypoints")
	if err != nil {
		return nil, err
	}
	var notes []string
	var candidates []apiEntryPoint
	for _, e := range eps {
		p, proto := e.portProto()
		if proto == "udp" {
			continue
		}
		if epName != "" {
			if e.Name == epName {
				candidates = append(candidates, e)
			}
		} else if p == port {
			candidates = append(candidates, e)
		}
	}
	if len(candidates) == 0 {
		if epName != "" {
			return nil, fmt.Errorf("entry point %q not found", epName)
		}
		for _, e := range eps {
			if _, proto := e.portProto(); proto != "udp" {
				candidates = append(candidates, e)
			}
		}
		notes = append(notes, fmt.Sprintf("no entry point listens on port %d (port forwarding?); all TCP entry points were considered - pass 'entrypoint' to be precise", port))
	}
	epSet := map[string]apiEntryPoint{}
	var epNames []string
	for _, e := range candidates {
		epSet[e.Name] = e
		epNames = append(epNames, e.Name)
	}
	onEP := func(list []string) bool {
		for _, n := range list {
			if _, ok := epSet[n]; ok {
				return true
			}
		}
		return false
	}
	out := map[string]any{"entrypoints": epNames}

	// Entry-point level redirect wins for plain HTTP.
	if !req.tls {
		for _, e := range candidates {
			if to, scheme, ok := e.redirect(); ok {
				out["entrypoint_redirect"] = map[string]any{"entrypoint": e.Name, "to": to, "scheme": scheme}
				notes = append(notes, fmt.Sprintf("entry point %s redirects every request to %s (%s) before routers apply", e.Name, to, scheme))
			}
		}
	}

	// TCP routers take precedence over HTTP routers on the same entry point.
	tcpRouters, err := fetchTyped[apiRouter](ctx, c, "/tcp/routers")
	if err != nil {
		return nil, err
	}
	var tcpMatch []routeCandidate
	var tcpWinner *apiRouter
	for i, rt := range tcpRouters {
		if rt.Status != "enabled" || !onEP(rt.entryPoints()) {
			continue
		}
		// TLS routers only see TLS connections; non-TLS routers only HostSNI(`*`).
		if rt.hasTLS() != req.tls {
			continue
		}
		node, err := parseRule(rt.Rule)
		if err != nil {
			notes = append(notes, fmt.Sprintf("tcp router %s: cannot parse rule: %v", rt.Name, err))
			continue
		}
		m := node.evalTCP(req)
		if m == triNo {
			continue
		}
		tcpMatch = append(tcpMatch, routeCandidate{Router: rt.Name, Priority: rt.effPriority(), Rule: rt.Rule, Match: m.String(), Unknown: node.unknownMatchers(true)})
		if m == triYes && (tcpWinner == nil || rt.effPriority() > tcpWinner.effPriority()) {
			tcpWinner = &tcpRouters[i]
		}
	}

	httpRouters, err := fetchTyped[apiRouter](ctx, c, "/http/routers")
	if err != nil {
		return nil, err
	}
	type scored struct {
		rt   apiRouter
		m    tri
		node *ruleNode
	}
	var matches []scored
	var disabled []string
	for _, rt := range httpRouters {
		if !onEP(rt.entryPoints()) || rt.hasTLS() != req.tls {
			continue
		}
		node, err := parseRule(rt.Rule)
		if err != nil {
			notes = append(notes, fmt.Sprintf("http router %s: cannot parse rule: %v", rt.Name, err))
			continue
		}
		m := node.evalHTTP(req)
		if m == triNo {
			continue
		}
		if rt.Status != "enabled" {
			disabled = append(disabled, fmt.Sprintf("%s (%s: %s)", rt.Name, rt.Status, strings.Join(rt.Error, "; ")))
			continue
		}
		matches = append(matches, scored{rt, m, node})
	}
	sort.SliceStable(matches, func(i, j int) bool {
		pi, pj := matches[i].rt.effPriority(), matches[j].rt.effPriority()
		if pi != pj {
			return pi > pj
		}
		return matches[i].rt.Name < matches[j].rt.Name
	})
	if len(disabled) > 0 {
		notes = append(notes, "matching routers that are not enabled: "+strings.Join(disabled, ", "))
	}

	var cands []routeCandidate
	var winner *scored
	var shadow []string
	for i := range matches {
		s := matches[i]
		if len(cands) < 10 {
			cands = append(cands, routeCandidate{Router: s.rt.Name, Priority: s.rt.effPriority(), Rule: s.rt.Rule, Match: s.m.String(), Unknown: s.node.unknownMatchers(false)})
		}
		if winner != nil {
			continue
		}
		if s.m == triYes {
			winner = &matches[i]
		} else {
			shadow = append(shadow, s.rt.Name)
		}
	}
	if len(tcpMatch) > 0 {
		out["tcp_candidates"] = tcpMatch
	}
	if cands != nil {
		out["http_candidates"] = cands
	}

	switch {
	case tcpWinner != nil:
		out["matched"] = "tcp"
		chain, err := tcpChain(ctx, c, *tcpWinner)
		if err != nil {
			return nil, err
		}
		out["route"] = chain
		notes = append(notes, "a TCP router matches; on this entry point TCP routers take precedence over HTTP routers")
	case winner != nil:
		out["matched"] = "http"
		chain, err := httpChain(ctx, c, winner.rt, epSet)
		if err != nil {
			return nil, err
		}
		out["route"] = chain
		if len(shadow) > 0 {
			notes = append(notes, "higher-priority routers depend on headers/query/client IP and may match first: "+strings.Join(shadow, ", "))
		}
	default:
		out["matched"] = "none"
		if len(shadow) > 0 {
			notes = append(notes, "only routers with conditions that cannot be evaluated (headers, query, client IP) may match: "+strings.Join(shadow, ", "))
		} else if out["entrypoint_redirect"] == nil {
			notes = append(notes, "no router matches; Traefik would answer 404")
		}
	}
	if notes != nil {
		out["notes"] = notes
	}
	return out, nil
}

// httpChain describes router -> middlewares -> service -> servers.
func httpChain(ctx context.Context, c *traefik.Client, rt apiRouter, eps map[string]apiEntryPoint) (map[string]any, error) {
	route := map[string]any{
		"router":      rt.Name,
		"rule":        rt.Rule,
		"priority":    rt.effPriority(),
		"entrypoints": rt.entryPoints(),
	}
	if rt.hasTLS() {
		route["tls"] = rt.TLS
	}
	// Entry point middlewares run before router middlewares. Traefik usually
	// merges them into the router's list already; add only missing ones.
	var routerMws []string
	for _, m := range rt.Middlewares {
		routerMws = append(routerMws, qualify(m, rt.Provider))
	}
	var mwNames []string
	for _, epn := range rt.entryPoints() {
		if ep, ok := eps[epn]; ok {
			for _, m := range ep.HTTP.Middlewares {
				if !slices.Contains(mwNames, m) && !slices.Contains(routerMws, m) {
					mwNames = append(mwNames, m)
				}
			}
		}
	}
	mwNames = append(mwNames, routerMws...)
	var mws []map[string]any
	for _, m := range mwNames {
		row := map[string]any{"name": m}
		mw, err := getTyped[apiMiddleware](ctx, c, "/http/middlewares/"+url.PathEscape(m))
		if err != nil {
			row["error"] = err.Error()
		} else {
			row["type"] = mw.Type
			row["status"] = mw.Status
		}
		mws = append(mws, row)
	}
	if mws != nil {
		route["middlewares"] = mws
	}
	route["service"] = serviceTree(ctx, c, "http", qualify(rt.Service, rt.Provider), 0)
	return route, nil
}

func tcpChain(ctx context.Context, c *traefik.Client, rt apiRouter) (map[string]any, error) {
	route := map[string]any{
		"router":      rt.Name,
		"rule":        rt.Rule,
		"priority":    rt.effPriority(),
		"entrypoints": rt.entryPoints(),
	}
	if rt.hasTLS() {
		route["tls"] = rt.TLS
	}
	if len(rt.Middlewares) > 0 {
		route["middlewares"] = rt.Middlewares
	}
	route["service"] = serviceTree(ctx, c, "tcp", qualify(rt.Service, rt.Provider), 0)
	return route, nil
}

// serviceTree fetches a service and, for weighted/failover/mirroring services,
// its children (two levels deep).
func serviceTree(ctx context.Context, c *traefik.Client, proto, name string, depth int) map[string]any {
	out := map[string]any{"name": name}
	resp, err := c.Get(ctx, "/"+proto+"/services/"+url.PathEscape(name), nil)
	if err != nil {
		out["error"] = err.Error()
		return out
	}
	var s apiService
	var rawMap map[string]any
	_ = json.Unmarshal(resp.Body, &s)
	_ = decodeExact(resp.Body, &rawMap)
	out["type"] = s.Type
	out["status"] = s.Status
	if len(s.Error) > 0 {
		out["errors"] = s.Error
	}
	if lb, ok := rawMap["loadBalancer"].(map[string]any); ok {
		if servers, ok := lb["servers"]; ok {
			out["servers"] = servers
		}
		if hc, ok := lb["healthCheck"]; ok {
			out["healthCheck"] = hc
		}
	}
	if len(s.ServerStatus) > 0 {
		out["serverStatus"] = s.ServerStatus
	}
	var children []string
	switch {
	case s.Weighted != nil:
		for _, ws := range s.Weighted.Services {
			children = append(children, ws.Name)
		}
	case s.Failover != nil:
		children = []string{s.Failover.Service, s.Failover.Fallback}
	case s.Mirroring != nil:
		children = []string{s.Mirroring.Service}
	}
	if len(children) > 0 {
		var kids []map[string]any
		for _, ch := range children {
			ch = qualify(ch, s.Provider)
			if depth >= 2 {
				kids = append(kids, map[string]any{"name": ch})
				continue
			}
			kids = append(kids, serviceTree(ctx, c, proto, ch, depth+1))
		}
		out["children"] = kids
	}
	return out
}
