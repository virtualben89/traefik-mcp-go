// Command traefik-mcp is a read-only Model Context Protocol server for the Traefik API.
package main

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/modelcontextprotocol/go-sdk/auth"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/virtualben89/traefik-mcp-go/internal/config"
	"github.com/virtualben89/traefik-mcp-go/internal/tools"
	"github.com/virtualben89/traefik-mcp-go/internal/traefik"
)

// Set via -ldflags at build time.
var (
	version = "dev"
	commit  = "none"
)

func main() {
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "version", "--version", "-v":
			fmt.Printf("traefik-mcp %s (%s)\n", version, commit)
			return
		case "healthcheck":
			os.Exit(healthcheck())
		}
	}
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

// healthcheck probes the local /healthz endpoint (for Docker HEALTHCHECK in scratch images).
func healthcheck() int {
	if t := strings.ToLower(os.Getenv("MCP_TRANSPORT")); t == "" || t == "stdio" {
		return 0
	}
	addr := os.Getenv("MCP_HTTP_ADDR")
	if addr == "" {
		addr = ":8080"
	}
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return 1
	}
	if host == "" || host == "0.0.0.0" || host == "::" {
		host = "127.0.0.1"
	}
	c := &http.Client{Timeout: 3 * time.Second}
	resp, err := c.Get("http://" + net.JoinHostPort(host, port) + "/healthz")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return 1
	}
	return 0
}

func newLogger(level, format string) *slog.Logger {
	var lvl slog.Level
	if err := lvl.UnmarshalText([]byte(level)); err != nil {
		lvl = slog.LevelInfo
	}
	opts := &slog.HandlerOptions{Level: lvl}
	// Always log to stderr: stdout belongs to the stdio transport.
	if strings.EqualFold(format, "json") {
		return slog.New(slog.NewJSONHandler(os.Stderr, opts))
	}
	return slog.New(slog.NewTextHandler(os.Stderr, opts))
}

// buildInstances creates one API client per configured instance.
func buildInstances(cfg *config.Config) (map[string]tools.Instance, error) {
	out := make(map[string]tools.Instance, len(cfg.Instances))
	for _, in := range cfg.Instances {
		c, err := traefik.New(traefik.Options{
			Name:               in.Name,
			BaseURL:            in.URL,
			Timeout:            in.Timeout,
			BearerToken:        in.BearerToken,
			BasicUser:          in.BasicUser,
			BasicPassword:      in.BasicPass,
			Headers:            in.Headers,
			InsecureSkipVerify: in.InsecureTLS,
			CAFile:             in.CAFile,
			UserAgent:          "traefik-mcp-go/" + version,
		})
		if err != nil {
			return nil, fmt.Errorf("instance %s: %w", in.Name, err)
		}
		out[in.Name] = tools.Instance{Client: c, URL: c.BaseURL(), Auth: in.AuthMode()}
	}
	return out, nil
}

func run() error {
	cfg, err := config.Load(os.Args[1:])
	if err != nil {
		return err
	}
	log := newLogger(cfg.LogLevel, cfg.LogFormat)
	slog.SetDefault(log)

	instances, err := buildInstances(cfg)
	if err != nil {
		return err
	}
	toolOpts := tools.Options{
		Prefix:         cfg.ToolPrefix,
		DefaultPerPage: cfg.DefaultPerPage,
		Default:        cfg.DefaultInstance,
		Order:          cfg.InstanceNames(),
	}
	server, names := NewServer(instances, toolOpts, log)
	log.Info("traefik-mcp starting", "version", version, "transport", cfg.Transport,
		"instances", strings.Join(cfg.InstanceNames(), ","), "default", cfg.DefaultInstance, "tools", len(names))

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// Non-fatal connectivity probe.
	for name, st := range probeAll(ctx, instances, 5*time.Second) {
		if st.Error != "" {
			log.Warn("traefik instance not reachable at startup", "instance", name, "err", st.Error)
		} else {
			log.Info("traefik instance reachable", "instance", name, "version", st.Version)
		}
	}

	if cfg.Transport == "stdio" {
		err := server.Run(ctx, &mcp.StdioTransport{})
		if err != nil && (errors.Is(err, context.Canceled) || errors.Is(err, io.EOF)) {
			return nil
		}
		return err
	}
	return serveHTTP(ctx, cfg, server, instances, log)
}

// NewServer builds the MCP server with all tools.
func NewServer(instances map[string]tools.Instance, opts tools.Options, log *slog.Logger) (*mcp.Server, []string) {
	server := mcp.NewServer(&mcp.Implementation{
		Name:    "traefik-mcp",
		Title:   "Traefik",
		Version: version,
	}, &mcp.ServerOptions{
		Instructions: "Read-only access to the Traefik reverse proxy API (routers, services, middlewares for HTTP, TCP and UDP). " +
			"Several Traefik instances may be configured: call list_instances first and pass 'instance' (omit for the default). " +
			"Object names carry a provider suffix (e.g. app@docker, secHeaders@file). A router points to a service and uses middlewares; " +
			"service serverStatus shows whether backends are UP or DOWN. Router status 'disabled' or 'warning' comes with an 'error' list explaining the problem.",
		Logger: log,
	})
	names := tools.Register(server, instances, opts)
	return server, names
}

type probeStatus struct {
	Version string `json:"version,omitempty"`
	Error   string `json:"error,omitempty"`
}

func probeAll(ctx context.Context, instances map[string]tools.Instance, timeout time.Duration) map[string]probeStatus {
	var mu sync.Mutex
	var wg sync.WaitGroup
	out := make(map[string]probeStatus, len(instances))
	for name, in := range instances {
		wg.Add(1)
		go func() {
			defer wg.Done()
			pctx, cancel := context.WithTimeout(ctx, timeout)
			defer cancel()
			st := probeStatus{}
			if v, err := in.Client.Version(pctx); err != nil {
				st.Error = err.Error()
			} else {
				st.Version = v.Version
			}
			mu.Lock()
			out[name] = st
			mu.Unlock()
		}()
	}
	wg.Wait()
	return out
}

func bearerVerifier(tokens []string) auth.TokenVerifier {
	hashes := make([][32]byte, len(tokens))
	for i, t := range tokens {
		hashes[i] = sha256.Sum256([]byte(t))
	}
	return func(_ context.Context, token string, _ *http.Request) (*auth.TokenInfo, error) {
		h := sha256.Sum256([]byte(token))
		match := 0
		for _, ref := range hashes {
			match |= subtle.ConstantTimeCompare(h[:], ref[:])
		}
		if match != 1 {
			return nil, auth.ErrInvalidToken
		}
		// Static tokens do not expire; give the middleware a rolling expiry.
		return &auth.TokenInfo{Expiration: time.Now().Add(time.Hour)}, nil
	}
}

func serveHTTP(ctx context.Context, cfg *config.Config, server *mcp.Server, instances map[string]tools.Instance, log *slog.Logger) error {
	if len(cfg.AuthTokens) == 0 {
		log.Warn("HTTP transport running WITHOUT authentication (MCP_ALLOW_NO_AUTH=true)")
	}
	srv := &http.Server{
		Addr:              cfg.HTTPAddr,
		Handler:           buildHandler(cfg, server, instances, log),
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       120 * time.Second,
	}
	errCh := make(chan error, 1)
	go func() {
		log.Info("listening", "addr", cfg.HTTPAddr, "path", cfg.HTTPPath, "sse", cfg.HTTPEnableSSE, "auth", len(cfg.AuthTokens) > 0)
		errCh <- srv.ListenAndServe()
	}()
	select {
	case err := <-errCh:
		return err
	case <-ctx.Done():
		log.Info("shutting down")
		sctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		return srv.Shutdown(sctx)
	}
}

// buildHandler assembles the HTTP routes: MCP endpoints (auth-protected) and health probes.
func buildHandler(cfg *config.Config, server *mcp.Server, instances map[string]tools.Instance, log *slog.Logger) http.Handler {
	getServer := func(*http.Request) *mcp.Server { return server }

	protect := func(h http.Handler) http.Handler { return h }
	if len(cfg.AuthTokens) > 0 {
		protect = auth.RequireBearerToken(bearerVerifier(cfg.AuthTokens), &auth.RequireBearerTokenOptions{})
	}

	mux := http.NewServeMux()
	streamable := mcp.NewStreamableHTTPHandler(getServer, &mcp.StreamableHTTPOptions{
		Stateless:      cfg.HTTPStateless,
		JSONResponse:   cfg.HTTPJSONResponse,
		SessionTimeout: cfg.HTTPSessionTimeout,
		Logger:         log,
	})
	mux.Handle(cfg.HTTPPath, protect(streamable))
	if !strings.HasSuffix(cfg.HTTPPath, "/") {
		mux.Handle(cfg.HTTPPath+"/", protect(streamable))
	}
	if cfg.HTTPEnableSSE {
		sse := mcp.NewSSEHandler(getServer, nil)
		mux.Handle("/sse", protect(sse))
		mux.Handle("/sse/", protect(sse))
	}
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = io.WriteString(w, "ok\n")
	})
	// /readyz is ready when every configured Traefik instance answers /api/version.
	// It only reports instance names and ok/fail, no upstream details.
	mux.HandleFunc("/readyz", func(w http.ResponseWriter, r *http.Request) {
		res := probeAll(r.Context(), instances, 5*time.Second)
		body := map[string]string{}
		code := http.StatusOK
		for name, st := range res {
			if st.Error != "" {
				body[name] = "unreachable"
				code = http.StatusServiceUnavailable
			} else {
				body[name] = "ok"
			}
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(code)
		_ = json.NewEncoder(w).Encode(body)
	})

	return logRequests(log, mux)
}

type statusWriter struct {
	http.ResponseWriter
	status int
}

func (w *statusWriter) WriteHeader(code int) {
	w.status = code
	w.ResponseWriter.WriteHeader(code)
}

func (w *statusWriter) Flush() {
	if f, ok := w.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

func (w *statusWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

func logRequests(log *slog.Logger, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/healthz" {
			next.ServeHTTP(w, r)
			return
		}
		start := time.Now()
		sw := &statusWriter{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(sw, r)
		lvl := slog.LevelDebug
		if sw.status == http.StatusUnauthorized || sw.status == http.StatusForbidden {
			lvl = slog.LevelWarn
		}
		log.Log(r.Context(), lvl, "http", "method", r.Method, "path", r.URL.Path, "status", sw.status,
			"remote", r.RemoteAddr, "duration", time.Since(start).Round(time.Millisecond))
	})
}
