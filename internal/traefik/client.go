// Package traefik is a small read-only client for the Traefik API (v2/v3).
package traefik

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

// maxResponseBytes caps the size of responses read from Traefik.
const maxResponseBytes = 32 << 20

// Options configures a Client.
type Options struct {
	Name               string
	BaseURL            string
	Timeout            time.Duration
	BearerToken        string
	BasicUser          string
	BasicPassword      string
	Headers            map[string]string
	InsecureSkipVerify bool
	CAFile             string
	UserAgent          string
}

// Client talks to one Traefik instance's /api endpoints.
type Client struct {
	name string
	base string
	http *http.Client
	opts Options
}

// APIError is returned for non-2xx responses.
type APIError struct {
	Instance string
	Path     string
	Status   int
	Body     string
}

func (e *APIError) Error() string {
	msg := strings.TrimSpace(e.Body)
	var m struct {
		Message string `json:"message"`
	}
	if json.Unmarshal([]byte(e.Body), &m) == nil && m.Message != "" {
		msg = m.Message
	}
	if len(msg) > 1000 {
		msg = msg[:1000] + "…"
	}
	hint := ""
	switch e.Status {
	case http.StatusUnauthorized, http.StatusForbidden:
		hint = " (check the upstream credentials for this instance)"
	}
	return fmt.Sprintf("traefik[%s] GET %s: HTTP %d: %s%s", e.Instance, e.Path, e.Status, msg, hint)
}

// IsNotFound reports whether err is a 404 from Traefik.
func IsNotFound(err error) bool {
	var ae *APIError
	return errors.As(err, &ae) && ae.Status == http.StatusNotFound
}

// New creates a client.
func New(o Options) (*Client, error) {
	tr := http.DefaultTransport.(*http.Transport).Clone()
	if o.InsecureSkipVerify || o.CAFile != "" {
		tc := &tls.Config{MinVersion: tls.VersionTLS12, InsecureSkipVerify: o.InsecureSkipVerify} //nolint:gosec // explicit opt-in
		if o.CAFile != "" {
			pem, err := os.ReadFile(o.CAFile)
			if err != nil {
				return nil, fmt.Errorf("reading CA file: %w", err)
			}
			pool, err := x509.SystemCertPool()
			if err != nil || pool == nil {
				pool = x509.NewCertPool()
			}
			if !pool.AppendCertsFromPEM(pem) {
				return nil, errors.New("CA file contains no valid certificates")
			}
			tc.RootCAs = pool
		}
		tr.TLSClientConfig = tc
	}
	if o.Timeout <= 0 {
		o.Timeout = 15 * time.Second
	}
	if o.UserAgent == "" {
		o.UserAgent = "traefik-mcp-go"
	}
	return &Client{
		name: o.Name,
		base: strings.TrimSuffix(strings.TrimRight(o.BaseURL, "/"), "/api") + "/api",
		http: &http.Client{
			Timeout:   o.Timeout,
			Transport: tr,
			// Never follow redirects: credentials (Authorization and custom headers)
			// must only ever reach the configured origin.
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
		opts: o,
	}, nil
}

// Name returns the instance name.
func (c *Client) Name() string { return c.name }

// BaseURL returns the API base URL (ending in /api).
func (c *Client) BaseURL() string { return c.base }

// Response is a raw API response.
type Response struct {
	Body []byte
	// NextPage is the value of X-Next-Page, 0 if there is no further page.
	NextPage int
}

// Get performs a GET request against /api<path>.
func (c *Client) Get(ctx context.Context, path string, query url.Values) (*Response, error) {
	u := c.base + path
	if len(query) > 0 {
		u += "?" + query.Encode()
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", c.opts.UserAgent)
	for k, v := range c.opts.Headers {
		req.Header.Set(k, v)
	}
	switch {
	case c.opts.BearerToken != "":
		req.Header.Set("Authorization", "Bearer "+c.opts.BearerToken)
	case c.opts.BasicUser != "":
		req.SetBasicAuth(c.opts.BasicUser, c.opts.BasicPassword)
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("traefik[%s] GET %s: %w", c.name, path, err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes))
	if err != nil {
		return nil, fmt.Errorf("traefik[%s]: reading response: %w", c.name, err)
	}
	if resp.StatusCode >= 300 && resp.StatusCode <= 399 {
		return nil, &APIError{Instance: c.name, Path: path, Status: resp.StatusCode,
			Body: "redirect not followed (credentials are only sent to the configured URL); point the instance URL at the final API address"}
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return nil, &APIError{Instance: c.name, Path: path, Status: resp.StatusCode, Body: string(data)}
	}
	if ct := resp.Header.Get("Content-Type"); ct != "" && !strings.Contains(ct, "json") {
		return nil, fmt.Errorf("traefik[%s] GET %s: unexpected content type %q (is the URL pointing to the Traefik API?)", c.name, path, ct)
	}
	out := &Response{Body: data}
	// Traefik sets X-Next-Page to 1 when the last page has been reached.
	if np, err := strconv.Atoi(resp.Header.Get("X-Next-Page")); err == nil && np > 1 {
		if p, _ := strconv.Atoi(query.Get("page")); np > max(p, 1) {
			out.NextPage = np
		}
	}
	return out, nil
}

// Version is the payload of /api/version.
type Version struct {
	Version   string `json:"Version"`
	Codename  string `json:"Codename"`
	StartDate string `json:"startDate"`
}

// Version returns the Traefik version (also used as health probe).
func (c *Client) Version(ctx context.Context) (*Version, error) {
	r, err := c.Get(ctx, "/version", nil)
	if err != nil {
		return nil, err
	}
	var v Version
	if err := json.Unmarshal(r.Body, &v); err != nil {
		return nil, fmt.Errorf("traefik[%s]: decoding /version: %w", c.name, err)
	}
	return &v, nil
}
