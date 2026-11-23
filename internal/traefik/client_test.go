package traefik

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

// Regression: credentials must never follow a redirect to another origin
// (or be downgraded to plain HTTP).
func TestNoRedirectFollow(t *testing.T) {
	var leaked atomic.Bool
	sink := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Api-Key") != "" || r.Header.Get("Authorization") != "" {
			leaked.Store(true)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"Version":"evil"}`)
	}))
	defer sink.Close()
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, sink.URL+"/api/version", http.StatusFound)
	}))
	defer up.Close()

	for _, o := range []Options{
		{Name: "bearer", BaseURL: up.URL, BearerToken: "dummy-bearer", Headers: map[string]string{"X-Api-Key": "dummy-key"}},
		{Name: "basic", BaseURL: up.URL, BasicUser: "u", BasicPassword: "dummy-pass"},
	} {
		c, err := New(o)
		if err != nil {
			t.Fatal(err)
		}
		_, err = c.Version(context.Background())
		if err == nil || !strings.Contains(err.Error(), "redirect not followed") {
			t.Errorf("%s: expected redirect error, got %v", o.Name, err)
		}
	}
	if leaked.Load() {
		t.Error("credentials reached the redirect target")
	}
}
