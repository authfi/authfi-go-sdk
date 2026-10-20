package authfi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestNew(t *testing.T) {
	c := New(Config{Tenant: "acme", APIKey: "sk_test"})
	if c.cfg.Tenant != "acme" {
		t.Fatalf("expected tenant acme, got %s", c.cfg.Tenant)
	}
	if c.cfg.APIURL != "https://api.authfi.io" {
		t.Fatalf("expected default API URL, got %s", c.cfg.APIURL)
	}
	if c.cfg.JWKSRefresh != 5*time.Minute {
		t.Fatalf("expected 5m JWKS refresh, got %v", c.cfg.JWKSRefresh)
	}
}

func TestNewCustomURL(t *testing.T) {
	c := New(Config{Tenant: "acme", APIKey: "sk_test", APIURL: "https://custom.api.com"})
	if c.cfg.APIURL != "https://custom.api.com" {
		t.Fatalf("expected custom URL, got %s", c.cfg.APIURL)
	}
}

func TestRegisterPermission(t *testing.T) {
	c := New(Config{Tenant: "acme", APIKey: "sk_test"})

	c.RegisterPermission("read:users", "Read user data")
	c.RegisterPermission("write:users", "")
	c.RegisterPermission("read:users", "") // duplicate — should not overwrite

	if len(c.permissions) != 2 {
		t.Fatalf("expected 2 permissions, got %d", len(c.permissions))
	}
	if c.permissions["read:users"] == nil || *c.permissions["read:users"] != "Read user data" {
		t.Fatal("expected read:users to have description")
	}
	if c.permissions["write:users"] != nil {
		t.Fatal("expected write:users to have nil description")
	}
}

func TestGetUserFromContext(t *testing.T) {
	claims := &Claims{Subject: "usr_123", Email: "test@acme.com"}
	ctx := context.WithValue(context.Background(), contextKey{}, claims)

	got := GetUser(ctx)
	if got == nil {
		t.Fatal("expected claims from context")
	}
	if got.Subject != "usr_123" {
		t.Fatalf("expected usr_123, got %s", got.Subject)
	}
}

func TestGetUserEmptyContext(t *testing.T) {
	got := GetUser(context.Background())
	if got != nil {
		t.Fatal("expected nil from empty context")
	}
}

func TestToSet(t *testing.T) {
	s := toSet([]string{"a", "b", "c"})
	if !s["a"] || !s["b"] || !s["c"] {
		t.Fatal("expected all keys to be true")
	}
	if s["d"] {
		t.Fatal("expected d to be false")
	}
}

// --- Sync tests ---

func TestSyncEmpty(t *testing.T) {
	c := New(Config{Tenant: "acme", APIKey: "sk_test"})
	// Empty sync should be no-op, no error
	err := c.Sync()
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
}

func TestSyncSendsPermissions(t *testing.T) {
	var received map[string]interface{}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// The edge dispatch is /<slug>/<path>: the slug comes FIRST. This asserted the transposed
		// shape, which is why the SDK could ship a URL that 404s against every real deployment.
		if r.URL.Path == "/acme/v1/permissions/sync" {
			json.NewDecoder(r.Body).Decode(&received)
			w.Write([]byte(`{"synced":2,"total":2}`))
			return
		}
		w.WriteHeader(404)
	}))
	defer srv.Close()

	c := New(Config{Tenant: "acme", APIKey: "sk_test", APIURL: srv.URL})
	c.RegisterPermission("read:users", "Read users")
	c.RegisterPermission("write:users", "")

	err := c.Sync()
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if received == nil {
		t.Fatal("expected sync request to be sent")
	}

	perms, ok := received["permissions"].([]interface{})
	if !ok || len(perms) != 2 {
		t.Fatalf("expected 2 permissions in sync, got %v", received)
	}
}
