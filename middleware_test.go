package authfi

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func serve(h http.Handler, authz string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, "/api/users", nil)
	if authz != "" {
		req.Header.Set("Authorization", authz)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func okHandler(t *testing.T) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		claims := GetUser(r.Context())
		if claims == nil {
			t.Error("no claims in the request context")
			return
		}
		_, _ = w.Write([]byte(claims.Subject))
	})
}

func neverCalled(t *testing.T) http.Handler {
	return http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Error("handler must not run") })
}

func errorCode(t *testing.T, rec *httptest.ResponseRecorder) string {
	t.Helper()
	var body map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("the body is not JSON: %q", rec.Body.String())
	}
	return body["error"]
}

func TestRequireAllowsAnEdDSAAgentTokenWithThePermission(t *testing.T) {
	f := newFixture(t)
	c := f.client()
	tok := f.mint(tokenSpec{kid: "ed1"})
	rec := serve(c.Require("read:users")(okHandler(t)), "Bearer "+tok)
	if rec.Code != http.StatusOK || rec.Body.String() != "usr_123" {
		t.Fatalf("got %d %q", rec.Code, rec.Body.String())
	}
}

func TestRequireRefusals(t *testing.T) {
	f := newFixture(t)
	c := f.client()
	h := c.Require("read:users")(neverCalled(t))

	rec := serve(c.Require("delete:users")(neverCalled(t)), "Bearer "+f.mint(tokenSpec{}))
	if rec.Code != http.StatusForbidden || errorCode(t, rec) != "insufficient permissions" {
		t.Fatalf("missing permission: %d %s", rec.Code, rec.Body)
	}

	if rec := serve(h, ""); rec.Code != http.StatusUnauthorized || errorCode(t, rec) != CodeMissingBearer {
		t.Fatalf("no header: %d %s", rec.Code, rec.Body)
	}
	if rec := serve(h, "Basic abc"); rec.Code != http.StatusUnauthorized {
		t.Fatalf("basic scheme: %d", rec.Code)
	}
	if rec := serve(h, "Bearer "); rec.Code != http.StatusUnauthorized {
		t.Fatalf("empty bearer: %d", rec.Code)
	}

	idToken := f.mint(tokenSpec{header: map[string]any{"typ": "JWT"}})
	rec = serve(h, "Bearer "+idToken)
	if rec.Code != http.StatusUnauthorized || errorCode(t, rec) != CodeTypInvalid {
		t.Fatalf("an ID token must be refused as an access token: %d %s", rec.Code, rec.Body)
	}
	if rec.Header().Get("WWW-Authenticate") == "" {
		t.Fatal("a 401 carries WWW-Authenticate")
	}
	if strings.Contains(rec.Body.String(), idToken) {
		t.Fatal("the response echoed the token")
	}
}

func TestBearerSchemeIsCaseInsensitive(t *testing.T) {
	f := newFixture(t)
	c := f.client()
	if rec := serve(c.Authenticate(okHandler(t)), "bearer "+f.mint(tokenSpec{})); rec.Code != http.StatusOK {
		t.Fatalf("got %d", rec.Code)
	}
}

// A kid is attacker-controlled. It must never reach the response unescaped.
func TestErrorBodyIsJSONWhateverTheTokenSays(t *testing.T) {
	f := newFixture(t)
	c := f.client()
	evil := `x"},"injected":{"a":"<script>alert(1)</script>`
	rec := serve(c.Authenticate(neverCalled(t)), "Bearer "+f.mint(tokenSpec{header: map[string]any{"kid": evil}}))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("got %d", rec.Code)
	}
	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil || len(body) != 1 {
		t.Fatalf("body must be one JSON field, got %q (%v)", rec.Body.String(), err)
	}
	if strings.Contains(rec.Body.String(), "script") {
		t.Fatal("the kid was echoed")
	}
}

func TestRequireRole(t *testing.T) {
	f := newFixture(t)
	c := f.client()
	tok := "Bearer " + f.mint(tokenSpec{claims: map[string]any{"roles": []string{"editor"}}})
	if rec := serve(c.RequireRole("admin", "editor")(okHandler(t)), tok); rec.Code != http.StatusOK {
		t.Fatalf("got %d", rec.Code)
	}
	if rec := serve(c.RequireRole("superadmin")(neverCalled(t)), tok); rec.Code != http.StatusForbidden {
		t.Fatalf("got %d", rec.Code)
	}
}

func TestMiddlewareAnswers503WhenItCannotVerify(t *testing.T) {
	f := newFixture(t)
	f.status.Store(500)
	rec := serve(f.client().Authenticate(neverCalled(t)), "Bearer "+f.mint(tokenSpec{}))
	if rec.Code != http.StatusServiceUnavailable || errorCode(t, rec) != CodeKeySetUnavailable {
		t.Fatalf("got %d %s", rec.Code, rec.Body)
	}
	rec = serve(New(Config{}).Authenticate(neverCalled(t)), "Bearer x.y.z")
	if rec.Code != http.StatusServiceUnavailable || errorCode(t, rec) != CodeNotConfigured {
		t.Fatalf("got %d %s", rec.Code, rec.Body)
	}
}

func TestStartFetchesTheKeySetAndFailsOnBadConfig(t *testing.T) {
	f := newFixture(t)
	if err := f.client().Start(); err != nil {
		t.Fatal(err)
	}
	if f.fetch.Load() != 1 {
		t.Fatalf("Start must prefetch the key set, fetches: %d", f.fetch.Load())
	}
	if err := New(Config{}).Start(); err == nil {
		t.Fatal("Start must report an unusable configuration")
	}
}
