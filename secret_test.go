package authfi

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// The values below are recognisable on purpose: the tests search every output for them.
const (
	sentinelClientSecret = "CLIENTSECRET-9f3a7c1e-sentinel"
	sentinelAPIKey       = "APIKEY-5b2d8e44-sentinel"
	sentinelUserToken    = "eyJhbGciOiJFZERTQSJ9.eyJzdWIiOiJTRU5USU5FTC1UT0tFTiJ9.SIGNATURE-sentinel"
)

var allVerbs = []string{"%v", "%+v", "%#v", "%s", "%q", "%x", "%X", "%d", "%T"}

func secrets() []string { return []string{sentinelClientSecret, sentinelAPIKey, sentinelUserToken} }

func assertNoSecret(t *testing.T, where, out string, extra ...string) {
	t.Helper()
	for _, s := range append(secrets(), extra...) {
		if strings.Contains(out, s) {
			t.Errorf("%s leaks %q: %s", where, s, out)
		}
		// hex of the value would still be the value
		if strings.Contains(out, fmt.Sprintf("%x", s)) {
			t.Errorf("%s leaks the hex of %q", where, s)
		}
	}
}

func secretConfig(apiURL string) Config {
	return Config{
		Issuer: "https://acme.authfi.io", Audience: []string{"api"}, Tenant: "acme",
		APIKey: sentinelAPIKey, ClientSecret: sentinelClientSecret, ApplicationID: "app_1", APIURL: apiURL,
	}
}

func TestConfigAndClientPrintNoSecret(t *testing.T) {
	cfg := secretConfig("")
	c := New(cfg)
	things := map[string]any{"Config": cfg, "*Config": &cfg, "Client": c, "[]Config": []Config{cfg}, "map": map[string]Config{"k": cfg}}
	for name, v := range things {
		for _, verb := range allVerbs {
			assertNoSecret(t, name+" "+verb, fmt.Sprintf(verb, v))
		}
		assertNoSecret(t, name+" Sprint", fmt.Sprint(v))
		assertNoSecret(t, name+" Sprintln", fmt.Sprintln(v))
		b, err := json.Marshal(v)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		assertNoSecret(t, name+" json", string(b))
	}
	if !strings.Contains(c.String(), "https://acme.authfi.io") {
		t.Fatal("the redacted form still names the issuer, so a log line is useful")
	}
}

func TestConfigAndClientAreRedactedInSlog(t *testing.T) {
	cfg := secretConfig("")
	c := New(cfg)
	for name, mk := range map[string]func(*bytes.Buffer) slog.Handler{
		"text": func(b *bytes.Buffer) slog.Handler { return slog.NewTextHandler(b, nil) },
		"json": func(b *bytes.Buffer) slog.Handler { return slog.NewJSONHandler(b, nil) },
	} {
		var buf bytes.Buffer
		l := slog.New(mk(&buf))
		l.Info("built", "cfg", cfg, "ptr", &cfg, "client", c, slog.Any("any", cfg))
		assertNoSecret(t, "slog "+name, buf.String())
		if buf.Len() == 0 {
			t.Fatal("nothing was logged")
		}
	}
}

func TestSecretTypeNeverPrintsItsValue(t *testing.T) {
	s := NewSecret(sentinelClientSecret)
	for _, verb := range allVerbs {
		assertNoSecret(t, "Secret "+verb, fmt.Sprintf(verb, s))
		assertNoSecret(t, "*Secret "+verb, fmt.Sprintf(verb, &s))
	}
	b, _ := json.Marshal(map[string]any{"s": s, "p": &s})
	assertNoSecret(t, "Secret json", string(b))
	var buf bytes.Buffer
	slog.New(slog.NewJSONHandler(&buf, nil)).Info("x", "s", s)
	assertNoSecret(t, "Secret slog", buf.String())
	assertNoSecret(t, "Secret.String", s.String())
	assertNoSecret(t, "Secret.GoString", s.GoString())
	text, _ := s.MarshalText()
	assertNoSecret(t, "Secret text", string(text))
	if s.Reveal() != sentinelClientSecret {
		t.Fatal("Reveal must return the value")
	}
	if got := NewSecret("").String(); got != "" {
		t.Fatalf("an empty secret prints empty, got %q", got)
	}
}

// A server that echoes what it was sent must not get a secret into our errors.
func TestErrorsFromAnEchoingServerCarryNoSecret(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = fmt.Fprintf(w, `{"error":"bad","got_secret":%q,"got_key":%q,"auth":%q,"hdr":%q}`,
			r.Header.Get("X-Client-Secret"), r.Header.Get("X-API-Key"), r.Header.Get("Authorization"), sentinelUserToken)
	}))
	defer srv.Close()
	c := New(secretConfig(srv.URL))
	c.RegisterPermission("read:users", "")

	_, credErr := c.CloudCredentials(sentinelUserToken, "gcp", nil)
	_, tokErr := c.CloudToken(sentinelUserToken, "aud", 60)
	syncErr := c.Sync()
	for name, err := range map[string]error{"CloudCredentials": credErr, "CloudToken": tokErr, "Sync": syncErr} {
		if err == nil {
			t.Fatalf("%s: expected an error", name)
		}
		assertNoSecret(t, name+" error", err.Error())
		for _, verb := range allVerbs {
			assertNoSecret(t, name+" error "+verb, fmt.Sprintf(verb, err))
		}
	}
}

func TestEchoedErrorIsBounded(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(strings.Repeat("A", 1<<20)))
	}))
	defer srv.Close()
	c := New(secretConfig(srv.URL))
	_, err := c.CloudCredentials("t", "gcp", nil)
	if err == nil || len(err.Error()) > 1024 {
		t.Fatalf("the echoed body must be bounded, got %d bytes", len(fmt.Sprint(err)))
	}
}

func TestCloudTokenReportsFailureInsteadOfAnEmptyToken(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"token":"not-a-grant"}`))
	}))
	defer srv.Close()
	tok, err := New(secretConfig(srv.URL)).CloudToken("t", "aud", 60)
	if err == nil || tok != "" {
		t.Fatalf("a 403 must be an error, got %q %v", tok, err)
	}
}

// Network failures carry the URL; a secret placed in the URL must not survive.
func TestTransportErrorCarriesNoSecret(t *testing.T) {
	c := New(secretConfig("http://127.0.0.1:1/" + sentinelClientSecret))
	_, err := c.CloudCredentials(sentinelUserToken, "gcp", nil)
	if err == nil {
		t.Fatal("expected a connection error")
	}
	assertNoSecret(t, "transport error", err.Error())
}

// Refusals and the debug log of a refusal hold the code, never the token.
func TestVerificationErrorsAndLogsCarryNoTokenMaterial(t *testing.T) {
	f := newFixture(t)
	var logs bytes.Buffer
	c := f.client(func(c *Config) {
		c.Logger = slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	})
	tokens := []string{
		f.mint(tokenSpec{header: map[string]any{"typ": "JWT"}}),
		f.mint(tokenSpec{claims: map[string]any{"aud": "other", "sub": "SUBJECT-sentinel"}}),
		f.mint(tokenSpec{header: map[string]any{"kid": "KID-sentinel"}}),
		f.mint(tokenSpec{claims: map[string]any{"iss": "ISSUER-sentinel"}}),
	}
	for _, tok := range tokens {
		_, err := c.VerifyToken(tok)
		if err == nil {
			t.Fatal("expected a refusal")
		}
		var e *Error
		if !errors.As(err, &e) {
			t.Fatalf("expected *Error, got %T", err)
		}
		parts := strings.Split(tok, ".")
		for _, p := range parts {
			if strings.Contains(err.Error(), p) || strings.Contains(logs.String(), p) {
				t.Fatalf("a token segment reached an error or a log: %v", err)
			}
		}
		for _, s := range []string{"SUBJECT-sentinel", "KID-sentinel", "ISSUER-sentinel"} {
			if strings.Contains(err.Error(), s) || strings.Contains(logs.String(), s) {
				t.Fatalf("claim value %q reached an error or a log", s)
			}
		}
	}
	if !strings.Contains(logs.String(), "code=token_typ_invalid") {
		t.Fatalf("a refusal is logged by code, got: %s", logs.String())
	}
}

func TestScrub(t *testing.T) {
	in := "bad request for " + sentinelClientSecret + " with Bearer abcdefgh12345678 and " + sentinelUserToken
	out := Scrub(in, sentinelClientSecret)
	assertNoSecret(t, "Scrub", out, "abcdefgh12345678")
	if !strings.Contains(out, "bad request") {
		t.Fatal("Scrub keeps the useful text")
	}
}

func TestScrubRemovesEncodedFormsOfASecret(t *testing.T) {
	const secret = "a b/c+d secret"
	for _, echoed := range []string{"a+b%2Fc%2Bd+secret", "a%20b%2Fc+d%20secret", "a b/c+d secret"} {
		out := Scrub("rejected "+echoed+" ok", secret)
		if strings.Contains(out, "secret") || !strings.Contains(out, "rejected") {
			t.Errorf("%q -> %q", echoed, out)
		}
	}
}
