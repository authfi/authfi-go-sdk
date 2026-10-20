package agent

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"go.opentelemetry.io/otel/trace"
	"golang.org/x/oauth2"
)

type staticSource struct {
	tok   string
	err   error
	calls atomic.Int32
}

func (s *staticSource) Token() (*oauth2.Token, error) {
	s.calls.Add(1)
	if s.err != nil {
		return nil, s.err
	}
	return &oauth2.Token{AccessToken: s.tok, TokenType: "Bearer", Expiry: time.Now().Add(time.Hour)}, nil
}

type recorder struct {
	got  *http.Request
	hits atomic.Int32
}

func (r *recorder) RoundTrip(req *http.Request) (*http.Response, error) {
	r.got = req
	r.hits.Add(1)
	return &http.Response{StatusCode: 200, Body: http.NoBody, Header: http.Header{}, Request: req}, nil
}

func TestTransportSetsBearerAndRemovesTheAPIKey(t *testing.T) {
	rec := &recorder{}
	rt, err := Transport(&staticSource{tok: "TOKEN-1"}, rec, "https://acme.authfi.io")
	if err != nil {
		t.Fatal(err)
	}
	req, _ := http.NewRequest("POST", "https://acme.authfi.io/mcp", nil)
	req.Header.Set("x-api-key", "LEFTOVER-ANTHROPIC-KEY")
	req.Header.Set("Authorization", "Bearer something-else")
	if _, err := rt.RoundTrip(req); err != nil {
		t.Fatal(err)
	}
	if rec.got.Header.Get("Authorization") != "Bearer TOKEN-1" {
		t.Fatalf("%q", rec.got.Header.Get("Authorization"))
	}
	if rec.got.Header.Get("X-Api-Key") != "" {
		t.Fatal("x-api-key must be removed: a leftover key beats the token")
	}
	if req.Header.Get("Authorization") != "Bearer something-else" || req.Header.Get("x-api-key") == "" {
		t.Fatal("the caller's request must not be modified")
	}
}

func TestTransportRefusesOtherOriginsBeforeAskingForAToken(t *testing.T) {
	src, rec := &staticSource{tok: "TOKEN-1"}, &recorder{}
	rt, _ := Transport(src, rec, "https://acme.authfi.io")
	for _, u := range []string{"https://evil.example/mcp", "http://acme.authfi.io/mcp", "https://acme.authfi.io:8443/mcp", "https://acme.authfi.io.evil.example/"} {
		req, _ := http.NewRequest("GET", u, nil)
		if _, err := rt.RoundTrip(req); !errors.Is(err, ErrDestinationNotAllowed) {
			t.Fatalf("%s: %v", u, err)
		}
	}
	if rec.hits.Load() != 0 || src.calls.Load() != 0 {
		t.Fatal("nothing may be sent and no token fetched for a refused destination")
	}
}

func TestTransportRefusesARedirectToAnotherOrigin(t *testing.T) {
	evil := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "" {
			t.Error("the token reached the other origin")
		}
	}))
	defer evil.Close()
	good := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, evil.URL+"/steal", http.StatusFound)
	}))
	defer good.Close()
	rt, err := Transport(&staticSource{tok: "TOKEN-1"}, nil, good.URL)
	if err != nil {
		t.Fatal(err)
	}
	_, err = (&http.Client{Transport: rt}).Get(good.URL + "/mcp")
	if !errors.Is(err, ErrDestinationNotAllowed) {
		t.Fatalf("%v", err)
	}
}

func TestTransportNeedsDestinationsAndASource(t *testing.T) {
	if _, err := Transport(&staticSource{}, nil); err == nil {
		t.Fatal("sendTo is required")
	}
	if _, err := Transport(nil, nil, "https://a.example"); err == nil {
		t.Fatal("a source is required")
	}
	for _, bad := range []string{"http://a.example", "https://a.example/path", "a.example", "https://u:p@a.example"} {
		if _, err := Transport(&staticSource{}, nil, bad); err == nil {
			t.Fatalf("%q accepted", bad)
		}
	}
}

func TestTransportPassesATokenFailureUp(t *testing.T) {
	want := &TokenError{Code: CodeInvalidClient}
	rec := &recorder{}
	rt, _ := Transport(&staticSource{err: want}, rec, "https://acme.authfi.io")
	req, _ := http.NewRequest("GET", "https://acme.authfi.io/mcp", nil)
	if _, err := rt.RoundTrip(req); !errors.Is(err, want) || rec.hits.Load() != 0 {
		t.Fatalf("%v", err)
	}
}

func TestTransportStampsTheTraceFromTheSpanInTheContext(t *testing.T) {
	rec := &recorder{}
	rt, _ := Transport(&staticSource{tok: "T"}, rec, "https://acme.authfi.io")
	tid, _ := trace.TraceIDFromHex("4bf92f3577b34da6a3ce929d0e0e4736")
	sid, _ := trace.SpanIDFromHex("00f067aa0ba902b7")
	sc := trace.NewSpanContext(trace.SpanContextConfig{TraceID: tid, SpanID: sid, TraceFlags: trace.FlagsSampled})
	ctx := trace.ContextWithSpanContext(context.Background(), sc)

	req, _ := http.NewRequestWithContext(ctx, "GET", "https://acme.authfi.io/mcp", nil)
	if _, err := rt.RoundTrip(req); err != nil {
		t.Fatal(err)
	}
	if got := rec.got.Header.Get("traceparent"); got != "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01" {
		t.Fatalf("traceparent %q", got)
	}
	if got := rec.got.Header.Get("X-Request-Id"); got != "otel-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7" {
		t.Fatalf("X-Request-Id %q", got)
	}

	req2, _ := http.NewRequestWithContext(ctx, "GET", "https://acme.authfi.io/mcp", nil)
	req2.Header.Set("traceparent", "00-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-bbbbbbbbbbbbbbbb-00")
	req2.Header.Set("X-Request-Id", "caller-chose-this")
	_, _ = rt.RoundTrip(req2)
	if !strings.HasPrefix(rec.got.Header.Get("traceparent"), "00-aaaa") || rec.got.Header.Get("X-Request-Id") != "caller-chose-this" {
		t.Fatal("headers the caller set are kept")
	}

	req3, _ := http.NewRequest("GET", "https://acme.authfi.io/mcp", nil)
	_, _ = rt.RoundTrip(req3)
	if rec.got.Header.Get("traceparent") != "" || rec.got.Header.Get("X-Request-Id") != "" {
		t.Fatal("no span, no trace headers")
	}
}

// The transport works end to end with a real agent as the source.
func TestTransportWithAnAgentSendsItsCurrentToken(t *testing.T) {
	k := keyFor(t, EdDSA)
	p := newPlatform(t, k)
	var seen string
	gw := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { seen = r.Header.Get("Authorization") }))
	defer gw.Close()
	a := p.agent(k)
	rt, err := Transport(a.TokenSource(), nil, gw.URL)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := (&http.Client{Transport: rt}).Get(gw.URL)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	own, _ := a.Token(context.Background())
	if seen != "Bearer "+own.Reveal() {
		t.Fatal("the gateway must see the agent's current token")
	}
}
