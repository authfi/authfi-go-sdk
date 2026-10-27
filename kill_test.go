package authfi

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestKillRefusalHeaders(t *testing.T) {
	g := newRig(t, func(rc *ReceiverConfig) { rc.AuthToken = NewSecret("s3cret-push") })
	w := g.push(g.f.mintSET(setSpec{}))
	if w.Code != 401 || !strings.HasPrefix(w.Header().Get("WWW-Authenticate"), "Bearer") {
		t.Fatalf("401 must carry WWW-Authenticate: %d %v", w.Code, w.Header())
	}
	g.f.status.Store(500)
	w = g.push(g.f.mintSET(setSpec{}), func(r *http.Request) { r.Header.Set("Authorization", "Bearer s3cret-push") })
	if w.Code != 503 || w.Header().Get("Retry-After") == "" {
		t.Fatalf("503 must carry Retry-After: %d %v", w.Code, w.Header())
	}
}

type endless struct{ n atomic.Int64 }

func (e *endless) Read(p []byte) (int, error) {
	if e.n.Load() > 8<<20 {
		return 0, io.EOF
	}
	e.n.Add(int64(len(p)))
	for i := range p {
		p[i] = 'A'
	}
	return len(p), nil
}

func TestKillBodyIsReadBoundedNotToTheEnd(t *testing.T) {
	g := newRig(t)
	src := &endless{}
	req := httptest.NewRequest(http.MethodPost, "/ssf/push", src)
	req.Header.Set("Content-Type", secevent)
	w := httptest.NewRecorder()
	g.r.ServeHTTP(w, req)
	if w.Code != 400 {
		t.Fatalf("status %d", w.Code)
	}
	if src.n.Load() > 1<<20 {
		t.Fatalf("read %d bytes of a body that can never be a valid SET", src.n.Load())
	}
}

func TestKillBodyWhitespaceAndBearerForms(t *testing.T) {
	g := newRig(t, func(rc *ReceiverConfig) { rc.AuthToken = NewSecret("s3cret-push") })
	set := g.f.mintSET(setSpec{})
	body := "\n" + set + "\r\n"
	for _, h := range []string{"bearer s3cret-push", "BEARER s3cret-push", "Bearer    s3cret-push"} {
		g2 := newRig(t, func(rc *ReceiverConfig) { rc.AuthToken = NewSecret("s3cret-push") })
		w := g2.push(g2.f.mintSET(setSpec{}), func(r *http.Request) { r.Header.Set("Authorization", h) })
		if w.Code != http.StatusAccepted {
			t.Fatalf("%q -> %d", h, w.Code)
		}
	}
	wantAccepted(t, g.push(body, func(r *http.Request) { r.Header.Set("Authorization", "Bearer s3cret-push") }))
}

func TestKillLengthAndTimeBoundaries(t *testing.T) {
	cases := []struct {
		name string
		mod  func(g *rig, c map[string]any)
		ok   bool
	}{
		{"jti 256", func(g *rig, c map[string]any) { c["jti"] = strings.Repeat("j", 256) }, true},
		{"jti 257", func(g *rig, c map[string]any) { c["jti"] = strings.Repeat("j", 257) }, false},
		{"subject 512", func(g *rig, c map[string]any) {
			c["sub_id"] = map[string]any{"format": "opaque", "id": strings.Repeat("s", 512)}
		}, true},
		{"subject 513", func(g *rig, c map[string]any) {
			c["sub_id"] = map[string]any{"format": "opaque", "id": strings.Repeat("s", 513)}
		}, false},
		{"iat +30s (inside leeway)", func(g *rig, c map[string]any) { c["iat"] = g.f.clock().Add(30 * time.Second).Unix() }, true},
		{"iat +60s (leeway edge)", func(g *rig, c map[string]any) { c["iat"] = g.f.clock().Add(60 * time.Second).Unix() }, true},
		{"iat +61s", func(g *rig, c map[string]any) { c["iat"] = g.f.clock().Add(61 * time.Second).Unix() }, false},
		{"iat one second inside the lifetime", func(g *rig, c map[string]any) {
			c["iat"] = g.f.clock().Add(-DefaultTokenLifetime + time.Second).Unix()
		}, true},
		{"exp 30s ago (inside leeway)", func(g *rig, c map[string]any) { c["exp"] = g.f.clock().Add(-30 * time.Second).Unix() }, true},
		{"exp 61s ago", func(g *rig, c map[string]any) { c["exp"] = g.f.clock().Add(-61 * time.Second).Unix() }, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			g := newRig(t)
			c := g.f.goodSET(evSessionRevoked, nil)
			tc.mod(g, c)
			w := g.push(g.f.mintSET(setSpec{claims: c}))
			if (w.Code == http.StatusAccepted) != tc.ok {
				t.Fatalf("status %d %s, accepted want %v", w.Code, w.Body.String(), tc.ok)
			}
		})
	}
}

func TestKillIgnoredEventNeverReachesTheHook(t *testing.T) {
	g := newRig(t)
	c := g.f.goodSET("https://example.test/event/unknown", nil)
	wantAccepted(t, g.push(g.f.mintSET(setSpec{claims: c})))
	if n := len(g.signals()); n != 0 {
		t.Fatalf("hook saw %d ignored events", n)
	}
}

func TestKillVerifyFailureOfAForeignErrorIsRetryable(t *testing.T) {
	st, code, _ := verifyFailure(errors.New("boom"))
	if st != 503 || code != "temporarily_unavailable" {
		t.Fatalf("%d %s", st, code)
	}
}

func TestKillSeenSetKeepsAsManyJTIsAsTheStore(t *testing.T) {
	g := newRig(t)
	g.store = NewRevocationStore(RevocationOptions{MaxEntries: 3})
	g.store.now = g.f.clock
	g.c = g.f.client(func(c *Config) { c.Revocations = g.store })
	var hooks atomic.Int32
	r, err := g.c.NewReceiver(ReceiverConfig{Audience: testStreamAudience, OnSignal: func(Signal) { hooks.Add(1) }})
	if err != nil {
		t.Fatal(err)
	}
	g.r = r
	a := g.f.mintSET(setSpec{})
	b := g.f.mintSET(setSpec{})
	wantAccepted(t, g.push(a))
	wantAccepted(t, g.push(b))
	wantAccepted(t, g.push(a)) // replay: applied once
	if hooks.Load() != 2 {
		t.Fatalf("hook ran %d times, want 2", hooks.Load())
	}
}

func TestKillRegisterStreamEdges(t *testing.T) {
	type reply struct {
		meta   func(base string) map[string]any
		status int
		body   string
		disc   int
	}
	run := func(rp reply, req StreamRequest) (*Stream, error, string) {
		var srv *httptest.Server
		var posted string
		srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/.well-known/ssf-configuration" {
				if rp.disc != 0 {
					w.WriteHeader(rp.disc)
				}
				_ = json.NewEncoder(w).Encode(rp.meta(srv.URL))
				return
			}
			raw, _ := io.ReadAll(r.Body)
			posted = string(raw)
			w.WriteHeader(rp.status)
			_, _ = w.Write([]byte(rp.body))
		}))
		defer srv.Close()
		st, err := New(Config{Issuer: srv.URL, Audience: []string{"api"}}).RegisterStream(context.Background(), NewSecret("operator-token"), req)
		return st, err, posted
	}
	good := func(b string) map[string]any {
		return map[string]any{"issuer": b, "configuration_endpoint": b + "/v1/ssf/streams"}
	}
	req := StreamRequest{Audience: "a", EndpointURL: "https://rp.test/ssf", Events: []string{evSessionRevoked}}

	if _, err, posted := run(reply{good, 201, `{"data":{"id":"s1"}}`, 0}, req); err != nil || !strings.Contains(posted, `"events_requested":["`+evSessionRevoked) {
		t.Fatalf("events must be sent: err=%v posted=%s", err, posted)
	}
	if _, err, _ := run(reply{good, 307, `{"data":{"id":"s1"}}`, 0}, req); err == nil {
		t.Fatal("a 3xx reply is not a registration")
	}
	if _, err, _ := run(reply{good, 201, `{"data":{}}`, 0}, req); err == nil {
		t.Fatal("a reply without a stream id is not a registration")
	}
	if _, err, _ := run(reply{good, 201, `{"data":{"id":"s1"}}`, 500}, req); err == nil {
		t.Fatal("a failing discovery document must stop the registration")
	}
	slash := func(b string) map[string]any {
		return map[string]any{"issuer": b + "/", "configuration_endpoint": b + "/v1/ssf/streams"}
	}
	if _, err, _ := run(reply{slash, 201, `{"data":{"id":"s1"}}`, 0}, req); err != nil {
		t.Fatalf("a trailing slash on the metadata issuer is the same issuer: %v", err)
	}
	for _, c := range []struct{ raw, base string }{
		{"https://h.test/x", "http://h.test"},
		{"http://u:p@h.test/x", "http://h.test"},
		{"http://h.test/x#f", "http://h.test"},
		{"", "http://h.test"},
	} {
		if sameOrigin(c.raw, c.base) {
			t.Fatalf("sameOrigin(%q,%q)", c.raw, c.base)
		}
	}
}

func TestKillDiscoveryReplyIsReadBounded(t *testing.T) {
	var written atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		chunk := []byte(strings.Repeat("x", 32<<10))
		for i := 0; i < 1024 && r.Context().Err() == nil; i++ {
			n, err := w.Write(chunk)
			written.Add(int64(n))
			if err != nil {
				return
			}
		}
	}))
	defer srv.Close()
	_, err := New(Config{Issuer: srv.URL, Audience: []string{"api"}}).RegisterStream(context.Background(), NewSecret("operator-token"), StreamRequest{Audience: "a", EndpointURL: "https://rp.test/ssf"})
	if err == nil {
		t.Fatal("garbage discovery must fail")
	}
	if written.Load() > 8<<20 {
		t.Fatalf("the client drained %d bytes of a discovery reply", written.Load())
	}
}

func TestKillStaleBoundaryIsExactlyTheRetention(t *testing.T) {
	for _, tc := range []struct {
		age     time.Duration
		applied bool
	}{
		{DefaultTokenLifetime + maxLeeway, false},
		{DefaultTokenLifetime + maxLeeway - time.Second, true},
	} {
		g := newRig(t)
		c := g.f.goodSET(evSessionRevoked, nil)
		c["iat"] = g.f.clock().Add(-tc.age).Unix()
		wantAccepted(t, g.push(g.f.mintSET(setSpec{claims: c})))
		if (g.store.Len() == 1) != tc.applied {
			t.Fatalf("age %v: recorded=%d want applied=%v", tc.age, g.store.Len(), tc.applied)
		}
	}
}
