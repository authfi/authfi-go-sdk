package authfi

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

const (
	testStreamAudience = "stream-aud-1"
	testAgentSubject   = "agent:agt_42"
	evSessionRevoked   = "https://schemas.openid.net/secevent/caep/event-type/session-revoked"
	evClaimsChange     = "https://schemas.openid.net/secevent/caep/event-type/token-claims-change"
	evAccountPurged    = "https://schemas.openid.net/secevent/risc/event-type/account-purged"
	evCompromise       = "https://schemas.openid.net/secevent/risc/event-type/credential-compromise"
	secevent           = "application/secevent+jwt"
)

// setSpec describes one SET the way the transmitter signs it (EdDSA, typ secevent+jwt, opaque
// sub_id), then overrides.
type setSpec struct {
	kid     string
	header  map[string]any
	claims  map[string]any
	dropClm []string
}

var jtiCounter atomic.Int64

func (f *fixture) goodSET(event string, extra map[string]any) map[string]any {
	ev := map[string]any{"event_timestamp": f.clock().Unix()}
	for k, v := range extra {
		ev[k] = v
	}
	return map[string]any{
		"iss": f.issuer(), "jti": "jti-" + string(rune('a'+jtiCounter.Add(1)%26)) + time.Now().Format("150405.000000000"),
		"iat": f.clock().Unix(), "aud": testStreamAudience,
		"sub_id": map[string]any{"format": "opaque", "id": testAgentSubject},
		"events": map[string]any{event: ev},
	}
}

func (f *fixture) mintSET(sp setSpec) string {
	f.t.Helper()
	if sp.kid == "" {
		sp.kid = "ed1"
	}
	f.mu.Lock()
	s := f.keys[sp.kid]
	f.mu.Unlock()
	hdr := map[string]any{"alg": s.alg, "typ": "secevent+jwt", "kid": s.kid}
	for k, v := range sp.header {
		hdr[k] = v
	}
	clm := sp.claims
	if clm == nil {
		clm = f.goodSET(evSessionRevoked, nil)
	}
	for _, k := range sp.dropClm {
		delete(clm, k)
	}
	hj, _ := json.Marshal(hdr)
	cj, _ := json.Marshal(clm)
	signed := b64(hj) + "." + b64(cj)
	return signed + "." + b64(s.sign(signed))
}

type rig struct {
	f     *fixture
	c     *Client
	store *RevocationStore
	r     *Receiver
	mu    sync.Mutex
	got   []Signal
}

func newRig(t *testing.T, mod ...func(*ReceiverConfig)) *rig {
	t.Helper()
	f := newFixture(t)
	g := &rig{f: f}
	g.store = NewRevocationStore(RevocationOptions{})
	g.store.now = f.clock
	g.c = f.client(func(c *Config) { c.Revocations = g.store })
	rc := ReceiverConfig{Audience: testStreamAudience, OnSignal: func(s Signal) {
		g.mu.Lock()
		g.got = append(g.got, s)
		g.mu.Unlock()
	}}
	for _, m := range mod {
		m(&rc)
	}
	r, err := g.c.NewReceiver(rc)
	if err != nil {
		t.Fatalf("NewReceiver: %v", err)
	}
	g.r = r
	return g
}

func (g *rig) signals() []Signal {
	g.mu.Lock()
	defer g.mu.Unlock()
	return append([]Signal(nil), g.got...)
}

func (g *rig) push(body string, mod ...func(*http.Request)) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, "/ssf/push", strings.NewReader(body))
	req.Header.Set("Content-Type", secevent)
	for _, m := range mod {
		m(req)
	}
	w := httptest.NewRecorder()
	g.r.ServeHTTP(w, req)
	return w
}

func wantErr(t *testing.T, w *httptest.ResponseRecorder, status int, code string) {
	t.Helper()
	if w.Code != status {
		t.Fatalf("status = %d, want %d (body %s)", w.Code, status, w.Body.String())
	}
	var b struct {
		Err string `json:"err"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &b)
	if b.Err != code {
		t.Fatalf("err = %q, want %q (body %s)", b.Err, code, w.Body.String())
	}
}

func wantAccepted(t *testing.T, w *httptest.ResponseRecorder) {
	t.Helper()
	if w.Code != http.StatusAccepted {
		t.Fatalf("status = %d, want 202 (body %s)", w.Code, w.Body.String())
	}
}

// tokenFor mints an agent access token: sub is the agent, issued at iat.
func (g *rig) tokenFor(sub string, iat time.Time, extra map[string]any) string {
	cl := map[string]any{"sub": sub, "iat": iat.Unix(), "exp": g.f.clock().Add(time.Hour).Unix()}
	for k, v := range extra {
		cl[k] = v
	}
	return g.f.mint(tokenSpec{claims: cl})
}

func (g *rig) verify(tok string) error {
	_, err := g.c.Verify(context.Background(), tok)
	return err
}

// --- the happy path and the two sides of the not-before line ---

func TestAcceptedRevocationRefusesEarlierTokensAndAllowsLaterOnes(t *testing.T) {
	g := newRig(t)
	now := g.f.clock()
	before := g.tokenFor(testAgentSubject, now.Add(-10*time.Second), nil)
	if err := g.verify(before); err != nil {
		t.Fatalf("a token is fine before any revocation: %v", err)
	}
	wantAccepted(t, g.push(g.f.mintSET(setSpec{})))

	mustCode(t, g.verify(before), CodeRevoked)
	same := g.tokenFor(testAgentSubject, now, nil)
	mustCode(t, g.verify(same), CodeRevoked) // issued in the same second: not provably later
	g.f.advance(2 * time.Second)
	after := g.tokenFor(testAgentSubject, g.f.clock(), nil)
	if err := g.verify(after); err != nil {
		t.Fatalf("a token issued after the revocation must be accepted: %v", err)
	}
	other := g.tokenFor("agent:agt_other", now.Add(-10*time.Second), nil)
	if err := g.verify(other); err != nil {
		t.Fatalf("another subject is unaffected: %v", err)
	}
	if got := g.signals(); len(got) != 1 || !got[0].Revoked || got[0].Subject != testAgentSubject || got[0].Event != evSessionRevoked {
		t.Fatalf("hook = %+v", got)
	}
}

func TestEveryRevokingEventRevokes(t *testing.T) {
	for _, ev := range []string{evSessionRevoked, evAccountPurged, evCompromise} {
		t.Run(ev[strings.LastIndex(ev, "/")+1:], func(t *testing.T) {
			g := newRig(t)
			tok := g.tokenFor(testAgentSubject, g.f.clock().Add(-time.Second), nil)
			wantAccepted(t, g.push(g.f.mintSET(setSpec{claims: g.f.goodSET(ev, nil)})))
			mustCode(t, g.verify(tok), CodeRevoked)
		})
	}
}

func TestDelegatedTokenIsRefusedWhenItsActorIsRevoked(t *testing.T) {
	g := newRig(t)
	tok := g.tokenFor("usr_7", g.f.clock().Add(-time.Second), map[string]any{"act": map[string]any{"sub": testAgentSubject}})
	if err := g.verify(tok); err != nil {
		t.Fatal(err)
	}
	wantAccepted(t, g.push(g.f.mintSET(setSpec{})))
	mustCode(t, g.verify(tok), CodeRevoked)
	// the person's own token, with no agent acting, is not touched
	if err := g.verify(g.tokenFor("usr_7", g.f.clock().Add(-time.Second), nil)); err != nil {
		t.Fatalf("the user is not revoked: %v", err)
	}
}

func TestTokenWithoutIatIsRefusedOnceItsSubjectIsRevoked(t *testing.T) {
	g := newRig(t)
	g.f.t.Helper()
	wantAccepted(t, g.push(g.f.mintSET(setSpec{})))
	tok := g.f.mint(tokenSpec{claims: map[string]any{"sub": testAgentSubject}, dropClm: []string{"iat"}})
	mustCode(t, g.verify(tok), CodeRevoked)
	other := g.f.mint(tokenSpec{claims: map[string]any{"sub": "agent:agt_9"}, dropClm: []string{"iat"}})
	if err := g.verify(other); err != nil {
		t.Fatalf("no revocation for this subject: %v", err)
	}
}

func TestSETIssuedBeforeTheTokenDoesNotRefuseIt(t *testing.T) {
	g := newRig(t)
	now := g.f.clock()
	set := g.f.goodSET(evSessionRevoked, nil)
	set["iat"] = now.Add(-30 * time.Second).Unix() // delivered late
	wantAccepted(t, g.push(g.f.mintSET(setSpec{claims: set})))
	if err := g.verify(g.tokenFor(testAgentSubject, now.Add(-5*time.Second), nil)); err != nil {
		t.Fatalf("minted after the revocation, accepted: %v", err)
	}
	mustCode(t, g.verify(g.tokenFor(testAgentSubject, now.Add(-40*time.Second), nil)), CodeRevoked)
}

func TestResumeIsAcceptedAndDoesNotLiftARevocation(t *testing.T) {
	g := newRig(t)
	now := g.f.clock()
	tok := g.tokenFor(testAgentSubject, now.Add(-time.Second), nil)
	wantAccepted(t, g.push(g.f.mintSET(setSpec{})))
	g.f.advance(time.Second)
	wantAccepted(t, g.push(g.f.mintSET(setSpec{claims: g.f.goodSET(evClaimsChange, map[string]any{"resumed": true})})))
	mustCode(t, g.verify(tok), CodeRevoked) // tokens from before the suspension stay dead
	if err := g.verify(g.tokenFor(testAgentSubject, g.f.clock().Add(time.Second), nil)); err != nil {
		t.Fatalf("a token minted after the resume works: %v", err)
	}
	got := g.signals()
	if len(got) != 2 || !got[1].Resumed || got[1].Revoked {
		t.Fatalf("signals = %+v", got)
	}
}

func TestClaimsChangeWithoutResumeAndUnknownEventsRevokeNothing(t *testing.T) {
	g := newRig(t)
	tok := g.tokenFor(testAgentSubject, g.f.clock().Add(-time.Second), nil)
	wantAccepted(t, g.push(g.f.mintSET(setSpec{claims: g.f.goodSET(evClaimsChange, map[string]any{"revoked_permission": "x"})})))
	wantAccepted(t, g.push(g.f.mintSET(setSpec{claims: g.f.goodSET("https://example.test/unknown", nil)})))
	if err := g.verify(tok); err != nil {
		t.Fatalf("nothing was revoked: %v", err)
	}
	if g.store.Len() != 0 {
		t.Fatal("store must be empty")
	}
}

func TestIssSubSubjectFormat(t *testing.T) {
	g := newRig(t)
	set := g.f.goodSET(evSessionRevoked, nil)
	set["sub_id"] = map[string]any{"format": "iss_sub", "iss": g.f.issuer(), "sub": "usr_5"}
	wantAccepted(t, g.push(g.f.mintSET(setSpec{claims: set})))
	mustCode(t, g.verify(g.tokenFor("usr_5", g.f.clock().Add(-time.Second), nil)), CodeRevoked)

	foreign := g.f.goodSET(evSessionRevoked, nil)
	foreign["sub_id"] = map[string]any{"format": "iss_sub", "iss": "https://elsewhere.test", "sub": "usr_6"}
	wantErr(t, g.push(g.f.mintSET(setSpec{claims: foreign})), 400, "invalid_request")
}

// --- the refusals: each must change nothing ---

func TestRefusedSETsRecordNothingAndNeverCallTheHook(t *testing.T) {
	flipSig := func(tok string) string {
		i := strings.LastIndex(tok, ".")
		return tok[:i+1] + flip(tok[i+1:])
	}
	now := func(g *rig) time.Time { return g.f.clock() }
	cases := []struct {
		name   string
		body   func(g *rig) string
		status int
		code   string
	}{
		{"bad signature", func(g *rig) string { return flipSig(g.f.mintSET(setSpec{})) }, 400, "authentication_failed"},
		{"payload tampered", func(g *rig) string {
			tok := g.f.mintSET(setSpec{})
			p := strings.Split(tok, ".")
			c := g.f.goodSET(evSessionRevoked, nil)
			c["sub_id"] = map[string]any{"format": "opaque", "id": "agent:agt_attacker_choice"}
			cj, _ := json.Marshal(c)
			return p[0] + "." + b64(cj) + "." + p[2]
		}, 400, "authentication_failed"},
		{"unknown kid", func(g *rig) string { return g.f.mintSET(setSpec{header: map[string]any{"kid": "nope"}}) }, 400, "invalid_key"},
		{"no kid", func(g *rig) string { return g.f.mintSET(setSpec{header: map[string]any{"kid": ""}}) }, 400, "invalid_key"},
		{"alg none", func(g *rig) string { return g.f.mintSET(setSpec{header: map[string]any{"alg": "none"}}) }, 400, "invalid_key"},
		{"alg does not match the key", func(g *rig) string { return g.f.mintSET(setSpec{header: map[string]any{"alg": "RS256"}}) }, 400, "invalid_key"},
		{"wrong issuer", func(g *rig) string {
			c := g.f.goodSET(evSessionRevoked, nil)
			c["iss"] = "https://evil.test"
			return g.f.mintSET(setSpec{claims: c})
		}, 400, "invalid_issuer"},
		{"no issuer", func(g *rig) string { return g.f.mintSET(setSpec{dropClm: []string{"iss"}}) }, 400, "invalid_issuer"},
		{"wrong audience", func(g *rig) string {
			c := g.f.goodSET(evSessionRevoked, nil)
			c["aud"] = "someone-else"
			return g.f.mintSET(setSpec{claims: c})
		}, 400, "invalid_audience"},
		{"no audience", func(g *rig) string { return g.f.mintSET(setSpec{dropClm: []string{"aud"}}) }, 400, "invalid_audience"},
		{"the API audience is not the stream audience", func(g *rig) string {
			c := g.f.goodSET(evSessionRevoked, nil)
			c["aud"] = testAudience
			return g.f.mintSET(setSpec{claims: c})
		}, 400, "invalid_audience"},
		{"expired", func(g *rig) string {
			c := g.f.goodSET(evSessionRevoked, nil)
			c["exp"] = now(g).Add(-10 * time.Minute).Unix()
			return g.f.mintSET(setSpec{claims: c})
		}, 400, "invalid_request"},
		{"iat in the future", func(g *rig) string {
			c := g.f.goodSET(evSessionRevoked, nil)
			c["iat"] = now(g).Add(10 * time.Minute).Unix()
			return g.f.mintSET(setSpec{claims: c})
		}, 400, "invalid_request"},
		{"iat older than any token could live", func(g *rig) string {
			c := g.f.goodSET(evSessionRevoked, nil)
			c["iat"] = now(g).Add(-25 * time.Hour).Unix()
			return g.f.mintSET(setSpec{claims: c})
		}, 400, "invalid_request"},
		{"no iat", func(g *rig) string { return g.f.mintSET(setSpec{dropClm: []string{"iat"}}) }, 400, "invalid_request"},
		{"no jti", func(g *rig) string { return g.f.mintSET(setSpec{dropClm: []string{"jti"}}) }, 400, "invalid_request"},
		{"no events", func(g *rig) string { return g.f.mintSET(setSpec{dropClm: []string{"events"}}) }, 400, "invalid_request"},
		{"empty events", func(g *rig) string {
			c := g.f.goodSET(evSessionRevoked, nil)
			c["events"] = map[string]any{}
			return g.f.mintSET(setSpec{claims: c})
		}, 400, "invalid_request"},
		{"event body is not an object", func(g *rig) string {
			c := g.f.goodSET(evSessionRevoked, nil)
			c["events"] = map[string]any{evSessionRevoked: "yes"}
			return g.f.mintSET(setSpec{claims: c})
		}, 400, "invalid_request"},
		{"no subject", func(g *rig) string { return g.f.mintSET(setSpec{dropClm: []string{"sub_id"}}) }, 400, "invalid_request"},
		{"empty subject", func(g *rig) string {
			c := g.f.goodSET(evSessionRevoked, nil)
			c["sub_id"] = map[string]any{"format": "opaque", "id": ""}
			return g.f.mintSET(setSpec{claims: c})
		}, 400, "invalid_request"},
		{"unsupported subject format", func(g *rig) string {
			c := g.f.goodSET(evSessionRevoked, nil)
			c["sub_id"] = map[string]any{"format": "email", "email": "a@b.test"}
			return g.f.mintSET(setSpec{claims: c})
		}, 400, "invalid_request"},
		{"an access token is not a SET", func(g *rig) string {
			return g.tokenFor(testAgentSubject, now(g), nil)
		}, 400, "invalid_request"},
		{"typ at+jwt on a SET body", func(g *rig) string { return g.f.mintSET(setSpec{header: map[string]any{"typ": "at+jwt"}}) }, 400, "invalid_request"},
		{"not a JWT", func(g *rig) string { return "hello" }, 400, "invalid_request"},
		{"empty body", func(g *rig) string { return "" }, 400, "invalid_request"},
		{"payload is not JSON", func(g *rig) string {
			p := strings.Split(g.f.mintSET(setSpec{}), ".")
			return p[0] + "." + b64([]byte("not json")) + "." + p[2]
		}, 400, "authentication_failed"},
		{"too large", func(g *rig) string { return strings.Repeat("a", 20<<10) }, 400, "invalid_request"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			g := newRig(t)
			wantErr(t, g.push(tc.body(g)), tc.status, tc.code)
			if g.store.Len() != 0 || len(g.signals()) != 0 {
				t.Fatalf("a refused SET changed state: store=%d signals=%d", g.store.Len(), len(g.signals()))
			}
			if err := g.verify(g.tokenFor(testAgentSubject, now(g).Add(-time.Second), nil)); err != nil {
				t.Fatalf("nothing was revoked, the token must verify: %v", err)
			}
		})
	}
}

func TestRequestShapeIsEnforced(t *testing.T) {
	g := newRig(t)
	set := g.f.mintSET(setSpec{})
	for _, ct := range []string{"", "application/json", "application/jwt", "text/plain"} {
		wantErr(t, g.push(set, func(r *http.Request) { r.Header.Set("Content-Type", ct) }), 400, "invalid_request")
	}
	for _, m := range []string{http.MethodGet, http.MethodPut, http.MethodDelete} {
		w := httptest.NewRecorder()
		g.r.ServeHTTP(w, httptest.NewRequest(m, "/ssf/push", nil))
		if w.Code != http.StatusMethodNotAllowed || w.Header().Get("Allow") != "POST" {
			t.Fatalf("%s: %d allow=%q", m, w.Code, w.Header().Get("Allow"))
		}
	}
	if g.store.Len() != 0 {
		t.Fatal("nothing may be recorded")
	}
	// media type parameters and case are fine
	wantAccepted(t, g.push(set, func(r *http.Request) { r.Header.Set("Content-Type", "Application/SecEvent+JWT; charset=utf-8") }))
}

func TestRefusalBodyHoldsNoTokenText(t *testing.T) {
	g := newRig(t)
	set := g.f.mintSET(setSpec{header: map[string]any{"kid": "nope"}})
	w := g.push(set)
	if strings.Contains(w.Body.String(), set[:20]) || strings.Contains(w.Body.String(), testAgentSubject) {
		t.Fatalf("body echoes input: %s", w.Body.String())
	}
	if w.Header().Get("Content-Type") != "application/json" {
		t.Fatalf("content type %q", w.Header().Get("Content-Type"))
	}
}

// --- replay ---

func TestReplayedJTIIsAcceptedOnceAndAppliedOnce(t *testing.T) {
	g := newRig(t)
	set := g.f.mintSET(setSpec{})
	wantAccepted(t, g.push(set))
	wantAccepted(t, g.push(set)) // the transmitter retried because it lost our 202
	wantAccepted(t, g.push(set))
	if n := len(g.signals()); n != 1 {
		t.Fatalf("hook ran %d times for one jti, want 1", n)
	}
}

func TestRefusedSETDoesNotBurnItsJTI(t *testing.T) {
	g := newRig(t)
	c := g.f.goodSET(evSessionRevoked, nil)
	c["jti"] = "shared-jti"
	bad := make(map[string]any)
	for k, v := range c {
		bad[k] = v
	}
	bad["aud"] = "wrong"
	wantErr(t, g.push(g.f.mintSET(setSpec{claims: bad})), 400, "invalid_audience")
	wantAccepted(t, g.push(g.f.mintSET(setSpec{claims: c})))
	if len(g.signals()) != 1 {
		t.Fatal("the good SET with the same jti must still apply")
	}
}

func TestConcurrentDuplicatesApplyOnce(t *testing.T) {
	g := newRig(t)
	set := g.f.mintSET(setSpec{})
	var wg sync.WaitGroup
	for i := 0; i < 40; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if w := g.push(set); w.Code != http.StatusAccepted {
				t.Errorf("status %d", w.Code)
			}
		}()
	}
	wg.Wait()
	if n := len(g.signals()); n != 1 {
		t.Fatalf("hook ran %d times, want 1", n)
	}
}

func TestSeenSetIsBoundedAndExpires(t *testing.T) {
	s := newSeenSet(3, time.Minute)
	t0 := time.Unix(1_000_000, 0)
	for _, id := range []string{"a", "b", "c"} {
		if !s.claim(id, t0) {
			t.Fatalf("%s should be new", id)
		}
	}
	if s.claim("b", t0) {
		t.Fatal("b is a duplicate")
	}
	if !s.claim("d", t0) { // full: forgets the oldest
		t.Fatal("d should be new")
	}
	if len(s.m) != 3 {
		t.Fatalf("size %d, want 3", len(s.m))
	}
	if !s.claim("a", t0) {
		t.Fatal("a was evicted, so it counts as new again")
	}
	if !s.claim("b", t0.Add(2*time.Minute)) || len(s.m) != 1 {
		t.Fatalf("everything expired: size %d", len(s.m))
	}
	for i := 0; i < 5000; i++ {
		s.claim(string(rune(i+1000))+"x", t0.Add(3*time.Minute))
	}
	if len(s.m) > 3 || len(s.q)-s.head != len(s.m) {
		t.Fatalf("bounded: map %d queue %d", len(s.m), len(s.q)-s.head)
	}
}

// --- authentication of the push itself ---

func TestPushBearerWhenConfigured(t *testing.T) {
	g := newRig(t, func(rc *ReceiverConfig) { rc.AuthToken = NewSecret("s3cret-push") })
	set := g.f.mintSET(setSpec{})
	for _, h := range []string{"", "Bearer wrong", "Bearer s3cret-pus", "Bearer s3cret-pushX", "Basic s3cret-push", "s3cret-push"} {
		w := g.push(set, func(r *http.Request) {
			if h != "" {
				r.Header.Set("Authorization", h)
			}
		})
		if w.Code != http.StatusUnauthorized {
			t.Fatalf("%q: status %d, want 401", h, w.Code)
		}
	}
	if g.store.Len() != 0 {
		t.Fatal("an unauthenticated push recorded something")
	}
	wantAccepted(t, g.push(set, func(r *http.Request) { r.Header.Set("Authorization", "Bearer s3cret-push") }))
}

// --- key set trouble ---

func TestKeySetOutageAnswers503AndRecordsNothing(t *testing.T) {
	g := newRig(t)
	set := g.f.mintSET(setSpec{})
	g.f.status.Store(500)
	w := g.push(set)
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("status %d, want 503 so the transmitter retries", w.Code)
	}
	if g.store.Len() != 0 {
		t.Fatal("recorded under an outage")
	}
	g.f.status.Store(0)
	g.f.advance(minRefetch + time.Second)
	wantAccepted(t, g.push(set)) // the retry lands, and its jti was not burned
}

func TestRotatedKeySignsSETs(t *testing.T) {
	g := newRig(t)
	_, _ = g.f.keys["ed1"], 0
	g.f.add(&signer{kid: "ed2", alg: "EdDSA", ed: g.f.keys["ed1"].ed})
	g.f.advance(minRefetch + time.Second)
	wantAccepted(t, g.push(g.f.mintSET(setSpec{kid: "ed2"})))
}

// --- configuration fails closed ---

func TestNewReceiverRefusesWhatCannotWork(t *testing.T) {
	f := newFixture(t)
	_, err := f.client().NewReceiver(ReceiverConfig{Audience: "a"})
	mustCode(t, err, CodeNotConfigured) // no store on the client
	_, err = f.client(func(c *Config) { c.Revocations = NewRevocationStore(RevocationOptions{}) }).NewReceiver(ReceiverConfig{})
	mustCode(t, err, CodeNotConfigured) // no audience
	_, err = f.client(func(c *Config) { c.Revocations = NewRevocationStore(RevocationOptions{}); c.Issuer = "" }).NewReceiver(ReceiverConfig{Audience: "a"})
	mustCode(t, err, CodeNotConfigured)
	_, err = f.client(func(c *Config) { c.Revocations = NewRevocationStore(RevocationOptions{}) }).NewReceiver(ReceiverConfig{Audience: "a", AuthToken: NewSecret("")})
	if err != nil {
		t.Fatalf("an empty secret is no secret: %v", err)
	}
}

func TestVerifyWithoutAStoreIsUnchanged(t *testing.T) {
	f := newFixture(t)
	c := f.client()
	if _, err := c.Verify(context.Background(), f.mint(tokenSpec{})); err != nil {
		t.Fatal(err)
	}
}

func TestHookPanicDoesNotUndoARevocation(t *testing.T) {
	g := newRig(t, func(rc *ReceiverConfig) { rc.OnSignal = func(Signal) { panic("boom") } })
	tok := g.tokenFor(testAgentSubject, g.f.clock().Add(-time.Second), nil)
	wantAccepted(t, g.push(g.f.mintSET(setSpec{})))
	mustCode(t, g.verify(tok), CodeRevoked)
}

// --- the store ---

func TestStoreMonotoneAndExpiring(t *testing.T) {
	now := time.Unix(2_000_000, 0)
	s := NewRevocationStore(RevocationOptions{TokenLifetime: time.Hour})
	s.now = func() time.Time { return now }
	s.Revoke("a", now)
	s.Revoke("a", now.Add(-time.Minute)) // an earlier time never lowers the line
	if !s.IsRevoked("a", now) {
		t.Fatal("line lowered")
	}
	s.Revoke("a", now.Add(time.Minute))
	if !s.IsRevoked("a", now.Add(time.Minute)) || s.IsRevoked("a", now.Add(time.Minute+time.Second)) {
		t.Fatal("line must rise to the later time and stop there")
	}
	now = now.Add(time.Hour + 2*time.Minute)
	if s.IsRevoked("a", now.Add(-2*time.Hour)) {
		t.Fatal("expired entries no longer refuse: every token they covered has expired")
	}
	if s.Revoke("old", now.Add(-2*time.Hour)); s.Len() != 1 {
		t.Fatalf("a revocation already past the lifetime must not be stored (len %d)", s.Len())
	}
	s.Revoke("z", now)
	if !s.IsRevoked("z", time.Time{}) || s.IsRevoked("y", time.Time{}) {
		t.Fatal("an unknown issue time is revoked exactly when the subject has a live revocation")
	}
	var nilStore *RevocationStore
	if nilStore.IsRevoked("a", now) || nilStore.Len() != 0 {
		t.Fatal("nil store")
	}
	nilStore.Revoke("a", now)
}

func TestStoreCapRaisesAFloorInsteadOfForgettingARevocation(t *testing.T) {
	now := time.Unix(3_000_000, 0)
	s := NewRevocationStore(RevocationOptions{MaxEntries: 20, TokenLifetime: time.Hour})
	s.now = func() time.Time { return now }
	for i := 0; i < 20; i++ {
		s.Revoke("s"+string(rune('A'+i)), now.Add(time.Duration(i)*time.Second))
	}
	if s.Len() != 20 {
		t.Fatalf("len %d", s.Len())
	}
	dropped := s.Revoke("newcomer", now.Add(30*time.Second))
	if dropped == 0 || s.Len() > 20 {
		t.Fatalf("dropped %d, len %d: the store must stay at its cap", dropped, s.Len())
	}
	// the oldest revocation was dropped; a token it covered is still refused, by the floor
	if !s.IsRevoked("sA", now.Add(-time.Minute)) {
		t.Fatal("a dropped revocation must still refuse the tokens it covered")
	}
	if !s.IsRevoked("someone-unrelated", now.Add(-time.Minute)) {
		t.Fatal("the floor applies to every subject")
	}
	if s.IsRevoked("someone-unrelated", now.Add(20*time.Second)) {
		t.Fatal("tokens newer than the floor are untouched")
	}
	t0 := now
	now = now.Add(2 * time.Hour)
	if s.IsRevoked("someone-unrelated", t0.Add(-time.Minute)) {
		t.Fatal("the floor ages out with the lifetime")
	}
}

func TestStoreStaysBoundedUnderAFlood(t *testing.T) {
	now := time.Unix(4_000_000, 0)
	s := NewRevocationStore(RevocationOptions{MaxEntries: 500, TokenLifetime: time.Hour})
	s.now = func() time.Time { return now }
	for i := 0; i < 20_000; i++ {
		s.Revoke("subject-"+itoa(i), now.Add(time.Duration(i)*time.Millisecond*10))
	}
	if s.Len() > 500 {
		t.Fatalf("len %d exceeds the cap", s.Len())
	}
}

func itoa(i int) string {
	b, _ := json.Marshal(i)
	return string(b)
}

// --- stream registration ---

func TestRegisterStream(t *testing.T) {
	var gotAuth, gotBody, gotPath string
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/.well-known/ssf-configuration":
			_ = json.NewEncoder(w).Encode(map[string]any{"issuer": srv.URL, "configuration_endpoint": srv.URL + "/v1/ssf/streams"})
		case r.URL.Path == "/v1/ssf/streams" && r.Method == http.MethodPost:
			gotAuth, gotPath = r.Header.Get("Authorization"), r.URL.Path
			raw, _ := io.ReadAll(r.Body)
			gotBody = string(raw)
			w.WriteHeader(201)
			_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"id": "str_1", "audience": "stream-aud-1", "endpoint_url": "https://rp.test/ssf", "status": "enabled", "events_requested": []string{evSessionRevoked}}})
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	c := New(Config{Issuer: srv.URL, Audience: []string{"api"}})
	st, err := c.RegisterStream(context.Background(), NewSecret("operator-token"), StreamRequest{
		Audience: "stream-aud-1", EndpointURL: "https://rp.test/ssf", AuthToken: NewSecret("push-secret"), Events: []string{evSessionRevoked},
	})
	if err != nil {
		t.Fatal(err)
	}
	if st.ID != "str_1" || st.Status != "enabled" || gotPath != "/v1/ssf/streams" || gotAuth != "Bearer operator-token" {
		t.Fatalf("st=%+v path=%s auth=%s", st, gotPath, gotAuth)
	}
	var sent map[string]any
	_ = json.Unmarshal([]byte(gotBody), &sent)
	if sent["audience"] != "stream-aud-1" || sent["endpoint_url"] != "https://rp.test/ssf" || sent["auth_token"] != "push-secret" {
		t.Fatalf("body %s", gotBody)
	}
	if strings.Contains(fmtAll(st), "push-secret") || strings.Contains(fmtAll(st), "operator-token") {
		t.Fatal("secrets printed")
	}
}

func fmtAll(v any) string { b, _ := json.Marshal(v); return string(b) }

func TestRegisterStreamRefusals(t *testing.T) {
	var hits atomic.Int32
	evil := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits.Add(1) }))
	t.Cleanup(evil.Close)
	serve := func(cfg func(base string) map[string]any, post int) *httptest.Server {
		var srv *httptest.Server
		srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/.well-known/ssf-configuration" {
				_ = json.NewEncoder(w).Encode(cfg(srv.URL))
				return
			}
			hits.Add(1)
			w.WriteHeader(post)
			if post/100 == 2 {
				_, _ = w.Write([]byte(`{"data":{"id":"str_1","status":"enabled"}}`))
				return
			}
			_, _ = w.Write([]byte(`{"error":"operator-token leaked"}`))
		}))
		t.Cleanup(srv.Close)
		return srv
	}
	req := StreamRequest{Audience: "a", EndpointURL: "https://rp.test/ssf"}
	tok := NewSecret("operator-token")

	t.Run("endpoint on another host would receive the bearer", func(t *testing.T) {
		hits.Store(0)
		srv := serve(func(b string) map[string]any {
			return map[string]any{"issuer": b, "configuration_endpoint": evil.URL + "/v1/ssf/streams"}
		}, 201)
		if _, err := New(Config{Issuer: srv.URL, Audience: []string{"api"}}).RegisterStream(context.Background(), tok, req); err == nil {
			t.Fatal("must refuse")
		}
		if hits.Load() != 0 {
			t.Fatal("the bearer was sent to another host")
		}
	})
	t.Run("metadata names another issuer", func(t *testing.T) {
		hits.Store(0)
		srv := serve(func(b string) map[string]any {
			return map[string]any{"issuer": "https://other.test", "configuration_endpoint": b + "/v1/ssf/streams"}
		}, 201)
		if _, err := New(Config{Issuer: srv.URL, Audience: []string{"api"}}).RegisterStream(context.Background(), tok, req); err == nil || hits.Load() != 0 {
			t.Fatalf("must refuse before registering (err=%v hits=%d)", err, hits.Load())
		}
	})
	t.Run("server refusal is an error that holds no secret", func(t *testing.T) {
		srv := serve(func(b string) map[string]any {
			return map[string]any{"issuer": b, "configuration_endpoint": b + "/v1/ssf/streams"}
		}, 403)
		_, err := New(Config{Issuer: srv.URL, Audience: []string{"api"}}).RegisterStream(context.Background(), tok, req)
		if err == nil || strings.Contains(err.Error(), "operator-token") {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("invalid requests are refused before any request is made", func(t *testing.T) {
		hits.Store(0)
		srv := serve(func(b string) map[string]any {
			return map[string]any{"issuer": b, "configuration_endpoint": b + "/v1/ssf/streams"}
		}, 201)
		c := New(Config{Issuer: srv.URL, Audience: []string{"api"}})
		for _, r := range []StreamRequest{{EndpointURL: "https://rp.test"}, {Audience: "a"}, {Audience: "a", EndpointURL: "http://rp.test/ssf"}, {Audience: "a", EndpointURL: "https://u:p@rp.test/ssf"}} {
			if _, err := c.RegisterStream(context.Background(), tok, r); err == nil {
				t.Fatalf("%+v must be refused", r)
			}
		}
		if _, err := c.RegisterStream(context.Background(), NewSecret(""), req); err == nil {
			t.Fatal("no bearer")
		}
		if hits.Load() != 0 {
			t.Fatal("an invalid request reached the transmitter")
		}
		if _, err := c.RegisterStream(context.Background(), tok, req); err != nil {
			t.Fatalf("control: a valid request registers: %v", err)
		}
	})
	t.Run("not configured", func(t *testing.T) {
		_, err := New(Config{}).RegisterStream(context.Background(), tok, req)
		var e *Error
		if !errors.As(err, &e) || e.Code != CodeNotConfigured {
			t.Fatalf("err = %v", err)
		}
	})
}
