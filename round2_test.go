package authfi

import (
	"context"
	"encoding/asn1"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// --- the replay guard: one key cannot lock out the others ---

func TestReplayFillLocksOutOthers(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	g := newMemoryReplayGuard(func() time.Time { return now })
	until := now.Add(65 * time.Second)
	ctx := context.Background()
	for i := 0; i < maxReplayPerKey; i++ {
		if fresh, err := g.Claim(ctx, "noisy:"+strconv.Itoa(i), until); err != nil || !fresh {
			t.Fatalf("claim %d: %v %v", i, fresh, err)
		}
	}
	if _, err := g.Claim(ctx, "noisy:extra", until); err != ErrReplayGuardFull {
		t.Fatalf("one key is capped: %v", err)
	}
	if fresh, err := g.Claim(ctx, "noisy:3", until); err != nil || fresh {
		t.Fatalf("a recorded id is still a replay when its key is capped: %v %v", fresh, err)
	}
	if fresh, err := g.Claim(ctx, "victim:1", until); err != nil || !fresh {
		t.Fatalf("another key must still work: %v %v", fresh, err)
	}
	now = now.Add(2 * time.Minute) // the entries expire
	if fresh, err := g.Claim(ctx, "noisy:extra", now.Add(time.Minute)); err != nil || !fresh {
		t.Fatalf("a capped key recovers when its entries expire: %v %v", fresh, err)
	}
	if len(g.seen) != 1 || len(g.perKey) != 1 || len(g.buckets) != 1 {
		t.Fatalf("expired entries were not released: %d %d %d", len(g.seen), len(g.perKey), len(g.buckets))
	}
	now = now.Add(48 * time.Hour) // a long idle gap releases everything at once
	if fresh, _ := g.Claim(ctx, "victim:2", now.Add(time.Minute)); !fresh || len(g.seen) != 1 {
		t.Fatalf("after a long gap: %d", len(g.seen))
	}
}

func TestReplayRefusalDoesNotScanTheGuard(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	g := newMemoryReplayGuard(func() time.Time { return now })
	until := now.Add(65 * time.Second)
	ctx := context.Background()
	for k := 0; k < 100; k++ {
		for i := 0; i < maxReplayPerKey; i++ {
			if _, err := g.Claim(ctx, "key"+strconv.Itoa(k)+":"+strconv.Itoa(i), until); err != nil {
				t.Fatal(err)
			}
		}
	}
	start := time.Now()
	for i := 0; i < 3000; i++ {
		if _, err := g.Claim(ctx, "key0:over"+strconv.Itoa(i), until); err != ErrReplayGuardFull {
			t.Fatal(err)
		}
	}
	if d := time.Since(start); d > 300*time.Millisecond {
		t.Fatalf("3000 refusals took %s with 100000 entries held: the refusal path scans", d)
	}
}

func TestReplayGuardFullAnswersItsOwnCode(t *testing.T) {
	e := newAgentEnv(t)
	c := e.client(func(c *Config) { c.ReplayGuard = stubGuard{err: ErrReplayGuardFull} })
	tok := e.token(nil, nil)
	_, err := e.call(c, tok, nil)
	mustCode(t, err, CodeDPoPReplayGuardFull)
	rec := httptest.NewRecorder()
	c.Require("read:users")(neverCalled(t)).ServeHTTP(rec, request("DPoP", tok, e.proof(tok, nil)))
	if rec.Code != 429 || errorCode(t, rec) != CodeDPoPReplayGuardFull {
		t.Fatalf("%d %s", rec.Code, rec.Body.String())
	}
}

func TestOneNoisyKeyDoesNotLockOutAnotherAgent(t *testing.T) {
	e := newAgentEnv(t)
	c := e.client()
	noisy, victim := newProofSigner("EdDSA"), newProofSigner("EdDSA")
	e.pk = noisy
	noisyTok := e.token(nil, nil)
	e.pk = victim
	victimTok := e.token(nil, nil)
	for i := 0; i < maxReplayPerKey; i++ {
		if _, err := c.VerifyRequest(request("DPoP", noisyTok, e.proofBy(noisy, noisyTok, nil))); err != nil {
			t.Fatalf("noisy %d: %v", i, err)
		}
	}
	_, err := c.VerifyRequest(request("DPoP", noisyTok, e.proofBy(noisy, noisyTok, nil)))
	mustCode(t, err, CodeDPoPReplayGuardFull)
	if _, err := c.VerifyRequest(request("DPoP", victimTok, e.proofBy(victim, victimTok, nil))); err != nil {
		t.Fatalf("the victim is locked out: %v", err)
	}
}

// --- forwarded headers: the last entry, the one the trusted proxy added ---

func TestForwardedHostTakesTheLastEntry(t *testing.T) {
	e := newAgentEnv(t)
	tok := e.token(nil, nil)
	c := e.client(func(c *Config) { c.PublicURL = ""; c.TrustForwarded = true })
	send := func(c *Client, htu string, hosts ...string) error {
		r := httptest.NewRequest(http.MethodGet, "/orders", nil)
		r.Host = "internal.svc"
		r.Header.Set("Authorization", "DPoP "+tok)
		for _, h := range hosts {
			r.Header.Add("X-Forwarded-Host", h)
		}
		r.Header.Set("X-Forwarded-Proto", "http, https")
		r.Header.Add("DPoP", e.proof(tok, func(h, cl map[string]any) { cl["htu"] = htu }))
		_, err := c.VerifyRequest(r)
		return err
	}
	mustCode(t, send(c, "https://attacker.example/orders", "attacker.example, api.example.com"), CodeDPoPURL)
	mustCode(t, send(c, "https://attacker.example/orders", "attacker.example", "api.example.com"), CodeDPoPURL)
	if err := send(c, "https://api.example.com/orders", "attacker.example, api.example.com"); err != nil {
		t.Fatalf("control, the proxy's own entry: %v", err)
	}
	// with PublicURL the headers are not read at all
	pinned := e.client(func(c *Config) { c.TrustForwarded = true })
	mustCode(t, send(pinned, "https://attacker.example/orders", "x.example, attacker.example"), CodeDPoPURL)
	if err := send(pinned, "https://api.example.com/orders", "x.example, attacker.example"); err != nil {
		t.Fatalf("PublicURL decides: %v", err)
	}
}

func TestLastListValue(t *testing.T) {
	cases := map[string][]string{"b": {"a, b"}, "c": {"a", "b, c"}, "a": {" a "}}
	if lastListValue(nil) != "" || lastListValue([]string{"a,"}) != "" {
		t.Error("empty")
	}
	for want, in := range cases {
		if got := lastListValue(in); got != want {
			t.Errorf("%q: got %q want %q", in, got, want)
		}
	}
}

// --- jwks.go: the certificate size cap ---

func TestX5cSizeCapIsAtTheLimit(t *testing.T) {
	atLimit := strings.Repeat("A", maxX5cCertSize)
	over := strings.Repeat("A", maxX5cCertSize+1)
	if got := boundedX5c([]string{atLimit}); len(got) != 1 {
		t.Fatal("a certificate at the cap is kept")
	}
	if got := boundedX5c([]string{"AAAA", over}); got != nil {
		t.Fatal("one oversize certificate drops the whole list")
	}
	many := make([]string, maxX5cCerts)
	if got := boundedX5c(many); len(got) != maxX5cCerts {
		t.Fatal("the count cap is inclusive")
	}
	if got := boundedX5c(append(many, "AAAA")); got != nil {
		t.Fatal("one certificate past the count cap drops the list")
	}
}

func TestOversizeCertificateGivesAKeyNoChain(t *testing.T) {
	e := newAgentEnv(t)
	e.f.keys["ed1"].x5c = append(certsB64(e.leaf, e.pki.inter.cert, e.pki.root.cert), strings.Repeat("A", maxX5cCertSize+1))
	_, err := e.call(e.client(), e.token(nil, nil), nil)
	mustCode(t, err, CodeChainNotProven)
}

// --- agent detection is not a string compare ---

func TestAgentDetectionIgnoresCaseAndSpaces(t *testing.T) {
	e := newAgentEnv(t)
	c := e.client()
	person := e.f.mint(tokenSpec{})
	if _, err := c.Verify(context.Background(), person); err != nil {
		t.Fatalf("control, a person: %v", err)
	}
	shapes := map[string]map[string]any{
		"AGT_9 subject":   {"sub": "AGT_9"},
		" agt_9 subject":  {"sub": " agt_9"},
		"Agt_9 client_id": {"client_id": "Agt_9"},
		"azp":             {"azp": "agt_9"},
		"azp upper":       {"azp": "  AGT_9"},
		"agent_id":        {"agent_id": "agt_9"},
		"agent_id upper":  {"agent_id": "AGT_9"},
	}
	for name, claims := range shapes {
		t.Run(name, func(t *testing.T) {
			tok := e.f.mint(tokenSpec{kid: "ed1", claims: claims})
			_, err := c.Verify(context.Background(), tok)
			mustCode(t, err, CodeAgentNeedsRequest)
			_, err = c.VerifyRequest(request("Bearer", tok))
			mustCode(t, err, CodeDPoPProofRequired)
		})
	}
	for _, notAgent := range []string{"agtx_9", "xagt_9", "agent_9", ""} {
		tok := e.f.mint(tokenSpec{claims: map[string]any{"azp": notAgent, "agent_id": notAgent}})
		if _, err := c.Verify(context.Background(), tok); err != nil {
			t.Errorf("%q is not an agent id: %v", notAgent, err)
		}
	}
}

// --- a leaf that is also for subject-held keys does not prove custody ---

func TestLeafStatingCustodyAndSubjectHeldIsRefused(t *testing.T) {
	e := newAgentEnv(t)
	e.setLeaf(e.pki.leaf(t, e.f.keys["ed1"].pub(), func(s *certSpec) {
		s.policies = []asn1.ObjectIdentifier{oidCustody, oidHeld}
	}), e.pki.inter.cert, e.pki.root.cert)
	_, err := e.call(e.client(), e.token(nil, nil), nil)
	mustCode(t, err, CodeChainPolicy)
	e.setLeaf(e.pki.leaf(t, e.f.keys["ed1"].pub(), func(s *certSpec) {
		s.policies = []asn1.ObjectIdentifier{oidResident}
	}), e.pki.inter.cert, e.pki.root.cert)
	if _, err := e.call(e.client(), e.token(nil, nil), nil); err != nil {
		t.Fatalf("control: %v", err)
	}
}

// --- the default key-set client does not follow a redirect off the issuer ---

func TestDefaultJWKSClientStaysOnTheIssuerHost(t *testing.T) {
	f := newFixture(t)
	var elsewhere atomic.Int32
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		elsewhere.Add(1)
		f.serve(w, r)
	}))
	t.Cleanup(other.Close)
	issuer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/jwks.json":
			http.Redirect(w, r, other.URL+"/.well-known/jwks.json", http.StatusFound)
		case "/same/jwks":
			f.serve(w, r)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(issuer.Close)
	tok := f.mint(tokenSpec{claims: map[string]any{"iss": issuer.URL}})
	c := New(Config{Issuer: issuer.URL, Audience: []string{testAudience}, TenantID: testTenant})
	c.clock = f.clock
	_, err := c.Verify(context.Background(), tok)
	mustCode(t, err, CodeKeySetUnavailable)
	if elsewhere.Load() != 0 {
		t.Fatal("the key set was fetched from another host")
	}
	// the redirect rule itself: the same host passes, another host or scheme does not
	same := httptest.NewRequest("GET", "http://a.test/y", nil)
	via := []*http.Request{httptest.NewRequest("GET", "http://a.test/x", nil)}
	if err := sameHostRedirect(same, via); err != nil {
		t.Fatalf("same host: %v", err)
	}
	if sameHostRedirect(httptest.NewRequest("GET", "http://b.test/y", nil), via) == nil {
		t.Fatal("another host")
	}
	if sameHostRedirect(httptest.NewRequest("GET", "https://a.test/y", nil), via) == nil {
		t.Fatal("another scheme")
	}
	if sameHostRedirect(same, append(via, via[0], via[0])) == nil {
		t.Fatal("too many hops")
	}
	// a client the caller supplies is left alone
	custom := &http.Client{}
	if New(Config{Issuer: issuer.URL, Audience: []string{testAudience}, HTTPClient: custom}).cfg.HTTPClient != custom {
		t.Fatal("a supplied client is used as given")
	}
}
