package authfi

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/asn1"
	"encoding/hex"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// --- the control leg and the positives ---

func TestAgentTokenWithProofAndChainIsAccepted(t *testing.T) {
	for _, alg := range []string{"EdDSA", "ES256", "PS256"} {
		t.Run(alg, func(t *testing.T) {
			e := newAgentEnv(t)
			e.pk = newProofSigner(alg)
			tok := e.token(nil, nil)
			got, err := e.call(e.client(), tok, nil)
			if err != nil || got.Subject != "agt_1" || got.ClientID != "agt_1" {
				t.Fatalf("a valid agent request: %+v %v", got, err)
			}
		})
	}
}

func TestPolicyOneTwoIsAcceptedToo(t *testing.T) {
	e := newAgentEnv(t)
	e.setLeaf(e.pki.leaf(t, e.f.keys["ed1"].pub(), func(s *certSpec) { s.policies = []asn1.ObjectIdentifier{oidResident} }),
		e.pki.inter.cert, e.pki.root.cert)
	if _, err := e.call(e.client(), e.token(nil, nil), nil); err != nil {
		t.Fatalf("policy .1.2: %v", err)
	}
	e2 := newAgentEnv(t)
	e2.pki = newPKI(t, e2.f.clock(), func(s *certSpec) { s.policies = []asn1.ObjectIdentifier{oidResident} })
	e2.setLeaf(e2.pki.leaf(t, e2.f.keys["ed1"].pub(), nil), e2.pki.inter.cert, e2.pki.root.cert)
	if _, err := e2.call(e2.client(), e2.token(nil, nil), nil); err != nil {
		t.Fatalf("a CA stating .1.2: %v", err)
	}
}

func TestEveryAgentShapeNeedsTheChecks(t *testing.T) {
	e := newAgentEnv(t)
	c := e.client()
	shapes := map[string]map[string]any{
		"agt_ subject":   {"sub": "agt_9", "client_id": "other"},
		"agt_ client id": {"sub": "usr_1", "client_id": "agt_9"},
		"act claim":      {"sub": "usr_1", "client_id": "app", "act": map[string]any{"sub": "agent:agt_1"}},
	}
	for name, claims := range shapes {
		t.Run(name, func(t *testing.T) {
			tok := e.token(claims, nil)
			bearer := request("Bearer", tok)
			_, err := c.VerifyRequest(bearer)
			mustCode(t, err, CodeDPoPProofRequired) // control: the same token with a proof is fine
			if _, err := e.call(c, tok, nil); err != nil {
				t.Fatalf("with a proof: %v", err)
			}
			// the same shape without cnf is refused in enforce mode
			unbound := e.f.mint(tokenSpec{kid: "ed1", claims: claims})
			_, err = c.VerifyRequest(request("Bearer", unbound))
			mustCode(t, err, CodeDPoPProofRequired)
		})
	}
}

func TestPersonBearerTokenIsUnchanged(t *testing.T) {
	f := newFixture(t)
	c := f.client()
	tok := f.mint(tokenSpec{})
	if _, err := c.Verify(context.Background(), tok); err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if _, err := c.VerifyRequest(request("Bearer", tok)); err != nil {
		t.Fatalf("VerifyRequest: %v", err)
	}
	_, err := c.VerifyRequest(request("DPoP", tok))
	mustCode(t, err, CodeMalformed) // a token that is not bound is not sent as DPoP
}

func TestPersonTokenWithCnfNeedsAProofButNoChain(t *testing.T) {
	e := newAgentEnv(t)
	c := e.client()
	tok := e.f.mint(tokenSpec{claims: map[string]any{"cnf": map[string]any{"jkt": e.pk.thumb()}}}) // rs1: no chain
	_, err := c.Verify(context.Background(), tok)
	mustCode(t, err, CodeDPoPProofRequired)
	_, err = c.VerifyRequest(request("Bearer", tok))
	mustCode(t, err, CodeDPoPProofRequired)
	if _, err := e.call(c, tok, nil); err != nil {
		t.Fatalf("a bound person token with its proof: %v", err)
	}
	mand := e.f.mint(tokenSpec{claims: map[string]any{"authfi_mandate": "m_1"}})
	_, err = e.call(c, mand, nil)
	mustCode(t, err, CodeDPoPProofRequired) // no cnf.jkt to hold a proof against
}

func TestVerifyRefusesAnAgentTokenWithoutARequest(t *testing.T) {
	e := newAgentEnv(t)
	tok := e.token(nil, nil)
	_, err := e.client().Verify(context.Background(), tok)
	mustCode(t, err, CodeAgentNeedsRequest)
	_, err = e.client().VerifyToken(tok)
	mustCode(t, err, CodeAgentNeedsRequest)
	// control: with the request it is accepted
	if _, err := e.call(e.client(), tok, nil); err != nil {
		t.Fatal(err)
	}
}

// --- DPoP proof refusals ---

func TestProofRefusals(t *testing.T) {
	now := func(e *agentEnv) int64 { return e.f.clock().Unix() }
	cases := []struct {
		name string
		mod  func(e *agentEnv) func(h, c map[string]any)
		want string
	}{
		{"wrong method", func(*agentEnv) func(h, c map[string]any) { return func(h, c map[string]any) { c["htm"] = "POST" } }, CodeDPoPMethod},
		{"no method", func(*agentEnv) func(h, c map[string]any) { return func(h, c map[string]any) { delete(c, "htm") } }, CodeDPoPMethod},
		{"wrong path", func(*agentEnv) func(h, c map[string]any) {
			return func(h, c map[string]any) { c["htu"] = testHost + "/other" }
		}, CodeDPoPURL},
		{"wrong host", func(*agentEnv) func(h, c map[string]any) {
			return func(h, c map[string]any) { c["htu"] = "https://evil.example/orders" }
		}, CodeDPoPURL},
		{"wrong scheme", func(*agentEnv) func(h, c map[string]any) {
			return func(h, c map[string]any) { c["htu"] = "http://api.example.com/orders" }
		}, CodeDPoPURL},
		{"stale iat", func(e *agentEnv) func(h, c map[string]any) {
			return func(h, c map[string]any) { c["iat"] = now(e) - 120 }
		}, CodeDPoPIssuedAt},
		{"iat ahead", func(e *agentEnv) func(h, c map[string]any) {
			return func(h, c map[string]any) { c["iat"] = now(e) + 30 }
		}, CodeDPoPIssuedAt},
		{"no iat", func(*agentEnv) func(h, c map[string]any) { return func(h, c map[string]any) { delete(c, "iat") } }, CodeDPoPIssuedAt},
		{"wrong ath", func(*agentEnv) func(h, c map[string]any) {
			return func(h, c map[string]any) { c["ath"] = athOf("another token") }
		}, CodeDPoPAccessTokenHash},
		{"no ath", func(*agentEnv) func(h, c map[string]any) { return func(h, c map[string]any) { delete(c, "ath") } }, CodeDPoPAccessTokenHash},
		{"wrong typ", func(*agentEnv) func(h, c map[string]any) { return func(h, c map[string]any) { h["typ"] = "JWT" } }, CodeDPoPType},
		{"alg none", func(*agentEnv) func(h, c map[string]any) { return func(h, c map[string]any) { h["alg"] = "none" } }, CodeDPoPAlg},
		{"alg HS256", func(*agentEnv) func(h, c map[string]any) { return func(h, c map[string]any) { h["alg"] = "HS256" } }, CodeDPoPAlg},
		{"alg not the key's", func(*agentEnv) func(h, c map[string]any) { return func(h, c map[string]any) { h["alg"] = "ES256" } }, CodeDPoPAlg},
		{"no jwk", func(*agentEnv) func(h, c map[string]any) { return func(h, c map[string]any) { delete(h, "jwk") } }, CodeDPoPMalformed},
		{"private jwk", func(e *agentEnv) func(h, c map[string]any) {
			return func(h, c map[string]any) {
				j := e.pk.jwk()
				j["d"] = base64URL(e.pk.ed.Seed())
				h["jwk"] = j
			}
		}, CodeDPoPMalformed},
		{"crit", func(*agentEnv) func(h, c map[string]any) {
			return func(h, c map[string]any) { h["crit"] = []string{"exp"} }
		}, CodeDPoPMalformed},
		{"no jti", func(*agentEnv) func(h, c map[string]any) { return func(h, c map[string]any) { delete(c, "jti") } }, CodeDPoPMalformed},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := newAgentEnv(t)
			c := e.client()
			tok := e.token(nil, nil)
			proof := e.proof(tok, tc.mod(e))
			_, err := c.VerifyRequest(request("DPoP", tok, proof))
			mustCode(t, err, tc.want)
			noLeak(t, err, tok, proof)
			if _, err := e.call(c, tok, nil); err != nil { // control: the same token with a good proof
				t.Fatalf("control: %v", err)
			}
		})
	}
}

func TestProofMissingMultipleMalformedSignature(t *testing.T) {
	e := newAgentEnv(t)
	c := e.client()
	tok := e.token(nil, nil)
	_, err := c.VerifyRequest(request("DPoP", tok))
	mustCode(t, err, CodeDPoPMissing)
	_, err = c.VerifyRequest(request("DPoP", tok, "  "))
	mustCode(t, err, CodeDPoPMissing)
	_, err = c.VerifyRequest(request("DPoP", tok, e.proof(tok, nil), e.proof(tok, nil)))
	mustCode(t, err, CodeDPoPMultiple)
	for _, junk := range []string{"junk", "a.b", "a.b.c", "!!.??.**", strings.Repeat("a", maxProofBytes+1)} {
		_, err = c.VerifyRequest(request("DPoP", tok, junk))
		mustCode(t, err, CodeDPoPMalformed)
	}
	// a proof whose payload was changed after signing
	good := e.proof(tok, nil)
	parts := strings.Split(good, ".")
	other := e.proof(tok, nil)
	forged := parts[0] + "." + strings.Split(other, ".")[1] + "." + parts[2]
	_, err = c.VerifyRequest(request("DPoP", tok, forged))
	mustCode(t, err, CodeDPoPSignature)
	noLeak(t, err, tok, forged)
	// a proof signed by another key than the one it names
	imposter := newProofSigner("EdDSA")
	h, _ := json.Marshal(map[string]any{"typ": "dpop+jwt", "alg": "EdDSA", "jwk": e.pk.jwk()})
	cl, _ := json.Marshal(map[string]any{"jti": "x1", "htm": "GET", "htu": testHost + "/orders", "iat": e.f.clock().Unix(), "ath": athOf(tok)})
	signed := base64URL(h) + "." + base64URL(cl)
	_, err = c.VerifyRequest(request("DPoP", tok, signed+"."+base64URL(imposter.sign(signed))))
	mustCode(t, err, CodeDPoPSignature)
	if _, err := e.call(c, tok, nil); err != nil {
		t.Fatalf("control: %v", err)
	}
}

func TestProofKeyMustBeTheBoundKey(t *testing.T) {
	e := newAgentEnv(t)
	c := e.client()
	tok := e.token(nil, nil)
	other := newProofSigner("EdDSA")
	_, err := c.VerifyRequest(request("DPoP", tok, e.proofBy(other, tok, nil)))
	mustCode(t, err, CodeDPoPKeyMismatch)
	if _, err := c.VerifyRequest(request("DPoP", tok, e.proof(tok, nil))); err != nil {
		t.Fatalf("control: %v", err)
	}
}

func TestBearerSchemeForABoundTokenIsRefused(t *testing.T) {
	e := newAgentEnv(t)
	c := e.client()
	tok := e.token(nil, nil)
	_, err := c.VerifyRequest(request("Bearer", tok, e.proof(tok, nil)))
	mustCode(t, err, CodeDPoPProofRequired)
	_, err = c.VerifyRequest(request("Bearer", tok))
	mustCode(t, err, CodeDPoPProofRequired)
	if _, err := e.call(c, tok, nil); err != nil {
		t.Fatalf("control: %v", err)
	}
}

func TestAgentTokenNeedsCnf(t *testing.T) {
	e := newAgentEnv(t)
	c := e.client()
	unbound := e.f.mint(tokenSpec{kid: "ed1", header: map[string]any{"x5t#S256": thumbprintS256(e.leaf.Raw)},
		claims: map[string]any{"sub": "agt_1"}})
	_, err := e.call(c, unbound, nil)
	mustCode(t, err, CodeDPoPProofRequired)
	noJkt := e.token(map[string]any{"cnf": map[string]any{"x5t#S256": "abc"}}, nil)
	_, err = e.call(c, noJkt, nil)
	mustCode(t, err, CodeDPoPProofRequired)
}

func TestAuthorizationHeaderForms(t *testing.T) {
	e := newAgentEnv(t)
	c := e.client()
	tok := e.token(nil, nil)
	r := request("DPoP", tok, e.proof(tok, nil))
	r.Header.Add("Authorization", "DPoP "+tok)
	_, err := c.VerifyRequest(r)
	mustCode(t, err, CodeMissingBearer)
	for _, h := range []string{"", "DPoP", "DPoP  ", "Basic abc", tok} {
		r := request("", "", e.proof(tok, nil))
		if h != "" {
			r.Header.Set("Authorization", h)
		}
		_, err = c.VerifyRequest(r)
		mustCode(t, err, CodeMissingBearer)
	}
	if _, err := c.VerifyRequest(request("dpop", tok, e.proof(tok, nil))); err != nil {
		t.Fatalf("the scheme is case-insensitive: %v", err)
	}
	if _, err := c.VerifyRequest(nil); err == nil {
		t.Fatal("a nil request is refused")
	}
}

// --- replay ---

func TestReplayedProofIsRefused(t *testing.T) {
	e := newAgentEnv(t)
	c := e.client()
	tok := e.token(nil, nil)
	proof := e.proof(tok, nil)
	if _, err := c.VerifyRequest(request("DPoP", tok, proof)); err != nil {
		t.Fatalf("first use: %v", err)
	}
	_, err := c.VerifyRequest(request("DPoP", tok, proof))
	mustCode(t, err, CodeDPoPReplayed)
	if _, err := e.call(c, tok, nil); err != nil { // control: a fresh proof for the same token
		t.Fatalf("a new proof: %v", err)
	}
}

func TestReplayIsKeyedByKeyAndJTI(t *testing.T) {
	e := newAgentEnv(t)
	c := e.client()
	a, b := newProofSigner("EdDSA"), newProofSigner("EdDSA")
	same := func(h, cl map[string]any) { cl["jti"] = "shared-jti" }
	e.pk = a
	tokA := e.token(nil, nil)
	e.pk = b
	tokB := e.token(nil, nil)
	if _, err := c.VerifyRequest(request("DPoP", tokA, e.proofBy(a, tokA, same))); err != nil {
		t.Fatalf("key A: %v", err)
	}
	if _, err := c.VerifyRequest(request("DPoP", tokB, e.proofBy(b, tokB, same))); err != nil {
		t.Fatalf("key B with the same jti is another proof: %v", err)
	}
	_, err := c.VerifyRequest(request("DPoP", tokA, e.proofBy(a, tokA, same)))
	mustCode(t, err, CodeDPoPReplayed)
}

func TestProofIsNotSpentByARefusedRequest(t *testing.T) {
	e := newAgentEnv(t)
	guard := newMemoryReplayGuard(e.f.clock)
	tok := e.token(nil, nil)
	proof := e.proof(tok, nil)
	bad := e.client(func(c *Config) { c.ReplayGuard = guard; c.RootPins = []string{strings.Repeat("ab", 32)} })
	_, err := bad.VerifyRequest(request("DPoP", tok, proof))
	mustCode(t, err, CodeChainPin)
	good := e.client(func(c *Config) { c.ReplayGuard = guard })
	if _, err := good.VerifyRequest(request("DPoP", tok, proof)); err != nil {
		t.Fatalf("a request refused on the chain must not have spent the proof: %v", err)
	}
}

type stubGuard struct {
	fresh bool
	err   error
}

func (g stubGuard) Claim(context.Context, string, time.Time) (bool, error) { return g.fresh, g.err }

func TestReplayGuardFailureRefuses(t *testing.T) {
	e := newAgentEnv(t)
	tok := e.token(nil, nil)
	c := e.client(func(c *Config) { c.ReplayGuard = stubGuard{fresh: true, err: errors.New("store down")} })
	_, err := e.call(c, tok, nil)
	mustCode(t, err, CodeDPoPReplayUnavailable)
	c = e.client(func(c *Config) { c.ReplayGuard = stubGuard{} })
	_, err = e.call(c, tok, nil)
	mustCode(t, err, CodeDPoPReplayed)
	c = e.client(func(c *Config) { c.ReplayGuard = stubGuard{fresh: true} })
	if _, err := e.call(c, tok, nil); err != nil {
		t.Fatalf("control: %v", err)
	}
}

func TestMemoryReplayGuardIsBounded(t *testing.T) {
	now := time.Now()
	g := newMemoryReplayGuard(func() time.Time { return now })
	until := now.Add(time.Minute)
	for i := 0; i < maxReplayEntries; i++ {
		fresh, err := g.Claim(context.Background(), "claim-"+itoa(i), until)
		if err != nil || !fresh {
			t.Fatalf("claim %d: %v %v", i, fresh, err)
		}
	}
	if _, err := g.Claim(context.Background(), "one more", until); err == nil {
		t.Fatal("a full guard must fail closed")
	}
	if fresh, _ := g.Claim(context.Background(), "claim-"+itoa(0), until); fresh {
		t.Fatal("a recorded id stays recorded when the guard is full")
	}
	now = now.Add(2 * time.Minute)
	if fresh, err := g.Claim(context.Background(), "one more", until.Add(time.Hour)); err != nil || !fresh {
		t.Fatalf("expired entries make room: %v %v", fresh, err)
	}
	if len(g.seen) > 1 {
		t.Fatalf("expired entries were not dropped: %d", len(g.seen))
	}
}

// --- htu: which URL the proof must name ---

func TestForwardingHeadersAreNotTrustedByDefault(t *testing.T) {
	e := newAgentEnv(t)
	tok := e.token(nil, nil)
	spoof := func(c *Client, hostHeader string) error {
		r := httptest.NewRequest(http.MethodGet, "/orders", nil)
		r.Host = "internal.svc"
		r.Header.Set("Authorization", "DPoP "+tok)
		r.Header.Set("X-Forwarded-Host", hostHeader)
		r.Header.Set("X-Forwarded-Proto", "https")
		r.Header.Add("DPoP", e.proof(tok, func(h, cl map[string]any) { cl["htu"] = "https://" + hostHeader + "/orders" }))
		_, err := c.VerifyRequest(r)
		return err
	}
	plain := e.client(func(c *Config) { c.PublicURL = "" })
	mustCode(t, spoof(plain, "evil.example"), CodeDPoPURL)
	pinned := e.client() // PublicURL wins over the header
	mustCode(t, spoof(pinned, "evil.example"), CodeDPoPURL)
	trusting := e.client(func(c *Config) { c.PublicURL = ""; c.TrustForwarded = true })
	if err := spoof(trusting, "api.example.com"); err != nil {
		t.Fatalf("control, trusted forwarding: %v", err)
	}
	// without any header the request's own host and scheme are the URL
	r := httptest.NewRequest(http.MethodGet, "/orders", nil)
	r.Host = "svc.local:8080"
	r.Header.Set("Authorization", "DPoP "+tok)
	r.Header.Add("DPoP", e.proof(tok, func(h, cl map[string]any) { cl["htu"] = "http://svc.local:8080/orders?x=1" }))
	if _, err := plain.VerifyRequest(r); err != nil {
		t.Fatalf("own host: %v", err)
	}
}

func TestPublicURLWithPathPrefix(t *testing.T) {
	e := newAgentEnv(t)
	tok := e.token(nil, nil)
	c := e.client(func(c *Config) { c.PublicURL = testHost + "/gw/" })
	r := httptest.NewRequest(http.MethodGet, "/orders", nil)
	r.Header.Set("Authorization", "DPoP "+tok)
	r.Header.Add("DPoP", e.proof(tok, func(h, cl map[string]any) { cl["htu"] = testHost + "/gw/orders" }))
	if _, err := c.VerifyRequest(r); err != nil {
		t.Fatal(err)
	}
}

func TestURLMatching(t *testing.T) {
	yes := [][2]string{
		{"https://API.example.com:443/a", "https://api.example.com/a"},
		{"http://h:80/a", "http://h/a"},
		{"https://h/a?q=1#f", "https://h/a"},
		{"https://h", "https://h/"},
	}
	for _, p := range yes {
		if !urlMatches(p[0], p[1]) {
			t.Errorf("%s should match %s", p[0], p[1])
		}
	}
	no := [][2]string{
		{"https://h/a", "https://h/A"}, {"https://h/a/", "https://h/a"}, {"https://h:444/a", "https://h/a"},
		{"http://h/a", "https://h/a"}, {"", "https://h/a"}, {"/a", "https://h/a"}, {"https://h/a", ""},
	}
	for _, p := range no {
		if urlMatches(p[0], p[1]) {
			t.Errorf("%s must not match %s", p[0], p[1])
		}
	}
}

// --- nonces ---

func TestServerNonces(t *testing.T) {
	e := newAgentEnv(t)
	key := bytes.Repeat([]byte{7}, 32)
	c := e.client(func(c *Config) { c.NonceKey = key })
	tok := e.token(nil, nil)
	_, err := e.call(c, tok, nil)
	mustCode(t, err, CodeDPoPNonce)
	var ae *Error
	if !errors.As(err, &ae) || ae.Nonce == "" {
		t.Fatalf("the refusal carries the nonce to send: %v", err)
	}
	withNonce := func(n string) func(h, cl map[string]any) { return func(h, cl map[string]any) { cl["nonce"] = n } }
	if _, err := e.call(c, tok, withNonce(ae.Nonce)); err != nil {
		t.Fatalf("with the nonce: %v", err)
	}
	_, err = e.call(c, tok, withNonce("bogus"))
	mustCode(t, err, CodeDPoPNonce)
	other := newHMACNonces(bytes.Repeat([]byte{9}, 32)).issue(e.f.clock())
	_, err = e.call(c, tok, withNonce(other))
	mustCode(t, err, CodeDPoPNonce)
	// valid in the window after it was issued, not two later
	e.f.advance(3 * time.Minute)
	tok = e.token(map[string]any{"exp": e.f.clock().Add(time.Hour).Unix(), "iat": e.f.clock().Unix()}, nil)
	if _, err := e.call(c, tok, withNonce(ae.Nonce)); err != nil {
		t.Fatalf("a nonce lives into the next window: %v", err)
	}
	e.f.advance(11 * time.Minute)
	tok = e.token(map[string]any{"exp": e.f.clock().Add(time.Hour).Unix(), "iat": e.f.clock().Unix()}, nil)
	_, err = e.call(c, tok, withNonce(ae.Nonce))
	mustCode(t, err, CodeDPoPNonce)
}

func TestNonceMiddlewareAnswer(t *testing.T) {
	e := newAgentEnv(t)
	c := e.client(func(c *Config) { c.NonceKey = bytes.Repeat([]byte{7}, 32) })
	tok := e.token(nil, nil)
	rec := httptest.NewRecorder()
	r := request("DPoP", tok, e.proof(tok, nil))
	c.Require("read:users")(neverCalled(t)).ServeHTTP(rec, r)
	if rec.Code != 401 || rec.Header().Get("DPoP-Nonce") == "" || !strings.Contains(rec.Header().Get("WWW-Authenticate"), `error="use_dpop_nonce"`) {
		t.Fatalf("nonce answer: %d %v", rec.Code, rec.Header())
	}
	nonce := rec.Header().Get("DPoP-Nonce")
	rec = httptest.NewRecorder()
	r = request("DPoP", tok, e.proof(tok, func(h, cl map[string]any) { cl["nonce"] = nonce }))
	c.Require("read:users")(okHandler(t)).ServeHTTP(rec, r)
	if rec.Code != 200 || rec.Body.String() != "agt_1" {
		t.Fatalf("with the nonce: %d %s", rec.Code, rec.Body.String())
	}
}

func TestNonceKeyTooShortIsAConfigError(t *testing.T) {
	e := newAgentEnv(t)
	c := e.client(func(c *Config) { c.NonceKey = []byte("short") })
	mustCode(t, c.Validate(), CodeNotConfigured)
}

// --- chain ---

func TestChainRefusals(t *testing.T) {
	type env = agentEnv
	pub := func(e *env) any { return e.f.keys["ed1"].pub() }
	cases := []struct {
		name  string
		setup func(e *env) (cfg func(*Config), header map[string]any)
		want  string
	}{
		{"planted key with no chain", func(e *env) (func(*Config), map[string]any) {
			e.f.keys["ed1"].x5c, e.f.keys["ed1"].x5t = nil, ""
			return nil, nil
		}, CodeChainNotProven},
		{"certificate without the PEN policy", func(e *env) (func(*Config), map[string]any) {
			e.setLeaf(e.pki.leaf(t, pub(e), func(s *certSpec) { s.policies = nil }), e.pki.inter.cert, e.pki.root.cert)
			return nil, nil
		}, CodeChainPolicy},
		{"leaf states only the subject-held policy", func(e *env) (func(*Config), map[string]any) {
			e.setLeaf(e.pki.leaf(t, pub(e), func(s *certSpec) { s.policies = []asn1.ObjectIdentifier{oidHeld} }), e.pki.inter.cert, e.pki.root.cert)
			return nil, nil
		}, CodeChainPolicy},
		{"wrong pin", func(e *env) (func(*Config), map[string]any) {
			return func(c *Config) { c.RootPins = []string{strings.Repeat("cd", 32)} }, nil
		}, CodeChainPin},
		{"root in the x5c, default pin", func(e *env) (func(*Config), map[string]any) {
			return func(c *Config) { c.RootPins = nil }, nil
		}, CodeChainPin},
		{"no root in the x5c", func(e *env) (func(*Config), map[string]any) {
			e.setLeaf(e.leaf, e.pki.inter.cert)
			return nil, nil
		}, CodeChainPin},
		{"root cert for the pinned key signed by someone else", func(e *env) (func(*Config), map[string]any) {
			attacker := newPKI(t, e.f.clock(), nil)
			forged, _ := issue(t, attacker.root.key, certSpec{cn: "Test Root", isCA: true, ku: x509.KeyUsageCertSign,
				notBefore: e.f.clock().Add(-time.Hour), notAfter: e.f.clock().Add(time.Hour), pub: &e.pki.root.key.PublicKey, parent: attacker.root})
			e.setLeaf(e.leaf, e.pki.inter.cert, forged)
			return nil, nil
		}, CodeChainPin},
		{"leaf is a CA", func(e *env) (func(*Config), map[string]any) {
			e.setLeaf(e.pki.leaf(t, pub(e), func(s *certSpec) { s.isCA = true; s.ku = x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature }),
				e.pki.inter.cert, e.pki.root.cert)
			return nil, nil
		}, CodeChainNotProven},
		{"leaf cannot sign", func(e *env) (func(*Config), map[string]any) {
			e.setLeaf(e.pki.leaf(t, pub(e), func(s *certSpec) { s.ku = x509.KeyUsageKeyEncipherment }), e.pki.inter.cert, e.pki.root.cert)
			return nil, nil
		}, CodeChainNotProven},
		{"leaf expired", func(e *env) (func(*Config), map[string]any) {
			e.setLeaf(e.pki.leaf(t, pub(e), func(s *certSpec) {
				s.notBefore, s.notAfter = e.f.clock().Add(-3*time.Hour), e.f.clock().Add(-time.Hour)
			}), e.pki.inter.cert, e.pki.root.cert)
			return nil, nil
		}, CodeChainNotProven},
		{"leaf not valid yet", func(e *env) (func(*Config), map[string]any) {
			e.setLeaf(e.pki.leaf(t, pub(e), func(s *certSpec) {
				s.notBefore, s.notAfter = e.f.clock().Add(time.Hour), e.f.clock().Add(2*time.Hour)
			}), e.pki.inter.cert, e.pki.root.cert)
			return nil, nil
		}, CodeChainNotProven},
		{"x5t#S256 of the token names another certificate", func(e *env) (func(*Config), map[string]any) {
			return nil, map[string]any{"x5t#S256": thumbprintS256(e.pki.inter.cert.Raw)}
		}, CodeChainNotProven},
		{"x5t#S256 of the key set names another certificate", func(e *env) (func(*Config), map[string]any) {
			e.f.keys["ed1"].x5t = thumbprintS256(e.pki.inter.cert.Raw)
			return nil, nil
		}, CodeChainNotProven},
		{"the certificate certifies a different key", func(e *env) (func(*Config), map[string]any) {
			e.setLeaf(e.pki.leaf(t, newProofSigner("EdDSA").pub(), nil), e.pki.inter.cert, e.pki.root.cert)
			return nil, nil
		}, CodeChainNotProven},
		{"a CA states no policy", func(e *env) (func(*Config), map[string]any) {
			e.pki = newPKI(t, e.f.clock(), func(s *certSpec) { s.policies = nil })
			e.setLeaf(e.pki.leaf(t, pub(e), nil), e.pki.inter.cert, e.pki.root.cert)
			return nil, nil
		}, CodeChainPolicy},
		{"a CA also states the subject-held policy", func(e *env) (func(*Config), map[string]any) {
			e.pki = newPKI(t, e.f.clock(), func(s *certSpec) { s.policies = []asn1.ObjectIdentifier{oidCustody, oidHeld} })
			e.setLeaf(e.pki.leaf(t, pub(e), nil), e.pki.inter.cert, e.pki.root.cert)
			return nil, nil
		}, CodeChainPolicy},
		{"a CA states only the subject-held policy", func(e *env) (func(*Config), map[string]any) {
			e.pki = newPKI(t, e.f.clock(), func(s *certSpec) { s.policies = []asn1.ObjectIdentifier{oidHeld} })
			e.setLeaf(e.pki.leaf(t, pub(e), nil), e.pki.inter.cert, e.pki.root.cert)
			return nil, nil
		}, CodeChainPolicy},
		{"a CA is expired", func(e *env) (func(*Config), map[string]any) {
			e.pki = newPKI(t, e.f.clock(), func(s *certSpec) { s.notAfter = e.f.clock().Add(-time.Minute) })
			e.setLeaf(e.pki.leaf(t, pub(e), nil), e.pki.inter.cert, e.pki.root.cert)
			return nil, nil
		}, CodeChainNotProven},
		{"the intermediate is missing", func(e *env) (func(*Config), map[string]any) {
			e.setLeaf(e.leaf, e.pki.root.cert)
			return nil, nil
		}, CodeChainNotProven},
		{"an x5c entry is not a certificate", func(e *env) (func(*Config), map[string]any) {
			e.f.keys["ed1"].x5c = []string{"!!not base64!!"}
			return nil, nil
		}, CodeChainNotProven},
		{"an x5c entry is not DER", func(e *env) (func(*Config), map[string]any) {
			e.f.keys["ed1"].x5c = []string{"AAAA"}
			return nil, nil
		}, CodeChainNotProven},
		{"too many certificates", func(e *env) (func(*Config), map[string]any) {
			e.f.keys["ed1"].x5c = certsB64(e.leaf, e.pki.inter.cert, e.pki.inter.cert, e.pki.inter.cert, e.pki.inter.cert, e.pki.inter.cert, e.pki.root.cert)
			return nil, nil
		}, CodeChainNotProven},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := newAgentEnv(t)
			cfg, header := tc.setup(e)
			var mods []func(*Config)
			if cfg != nil {
				mods = append(mods, cfg)
			}
			c := e.client(mods...)
			tok := e.token(nil, header)
			proof := e.proof(tok, nil)
			_, err := c.VerifyRequest(request("DPoP", tok, proof))
			mustCode(t, err, tc.want)
			noLeak(t, err, tok, proof)
		})
	}
}

func TestChainControlLegs(t *testing.T) {
	e := newAgentEnv(t)
	if _, err := e.call(e.client(), e.token(nil, nil), nil); err != nil {
		t.Fatal(err)
	}
	// a leaf signed directly by the root, no intermediate
	e2 := newAgentEnv(t)
	direct := certSpec{cn: "Direct", ku: x509.KeyUsageDigitalSignature, policies: []asn1.ObjectIdentifier{oidCustody},
		notBefore: e2.f.clock().Add(-time.Hour), notAfter: e2.f.clock().Add(time.Hour), pub: e2.f.keys["ed1"].pub(), parent: e2.pki.root}
	leaf, _ := issue(t, nil, direct)
	e2.setLeaf(leaf, e2.pki.root.cert)
	if _, err := e2.call(e2.client(), e2.token(nil, nil), nil); err != nil {
		t.Fatalf("leaf under the root: %v", err)
	}
	// a pin list may hold several roots; the colon form is accepted
	e3 := newAgentEnv(t)
	var pairs []string
	for i := 0; i < len(e3.pki.pin()); i += 2 {
		pairs = append(pairs, e3.pki.pin()[i:i+2])
	}
	colon := strings.Join(pairs, ":")
	c := e3.client(func(c *Config) { c.RootPins = []string{strings.Repeat("ab", 32), strings.ToUpper(colon)} })
	if _, err := e3.call(c, e3.token(nil, nil), nil); err != nil {
		t.Fatalf("pin list: %v", err)
	}
}

func TestChainIsCheckedInDateOnEveryCall(t *testing.T) {
	e := newAgentEnv(t)
	c := e.client()
	long := map[string]any{"exp": e.f.clock().Add(10 * time.Hour).Unix()}
	if _, err := e.call(c, e.token(long, nil), nil); err != nil {
		t.Fatalf("first call: %v", err)
	}
	if _, err := e.call(c, e.token(long, nil), nil); err != nil {
		t.Fatalf("a cached chain: %v", err)
	}
	e.f.advance(3 * time.Hour) // the leaf ran out at +2h; the cache entry would live to the chain's end
	long = map[string]any{"exp": e.f.clock().Add(time.Hour).Unix(), "iat": e.f.clock().Unix()}
	_, err := e.call(c, e.token(long, nil), nil)
	mustCode(t, err, CodeChainNotProven)
}

func TestChainCacheLapsesAfterTenMinutes(t *testing.T) {
	e := newAgentEnv(t)
	c := e.client()
	long := map[string]any{"exp": e.f.clock().Add(10 * time.Hour).Unix()}
	if _, err := e.call(c, e.token(long, nil), nil); err != nil {
		t.Fatal(err)
	}
	// the intermediate is replaced by one without a policy, under the same leaf thumbprint nothing changes;
	// what matters is that after 11 minutes the chain is validated again, so a CA that expired is seen
	if n := len(c.chain.cache); n != 1 {
		t.Fatalf("one chain is cached, got %d", n)
	}
	for _, ent := range c.chain.cache {
		if want := e.f.clock().Add(chainRefresh); ent.expires.After(want) || ent.expires.Before(want.Add(-time.Second)) {
			t.Fatalf("the cache lives %s, want %s", ent.expires.Sub(e.f.clock()), chainRefresh)
		}
	}
}

func TestChainCacheIsBounded(t *testing.T) {
	v := newChainVerifier(nil)
	for i := 0; i < maxChainCached+5; i++ {
		v.mu.Lock()
		if len(v.cache) >= maxChainCached {
			v.cache = map[[32]byte]chainEntry{}
		}
		v.cache[[32]byte{byte(i), byte(i >> 8)}] = chainEntry{}
		v.mu.Unlock()
	}
	if len(v.cache) > maxChainCached {
		t.Fatal("unbounded")
	}
}

// --- modes ---

func TestWatchModeAcceptsAndLogsOncePerWindow(t *testing.T) {
	e := newAgentEnv(t)
	var buf bytes.Buffer
	log := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn}))
	c := e.client(func(c *Config) { c.AgentTokens = AgentWatch; c.Logger = log })
	tok := e.token(nil, nil)
	for i := 0; i < 3; i++ { // a bearer agent token: enforce would refuse
		if _, err := c.VerifyRequest(request("Bearer", tok)); err != nil {
			t.Fatalf("watch accepts: %v", err)
		}
	}
	if n := strings.Count(buf.String(), "watch mode"); n != 1 {
		t.Fatalf("one log line per key and reason window, got %d: %s", n, buf.String())
	}
	if !strings.Contains(buf.String(), CodeDPoPProofRequired) || strings.Contains(buf.String(), tok) {
		t.Fatalf("the line names the code and nothing of the token: %s", buf.String())
	}
	e.f.advance(2 * time.Minute)
	tok = e.token(map[string]any{"exp": e.f.clock().Add(time.Hour).Unix(), "iat": e.f.clock().Unix()}, nil)
	if _, err := c.VerifyRequest(request("Bearer", tok)); err != nil {
		t.Fatal(err)
	}
	if n := strings.Count(buf.String(), "watch mode"); n != 2 {
		t.Fatalf("logged again in the next window, got %d", n)
	}
	// a different reason is a different line
	e.f.keys["ed1"].x5c = nil
	c2 := e.client(func(c *Config) { c.AgentTokens = AgentWatch; c.Logger = log })
	tok = e.token(map[string]any{"exp": e.f.clock().Add(time.Hour).Unix(), "iat": e.f.clock().Unix()}, nil)
	if _, err := e.call(c2, tok, nil); err != nil {
		t.Fatalf("watch accepts a key with no chain: %v", err)
	}
	if !strings.Contains(buf.String(), CodeChainNotProven) {
		t.Fatalf("the chain code is logged: %s", buf.String())
	}
	// watch still refuses what is not an agent-token matter
	_, err := c.VerifyRequest(request("Bearer", e.f.mint(tokenSpec{claims: map[string]any{"aud": "other"}})))
	mustCode(t, err, CodeAudienceMismatch)
	// and a bound person token is never watched
	person := e.f.mint(tokenSpec{claims: map[string]any{"cnf": map[string]any{"jkt": "x"}}})
	_, err = c.VerifyRequest(request("Bearer", person))
	mustCode(t, err, CodeDPoPProofRequired)
}

func TestWatchModeVerifyWithoutRequest(t *testing.T) {
	e := newAgentEnv(t)
	c := e.client(func(c *Config) { c.AgentTokens = AgentWatch })
	if _, err := c.Verify(context.Background(), e.token(nil, nil)); err != nil {
		t.Fatalf("watch accepts: %v", err)
	}
}

func TestOffModeSkipsTheAgentChecksOnly(t *testing.T) {
	e := newAgentEnv(t)
	c := e.client(func(c *Config) { c.AgentTokens = AgentOff })
	unbound := e.f.mint(tokenSpec{kid: "ed1", claims: map[string]any{"sub": "agt_1"}})
	if _, err := c.Verify(context.Background(), unbound); err != nil {
		t.Fatalf("off accepts an unbound agent bearer token: %v", err)
	}
	// a token that is bound still needs its proof
	_, err := c.VerifyRequest(request("Bearer", e.token(nil, nil)))
	mustCode(t, err, CodeDPoPProofRequired)
	// no chain is demanded when off
	e.f.keys["ed1"].x5c = nil
	c = e.client(func(c *Config) { c.AgentTokens = AgentOff })
	if _, err := e.call(c, e.token(nil, nil), nil); err != nil {
		t.Fatalf("off asks for no chain: %v", err)
	}
	// enforce is the default: the same unbound token is refused with the zero value
	_, err = e.client().VerifyRequest(request("Bearer", unbound))
	mustCode(t, err, CodeDPoPProofRequired)
}

func TestConfigRefusals(t *testing.T) {
	f := newFixture(t)
	for _, mod := range map[string]func(*Config){
		"unknown mode":    func(c *Config) { c.AgentTokens = "maybe" },
		"bad pin":         func(c *Config) { c.RootPins = []string{"nothex"} },
		"short pin":       func(c *Config) { c.RootPins = []string{"abcd"} },
		"http PublicURL":  func(c *Config) { c.PublicURL = "http://api.example.com" },
		"PublicURL query": func(c *Config) { c.PublicURL = "https://api.example.com?x=1" },
	} {
		mustCode(t, f.client(mod).Validate(), CodeNotConfigured)
		_, err := f.client(mod).Verify(context.Background(), f.mint(tokenSpec{}))
		mustCode(t, err, CodeNotConfigured)
	}
	if err := f.client(func(c *Config) { c.PublicURL = "https://api.example.com/gw" }).Validate(); err != nil {
		t.Fatal(err)
	}
	if _, err := parsePins(nil); err != nil {
		t.Fatal(err)
	}
	pins, _ := parsePins(nil)
	if hexOf(pins[0]) != DefaultRootPin {
		t.Fatal("the default pin is AuthFI Root CA R1")
	}
}

func hexOf(b [32]byte) string { return hex.EncodeToString(b[:]) }

// --- the middleware ---

func TestRequireWithAgentToken(t *testing.T) {
	e := newAgentEnv(t)
	c := e.client()
	h := c.Require("read:users")(okHandler(t))
	tok := e.token(nil, nil)

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, request("DPoP", tok, e.proof(tok, nil)))
	if rec.Code != 200 || rec.Body.String() != "agt_1" {
		t.Fatalf("control: %d %s", rec.Code, rec.Body.String())
	}
	refused := map[string]*http.Request{
		CodeDPoPMissing:         request("DPoP", tok),
		CodeDPoPProofRequired:   request("Bearer", tok),
		CodeDPoPAccessTokenHash: request("DPoP", tok, e.proof(tok, func(h, c map[string]any) { c["ath"] = athOf("x") })),
		CodeDPoPMethod:          request("DPoP", tok, e.proof(tok, func(h, c map[string]any) { c["htm"] = "POST" })),
		CodeDPoPKeyMismatch:     request("DPoP", tok, e.proofBy(newProofSigner("EdDSA"), tok, nil)),
	}
	for code, r := range refused {
		rec := httptest.NewRecorder()
		c.Require("read:users")(neverCalled(t)).ServeHTTP(rec, r)
		if rec.Code != 401 || errorCode(t, rec) != code {
			t.Fatalf("%s: %d %s", code, rec.Code, rec.Body.String())
		}
		if !strings.HasPrefix(rec.Header().Get("WWW-Authenticate"), "DPoP ") || !strings.Contains(rec.Header().Get("WWW-Authenticate"), "invalid_dpop_proof") {
			t.Fatalf("%s: challenge %q", code, rec.Header().Get("WWW-Authenticate"))
		}
		if rec.Header().Get("DPoP-Nonce") != "" {
			t.Fatalf("%s: no nonce without a nonce key", code)
		}
	}
	// the permissions are still checked after the proof
	rec = httptest.NewRecorder()
	tok2 := e.token(map[string]any{"permissions": []string{}}, nil)
	c.Require("read:users")(neverCalled(t)).ServeHTTP(rec, request("DPoP", tok2, e.proof(tok2, nil)))
	if rec.Code != 403 {
		t.Fatalf("permission: %d", rec.Code)
	}
	// the other middleware use the same path
	rec = httptest.NewRecorder()
	c.Authenticate(neverCalled(t)).ServeHTTP(rec, request("Bearer", tok))
	if rec.Code != 401 {
		t.Fatalf("Authenticate: %d", rec.Code)
	}
	rec = httptest.NewRecorder()
	c.RequireRole("admin")(neverCalled(t)).ServeHTTP(rec, request("Bearer", tok))
	if rec.Code != 401 {
		t.Fatalf("RequireRole: %d", rec.Code)
	}
	// a replay through the middleware
	rec = httptest.NewRecorder()
	proof := e.proof(tok, nil)
	c.Require("read:users")(okHandler(t)).ServeHTTP(rec, request("DPoP", tok, proof))
	rec = httptest.NewRecorder()
	c.Require("read:users")(neverCalled(t)).ServeHTTP(rec, request("DPoP", tok, proof))
	if rec.Code != 401 || errorCode(t, rec) != CodeDPoPReplayed {
		t.Fatalf("replay: %d %s", rec.Code, rec.Body.String())
	}
	// a replay store that is down is the server's fault
	down := e.client(func(c *Config) { c.ReplayGuard = stubGuard{err: errors.New("down")} })
	rec = httptest.NewRecorder()
	down.Require("read:users")(neverCalled(t)).ServeHTTP(rec, request("DPoP", tok, e.proof(tok, nil)))
	if rec.Code != 503 || errorCode(t, rec) != CodeDPoPReplayUnavailable {
		t.Fatalf("replay unavailable: %d %s", rec.Code, rec.Body.String())
	}
	// a person's Bearer request keeps its Bearer challenge
	rec = httptest.NewRecorder()
	c.Require("read:users")(neverCalled(t)).ServeHTTP(rec, serve2("Bearer bad"))
	if !strings.HasPrefix(rec.Header().Get("WWW-Authenticate"), "Bearer ") {
		t.Fatalf("person challenge: %q", rec.Header().Get("WWW-Authenticate"))
	}
}

func serve2(authz string) *http.Request {
	r := httptest.NewRequest(http.MethodGet, "/api/users", nil)
	r.Header.Set("Authorization", authz)
	return r
}

func TestRS256ProofIsNotAccepted(t *testing.T) {
	e := newAgentEnv(t)
	c := e.client()
	rk, _ := sharedRSA()
	e.pk = &signer{kid: "p", alg: "RS256", rsa: rk}
	tok := e.token(nil, nil)
	_, err := e.call(c, tok, nil)
	mustCode(t, err, CodeDPoPAlg)
	e.pk = newProofSigner("PS256") // control: the same key type with PS256
	if _, err := e.call(c, e.token(nil, nil), nil); err != nil {
		t.Fatal(err)
	}
}

func TestChainProofEndsAtTheEarliestExpiry(t *testing.T) {
	e := newAgentEnv(t)
	e.pki = newPKI(t, e.f.clock(), func(s *certSpec) { s.notAfter = e.f.clock().Add(5 * time.Minute) })
	e.setLeaf(e.pki.leaf(t, e.f.keys["ed1"].pub(), func(s *certSpec) { s.notAfter = e.f.clock().Add(5 * time.Minute) }), e.pki.inter.cert, e.pki.root.cert)
	c := e.client()
	if _, err := e.call(c, e.token(nil, nil), nil); err != nil {
		t.Fatal(err)
	}
	for _, ent := range c.chain.cache {
		if ent.expires.After(e.f.clock().Add(5 * time.Minute)) {
			t.Fatalf("a proof outlives the CA that vouches for it: %s", ent.expires.Sub(e.f.clock()))
		}
	}
}

func TestCachedLeafWithAnotherChainIsValidatedAgain(t *testing.T) {
	e := newAgentEnv(t)
	c := e.client()
	if _, err := e.call(c, e.token(nil, nil), nil); err != nil {
		t.Fatal(err)
	}
	// the same leaf, now presented under a CA that states no policy
	bad := newPKI(t, e.f.clock(), func(s *certSpec) { s.policies = nil })
	e.f.keys["ed1"].x5c = certsB64(e.leaf, bad.inter.cert, e.pki.root.cert)
	c2 := e.client()
	c2.chain = c.chain // share the cache
	_, err := e.call(c2, e.token(nil, nil), nil)
	if err == nil {
		t.Fatal("a cached leaf must not carry a different chain with it")
	}
}

func TestOversizeAndOverlongProofsAreMalformed(t *testing.T) {
	e := newAgentEnv(t)
	c := e.client()
	tok := e.token(nil, nil)
	big := e.proof(tok, func(h, cl map[string]any) { cl["pad"] = strings.Repeat("a", maxProofBytes) })
	_, err := c.VerifyRequest(request("DPoP", tok, big))
	mustCode(t, err, CodeDPoPMalformed) // validly signed, only too large
	good := e.proof(tok, nil)
	_, err = c.VerifyRequest(request("DPoP", tok, good+".extra"))
	mustCode(t, err, CodeDPoPMalformed) // four parts
	if _, err := c.VerifyRequest(request("DPoP", tok, good)); err != nil {
		t.Fatalf("control: %v", err)
	}
}

func TestChainPathMustEndAtAPinnedRoot(t *testing.T) {
	e := newAgentEnv(t)
	v := newChainVerifier(mustPins(t, e.pki.pin()))
	other := newPKI(t, e.f.clock(), nil)
	if err := v.checkPath([]*x509.Certificate{e.leaf, e.pki.inter.cert, other.root.cert}); err == nil || err.Code != CodeChainPin {
		t.Fatalf("a path ending at an unpinned root: %v", err)
	}
	if err := v.checkPath([]*x509.Certificate{e.leaf, e.pki.inter.cert, e.pki.root.cert}); err != nil {
		t.Fatalf("control: %v", err)
	}
}

func TestPinnedRootThatIsNotACAIsNotAnAnchor(t *testing.T) {
	e := newAgentEnv(t)
	v := newChainVerifier(mustPins(t, e.pki.pin()))
	// a self-signed certificate for the pinned key that does not claim to be a CA
	plain, _ := issue(t, e.pki.root.key, certSpec{cn: "Test Root", ku: x509.KeyUsageDigitalSignature,
		notBefore: e.f.clock().Add(-time.Hour), notAfter: e.f.clock().Add(time.Hour)})
	certs := []*x509.Certificate{e.leaf, e.pki.inter.cert, plain}
	if a := v.anchorFor(certs); a != nil {
		t.Fatal("a certificate that is not a CA is not a root")
	}
	if a := v.anchorFor([]*x509.Certificate{e.leaf, e.pki.inter.cert, e.pki.root.cert}); a == nil {
		t.Fatal("control: the real root is the anchor")
	}
}

func TestChainLeafNotYetValidIsRefusedFromTheCache(t *testing.T) {
	e := newAgentEnv(t)
	v := newChainVerifier(mustPins(t, e.pki.pin()))
	x5c := certsB64(e.leaf, e.pki.inter.cert, e.pki.root.cert)
	pub := e.f.keys["ed1"].pub()
	now := e.f.clock()
	if err := v.check(pub, x5c, "", "", now); err != nil {
		t.Fatal(err)
	}
	// a clock that went back to before the certificate began; the cached proof still stands
	if err := v.check(pub, x5c, "", "", now.Add(-3*time.Hour)); err == nil || err.Code != CodeChainNotProven {
		t.Fatalf("not valid yet: %v", err)
	}
}

func mustPins(t *testing.T, pins ...string) [][32]byte {
	t.Helper()
	p, err := parsePins(pins)
	if err != nil {
		t.Fatal(err)
	}
	return p
}
