package authfi

import (
	"net/http"
	"testing"
	"time"
)

// A token with no iat has no provable lifetime, so with a store configured it is refused outright.
func TestR2TokenWithoutIatOutlivesItsRevocation(t *testing.T) {
	g := newRig(t)
	tok := g.f.mint(tokenSpec{claims: map[string]any{"sub": testAgentSubject, "exp": g.f.clock().Add(72 * time.Hour).Unix()}, dropClm: []string{"iat"}})
	wantAccepted(t, g.push(g.f.mintSET(setSpec{})))
	mustCode(t, g.verify(tok), CodeIssuedAtRequired)
	g.f.advance(DefaultTokenLifetime + 6*time.Minute)
	mustCode(t, g.verify(tok), CodeIssuedAtRequired) // never trusted, so never forgotten into validity
}

// Unknown kid heals on the transmitter's retry schedule.
func TestR2UnknownKidHealsOnRetry(t *testing.T) {
	g := newRig(t)
	wantAccepted(t, g.push(g.f.mintSET(setSpec{})))
	g.f.add(&signer{kid: "ed2", alg: "EdDSA", ed: g.f.keys["ed1"].ed})
	g.f.advance(2 * time.Second)
	set := g.f.mintSET(setSpec{kid: "ed2", claims: g.f.goodSET(evSessionRevoked, nil)})
	if w := g.push(set); w.Code != http.StatusServiceUnavailable {
		t.Fatalf("first: %d", w.Code)
	}
	g.f.advance(16 * time.Second)
	wantAccepted(t, g.push(set))
}

// Sub-second boundary: exp-iat truncates to whole seconds, verification uses the fraction.
func TestR2FractionalExpPastRetention(t *testing.T) {
	g := newRig(t)
	g.store = NewRevocationStore(RevocationOptions{TokenLifetime: time.Hour})
	g.store.now = g.f.clock
	g.c = g.f.client(func(c *Config) { c.Revocations = g.store; c.Leeway = 300 * time.Second })
	r, _ := g.c.NewReceiver(ReceiverConfig{Audience: testStreamAudience})
	g.r = r
	iat := g.f.clock()
	tok := g.tokenFor(testAgentSubject, iat, map[string]any{"exp": float64(iat.Unix()+3600) + 0.9})
	wantAccepted(t, g.push(g.f.mintSET(setSpec{})))
	g.f.advance(time.Hour + 300*time.Second) // whole second: entry dropped; token valid to exp+300 = +0.9 s later
	g.f.nowMu.Lock()
	g.f.now = g.f.now.Add(500 * time.Millisecond)
	g.f.nowMu.Unlock()
	if err := g.verify(tok); err == nil {
		t.Fatal("revoked token verifies in the last fraction of a second")
	}
}
func TestKillR2GuardIsTheStoreLifetimeNotTheRetention(t *testing.T) {
	g := newRig(t)
	g.store = NewRevocationStore(RevocationOptions{TokenLifetime: time.Hour})
	g.store.now = g.f.clock
	g.c = g.f.client(func(c *Config) { c.Revocations = g.store })
	iat := g.f.clock()
	tok := g.tokenFor("usr_1", iat, map[string]any{"exp": iat.Add(time.Hour + 100*time.Second).Unix()})
	mustCode(t, g.verify(tok), CodeNotConfigured)
}
