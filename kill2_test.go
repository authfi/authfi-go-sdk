package authfi

import (
	"context"
	"strings"
	"testing"
	"time"
)

func storeAtT(max int) (*RevocationStore, *time.Time) {
	now := time.Unix(2_000_000_000, 0)
	s := NewRevocationStore(RevocationOptions{MaxEntries: max, TokenLifetime: time.Hour})
	s.now = func() time.Time { return now }
	return s, &now
}

func TestKillEvictionDropsTheOldestTenthAndFloorsAtTheNewestDropped(t *testing.T) {
	s, now := storeAtT(20)
	t0 := *now
	for i := 0; i < 20; i++ {
		s.Revoke("s"+itoa(i), t0.Add(time.Duration(i)*time.Second))
	}
	if dropped := s.Revoke("newcomer", t0.Add(30*time.Second)); dropped != 3 {
		t.Fatalf("dropped %d, want floor(20/10)+1", dropped)
	}
	if !s.IsRevoked("unrelated", t0.Add(2*time.Second)) {
		t.Fatal("floor: equal iat is refused")
	}
	if s.IsRevoked("unrelated", t0.Add(5*time.Second)) {
		t.Fatal("floor must be the newest of the OLDEST dropped, not the newest entry")
	}
	if !s.IsRevoked("s10", t0.Add(10*time.Second)) {
		t.Fatal("a retained entry still refuses its subject")
	}
}

func TestKillSweepRunsBeforeEviction(t *testing.T) {
	s, now := storeAtT(10)
	t0 := *now
	s.Revoke("old1", t0)
	s.Revoke("old2", t0.Add(time.Second))
	for i := 0; i < 8; i++ {
		s.Revoke("new"+itoa(i), t0.Add(3000*time.Second+time.Duration(i)*time.Second))
	}
	*now = t0.Add(time.Hour + maxLeeway + time.Second)
	if d := s.Revoke("newcomer", t0.Add(time.Hour)); d != 0 {
		t.Fatalf("dropped %d live entries although two had expired", d)
	}
	if s.IsRevoked("unrelated", t0.Add(100*time.Second)) {
		t.Fatal("no floor may be raised when expiry made room")
	}
}

func TestKillExpiryIsExclusiveAtExactlyOneLifetime(t *testing.T) {
	s, now := storeAtT(2)
	t0 := *now
	s.Revoke("a", t0)
	s.Revoke("b", t0.Add(100*time.Second))
	*now = t0.Add(time.Hour + maxLeeway + time.Second)
	if s.IsRevoked("a", time.Unix(0, 0)) {
		t.Fatal("IsRevoked: expired at exactly one lifetime")
	}
	if d := s.Revoke("c", *now); d != 0 {
		t.Fatalf("sweep must drop a at exactly one lifetime (dropped %d)", d)
	}
	s.Revoke("late", t0)
	if s.Len() != 2 || s.IsRevoked("late", t0.Add(-time.Second)) {
		t.Fatal("Revoke: an entry already one lifetime old must not be stored")
	}
}

func TestKillEmptySubjectIsNeverStored(t *testing.T) {
	s, now := storeAtT(5)
	s.Revoke("", *now)
	if s.Len() != 0 || s.IsRevoked("", time.Unix(0, 0)) {
		t.Fatal("empty subject stored")
	}
}

func TestKillSeenSetExpiresAtItsTTLAndKeepsBeforeIt(t *testing.T) {
	s := newSeenSet(10, 100*time.Second)
	t0 := time.Unix(2_000_000_000, 0)
	if !s.claim("j", t0) {
		t.Fatal("first claim")
	}
	if s.claim("j", t0.Add(99*time.Second)) {
		t.Fatal("still remembered before the ttl")
	}
	if !s.claim("j", t0.Add(100*time.Second)) {
		t.Fatal("must be forgotten at exactly the ttl")
	}
}

func TestKillSeenSetQueueIsCompacted(t *testing.T) {
	s := newSeenSet(100000, time.Second)
	t0 := time.Unix(2_000_000_000, 0)
	for i := 0; i < 5000; i++ {
		s.claim("j"+itoa(i), t0.Add(time.Duration(i)*2*time.Second)) // each one expires the previous
	}
	if len(s.q) > 2100 {
		t.Fatalf("queue holds %d slots for %d live ids: the consumed head is never released", len(s.q), len(s.m))
	}
}

func TestKillEmptySignatureIsMalformedNotABadSignature(t *testing.T) {
	g := newRig(t)
	tok := g.tokenFor("usr_1", g.f.clock(), nil)
	i := strings.LastIndex(tok, ".")
	_, err := g.c.Verify(nil2ctx(), tok[:i+1])
	mustCode(t, err, CodeMalformed)
}

func nil2ctx() context.Context { return context.Background() }
