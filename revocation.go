package authfi

import (
	"sort"
	"sync"
	"time"
)

const (
	// DefaultRevocationEntries is how many subjects a RevocationStore remembers.
	DefaultRevocationEntries = 100_000
	// DefaultTokenLifetime is how long a revocation is remembered past its time: the longest an
	// access token of this project is expected to live.
	DefaultTokenLifetime = 24 * time.Hour

	// evictFraction is the share of the cap dropped in one pass when the store is full, so a
	// stream of new subjects does not pay for a scan on every insert.
	evictFraction = 10
)

// RevocationOptions sizes a RevocationStore. Zero values take the defaults.
type RevocationOptions struct {
	// MaxEntries caps the subjects remembered. Default DefaultRevocationEntries.
	MaxEntries int
	// TokenLifetime must be at least the longest lifetime of any token you accept: once a
	// revocation is older than that (plus the clock leeway), every token it could refuse has expired
	// by itself, and the entry is dropped. Verify refuses a token that lives longer than this.
	// Default DefaultTokenLifetime.
	TokenLifetime time.Duration
}

// RevocationStore remembers, per subject, the time before which tokens are dead: "tokens issued at
// or before this instant for this subject are revoked". It is safe for concurrent use and bounded.
//
// When it is full it drops the oldest revocations and raises a floor: every token issued at or
// before the newest dropped revocation is then refused whatever its subject. That costs those
// holders a new token and never lets a revoked token through, which is why the cap cannot be used
// to push a revocation out.
type RevocationStore struct {
	max  int
	life time.Duration
	now  func() time.Time // tests only

	mu    sync.RWMutex
	nb    map[string]int64 // subject -> not-before, Unix seconds
	floor int64            // Unix seconds; zero when no entry was ever dropped for room
}

// NewRevocationStore builds an empty store.
func NewRevocationStore(o RevocationOptions) *RevocationStore {
	if o.MaxEntries <= 0 {
		o.MaxEntries = DefaultRevocationEntries
	}
	if o.TokenLifetime <= 0 {
		o.TokenLifetime = DefaultTokenLifetime
	}
	return &RevocationStore{max: o.MaxEntries, life: o.TokenLifetime, nb: make(map[string]int64)}
}

func (s *RevocationStore) clock() time.Time {
	if s.now != nil {
		return s.now()
	}
	return time.Now()
}

// Revoke records that tokens of subject issued at or before notBefore are dead. A later call with
// an earlier time changes nothing. It returns how many other subjects were dropped to make room
// (see the type comment); zero in normal operation.
func (s *RevocationStore) Revoke(subject string, notBefore time.Time) (dropped int) {
	if s == nil || subject == "" {
		return 0
	}
	at, now := notBefore.Unix(), s.clock().Unix()
	s.mu.Lock()
	defer s.mu.Unlock()
	if at+s.lifeSeconds() <= now {
		return 0 // every token this could refuse has already expired
	}
	if cur, ok := s.nb[subject]; ok {
		if at > cur {
			s.nb[subject] = at
		}
		return 0
	}
	if len(s.nb) >= s.max {
		dropped = s.makeRoomLocked(now)
	}
	s.nb[subject] = at
	return dropped
}

// retention is how long a revocation matters: a token issued at the revocation can live for the
// token lifetime and then still verifies for the clock leeway.
func (s *RevocationStore) retention() time.Duration { return s.life + maxLeeway }

func (s *RevocationStore) lifeSeconds() int64 { return int64(s.retention() / time.Second) }

// makeRoomLocked drops expired entries, and if the store is still full, the oldest tenth.
func (s *RevocationStore) makeRoomLocked(now int64) int {
	life := s.lifeSeconds()
	for k, at := range s.nb {
		if at+life <= now {
			delete(s.nb, k)
		}
	}
	if len(s.nb) < s.max {
		return 0
	}
	type entry struct {
		subject string
		at      int64
	}
	all := make([]entry, 0, len(s.nb))
	for k, at := range s.nb {
		all = append(all, entry{k, at})
	}
	sort.Slice(all, func(i, j int) bool { return all[i].at < all[j].at })
	n := s.max/evictFraction + 1
	if n > len(all) {
		n = len(all)
	}
	for _, e := range all[:n] {
		delete(s.nb, e.subject)
	}
	if last := all[n-1].at; last > s.floor {
		s.floor = last
	}
	return n
}

// IsRevoked reports whether a token of subject issued at issuedAt is revoked. A zero issuedAt
// means the issue time is unknown: it counts as older than every revocation, so it is revoked
// whenever the subject has a live one, because it cannot be shown to be newer.
func (s *RevocationStore) IsRevoked(subject string, issuedAt time.Time) bool {
	if s == nil {
		return false
	}
	now := s.clock().Unix()
	life := s.lifeSeconds()
	s.mu.RLock()
	defer s.mu.RUnlock()
	// A zero issuedAt (an unknown issue time) has a Unix time far before every revocation, so it
	// is covered by every live one.
	iat := issuedAt.Unix()
	if s.floor != 0 && s.floor+life > now && iat <= s.floor {
		return true
	}
	at, ok := s.nb[subject]
	if !ok || at+life <= now {
		return false
	}
	return iat <= at
}

// Len is the number of subjects remembered, expired ones included until they are next swept.
func (s *RevocationStore) Len() int {
	if s == nil {
		return 0
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.nb)
}

// checkRevoked refuses a verified token whose subject, or the actor on a delegated token, is
// revoked. Without a store configured nothing is checked.
func (c *Client) checkRevoked(cl *Claims) error {
	st := c.cfg.Revocations
	if st == nil {
		return nil
	}
	var iat time.Time
	if cl.IssuedAt > 0 {
		iat = time.Unix(cl.IssuedAt, 0)
		// The store forgets a revocation once the longest token it was told about has expired. A
		// longer-lived token would outlive its revocation, so it is refused rather than trusted.
		if cl.ExpiresAt-cl.IssuedAt > int64(st.life/time.Second) {
			return refuse(CodeNotConfigured, "RevocationOptions.TokenLifetime (%s) is shorter than the lifetime of this token; raise it", st.life)
		}
	}
	if st.IsRevoked(cl.Subject, iat) || (cl.Actor != "" && st.IsRevoked(cl.Actor, iat)) {
		return refuse(CodeRevoked, "access for this subject was withdrawn after the token was issued")
	}
	return nil
}

// seenSet remembers recently accepted jti values, bounded in count and in time.
type seenSet struct {
	mu   sync.Mutex
	max  int
	ttl  time.Duration
	m    map[string]struct{}
	q    []seenItem // oldest first
	head int
}

type seenItem struct {
	jti     string
	expires int64
}

func newSeenSet(max int, ttl time.Duration) *seenSet {
	return &seenSet{max: max, ttl: ttl, m: make(map[string]struct{})}
}

// claim records jti and reports whether it was new. When the set is full the oldest id is
// forgotten: a replay of it is then applied again, which is harmless because applying a
// revocation twice changes nothing.
func (s *seenSet) claim(jti string, now time.Time) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	at := now.Unix()
	for s.head < len(s.q) && s.q[s.head].expires <= at {
		s.dropHead()
	}
	if _, dup := s.m[jti]; dup {
		return false
	}
	if len(s.m) >= s.max {
		s.dropHead()
	}
	s.m[jti] = struct{}{}
	s.q = append(s.q, seenItem{jti, at + int64(s.ttl/time.Second)})
	if s.head > len(s.q)/2 && s.head > 1024 {
		s.q = append([]seenItem(nil), s.q[s.head:]...)
		s.head = 0
	}
	return true
}

func (s *seenSet) dropHead() {
	delete(s.m, s.q[s.head].jti)
	s.q[s.head] = seenItem{}
	s.head++
}
