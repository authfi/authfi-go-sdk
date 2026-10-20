package authfi

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

const (
	jwksPath         = "/.well-known/jwks.json"
	jwksMaxBytes     = 1 << 20
	jwksMaxKeys      = 100
	jwksFetchTimeout = 10 * time.Second
	// minRefetch bounds how often an unknown kid may cost a fetch, so a stream of forged kids
	// cannot turn this server into an amplifier against the issuer.
	minRefetch = 15 * time.Second
	// staleGrace is how long past its refresh time a cached key may still verify when the
	// issuer cannot be reached.
	staleGrace = time.Hour
	minRSABits = 2048
)

// verifyKey is one public key of the issuer with the algorithms it may verify.
type verifyKey struct {
	pub  any // *rsa.PublicKey, *ecdsa.PublicKey or ed25519.PublicKey
	algs []string
}

func (k verifyKey) allows(alg string) bool {
	for _, a := range k.algs {
		if a == alg {
			return true
		}
	}
	return false
}

// keySet caches the issuer's key set. Reads take the fast path; a refresh is serialised so a
// burst of requests costs one fetch.
type keySet struct {
	url    string
	ttl    time.Duration
	client *http.Client
	now    func() time.Time

	mu        sync.RWMutex
	keys      map[string]verifyKey
	fetched   time.Time
	attempted time.Time
	failure   error // why the last attempt failed; nil when it succeeded

	fetchMu sync.Mutex
}

func (s *keySet) get(ctx context.Context, kid string) (verifyKey, error) {
	if k, ok := s.fresh(kid); ok {
		return k, nil
	}
	s.fetchMu.Lock()
	defer s.fetchMu.Unlock()
	if k, ok := s.fresh(kid); ok { // another request refreshed while this one waited
		return k, nil
	}
	// One attempt per minRefetch, whatever came of the last one. This bounds what forged kids, an
	// expired cache and a down issuer can cost the issuer: not one fetch per request.
	if s.now().Sub(s.lastAttempt()) < minRefetch {
		if k, ok := s.stale(kid); ok {
			return k, nil
		}
		if err := s.lastFailure(); err != nil {
			return verifyKey{}, err
		}
		return verifyKey{}, refuse(CodeUnknownKey, "the issuer's key set has no such key")
	}
	if err := s.refresh(ctx); err != nil {
		if k, ok := s.stale(kid); ok {
			return k, nil
		}
		return verifyKey{}, err
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	k, ok := s.keys[kid]
	if !ok {
		return verifyKey{}, refuse(CodeUnknownKey, "the issuer's key set has no such key")
	}
	return k, nil
}

func (s *keySet) lastAttempt() time.Time {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.attempted
}

func (s *keySet) lastFailure() error {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.failure
}

// stale returns a cached key that is past its refresh time but within the grace period.
func (s *keySet) stale(kid string) (verifyKey, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	k, ok := s.keys[kid]
	if !ok || s.now().Sub(s.fetched) >= s.ttl+staleGrace {
		return verifyKey{}, false
	}
	return k, true
}

func (s *keySet) fresh(kid string) (verifyKey, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	k, ok := s.keys[kid]
	if !ok || s.now().Sub(s.fetched) >= s.ttl {
		return verifyKey{}, false
	}
	return k, true
}

func (s *keySet) refresh(ctx context.Context) error {
	s.mu.Lock()
	previous := s.attempted
	s.attempted = s.now()
	s.mu.Unlock()

	keys, err := s.fetch(ctx)

	s.mu.Lock()
	defer s.mu.Unlock()
	if err != nil {
		if ctx.Err() != nil {
			// The caller gave up; that says nothing about the issuer, so it is not an attempt.
			s.attempted = previous
			return &Error{Code: CodeKeySetUnavailable, Message: "the request ended before the key set arrived", Err: ctx.Err()}
		}
		s.failure = err
		return err
	}
	s.keys, s.fetched, s.failure = keys, s.now(), nil
	return nil
}

func (s *keySet) fetch(ctx context.Context) (map[string]verifyKey, error) {
	ctx, cancel := context.WithTimeout(ctx, jwksFetchTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.url, nil)
	if err != nil {
		return nil, &Error{Code: CodeKeySetUnavailable, Message: "the key set URL is invalid", Err: err}
	}
	req.Header.Set("Accept", "application/json")
	resp, err := s.client.Do(req)
	if err != nil {
		return nil, &Error{Code: CodeKeySetUnavailable, Message: "the key set of the issuer could not be fetched", Err: err}
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, refuse(CodeKeySetUnavailable, "the key set of the issuer answered HTTP %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, jwksMaxBytes+1))
	if err != nil || len(body) > jwksMaxBytes {
		return nil, refuse(CodeKeySetUnavailable, "the key set of the issuer could not be read")
	}
	keys, err := parseKeySet(body)
	if err != nil {
		return nil, err
	}
	if len(keys) == 0 {
		// An empty set would wipe the keys that still verify; treat it as the failure it is.
		return nil, refuse(CodeKeySetUnavailable, "the key set of the issuer holds no usable key")
	}
	return keys, nil
}

type jwk struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	Use string `json:"use"`
	Alg string `json:"alg"`
	Crv string `json:"crv"`
	N   string `json:"n"`
	E   string `json:"e"`
	X   string `json:"x"`
	Y   string `json:"y"`
}

func parseKeySet(body []byte) (map[string]verifyKey, error) {
	var doc struct {
		Keys []jwk `json:"keys"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, refuse(CodeKeySetUnavailable, "the issuer's key set is not a JWKS document")
	}
	out := make(map[string]verifyKey, len(doc.Keys))
	for i, k := range doc.Keys {
		if i >= jwksMaxKeys {
			break
		}
		if k.Kid == "" || (k.Use != "" && k.Use != "sig") {
			continue
		}
		if vk, ok := k.verifyKey(); ok {
			out[k.Kid] = vk // a key that does not parse is skipped, never fatal to the others
		}
	}
	return out, nil
}

// verifyKey builds the public key and fixes the algorithms it may verify. A JWK's own alg is
// authoritative; without one the key type decides.
func (k jwk) verifyKey() (verifyKey, bool) {
	switch k.Kty {
	case "RSA":
		n, e := b64Int(k.N), b64Int(k.E)
		if n == nil || e == nil || n.BitLen() < minRSABits || !e.IsInt64() || e.Int64() < 3 || e.Int64() > 1<<31-1 {
			return verifyKey{}, false
		}
		algs := []string{"RS256", "PS256"}
		if k.Alg != "" {
			if k.Alg != "RS256" && k.Alg != "PS256" {
				return verifyKey{}, false
			}
			algs = []string{k.Alg}
		}
		return verifyKey{pub: &rsa.PublicKey{N: n, E: int(e.Int64())}, algs: algs}, true
	case "EC":
		if k.Crv != "P-256" || (k.Alg != "" && k.Alg != "ES256") {
			return verifyKey{}, false
		}
		x, y := b64Int(k.X), b64Int(k.Y)
		if x == nil || y == nil || !elliptic.P256().IsOnCurve(x, y) {
			return verifyKey{}, false
		}
		return verifyKey{pub: &ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y}, algs: []string{"ES256"}}, true
	case "OKP":
		x, err := base64.RawURLEncoding.DecodeString(k.X)
		if k.Crv != "Ed25519" || err != nil || len(x) != ed25519.PublicKeySize || (k.Alg != "" && k.Alg != "EdDSA") {
			return verifyKey{}, false
		}
		return verifyKey{pub: ed25519.PublicKey(x), algs: []string{"EdDSA"}}, true
	}
	return verifyKey{}, false
}

func b64Int(s string) *big.Int {
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil || len(b) == 0 {
		return nil
	}
	return new(big.Int).SetBytes(b)
}

// checkIssuerURL accepts an https issuer, or http on a loopback host for local development.
func checkIssuerURL(issuer string) error {
	u, err := url.Parse(issuer)
	if err != nil || u.Host == "" || u.RawQuery != "" || u.Fragment != "" || u.User != nil {
		return refuse(CodeNotConfigured, "Issuer must be an absolute URL without query, fragment or credentials")
	}
	switch u.Scheme {
	case "https":
		return nil
	case "http":
		h := u.Hostname()
		if h == "localhost" || h == "127.0.0.1" || h == "::1" {
			return nil
		}
	}
	return refuse(CodeNotConfigured, "Issuer must use https")
}

func trimIssuer(s string) string { return strings.TrimRight(strings.TrimSpace(s), "/") }
