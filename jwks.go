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
	x5c  []string // base64 DER certificates, leaf first, as published
	x5t  string   // x5t#S256 as published
}

func (k verifyKey) allows(alg string) bool {
	for _, a := range k.algs {
		if a == alg {
			return true
		}
	}
	return false
}

// keySet caches the key set of the issuer. Reads take the fast path. A fetch runs on its own
// goroutine with its own deadline, one at a time: callers wait for it or leave on their own context,
// and a caller that leaves does not cancel it, so dropped connections cannot turn into repeated
// fetches against the issuer.
type keySet struct {
	url     string
	ttl     time.Duration
	timeout time.Duration
	client  *http.Client
	now     func() time.Time

	mu        sync.RWMutex
	keys      map[string]verifyKey
	fetched   time.Time
	attempted time.Time
	failure   error // why the last attempt failed; nil when it succeeded
	flight    *flight
}

// flight is one fetch in progress; err is set before done is closed.
type flight struct {
	done chan struct{}
	err  error
}

func noSuchKey() *Error { return refuse(CodeUnknownKey, "the key set of the issuer has no such key") }

func (s *keySet) get(ctx context.Context, kid string) (verifyKey, error) {
	if k, ok := s.fresh(kid); ok {
		return k, nil
	}
	if err := ctx.Err(); err != nil { // a request that is already over starts nothing
		return verifyKey{}, &Error{Code: CodeKeySetUnavailable, Message: "the request ended before the key set arrived", Err: err}
	}
	s.mu.Lock()
	f := s.flight
	if f == nil {
		// One attempt per minRefetch, whatever came of the last one. This bounds what forged kids,
		// an expired cache and a down issuer can cost the issuer: not one fetch per request. A
		// failure is remembered for that interval, even if the issuer recovers inside it.
		if s.now().Sub(s.attempted) < minRefetch {
			k, ok := s.staleLocked(kid)
			failure := s.failure
			s.mu.Unlock()
			switch {
			case ok:
				return k, nil
			case failure != nil:
				return verifyKey{}, failure
			}
			return verifyKey{}, noSuchKey()
		}
		f = s.startLocked()
	}
	s.mu.Unlock()
	return s.await(ctx, f, kid)
}

// load fetches now, unless a fetch is already running (Start).
func (s *keySet) load(ctx context.Context) error {
	s.mu.Lock()
	f := s.flight
	if f == nil {
		f = s.startLocked()
	}
	s.mu.Unlock()
	select {
	case <-f.done:
		return f.err
	case <-ctx.Done():
		return &Error{Code: CodeKeySetUnavailable, Message: "the request ended before the key set arrived", Err: ctx.Err()}
	}
}

func (s *keySet) await(ctx context.Context, f *flight, kid string) (verifyKey, error) {
	select {
	case <-f.done:
	case <-ctx.Done():
		return verifyKey{}, &Error{Code: CodeKeySetUnavailable, Message: "the request ended before the key set arrived", Err: ctx.Err()}
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	if f.err != nil {
		if k, ok := s.staleLocked(kid); ok {
			return k, nil
		}
		return verifyKey{}, f.err
	}
	k, ok := s.keys[kid]
	if !ok {
		return verifyKey{}, noSuchKey()
	}
	return k, nil
}

// startLocked begins a fetch. s.mu must be held for writing and no fetch may be running.
func (s *keySet) startLocked() *flight {
	f := &flight{done: make(chan struct{})}
	s.flight, s.attempted = f, s.now()
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), s.timeout)
		defer cancel()
		keys, err := s.safeFetch(ctx)
		s.mu.Lock()
		if err != nil {
			s.failure = err
		} else {
			s.keys, s.fetched, s.failure = keys, s.now(), nil
		}
		f.err, s.flight = err, nil
		s.mu.Unlock()
		close(f.done)
	}()
	return f
}

// safeFetch turns a panic in the fetch (a custom HTTPClient transport can panic) into a failed
// fetch: this runs on its own goroutine, where nothing else would recover it, and an unrecovered
// panic here ends the process.
func (s *keySet) safeFetch(ctx context.Context) (keys map[string]verifyKey, err error) {
	defer func() {
		if recover() != nil {
			keys, err = nil, refuse(CodeKeySetUnavailable, "the key set fetch failed unexpectedly")
		}
	}()
	return s.fetch(ctx)
}

// staleLocked returns a cached key that is past its refresh time but within the grace period.
func (s *keySet) staleLocked(kid string) (verifyKey, bool) {
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

func (s *keySet) fetch(ctx context.Context) (map[string]verifyKey, error) {
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

	X5c []string `json:"x5c"`
	X5t string   `json:"x5t#S256"`
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
			vk.x5c, vk.x5t = boundedX5c(k.X5c), k.X5t
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

const (
	maxX5cCerts    = 6
	maxX5cCertSize = 16 << 10
)

// boundedX5c keeps a certificate list the chain check can afford to parse. An oversize list is
// dropped whole, so a key that publishes one has no chain and is refused where a chain is required.
func boundedX5c(x5c []string) []string {
	if len(x5c) > maxX5cCerts {
		return nil
	}
	for _, c := range x5c {
		if len(c) > maxX5cCertSize {
			return nil
		}
	}
	return x5c
}
