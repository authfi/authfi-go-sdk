package authfi

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

const (
	testAudience = "api-orders"
	testTenant   = "4e46e0c4-ec26-48e1-b5bb-04a1ec3ff358"
)

// fixture is a fake issuer: it serves a key set and signs tokens with the keys in it.
type fixture struct {
	t      *testing.T
	srv    *httptest.Server
	now    time.Time
	nowMu  sync.Mutex
	fetch  atomic.Int32
	status atomic.Int32 // when non-zero, the key set answers this status

	mu   sync.Mutex
	keys map[string]*signer // by kid; all are published
}

type signer struct {
	kid, alg string
	rsa      *rsa.PrivateKey
	ec       *ecdsa.PrivateKey
	ed       ed25519.PrivateKey
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	f := &fixture{t: t, now: time.Now().Truncate(time.Second), keys: map[string]*signer{}}
	f.srv = httptest.NewServer(http.HandlerFunc(f.serve))
	t.Cleanup(f.srv.Close)
	rk, pk := sharedRSA()
	ek, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	_, edk, _ := ed25519.GenerateKey(rand.Reader)
	f.add(&signer{kid: "rs1", alg: "RS256", rsa: rk})
	f.add(&signer{kid: "ps1", alg: "PS256", rsa: pk})
	f.add(&signer{kid: "es1", alg: "ES256", ec: ek})
	f.add(&signer{kid: "ed1", alg: "EdDSA", ed: edk})
	return f
}

var (
	rsaOnce    sync.Once
	rsaA, rsaB *rsa.PrivateKey
)

// sharedRSA returns two RSA keys generated once per test run: generation dominates test time.
func sharedRSA() (*rsa.PrivateKey, *rsa.PrivateKey) {
	rsaOnce.Do(func() {
		rsaA, _ = rsa.GenerateKey(rand.Reader, 2048)
		rsaB, _ = rsa.GenerateKey(rand.Reader, 2048)
	})
	return rsaA, rsaB
}

func (f *fixture) add(s *signer) {
	f.mu.Lock()
	f.keys[s.kid] = s
	f.mu.Unlock()
}

func (f *fixture) issuer() string { return f.srv.URL }

func (f *fixture) clock() time.Time {
	f.nowMu.Lock()
	defer f.nowMu.Unlock()
	return f.now
}

func (f *fixture) advance(d time.Duration) {
	f.nowMu.Lock()
	f.now = f.now.Add(d)
	f.nowMu.Unlock()
}

func (f *fixture) serve(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/.well-known/jwks.json" {
		http.NotFound(w, r)
		return
	}
	f.fetch.Add(1)
	st := int(f.status.Load())
	f.mu.Lock()
	defer f.mu.Unlock()
	keys := []map[string]string{}
	for _, s := range f.keys {
		keys = append(keys, s.jwk())
	}
	w.Header().Set("Content-Type", "application/json")
	if st != 0 {
		w.WriteHeader(st) // the body is still a usable key set: only the status says no
	}
	_ = json.NewEncoder(w).Encode(map[string]any{"keys": keys})
}

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func (s *signer) jwk() map[string]string {
	switch {
	case s.rsa != nil:
		return map[string]string{"kty": "RSA", "kid": s.kid, "use": "sig", "alg": s.alg,
			"n": b64(s.rsa.N.Bytes()), "e": b64(big.NewInt(int64(s.rsa.E)).Bytes())}
	case s.ec != nil:
		return map[string]string{"kty": "EC", "crv": "P-256", "kid": s.kid, "use": "sig", "alg": "ES256",
			"x": b64(s.ec.X.FillBytes(make([]byte, 32))), "y": b64(s.ec.Y.FillBytes(make([]byte, 32)))}
	}
	return map[string]string{"kty": "OKP", "crv": "Ed25519", "kid": s.kid, "use": "sig", "alg": "EdDSA",
		"x": b64(s.ed.Public().(ed25519.PublicKey))}
}

// sign signs data the way the signer's own algorithm does, whatever the header will claim.
func (s *signer) sign(data string) []byte {
	h := sha256.Sum256([]byte(data))
	switch {
	case s.rsa != nil && s.alg == "PS256":
		sig, _ := rsa.SignPSS(rand.Reader, s.rsa, crypto.SHA256, h[:], &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash})
		return sig
	case s.rsa != nil:
		sig, _ := rsa.SignPKCS1v15(rand.Reader, s.rsa, crypto.SHA256, h[:])
		return sig
	case s.ec != nil:
		r, ss, _ := ecdsa.Sign(rand.Reader, s.ec, h[:])
		out := make([]byte, 64)
		r.FillBytes(out[:32])
		ss.FillBytes(out[32:])
		return out
	}
	return ed25519.Sign(s.ed, []byte(data))
}

// tokenSpec describes one token: a good one by default, then overrides.
type tokenSpec struct {
	kid     string // the signing key; default rs1
	header  map[string]any
	claims  map[string]any
	dropHdr []string
	dropClm []string
}

func (f *fixture) goodClaims() map[string]any {
	return map[string]any{
		"iss": f.issuer(), "sub": "usr_123", "aud": testAudience, "tenant_id": testTenant,
		"exp": f.clock().Add(time.Hour).Unix(), "iat": f.clock().Unix(),
		"roles": []string{"admin"}, "permissions": []string{"read:users"},
	}
}

func (f *fixture) mint(sp tokenSpec) string {
	f.t.Helper()
	if sp.kid == "" {
		sp.kid = "rs1"
	}
	f.mu.Lock()
	s := f.keys[sp.kid]
	f.mu.Unlock()
	hdr := map[string]any{"alg": s.alg, "typ": "at+jwt", "kid": s.kid}
	for k, v := range sp.header {
		hdr[k] = v
	}
	for _, k := range sp.dropHdr {
		delete(hdr, k)
	}
	clm := f.goodClaims()
	for k, v := range sp.claims {
		clm[k] = v
	}
	for _, k := range sp.dropClm {
		delete(clm, k)
	}
	hj, _ := json.Marshal(hdr)
	cj, _ := json.Marshal(clm)
	signed := b64(hj) + "." + b64(cj)
	return signed + "." + b64(s.sign(signed))
}

func (f *fixture) client(mod ...func(*Config)) *Client {
	cfg := Config{Issuer: f.issuer(), Audience: []string{testAudience}, TenantID: testTenant}
	for _, m := range mod {
		m(&cfg)
	}
	c := New(cfg)
	c.clock = f.clock
	return c
}

func mustCode(t *testing.T, err error, want string) {
	t.Helper()
	if err == nil {
		t.Fatalf("expected %s, got no error", want)
	}
	e, ok := err.(*Error)
	if !ok {
		t.Fatalf("expected *Error %s, got %T: %v", want, err, err)
	}
	if e.Code != want {
		t.Fatalf("expected code %s, got %s (%s)", want, e.Code, e.Message)
	}
}
