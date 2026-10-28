package authfi

// This file and chain.go verify DPoP proofs and certificate chains. They hold no secret and read
// nothing of the client's Config (a test enforces it), so they can be lifted into a package of their
// own and published as one.

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"sync"
	"time"
)

// DPoP wire names (RFC 9449).
const (
	headerDPoP      = "DPoP"
	headerDPoPNonce = "DPoP-Nonce"
	schemeDPoP      = "DPoP"
	proofTyp        = "dpop+jwt"

	// proofWindow is how old a proof's iat may be, and proofSkew how far ahead of this clock.
	proofWindow    = 60 * time.Second
	proofSkew      = 5 * time.Second
	maxProofBytes  = 8 << 10
	nonceWindow    = 5 * time.Minute
	minNonceKeyLen = 32
)

// ReplayGuard records that a DPoP proof id was used. Claim returns fresh=true the first time id is
// seen and false until at least until. An error is never fresh: the request is refused.
//
// The default guard lives in the memory of one process. With more than one replica of the resource
// server, give each the same shared store (a database or Redis) behind this interface, or a proof
// replayed against another replica is accepted inside its window.
type ReplayGuard interface {
	Claim(ctx context.Context, id string, until time.Time) (fresh bool, err error)
}

const (
	// maxReplayEntries bounds the default guard as a whole and maxReplayPerKey what one proof key may
	// hold in it, so one bound key cannot fill the guard and lock the others out.
	maxReplayEntries = 1 << 17
	maxReplayPerKey  = 1000
	// replayBucket is the granularity, in seconds, entries expire at, so expiry never scans the
	// whole guard.
	replayBucket = 10
)

// ErrReplayGuardFull is what a ReplayGuard returns from Claim when it refuses to record an id
// because it holds too many (for that key, or in all). The request is refused with
// dpop_replay_guard_full.
var ErrReplayGuardFull = errors.New("replay guard is full")

// memoryReplayGuard is the default ReplayGuard: bounded in total and per proof key, expired in
// time buckets, and fail closed when full.
type memoryReplayGuard struct {
	mu      sync.Mutex
	now     func() time.Time
	seen    map[[32]byte]struct{}
	perKey  map[string]int
	buckets map[int64][]replayEntry // by the bucket the entry expires in
	swept   int64                   // buckets before this one are gone
}

type replayEntry struct {
	hash [32]byte
	key  string
}

func newMemoryReplayGuard(now func() time.Time) *memoryReplayGuard {
	return &memoryReplayGuard{now: now, seen: map[[32]byte]struct{}{}, perKey: map[string]int{}, buckets: map[int64][]replayEntry{}}
}

// replayKey is the proof key an id belongs to: ids are thumbprint:jti and a thumbprint has no colon.
func replayKey(id string) string {
	k, _, _ := strings.Cut(id, ":")
	return k
}

func (g *memoryReplayGuard) Claim(_ context.Context, id string, until time.Time) (bool, error) {
	hash := sha256.Sum256([]byte(id))
	key := replayKey(id)
	now := g.now()
	g.mu.Lock()
	defer g.mu.Unlock()
	g.sweep(now)
	if _, dup := g.seen[hash]; dup {
		return false, nil
	}
	if g.perKey[key] >= maxReplayPerKey || len(g.seen) >= maxReplayEntries {
		return false, ErrReplayGuardFull
	}
	b := until.Unix() / replayBucket
	g.seen[hash] = struct{}{}
	g.perKey[key]++
	g.buckets[b] = append(g.buckets[b], replayEntry{hash, key})
	return true, nil
}

// sweep drops the buckets that ended before now. Each bucket is visited once, so the work follows
// what expired and not what the guard holds.
func (g *memoryReplayGuard) sweep(now time.Time) {
	cur := now.Unix() / replayBucket
	if g.swept == 0 || cur-g.swept > int64(len(g.buckets)) {
		for b := range g.buckets {
			if b < cur {
				g.drop(b)
			}
		}
	} else {
		for b := g.swept; b < cur; b++ {
			g.drop(b)
		}
	}
	g.swept = cur
}

func (g *memoryReplayGuard) drop(b int64) {
	for _, e := range g.buckets[b] {
		delete(g.seen, e.hash)
		if g.perKey[e.key]--; g.perKey[e.key] <= 0 {
			delete(g.perKey, e.key)
		}
	}
	delete(g.buckets, b)
}

// hmacNonces issues stateless server nonces: a time window and an HMAC over it. A nonce is valid in
// the window it was issued in and the one after.
type hmacNonces struct {
	key    []byte
	window time.Duration
}

func newHMACNonces(key []byte) *hmacNonces {
	return &hmacNonces{key: append([]byte(nil), key...), window: nonceWindow}
}

func (n *hmacNonces) issue(now time.Time) string { return n.nonceFor(now.UnixNano() / int64(n.window)) }

func (n *hmacNonces) valid(nonce string, now time.Time) bool {
	if nonce == "" {
		return false
	}
	w := now.UnixNano() / int64(n.window)
	ok := false
	for _, cand := range []int64{w, w - 1} {
		if hmac.Equal([]byte(nonce), []byte(n.nonceFor(cand))) {
			ok = true
		}
	}
	return ok
}

func (n *hmacNonces) nonceFor(window int64) string {
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], uint64(window))
	mac := hmac.New(sha256.New, n.key)
	mac.Write(b[:])
	return base64.RawURLEncoding.EncodeToString(append(b[:], mac.Sum(nil)[:16]...))
}

// proofEnv is what verifying a proof needs from its surroundings: the time, the nonces when the
// server issues them, and how the request URL is read.
type proofEnv struct {
	now            time.Time
	nonces         *hmacNonces
	publicURL      string
	trustForwarded bool
}

// proofRequest is the part of an HTTP request a proof is checked against.
type proofRequest struct {
	method, host, requestURI, path string
	tls                            bool
	proofs                         []string // every DPoP header value
	forwardedHost, forwardedProto  []string // every X-Forwarded-Host and -Proto value
}

// proofResult is a proof that passed every check except the replay claim.
type proofResult struct {
	thumbprint string
	id         string // thumbprint + jti: the replay key
	until      time.Time
}

type proofHeader struct {
	Typ  string          `json:"typ"`
	Alg  string          `json:"alg"`
	JWK  json.RawMessage `json:"jwk"`
	Crit json.RawMessage `json:"crit"`
}

type proofClaims struct {
	JTI   string `json:"jti"`
	HTM   string `json:"htm"`
	HTU   string `json:"htu"`
	IAT   *int64 `json:"iat"`
	ATH   string `json:"ath"`
	Nonce string `json:"nonce"`
}

func proofRefusal(code, format string, args ...any) *Error { return refuse(code, format, args...) }

// verifyProof checks the DPoP header of r against r and token. It records nothing.
func verifyProof(r proofRequest, token string, env proofEnv) (proofResult, *Error) {
	values := r.proofs
	switch {
	case len(values) == 0 || strings.TrimSpace(values[0]) == "":
		return proofResult{}, proofRefusal(CodeDPoPMissing, "the request carries no DPoP proof")
	case len(values) > 1:
		return proofResult{}, proofRefusal(CodeDPoPMultiple, "the request carries more than one DPoP proof")
	}
	raw := strings.TrimSpace(values[0])
	if len(raw) > maxProofBytes {
		return proofResult{}, proofRefusal(CodeDPoPMalformed, "the DPoP proof is too large")
	}
	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		return proofResult{}, proofRefusal(CodeDPoPMalformed, "a DPoP proof is three dot-separated parts")
	}
	var hdr proofHeader
	if decodeSegment(parts[0], &hdr) != nil || present(hdr.Crit) {
		return proofResult{}, proofRefusal(CodeDPoPMalformed, "the DPoP proof header is not valid")
	}
	if hdr.Typ != proofTyp {
		return proofResult{}, proofRefusal(CodeDPoPType, "the DPoP proof is not typed %s", proofTyp)
	}
	key, err := proofKey(hdr.JWK, hdr.Alg)
	if err != nil {
		return proofResult{}, err
	}
	sig, derr := decodeB64(parts[2])
	if derr != nil || !verifySignature(hdr.Alg, key.pub, []byte(parts[0]+"."+parts[1]), sig) {
		return proofResult{}, proofRefusal(CodeDPoPSignature, "the DPoP proof signature does not verify")
	}
	var pc proofClaims
	if decodeSegment(parts[1], &pc) != nil || strings.TrimSpace(pc.JTI) == "" {
		return proofResult{}, proofRefusal(CodeDPoPMalformed, "the DPoP proof claims are not valid")
	}
	if err := env.checkProofClaims(pc, r, token); err != nil {
		return proofResult{}, err
	}
	thumb, terr := jwkThumbprint(key.pub)
	if terr != nil {
		return proofResult{}, proofRefusal(CodeDPoPMalformed, "the DPoP proof key is not valid")
	}
	return proofResult{
		thumbprint: thumb,
		id:         thumb + ":" + pc.JTI,
		until:      time.Unix(*pc.IAT, 0).Add(proofWindow + proofSkew),
	}, nil
}

// proofKey parses the embedded JWK and fixes the algorithm: EdDSA, ES256 or PS256, and the one the
// key itself allows. A private member in the JWK is refused.
func proofKey(raw json.RawMessage, alg string) (verifyKey, *Error) {
	var members map[string]json.RawMessage
	if json.Unmarshal(raw, &members) != nil || len(members) == 0 {
		return verifyKey{}, proofRefusal(CodeDPoPMalformed, "the DPoP proof carries no key")
	}
	for _, private := range []string{"d", "p", "q", "dp", "dq", "qi", "oth", "k"} {
		if _, ok := members[private]; ok {
			return verifyKey{}, proofRefusal(CodeDPoPMalformed, "the DPoP proof key holds private members")
		}
	}
	var k jwk
	if json.Unmarshal(raw, &k) != nil {
		return verifyKey{}, proofRefusal(CodeDPoPMalformed, "the DPoP proof key is not valid")
	}
	vk, ok := k.verifyKey()
	if !ok || (alg != "EdDSA" && alg != "ES256" && alg != "PS256") || !vk.allows(alg) {
		return verifyKey{}, proofRefusal(CodeDPoPAlg, "the DPoP proof algorithm is not accepted for its key")
	}
	return vk, nil
}

// checkProofClaims checks what the proof states about this request.
func (env proofEnv) checkProofClaims(pc proofClaims, r proofRequest, token string) *Error {
	now := env.now
	if pc.HTM == "" || pc.HTM != r.method {
		return proofRefusal(CodeDPoPMethod, "the DPoP proof is for another method")
	}
	if !urlMatches(pc.HTU, env.requestURL(r)) {
		return proofRefusal(CodeDPoPURL, "the DPoP proof is for another URL")
	}
	if pc.IAT == nil {
		return proofRefusal(CodeDPoPIssuedAt, "the DPoP proof has no iat")
	}
	iat := time.Unix(*pc.IAT, 0)
	if iat.Before(now.Add(-proofWindow)) || iat.After(now.Add(proofSkew)) {
		return proofRefusal(CodeDPoPIssuedAt, "the DPoP proof is outside its time window")
	}
	sum := sha256.Sum256([]byte(token))
	if subtle.ConstantTimeCompare([]byte(pc.ATH), []byte(base64.RawURLEncoding.EncodeToString(sum[:]))) != 1 {
		return proofRefusal(CodeDPoPAccessTokenHash, "the DPoP proof is for another access token")
	}
	if env.nonces != nil && !env.nonces.valid(pc.Nonce, now) {
		e := proofRefusal(CodeDPoPNonce, "the DPoP proof carries no current server nonce")
		e.Nonce = env.nonces.issue(now)
		return e
	}
	return nil
}

// requestURL is the URL the client addressed, for htu: the public URL when configured, else the
// forwarded host and scheme (the last entry) when forwarding headers are trusted, else this request's own host.
func (env proofEnv) requestURL(r proofRequest) string {
	path := r.path
	if r.requestURI != "" {
		if u, err := url.ParseRequestURI(r.requestURI); err == nil && u.EscapedPath() != "" {
			path = u.EscapedPath()
		}
	}
	if base := trimIssuer(env.publicURL); base != "" {
		return base + path
	}
	if env.trustForwarded {
		if host := lastListValue(r.forwardedHost); host != "" {
			proto := strings.ToLower(lastListValue(r.forwardedProto))
			if proto != "http" {
				proto = "https"
			}
			return proto + "://" + host + path
		}
	}
	scheme := "http"
	if r.tls {
		scheme = "https"
	}
	return scheme + "://" + r.host + path
}

// lastListValue is the last entry of a comma-separated header, across its lines: the one the proxy
// nearest to this server appended. The entries before it are whatever the client sent.
func lastListValue(values []string) string {
	if len(values) == 0 {
		return ""
	}
	v := values[len(values)-1]
	if i := strings.LastIndex(v, ","); i >= 0 {
		v = v[i+1:]
	}
	return strings.TrimSpace(v)
}

// urlMatches compares htu with the request URL per RFC 9449 section 4.3: scheme and host without
// case, a default port equal to none, query and fragment ignored, the path exact.
func urlMatches(htu, want string) bool {
	a, ok := normalizeURL(htu)
	if !ok {
		return false
	}
	b, ok := normalizeURL(want)
	return ok && a == b
}

func normalizeURL(raw string) (string, bool) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Scheme == "" || u.Host == "" {
		return "", false
	}
	scheme := strings.ToLower(u.Scheme)
	host := strings.ToLower(u.Hostname())
	port := u.Port()
	if (scheme == "https" && port == "443") || (scheme == "http" && port == "80") {
		port = ""
	}
	if port != "" {
		host += ":" + port
	}
	path := u.EscapedPath()
	if path == "" {
		path = "/"
	}
	return scheme + "://" + host + path, true
}

// jwkThumbprint is the RFC 7638 SHA-256 thumbprint of a public key.
func jwkThumbprint(pub any) (string, error) {
	var canonical string
	switch k := pub.(type) {
	case ed25519.PublicKey:
		canonical = fmt.Sprintf(`{"crv":"Ed25519","kty":"OKP","x":%q}`, base64URL(k))
	case *ecdsa.PublicKey:
		canonical = fmt.Sprintf(`{"crv":"P-256","kty":"EC","x":%q,"y":%q}`,
			base64URL(k.X.FillBytes(make([]byte, 32))), base64URL(k.Y.FillBytes(make([]byte, 32))))
	case *rsa.PublicKey:
		e := make([]byte, 8)
		binary.BigEndian.PutUint64(e, uint64(k.E))
		canonical = fmt.Sprintf(`{"e":%q,"kty":"RSA","n":%q}`, base64URL(trimLeadingZeros(e)), base64URL(k.N.Bytes()))
	default:
		return "", errors.New("unsupported key")
	}
	sum := sha256.Sum256([]byte(canonical))
	return base64URL(sum[:]), nil
}

func trimLeadingZeros(b []byte) []byte {
	for len(b) > 1 && b[0] == 0 {
		b = b[1:]
	}
	return b
}

func base64URL(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }
