package agent

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"
)

const (
	testInstAgent  = "agt_inst_1"
	testCfgDigest  = "sha256:0000000000000000000000000000000000000000000000000000000000000001"
	testPlatformOK = "ok"
)

// instPlatform is a fake AuthFI project for instance sign-in. It checks what the real agent-identity
// service checks (internal/service/attest): the body decodes with no unknown field, the proof is by
// the instance key over a nonce this service issued and has not spent, the evidence matches the
// binding, the configuration is the approved one; and at the token endpoint the attestation is the
// platform's, the proof of possession is by the instance key, and the DPoP key is the attested key.
type instPlatform struct {
	t   *testing.T
	srv *httptest.Server

	mu  sync.Mutex
	now time.Time

	signKey ed25519.PrivateKey

	// the binding
	kind         string            // "k8s" or "device"
	deviceJWK    map[string]string // device binding
	deviceAlg    Algorithm
	approvedVer  int
	approvedDig  string
	observeOpen  bool
	attestTTL    int
	tokenTTL     int
	requireNonce bool // the token endpoint wants a DPoP nonce first

	// state
	nonces    map[string]bool // issued -> spent
	k8sSpent  map[string]bool
	popJTI    map[string]bool
	proofJTI  map[string]bool
	seq       int
	instances map[string]string // attestation jti -> jkt

	// scripts
	attestStatus   int                                               // when set, attest answers this status
	mutate         func(claims map[string]any)                       // changes the attestation before it is signed
	mutateHeader   func(header map[string]any)                       // changes the attestation header
	tokenStatuses  []int                                             // statuses the token endpoint answers before succeeding
	log            []string                                          // "METHOD path" of every request, in order
	attests        []map[string]any                                  // every decoded attest body
	tokenReqs      []tokenReq                                        // every token request seen
	issuedTokens   map[string]string                                 // access token -> cnf jkt
	refusals       []string                                          // why each refusal happened
	extraAttest    func(w http.ResponseWriter) bool                  // answer the attest in a special way
	extraChallenge func(w http.ResponseWriter) bool                  // answer the challenge in a special way
	extraToken     func(w http.ResponseWriter, r *http.Request) bool // answer the token request in a special way
}

type tokenReq struct {
	form   url.Values
	header http.Header
}

func newInstPlatform(t *testing.T) *instPlatform {
	t.Helper()
	p := &instPlatform{t: t, now: time.Now().Truncate(time.Second), kind: kindKubernetes, approvedVer: 3, approvedDig: testCfgDigest,
		attestTTL: 900, tokenTTL: 600, nonces: map[string]bool{}, k8sSpent: map[string]bool{}, popJTI: map[string]bool{},
		proofJTI: map[string]bool{}, issuedTokens: map[string]string{}}
	_, p.signKey, _ = ed25519.GenerateKey(rand.Reader)
	p.srv = httptest.NewServer(http.HandlerFunc(p.serve))
	t.Cleanup(p.srv.Close)
	return p
}

// script changes the fake's scripted behaviour while the server may be handling a request.
func (p *instPlatform) script(f func()) {
	p.mu.Lock()
	defer p.mu.Unlock()
	f()
}

func (p *instPlatform) issuer() string { return p.srv.URL }

func (p *instPlatform) clock() time.Time {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.now
}

func (p *instPlatform) advance(d time.Duration) {
	p.mu.Lock()
	p.now = p.now.Add(d)
	p.mu.Unlock()
}

func (p *instPlatform) count(what string) int {
	p.mu.Lock()
	defer p.mu.Unlock()
	n := 0
	for _, l := range p.log {
		if l == what {
			n++
		}
	}
	return n
}

func (p *instPlatform) requests() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.log)
}

// k8sToken is a projected service-account token for audience, valid for ttl, made unique by n.
func (p *instPlatform) k8sToken(aud string, ttl time.Duration, n string) string {
	h, _ := json.Marshal(map[string]string{"alg": "RS256", "typ": "JWT"})
	c, _ := json.Marshal(map[string]any{"aud": []string{aud}, "iss": "https://kubernetes.default.svc", "sub": "system:serviceaccount:ns:sa",
		"jti": n, "iat": p.clock().Unix(), "exp": p.clock().Add(ttl).Unix()})
	return b64(h) + "." + b64(c) + "." + b64([]byte("sig"))
}

func (p *instPlatform) instance(opts ...Option) *Agent { return p.instanceWith(nil, opts...) }

func (p *instPlatform) instanceWith(ev Evidence, opts ...Option) *Agent {
	p.t.Helper()
	if ev == nil {
		ev = KubernetesEvidence(p.t.TempDir() + "/missing")
	}
	a, err := NewInstance(p.issuer(), testInstAgent, ev, Configuration{Version: p.approvedVer, Digest: p.approvedDig}, opts...)
	if err != nil {
		p.t.Fatal(err)
	}
	a.now = p.clock
	a.sleep = func(_ context.Context, d time.Duration) error { p.advance(d); return nil }
	return a
}

func (p *instPlatform) refuse(w http.ResponseWriter, status int, why string, args ...any) {
	p.refusals = append(p.refusals, fmt.Sprintf(why, args...))
	body := `{"error":"unauthorized","error_description":"unauthorized"}`
	if status == 503 {
		body = `{"error":"temporarily_unavailable","error_description":"temporarily_unavailable"}`
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = io.WriteString(w, body)
}

func (p *instPlatform) serve(w http.ResponseWriter, r *http.Request) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.log = append(p.log, r.Method+" "+r.URL.Path)
	switch r.URL.Path {
	case "/.well-known/oauth-authorization-server":
		writeJSONTest(w, 200, map[string]any{"issuer": p.issuer(), "token_endpoint": p.issuer() + "/oauth/token"})
	case "/.well-known/agent-configuration":
		http.NotFound(w, r)
	case challengePath:
		if p.extraChallenge != nil && p.extraChallenge(w) {
			return
		}
		p.seq++
		n := fmt.Sprintf("nonce-%d-%s", p.seq, randomHex(6))
		p.nonces[n] = false
		writeJSONTest(w, 200, map[string]string{"nonce": n})
	case attestPath:
		p.attest(w, r)
	case "/oauth/token":
		p.token(w, r)
	default:
		http.NotFound(w, r)
	}
}

func randomHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// attest is Service.Attest in agent-identity, reduced to the checks an SDK can get wrong.
func (p *instPlatform) attest(w http.ResponseWriter, r *http.Request) {
	if p.extraAttest != nil && p.extraAttest(w) {
		return
	}
	var req struct {
		AgentID  string `json:"agent_id"`
		Evidence struct {
			Kind  string `json:"kind"`
			Token string `json:"token"`
		} `json:"evidence"`
		InstanceKey map[string]any `json:"instance_key"`
		Config      struct {
			Version int    `json:"version"`
			Digest  string `json:"digest"`
		} `json:"config"`
		ImageDigest string `json:"image_digest"`
		Proof       string `json:"proof"`
	}
	raw, _ := io.ReadAll(r.Body)
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		p.refuse(w, 400, "body: %v", err)
		return
	}
	var generic map[string]any
	_ = json.Unmarshal(raw, &generic)
	p.attests = append(p.attests, generic)
	if p.attestStatus != 0 {
		p.refuse(w, p.attestStatus, "scripted")
		return
	}
	jwk := map[string]string{}
	for k, v := range req.InstanceKey {
		s, ok := v.(string)
		if !ok {
			p.refuse(w, 401, "instance key has a non-string member %s", k)
			return
		}
		jwk[k] = s
	}
	if _, private := jwk["d"]; private {
		p.refuse(w, 401, "private member")
		return
	}
	jkt := thumbprint(jwk)
	header, claims, err := jwtParts(req.Proof)
	if err != nil {
		p.refuse(w, 401, "proof: %v", err)
		return
	}
	if !verifyJWT(req.Proof, jwk, header["alg"].(string)) {
		p.refuse(w, 401, "the proof is not signed by the instance key")
		return
	}
	nonce, _ := claims["nonce"].(string)
	switch {
	case claims["agent_id"] != req.AgentID || req.AgentID != testInstAgent:
		p.refuse(w, 401, "the proof names another agent")
		return
	case !audienceHas(claims["aud"], p.issuer()):
		p.refuse(w, 401, "the proof is not for this project: %v", claims["aud"])
		return
	}
	jti, _ := claims["jti"].(string)
	if jti == "" {
		p.refuse(w, 401, "no jti")
		return
	}
	if req.Evidence.Kind != p.kind {
		p.refuse(w, 401, "evidence kind %s, binding %s", req.Evidence.Kind, p.kind)
		return
	}
	if p.kind == kindKubernetes {
		if !p.checkK8s(req.Evidence.Token) {
			p.refuse(w, 401, "k8s evidence")
			return
		}
	} else if !p.checkDevice(req.Evidence.Token, nonce, req.AgentID, jkt) {
		p.refuse(w, 401, "device signature")
		return
	}
	cfgOK := req.Config.Version == p.approvedVer && req.Config.Digest == p.approvedDig
	observe := req.Config.Version == 0 && req.Config.Digest == ""
	if !(cfgOK || (observe && p.observeOpen)) {
		p.refuse(w, 401, "configuration %d %s is not approved", req.Config.Version, req.Config.Digest)
		return
	}
	spent, issued := p.nonces[nonce]
	if !issued {
		p.refuse(w, 401, "nonce not issued")
		return
	}
	if spent {
		p.refuse(w, 401, "nonce reused")
		return
	}
	p.nonces[nonce] = true
	p.seq++
	id := fmt.Sprintf("inst_%032x", p.seq)
	iat := p.now.Unix()
	cl := map[string]any{
		"iss": "spiffe://test/" + testInstAgent, "sub": testInstAgent, "iat": iat, "exp": iat + int64(p.attestTTL), "jti": fmt.Sprintf("att-%d", p.seq),
		"cnf":             map[string]any{"jwk": jwk},
		"authfi_instance": map[string]any{"instance_id": id, "config": map[string]any{"version": req.Config.Version, "digest": req.Config.Digest}, "custody": "software", "environment": "np"},
	}
	if p.mutate != nil {
		p.mutate(cl)
	}
	h := map[string]any{"typ": typAttestation, "alg": "EdDSA", "kid": "agent-kms-key"}
	if p.mutateHeader != nil {
		p.mutateHeader(h)
	}
	hb, _ := json.Marshal(h)
	cb, _ := json.Marshal(cl)
	signed := b64(hb) + "." + b64(cb)
	att := signed + "." + b64(ed25519.Sign(p.signKey, []byte(signed)))
	writeJSONTest(w, 200, map[string]any{"attestation": att, "expires_in": p.attestTTL})
}

func (p *instPlatform) checkK8s(tok string) bool {
	claims, err := jwtClaims(tok)
	if err != nil || !audienceHas(claims["aud"], p.issuer()) || p.k8sSpent[tok] {
		return false
	}
	if exp, _ := claims["exp"].(float64); int64(exp) <= p.now.Unix() {
		return false
	}
	p.k8sSpent[tok] = true
	return true
}

func (p *instPlatform) checkDevice(tok, nonce, agent, jkt string) bool {
	sig, err := base64.RawURLEncoding.DecodeString(tok)
	if err != nil {
		return false
	}
	return verifyRaw(p.deviceJWK, p.deviceAlg, bindingMessage(nonce, agent, jkt), sig)
}

func (p *instPlatform) token(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	p.tokenReqs = append(p.tokenReqs, tokenReq{form: r.PostForm, header: r.Header.Clone()})
	if p.extraToken != nil && p.extraToken(w, r) {
		return
	}
	if len(p.tokenStatuses) > 0 {
		st := p.tokenStatuses[0]
		p.tokenStatuses = p.tokenStatuses[1:]
		w.WriteHeader(st)
		return
	}
	fail := func(status int, code, why string) {
		p.refusals = append(p.refusals, why)
		writeJSONTest(w, status, map[string]string{"error": code})
	}
	if r.PostForm.Get("grant_type") != "client_credentials" || r.PostForm.Get("client_id") != testInstAgent {
		fail(400, "invalid_request", "grant or client")
		return
	}
	if r.PostForm.Get("client_assertion") != "" || r.PostForm.Get("client_assertion_type") != "" {
		fail(401, "invalid_client", "a bound agent sends no client assertion")
		return
	}
	att := r.Header.Get(headerAttestation)
	hdr, claims, err := jwtParts(att)
	if err != nil || hdr["typ"] != typAttestation {
		fail(401, "invalid_client", "attestation")
		return
	}
	pub := p.signKey.Public().(ed25519.PublicKey)
	parts := strings.Split(att, ".")
	sig, _ := base64.RawURLEncoding.DecodeString(parts[2])
	if !ed25519.Verify(pub, []byte(parts[0]+"."+parts[1]), sig) {
		fail(401, "invalid_client", "attestation signature")
		return
	}
	if exp, _ := claims["exp"].(float64); int64(exp) <= p.now.Unix() {
		fail(401, "invalid_client", "attestation expired")
		return
	}
	cnf := cnfJWK(claims["cnf"])
	// the proof of possession
	pop := r.Header.Get(headerPoP)
	ph, pc, err := jwtParts(pop)
	if err != nil || ph["typ"] != typPoP || !verifyJWT(pop, cnf, ph["alg"].(string)) {
		fail(401, "invalid_client", "pop")
		return
	}
	jti, _ := pc["jti"].(string)
	iat, _ := pc["iat"].(float64)
	if pc["iss"] != testInstAgent || !audienceHas(pc["aud"], p.issuer()) || jti == "" || p.popJTI[jti] ||
		absDur(time.Unix(int64(iat), 0).Sub(p.now)) > 2*time.Minute {
		fail(401, "invalid_client", "pop claims or reuse")
		return
	}
	p.popJTI[jti] = true
	// the DPoP proof must be by the attested key
	dp := r.Header.Get(headerDPoP)
	dh, dc, err := jwtParts(dp)
	if err != nil || dh["typ"] != "dpop+jwt" {
		fail(400, "invalid_dpop_proof", "dpop")
		return
	}
	djwk := map[string]string{}
	if m, ok := dh["jwk"].(map[string]any); ok {
		for k, v := range m {
			djwk[k], _ = v.(string)
		}
	}
	if !verifyJWT(dp, djwk, dh["alg"].(string)) || thumbprint(djwk) != thumbprint(cnf) {
		fail(400, "invalid_dpop_proof", "the DPoP key is not the attested key")
		return
	}
	dj, _ := dc["jti"].(string)
	if dc["htm"] != "POST" || dc["htu"] != p.issuer()+"/oauth/token" || dj == "" || p.proofJTI[dj] {
		fail(400, "invalid_dpop_proof", "dpop claims or reuse")
		return
	}
	if p.requireNonce && dc["nonce"] != "server-nonce-1" {
		w.Header().Set("DPoP-Nonce", "server-nonce-1")
		fail(400, "use_dpop_nonce", "nonce wanted")
		return
	}
	p.proofJTI[dj] = true
	tok := "at_" + randomHex(16)
	p.issuedTokens[tok] = thumbprint(cnf)
	writeJSONTest(w, 200, map[string]any{"access_token": tok, "token_type": "DPoP", "expires_in": p.tokenTTL})
}

func absDur(d time.Duration) time.Duration {
	if d < 0 {
		return -d
	}
	return d
}

func cnfJWK(cnf any) map[string]string {
	out := map[string]string{}
	if m, ok := cnf.(map[string]any); ok {
		if j, ok := m["jwk"].(map[string]any); ok {
			for k, v := range j {
				out[k], _ = v.(string)
			}
		}
	}
	return out
}

// verifyJWT checks a compact JWT's signature with the public JWK, for the algorithm named.
func verifyJWT(compact string, jwk map[string]string, alg string) bool {
	parts := strings.Split(compact, ".")
	if len(parts) != 3 {
		return false
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return false
	}
	return verifyRaw(jwk, Algorithm(alg), []byte(parts[0]+"."+parts[1]), sig)
}

func verifyRaw(jwk map[string]string, alg Algorithm, data, sig []byte) bool {
	dec := func(s string) []byte { b, _ := base64.RawURLEncoding.DecodeString(s); return b }
	switch alg {
	case EdDSA:
		x := dec(jwk["x"])
		return jwk["kty"] == "OKP" && len(x) == ed25519.PublicKeySize && ed25519.Verify(x, data, sig)
	case ES256:
		if jwk["kty"] != "EC" || len(sig) != 64 {
			return false
		}
		pub := ecdsa.PublicKey{Curve: elliptic.P256(), X: new(big.Int).SetBytes(dec(jwk["x"])), Y: new(big.Int).SetBytes(dec(jwk["y"]))}
		h := sha256.Sum256(data)
		return ecdsa.Verify(&pub, h[:], new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:]))
	case PS256:
		pub := rsa.PublicKey{N: new(big.Int).SetBytes(dec(jwk["n"])), E: int(new(big.Int).SetBytes(dec(jwk["e"])).Int64())}
		h := sha256.Sum256(data)
		return rsa.VerifyPSS(&pub, crypto.SHA256, h[:], sig, &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash}) == nil
	}
	return false
}
