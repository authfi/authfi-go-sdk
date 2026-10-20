package agent

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"
)

const testAgentID = "agt_test_1"

// platform is a fake AuthFI project. It checks what the real agent-identity service checks of an
// agent's request: the assertion's signature against the registered key, iss and sub, the
// audience, the lifetime cap and that a jti is used once.
type platform struct {
	t   *testing.T
	srv *httptest.Server

	mu       sync.Mutex
	now      time.Time
	agentJWK map[string]string
	agentKID string
	seenJTI  map[string]bool
	tokenKey ed25519.PrivateKey

	// scripts and recordings
	forms        []url.Values // every token-endpoint form, in order
	backchannel  []url.Values
	mintStatus   []int    // statuses to answer the next mints with, before succeeding
	cibaAnswers  []string // pending, slow_down, 429, denied, expired, ok
	cibaDefault  string   // the answer once cibaAnswers runs out; default ok
	expiresIn    int
	approvalBody string
	approvalCode int
	noAgentCfg   bool
	issuerClaim  string // overrides the issuer in the metadata
	tokenHost    string // overrides the token endpoint
	echoAssert   bool   // refusals echo the assertion in error_description
	approvalAuth []string
	slept        []time.Duration
	noInterval   bool   // the CIBA start omits the polling interval
	asHits       int    // fetches of the authorization server metadata
	redirectTo   string // the token endpoint answers 307 to this URL
	cibaRedirect bool   // the CIBA start answers 307 to itself
	configStatus int    // the agent configuration answers this status
	approvalNoID bool   // the approval endpoint template has no {id}
	cibaExpires  int    // expires_in of the CIBA start; default 300
	cibaInterval any    // interval of the CIBA start; default 5
	hugeValid    bool   // the token endpoint answers valid JSON larger than the SDK reads
	hugeReply    bool   // the token endpoint answers more than the SDK reads
	approvalHit  string // body served with a 500 on the approval endpoint
}

func newPlatform(t *testing.T, key *Key) *platform {
	t.Helper()
	p := &platform{t: t, now: time.Now().Truncate(time.Second), agentJWK: key.PublicJWK(), agentKID: key.KID(),
		seenJTI: map[string]bool{}, expiresIn: 600, approvalCode: 200}
	_, p.tokenKey, _ = ed25519.GenerateKey(rand.Reader)
	p.srv = httptest.NewServer(http.HandlerFunc(p.serve))
	t.Cleanup(p.srv.Close)
	return p
}

func (p *platform) issuer() string { return p.srv.URL }

func (p *platform) clock() time.Time {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.now
}

func (p *platform) advance(d time.Duration) {
	p.mu.Lock()
	p.now = p.now.Add(d)
	p.mu.Unlock()
}

func (p *platform) agent(key *Key, opts ...Option) *Agent {
	p.t.Helper()
	a, err := New(p.issuer(), testAgentID, key, opts...)
	if err != nil {
		p.t.Fatal(err)
	}
	a.now = p.clock
	a.sleep = func(ctx context.Context, d time.Duration) error {
		p.mu.Lock()
		p.slept = append(p.slept, d)
		p.now = p.now.Add(d)
		p.mu.Unlock()
		return ctx.Err()
	}
	return a
}

func (p *platform) serve(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case "/.well-known/oauth-authorization-server":
		p.mu.Lock()
		p.asHits++
		p.mu.Unlock()
		iss := p.issuer()
		if p.issuerClaim != "" {
			iss = p.issuerClaim
		}
		tok := p.issuer() + "/oauth/token"
		if p.tokenHost != "" {
			tok = p.tokenHost
		}
		writeJSONTest(w, 200, map[string]any{"issuer": iss, "token_endpoint": tok})
	case "/.well-known/agent-configuration":
		if p.noAgentCfg {
			http.NotFound(w, r)
			return
		}
		if p.configStatus != 0 {
			w.WriteHeader(p.configStatus)
			return
		}
		approval := p.issuer() + "/approvals/{id}"
		if p.approvalNoID {
			approval = p.issuer() + "/approvals/fixed"
		}
		writeJSONTest(w, 200, map[string]any{
			"backchannel_authentication_endpoint": p.issuer() + "/ciba",
			"endpoints":                           map[string]string{"approval": approval},
		})
	case "/oauth/token":
		p.token(w, r)
	case "/ciba":
		p.ciba(w, r)
	default:
		if strings.HasPrefix(r.URL.Path, "/approvals/") {
			p.approval(w, r)
			return
		}
		http.NotFound(w, r)
	}
}

func writeJSONTest(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func (p *platform) refuse(w http.ResponseWriter, status int, code, desc string) {
	writeJSONTest(w, status, map[string]string{"error": code, "error_description": desc})
}

// checkAssertion returns "" for a good assertion, else why not. Audience may be the token
// endpoint or the issuer, as the real service accepts.
func (p *platform) checkAssertion(form url.Values) string {
	if form.Get("client_assertion_type") != assertionType {
		return "bad client_assertion_type"
	}
	if form.Get("client_id") != testAgentID {
		return "bad client_id"
	}
	parts := strings.Split(form.Get("client_assertion"), ".")
	if len(parts) != 3 {
		return "not a JWS"
	}
	var hdr struct{ Alg, Kid string }
	hb, _ := base64.RawURLEncoding.DecodeString(parts[0])
	_ = json.Unmarshal(hb, &hdr)
	if hdr.Kid != p.agentKID {
		return "bad kid"
	}
	sig, _ := base64.RawURLEncoding.DecodeString(parts[2])
	signed := []byte(parts[0] + "." + parts[1])
	if !p.verifySig(hdr.Alg, signed, sig) {
		return "bad signature"
	}
	var c struct {
		Iss, Sub, Aud, Jti string
		Iat, Exp           int64
	}
	cb, _ := base64.RawURLEncoding.DecodeString(parts[1])
	_ = json.Unmarshal(cb, &c)
	if c.Iss != testAgentID || c.Sub != testAgentID {
		return "bad iss/sub"
	}
	if c.Aud != p.issuer()+"/oauth/token" && c.Aud != p.issuer() {
		return "bad aud " + c.Aud
	}
	if c.Exp-c.Iat > 300 || c.Exp <= c.Iat {
		return "bad lifetime"
	}
	now := p.clock().Unix()
	if now > c.Exp+60 || c.Iat > now+60 {
		return "assertion not current"
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if c.Jti == "" || p.seenJTI[c.Jti] {
		return "jti reused"
	}
	p.seenJTI[c.Jti] = true
	return ""
}

func (p *platform) verifySig(alg string, signed, sig []byte) bool {
	jwk := p.agentJWK
	d := func(s string) []byte { b, _ := base64.RawURLEncoding.DecodeString(s); return b }
	h := sha256.Sum256(signed)
	switch alg {
	case "EdDSA":
		return jwk["kty"] == "OKP" && ed25519.Verify(ed25519.PublicKey(d(jwk["x"])), signed, sig)
	case "ES256":
		if jwk["kty"] != "EC" || len(sig) != 64 {
			return false
		}
		pub := &ecdsa.PublicKey{Curve: elliptic.P256(), X: new(big.Int).SetBytes(d(jwk["x"])), Y: new(big.Int).SetBytes(d(jwk["y"]))}
		return ecdsa.Verify(pub, h[:], new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:]))
	case "PS256":
		if jwk["kty"] != "RSA" {
			return false
		}
		pub := &rsa.PublicKey{N: new(big.Int).SetBytes(d(jwk["n"])), E: int(new(big.Int).SetBytes(d(jwk["e"])).Int64())}
		return rsa.VerifyPSS(pub, crypto.SHA256, h[:], sig, &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash}) == nil
	}
	return false
}

func (p *platform) mintJWT(claims map[string]any) string {
	now := p.clock().Unix()
	c := map[string]any{"iss": p.issuer(), "iat": now, "exp": now + int64(p.expiresIn), "tenant_id": "t1"}
	for k, v := range claims {
		c[k] = v
	}
	hj, _ := json.Marshal(map[string]string{"alg": "EdDSA", "typ": "at+jwt", "kid": "plat"})
	cj, _ := json.Marshal(c)
	signed := b64(hj) + "." + b64(cj)
	return signed + "." + b64(ed25519.Sign(p.tokenKey, []byte(signed)))
}

func (p *platform) tokenReply(w http.ResponseWriter, claims map[string]any) {
	writeJSONTest(w, 200, map[string]any{"access_token": p.mintJWT(claims), "token_type": "Bearer", "expires_in": p.expiresIn, "scope": "tools.read"})
}

func (p *platform) token(w http.ResponseWriter, r *http.Request) {
	if p.redirectTo != "" {
		http.Redirect(w, r, p.redirectTo, http.StatusTemporaryRedirect)
		return
	}
	if p.hugeValid {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"x","token_type":"Bearer","expires_in":60,"scope":"` + strings.Repeat("a", 2<<20) + `"}`))
		return
	}
	if p.hugeReply {
		w.WriteHeader(200)
		_, _ = w.Write(make([]byte, 2<<20))
		return
	}
	_ = r.ParseForm()
	form := r.PostForm
	p.mu.Lock()
	p.forms = append(p.forms, form)
	if len(p.mintStatus) > 0 && form.Get("grant_type") == grantClientCreds {
		st := p.mintStatus[0]
		p.mintStatus = p.mintStatus[1:]
		p.mu.Unlock()
		p.refuse(w, st, "temporarily_unavailable", "try again")
		return
	}
	p.mu.Unlock()

	if form.Get("grant_type") == grantTokenExchange {
		p.exchange(w, form)
		return
	}
	if msg := p.checkAssertion(form); msg != "" {
		desc := msg
		if p.echoAssert {
			desc = "rejected " + form.Get("client_assertion") + " and handle " + form.Get("auth_req_id")
		}
		p.refuse(w, 401, "invalid_client", desc)
		return
	}
	switch form.Get("grant_type") {
	case grantClientCreds:
		claims := map[string]any{"sub": testAgentID, "client_id": testAgentID, "aud": p.issuer() + "/mcp"}
		if res := form.Get("resource"); res != "" {
			claims["aud"] = res
		}
		p.tokenReply(w, claims)
	case grantCIBA:
		p.mu.Lock()
		answer := "ok"
		if p.cibaDefault != "" {
			answer = p.cibaDefault
		}
		if len(p.cibaAnswers) > 0 {
			answer, p.cibaAnswers = p.cibaAnswers[0], p.cibaAnswers[1:]
		}
		p.mu.Unlock()
		switch answer {
		case "pending":
			p.refuse(w, 400, "authorization_pending", "")
		case "slow_down":
			p.refuse(w, 400, "slow_down", "")
		case "429":
			p.refuse(w, 429, "too_many_requests", "")
		case "echo-handle":
			p.refuse(w, 400, form.Get("auth_req_id"), "")
		case "denied":
			p.refuse(w, 400, "access_denied", "")
		case "expired":
			p.refuse(w, 400, "expired_token", "")
		default:
			claims := map[string]any{"sub": "user:jane@example.com", "act": map[string]any{"sub": "agent:" + testAgentID},
				"aud": p.issuer() + "/mcp", "scope": form.Get("scope")}
			if res := form.Get("resource"); res != "" {
				claims["aud"] = res
			}
			p.tokenReply(w, claims)
		}
	default:
		p.refuse(w, 400, "unsupported_grant_type", "")
	}
}

func (p *platform) exchange(w http.ResponseWriter, form url.Values) {
	if form.Get("client_assertion") != "" || form.Get("client_id") != "" || form.Get("client_secret") != "" {
		p.refuse(w, 401, "invalid_client", "an exchange carries no client authentication")
		return
	}
	if form.Get("subject_token") == "" || form.Get("actor_token") == "" || form.Get("subject_token") == "expired-subject" || strings.HasPrefix(form.Get("subject_token"), "bad/") {
		p.refuse(w, 400, "invalid_grant", "subject token "+form.Get("subject_token")+" as form subject_token="+url.QueryEscape(form.Get("subject_token")))
		return
	}
	p.tokenReply(w, map[string]any{"sub": "user:jane@example.com", "act": map[string]any{"sub": "agent:" + testAgentID}, "aud": p.issuer() + "/mcp"})
}

func (p *platform) ciba(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	form := r.PostForm
	p.mu.Lock()
	p.backchannel = append(p.backchannel, form)
	p.mu.Unlock()
	if p.cibaRedirect {
		http.Redirect(w, r, p.issuer()+"/ciba", http.StatusTemporaryRedirect)
		return
	}
	if msg := p.checkAssertion(form); msg != "" {
		p.refuse(w, 401, "invalid_client", msg)
		return
	}
	exp := 300
	if p.cibaExpires != 0 {
		exp = p.cibaExpires
	}
	var interval any = 5
	if p.cibaInterval != nil {
		interval = p.cibaInterval
	}
	body := map[string]any{"auth_req_id": "REQ-HANDLE-0001", "expires_in": exp, "interval": interval, "approval_url": p.issuer() + "/approve/x"}
	if p.noInterval {
		delete(body, "interval")
	}
	writeJSONTest(w, 200, body)
}

func (p *platform) approval(w http.ResponseWriter, r *http.Request) {
	p.mu.Lock()
	p.approvalAuth = append(p.approvalAuth, r.Header.Get("Authorization"))
	body, code := p.approvalBody, p.approvalCode
	p.mu.Unlock()
	if body == "" {
		body = fmt.Sprintf(`{"data":{"approval_id":%q,"status":"approved","requesting_action":"refund","expires_at":"2030-01-01T00:00:00Z"}}`, strings.TrimPrefix(r.URL.Path, "/approvals/"))
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_, _ = w.Write([]byte(body))
}

func (p *platform) tokenForms(grant string) []url.Values {
	p.mu.Lock()
	defer p.mu.Unlock()
	var out []url.Values
	for _, f := range p.forms {
		if f.Get("grant_type") == grant {
			out = append(out, f)
		}
	}
	return out
}

// mustKey generates a key of each algorithm; RSA keys are reused across tests (slow to make).
var (
	rsaKeyOnce sync.Once
	rsaKey     *Key
)

func keyFor(t *testing.T, alg Algorithm) *Key {
	t.Helper()
	if alg == PS256 {
		rsaKeyOnce.Do(func() {
			k, err := GenerateKey(PS256, "")
			if err != nil {
				panic(err)
			}
			rsaKey = k
		})
		return rsaKey
	}
	k, err := GenerateKey(alg, "")
	if err != nil {
		t.Fatal(err)
	}
	return k
}
