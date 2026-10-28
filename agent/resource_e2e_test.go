package agent

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	authfi "github.com/authfi/authfi-go-sdk"
)

const e2eAudience = "api-orders"

// e2eIssuer is a project issuer for the end-to-end test: it serves discovery and a key set whose
// key has a certificate chain, and mints agent tokens bound to the key of the DPoP proof it is sent.
type e2eIssuer struct {
	srv        *httptest.Server
	signKey    ed25519.PrivateKey
	x5c        []string
	x5t        string
	rootPin    string
	wantNonce  bool // the token endpoint asks for a nonce first
	bound      atomic.Int32
	nonceAsked atomic.Int32
}

func e2eCert(t *testing.T, tmpl *x509.Certificate, pub crypto.PublicKey, parent *x509.Certificate, signer crypto.Signer) *x509.Certificate {
	t.Helper()
	tmpl.SerialNumber = big.NewInt(time.Now().UnixNano())
	tmpl.NotBefore, tmpl.NotAfter = time.Now().Add(-time.Hour), time.Now().Add(24*time.Hour)
	tmpl.BasicConstraintsValid = true
	if parent == nil {
		parent = tmpl
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, pub, signer)
	if err != nil {
		t.Fatal(err)
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func newE2EIssuer(t *testing.T) *e2eIssuer {
	t.Helper()
	is := &e2eIssuer{}
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	is.signKey = priv
	rk, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	ik, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	policy := []asn1.ObjectIdentifier{{1, 3, 6, 1, 4, 1, 67322, 1, 1}}
	root := e2eCert(t, &x509.Certificate{Subject: pkix.Name{CommonName: "E2E Root"}, IsCA: true, KeyUsage: x509.KeyUsageCertSign, MaxPathLen: 2}, &rk.PublicKey, nil, rk)
	inter := e2eCert(t, &x509.Certificate{Subject: pkix.Name{CommonName: "E2E Intermediate"}, IsCA: true, KeyUsage: x509.KeyUsageCertSign,
		MaxPathLen: 0, MaxPathLenZero: true, PolicyIdentifiers: policy}, &ik.PublicKey, root, rk)
	leaf := e2eCert(t, &x509.Certificate{Subject: pkix.Name{CommonName: "E2E Token Key"}, KeyUsage: x509.KeyUsageDigitalSignature,
		PolicyIdentifiers: policy}, pub, inter, ik)
	for _, c := range []*x509.Certificate{leaf, inter, root} {
		is.x5c = append(is.x5c, base64.StdEncoding.EncodeToString(c.Raw))
	}
	sum := sha256.Sum256(leaf.Raw)
	is.x5t = b64(sum[:])
	pin := sha256.Sum256(root.RawSubjectPublicKeyInfo)
	is.rootPin = hex.EncodeToString(pin[:])
	is.srv = httptest.NewServer(http.HandlerFunc(is.serve))
	t.Cleanup(is.srv.Close)
	return is
}

func (is *e2eIssuer) serve(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case "/.well-known/oauth-authorization-server":
		_ = json.NewEncoder(w).Encode(map[string]any{"issuer": is.srv.URL, "token_endpoint": is.srv.URL + "/oauth/token"})
	case "/.well-known/jwks.json":
		pub := is.signKey.Public().(ed25519.PublicKey)
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": []map[string]any{{
			"kty": "OKP", "crv": "Ed25519", "kid": "k1", "use": "sig", "alg": "EdDSA", "x": b64(pub),
			"x5c": is.x5c, "x5t#S256": is.x5t,
		}}})
	case "/oauth/token":
		is.token(w, r)
	default:
		http.NotFound(w, r)
	}
}

// token mints a token bound to the key of the proof, or a Bearer one when there is no proof.
func (is *e2eIssuer) token(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	claims := map[string]any{
		"iss": is.srv.URL, "sub": "agt_e2e", "client_id": "agt_e2e", "aud": e2eAudience, "tenant_id": "t1",
		"exp": time.Now().Add(15 * time.Minute).Unix(), "iat": time.Now().Unix(), "scope": "orders.read",
		"permissions": []string{"read:orders"},
	}
	tokenType := "Bearer"
	if proof := r.Header.Get("DPoP"); proof != "" {
		parts := strings.Split(proof, ".")
		var hdr struct {
			JWK map[string]string `json:"jwk"`
		}
		var body struct {
			Nonce string `json:"nonce"`
			HTU   string `json:"htu"`
			HTM   string `json:"htm"`
		}
		hb, _ := base64.RawURLEncoding.DecodeString(parts[0])
		bb, _ := base64.RawURLEncoding.DecodeString(parts[1])
		if json.Unmarshal(hb, &hdr) != nil || json.Unmarshal(bb, &body) != nil || body.HTM != "POST" || !strings.HasSuffix(body.HTU, "/oauth/token") {
			http.Error(w, `{"error":"invalid_dpop_proof"}`, http.StatusBadRequest)
			return
		}
		if is.wantNonce && body.Nonce != "issuer-nonce" {
			is.nonceAsked.Add(1)
			w.Header().Set("DPoP-Nonce", "issuer-nonce")
			http.Error(w, `{"error":"use_dpop_nonce"}`, http.StatusBadRequest)
			return
		}
		claims["cnf"] = map[string]string{"jkt": thumbprint(hdr.JWK)}
		tokenType = "DPoP"
		is.bound.Add(1)
	}
	h, _ := json.Marshal(map[string]any{"alg": "EdDSA", "typ": "at+jwt", "kid": "k1", "x5t#S256": is.x5t})
	c, _ := json.Marshal(claims)
	signed := b64(h) + "." + b64(c)
	tok := signed + "." + b64(ed25519.Sign(is.signKey, []byte(signed)))
	_ = json.NewEncoder(w).Encode(map[string]any{"access_token": tok, "token_type": tokenType, "expires_in": 900, "scope": "orders.read"})
}

// resourceServer is an API protected by the SDK's middleware.
func resourceServer(t *testing.T, is *e2eIssuer, mod func(*authfi.Config)) *httptest.Server {
	t.Helper()
	cfg := authfi.Config{Issuer: is.srv.URL, Audience: []string{e2eAudience}, RootPins: []string{is.rootPin}}
	if mod != nil {
		mod(&cfg)
	}
	auth := authfi.New(cfg)
	mux := http.NewServeMux()
	mux.Handle("/orders", auth.Require("read:orders")(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		_, _ = w.Write([]byte(authfi.GetUser(r.Context()).Subject + ":" + string(b)))
	})))
	srv := httptest.NewTLSServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func e2eAgent(t *testing.T, is *e2eIssuer, opts ...Option) *Agent {
	t.Helper()
	key, err := GenerateKey(EdDSA, "")
	if err != nil {
		t.Fatal(err)
	}
	a, err := New(is.srv.URL, "agt_e2e", key, append([]Option{WithResource(e2eAudience)}, opts...)...)
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func get(t *testing.T, rt http.RoundTripper, url, method, body string) (int, string) {
	t.Helper()
	req, err := http.NewRequest(method, url, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	resp, err := (&http.Client{Transport: rt}).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

// An agent made with this package calls a resource protected by the SDK: the token is bound to the
// agent's DPoP key at the token endpoint, each request carries a proof, and the resource checks the
// proof and the custody chain of the key that signed the token.
func TestAgentCallsAResourceProtectedByTheSDK(t *testing.T) {
	is := newE2EIssuer(t)
	srv := resourceServer(t, is, nil)
	dkey, _ := GenerateKey(ES256, "")
	a := e2eAgent(t, is, WithDPoP(dkey))
	rt, err := a.DPoPTransport(srv.Client().Transport, srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ { // each call carries its own proof
		if code, body := get(t, rt, srv.URL+"/orders", "GET", ""); code != 200 || body != "agt_e2e:" {
			t.Fatalf("call %d: %d %s", i, code, body)
		}
	}
	if is.bound.Load() != 1 {
		t.Fatalf("the token is minted once with a proof, got %d", is.bound.Load())
	}
	if code, body := get(t, rt, srv.URL+"/orders?x=1", "POST", "hello"); code != 200 || body != "agt_e2e:hello" {
		t.Fatalf("POST with a query: %d %s", code, body)
	}
}

func TestAgentWithoutDPoPIsRefusedByTheResource(t *testing.T) {
	is := newE2EIssuer(t)
	srv := resourceServer(t, is, nil)
	a := e2eAgent(t, is) // control: the same agent, same resource, no key binding
	rt, err := Transport(a.TokenSource(), srv.Client().Transport, srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	code, body := get(t, rt, srv.URL+"/orders", "GET", "")
	if code != 401 || !strings.Contains(body, "token_dpop_proof_required") {
		t.Fatalf("a bearer agent token: %d %s", code, body)
	}
	// the same resource with the checks off accepts it, which shows the refusal is the new check
	off := resourceServer(t, is, func(c *authfi.Config) { c.AgentTokens = authfi.AgentOff })
	rt2, _ := Transport(a.TokenSource(), off.Client().Transport, off.URL)
	if code, _ := get(t, rt2, off.URL+"/orders", "GET", ""); code != 200 {
		t.Fatalf("off: %d", code)
	}
}

func TestAnotherKeyCannotUseTheToken(t *testing.T) {
	is := newE2EIssuer(t)
	srv := resourceServer(t, is, nil)
	bound, _ := GenerateKey(EdDSA, "")
	thief, _ := GenerateKey(EdDSA, "")
	a := e2eAgent(t, is, WithDPoP(bound))
	rt, err := DPoPTransport(a.TokenSource(), thief, srv.Client().Transport, srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	code, body := get(t, rt, srv.URL+"/orders", "GET", "")
	if code != 401 || !strings.Contains(body, "dpop_key_mismatch") {
		t.Fatalf("a token used with another key: %d %s", code, body)
	}
}

func TestServerNonceIsEchoedOnce(t *testing.T) {
	is := newE2EIssuer(t)
	is.wantNonce = true
	srv := resourceServer(t, is, func(c *authfi.Config) { c.NonceKey = []byte(strings.Repeat("k", 32)) })
	dkey, _ := GenerateKey(EdDSA, "")
	a := e2eAgent(t, is, WithDPoP(dkey))
	rt, _ := a.DPoPTransport(srv.Client().Transport, srv.URL)
	if code, body := get(t, rt, srv.URL+"/orders", "GET", ""); code != 200 || body != "agt_e2e:" {
		t.Fatalf("GET with a nonce: %d %s", code, body)
	}
	if is.nonceAsked.Load() != 1 {
		t.Fatalf("the token endpoint was asked for a nonce once, got %d", is.nonceAsked.Load())
	}
	if code, body := get(t, rt, srv.URL+"/orders", "POST", "payload"); code != 200 || body != "agt_e2e:payload" {
		t.Fatalf("POST keeps its body across the nonce: %d %s", code, body)
	}
}

func TestDPoPTransportNeedsAKey(t *testing.T) {
	is := newE2EIssuer(t)
	a := e2eAgent(t, is)
	if _, err := a.DPoPTransport(nil, "https://x.example"); err == nil {
		t.Fatal("an agent without WithDPoP has no DPoP transport")
	}
	if _, err := DPoPTransport(a.TokenSource(), nil, nil, "https://x.example"); err == nil {
		t.Fatal("a nil key")
	}
	if _, err := DPoPTransport(a.TokenSource(), a.key, nil); err == nil {
		t.Fatal("sendTo is required")
	}
}
