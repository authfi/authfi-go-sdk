package authfi

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
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

var (
	oidCustody  = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 67322, 1, 1}
	oidResident = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 67322, 1, 2}
	oidHeld     = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 67322, 1, 3}
)

const testHost = "https://api.example.com"

// certSpec describes one certificate of a throwaway PKI.
type certSpec struct {
	cn                  string
	policies            []asn1.ObjectIdentifier
	isCA                bool
	ku                  x509.KeyUsage
	notBefore, notAfter time.Time
	pub                 crypto.PublicKey
	parent              *testCA // nil: self-signed
}

type testCA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
}

func issue(t *testing.T, own *ecdsa.PrivateKey, s certSpec) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	if own == nil {
		own, _ = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	}
	pub := s.pub
	if pub == nil {
		pub = &own.PublicKey
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: s.cn},
		NotBefore: s.notBefore, NotAfter: s.notAfter, KeyUsage: s.ku,
		BasicConstraintsValid: true, IsCA: s.isCA, PolicyIdentifiers: s.policies,
	}
	if s.isCA {
		tmpl.MaxPathLen, tmpl.MaxPathLenZero = 2, false
	}
	parent, signer := tmpl, own
	if s.parent != nil {
		parent, signer = s.parent.cert, s.parent.key
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, pub, signer)
	if err != nil {
		t.Fatalf("certificate %s: %v", s.cn, err)
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return c, own
}

// pki is a throwaway root and intermediate; the root carries no policy, as AuthFI's does.
type pki struct {
	root, inter *testCA
	now         time.Time
}

func newPKI(t *testing.T, now time.Time, mod func(inter *certSpec)) *pki {
	t.Helper()
	nb, na := now.Add(-time.Hour), now.Add(24*time.Hour)
	rc, rk := issue(t, nil, certSpec{cn: "Test Root", isCA: true, ku: x509.KeyUsageCertSign, notBefore: nb, notAfter: na})
	p := &pki{root: &testCA{rc, rk}, now: now}
	is := certSpec{cn: "Test Intermediate", isCA: true, ku: x509.KeyUsageCertSign, notBefore: nb, notAfter: na,
		policies: []asn1.ObjectIdentifier{oidCustody}, parent: p.root}
	if mod != nil {
		mod(&is)
	}
	ic, ik := issue(t, nil, is)
	p.inter = &testCA{ic, ik}
	return p
}

func (p *pki) pin() string { return pinOf(p.root.cert) }

func pinOf(c *x509.Certificate) string {
	sum := sha256.Sum256(c.RawSubjectPublicKeyInfo)
	return hex.EncodeToString(sum[:])
}

func (p *pki) leaf(t *testing.T, pub crypto.PublicKey, mod func(*certSpec)) *x509.Certificate {
	t.Helper()
	s := certSpec{cn: "Test Token Key", ku: x509.KeyUsageDigitalSignature, policies: []asn1.ObjectIdentifier{oidCustody},
		notBefore: p.now.Add(-time.Hour), notAfter: p.now.Add(2 * time.Hour), pub: pub, parent: p.inter}
	if mod != nil {
		mod(&s)
	}
	c, _ := issue(t, nil, s)
	return c
}

func certsB64(cs ...*x509.Certificate) []string {
	out := make([]string, len(cs))
	for i, c := range cs {
		out[i] = base64.StdEncoding.EncodeToString(c.Raw)
	}
	return out
}

func (s *signer) pub() any {
	switch {
	case s.rsa != nil:
		return &s.rsa.PublicKey
	case s.ec != nil:
		return &s.ec.PublicKey
	}
	return s.ed.Public()
}

func (s *signer) thumb() string {
	t, _ := jwkThumbprint(s.pub())
	return t
}

func newProofSigner(alg string) *signer {
	switch alg {
	case "ES256":
		k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		return &signer{kid: "p", alg: alg, ec: k}
	case "PS256":
		_, k := sharedRSA()
		return &signer{kid: "p", alg: alg, rsa: k}
	}
	_, k, _ := ed25519.GenerateKey(rand.Reader)
	return &signer{kid: "p", alg: "EdDSA", ed: k}
}

// agentEnv is an issuer whose EdDSA key ed1 has a certificate chain, an agent key that signs
// proofs, and helpers to send agent requests to a client.
type agentEnv struct {
	t    *testing.T
	f    *fixture
	pki  *pki
	leaf *x509.Certificate
	pk   *signer // the agent's proof key
	jti  atomic.Int64
}

func newAgentEnv(t *testing.T) *agentEnv {
	t.Helper()
	f := newFixture(t)
	e := &agentEnv{t: t, f: f, pk: newProofSigner("EdDSA")}
	e.pki = newPKI(t, f.clock(), nil)
	e.setLeaf(e.pki.leaf(t, f.keys["ed1"].pub(), nil), e.pki.inter.cert, e.pki.root.cert)
	return e
}

// setLeaf publishes certs as the chain of ed1: the first is the leaf.
func (e *agentEnv) setLeaf(certs ...*x509.Certificate) {
	e.leaf = certs[0]
	e.f.keys["ed1"].x5c = certsB64(certs...)
	e.f.keys["ed1"].x5t = thumbprintS256(certs[0].Raw)
}

func (e *agentEnv) client(mod ...func(*Config)) *Client {
	all := append([]func(*Config){func(c *Config) { c.RootPins = []string{e.pki.pin()}; c.PublicURL = testHost }}, mod...)
	return e.f.client(all...)
}

func (e *agentEnv) token(claims map[string]any, header map[string]any) string {
	cl := map[string]any{"sub": "agt_1", "client_id": "agt_1", "scope": "tools.read",
		"permissions": []string{"read:users"}, "cnf": map[string]any{"jkt": e.pk.thumb()}}
	for k, v := range claims {
		cl[k] = v
	}
	h := map[string]any{"x5t#S256": thumbprintS256(e.leaf.Raw)}
	for k, v := range header {
		h[k] = v
	}
	return e.f.mint(tokenSpec{kid: "ed1", claims: cl, header: h})
}

func athOf(token string) string {
	sum := sha256.Sum256([]byte(token))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// proof builds a proof for a GET of /orders with token, signed by e.pk, then lets mod change it.
func (e *agentEnv) proof(token string, mod func(h, c map[string]any)) string {
	return e.proofBy(e.pk, token, mod)
}

func (e *agentEnv) proofBy(s *signer, token string, mod func(h, c map[string]any)) string {
	h := map[string]any{"typ": "dpop+jwt", "alg": s.alg, "jwk": s.jwk()}
	c := map[string]any{"jti": fmt.Sprintf("jti-%d", e.jti.Add(1)), "htm": "GET", "htu": testHost + "/orders",
		"iat": e.f.clock().Unix(), "ath": athOf(token)}
	if mod != nil {
		mod(h, c)
	}
	hj, _ := json.Marshal(h)
	cj, _ := json.Marshal(c)
	signed := base64URL(hj) + "." + base64URL(cj)
	return signed + "." + base64URL(s.sign(signed))
}

// request is a GET /orders carrying token under scheme and the given proofs.
func request(scheme, token string, proofs ...string) *http.Request {
	r := httptest.NewRequest(http.MethodGet, testHost+"/orders", nil)
	if token != "" {
		r.Header.Set("Authorization", scheme+" "+token)
	}
	for _, p := range proofs {
		r.Header.Add("DPoP", p)
	}
	return r
}

// call sends token with a fresh proof changed by mod, under the DPoP scheme.
func (e *agentEnv) call(c *Client, token string, mod func(h, c map[string]any)) (*Claims, error) {
	return c.VerifyRequest(request("DPoP", token, e.proof(token, mod)))
}

// noLeak fails when an error text holds anything of the token or proof it refused.
func noLeak(t *testing.T, err error, secrets ...string) {
	t.Helper()
	if err == nil {
		return
	}
	text := err.Error()
	for _, s := range secrets {
		for _, seg := range strings.Split(s, ".") {
			if len(seg) > 12 && strings.Contains(text, seg) {
				t.Fatalf("the error holds part of a token or proof: %q", text)
			}
		}
	}
}
