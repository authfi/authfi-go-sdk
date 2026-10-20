package agent

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	authfi "github.com/authfi/authfi-go-sdk"
)

var algs = []Algorithm{EdDSA, ES256, PS256}

// --- keys ---

func TestGeneratedKeysPublishOnlyThePublicHalf(t *testing.T) {
	for _, alg := range algs {
		k := keyFor(t, alg)
		if k.Alg() != alg || k.KID() == "" {
			t.Fatalf("%s: alg %s kid %q", alg, k.Alg(), k.KID())
		}
		for _, private := range []string{"d", "p", "q", "dp", "dq", "qi", "k"} {
			if _, has := k.PublicJWK()[private]; has {
				t.Fatalf("%s: public JWK carries private member %s", alg, private)
			}
		}
	}
}

// RFC 7638 appendix A's RSA example fixes the thumbprint algorithm.
func TestThumbprintMatchesRFC7638(t *testing.T) {
	jwk := map[string]string{"kty": "RSA", "e": "AQAB", "n": "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw"}
	if got := thumbprint(jwk); got != "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs" {
		t.Fatalf("thumbprint %s", got)
	}
}

func TestKeyKIDIsKeptWhenGiven(t *testing.T) {
	k, err := GenerateKey(EdDSA, "console-registered-kid")
	if err != nil || k.KID() != "console-registered-kid" {
		t.Fatalf("%v %v", k, err)
	}
	if _, err := GenerateKey("HS256", ""); err == nil {
		t.Fatal("HS256 is not an agent key algorithm")
	}
}

func TestKeyRoundTripsThroughAFileWithOwnerOnlyMode(t *testing.T) {
	for _, alg := range algs {
		k := keyFor(t, alg)
		path := filepath.Join(t.TempDir(), "agent.key")
		if err := k.WriteFile(path); err != nil {
			t.Fatal(err)
		}
		if err := k.WriteFile(path); err == nil {
			t.Fatal("WriteFile must not overwrite")
		}
		if runtime.GOOS != "windows" {
			if fi, _ := os.Stat(path); fi.Mode().Perm() != 0o600 {
				t.Fatalf("mode %o", fi.Mode().Perm())
			}
		}
		got, err := LoadKey(path, k.KID())
		if err != nil {
			t.Fatal(err)
		}
		if got.Alg() != alg || got.PublicJWK()["kty"] != k.PublicJWK()["kty"] {
			t.Fatalf("%s: loaded %v", alg, got)
		}
		if _, err := clientAssertion(got, "a", "b", time.Now()); err != nil {
			t.Fatal(err)
		}
	}
}

func TestLoadKeyRefusesAFileOthersCanRead(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX modes only")
	}
	path := filepath.Join(t.TempDir(), "agent.key")
	if err := keyFor(t, EdDSA).WriteFile(path); err != nil {
		t.Fatal(err)
	}
	for _, mode := range []os.FileMode{0o640, 0o604, 0o644, 0o660} {
		_ = os.Chmod(path, mode)
		_, err := LoadKey(path, "")
		if err == nil || !strings.Contains(err.Error(), "chmod 600") {
			t.Fatalf("mode %o: %v", mode, err)
		}
	}
	_ = os.Chmod(path, 0o400)
	if _, err := LoadKey(path, ""); err != nil {
		t.Fatalf("a read-only owner file is fine: %v", err)
	}
}

func TestLoadKeyErrorsNameNothingSecret(t *testing.T) {
	path := filepath.Join(t.TempDir(), "agent.key")
	_ = os.WriteFile(path, []byte("-----BEGIN PRIVATE KEY-----\nQUJDREVGR0hJSktMTU5PUA==\n-----END PRIVATE KEY-----\n"), 0o600)
	_, err := LoadKey(path, "")
	if err == nil || strings.Contains(err.Error(), "QUJDREVG") {
		t.Fatalf("%v", err)
	}
	if _, err := LoadKey(filepath.Join(t.TempDir(), "missing"), ""); err == nil {
		t.Fatal("a missing file is an error")
	}
	if _, err := ParseKey([]byte("not pem"), ""); err == nil {
		t.Fatal("not PEM")
	}
}

func TestWeakKeysAreRefused(t *testing.T) {
	// A 1024-bit RSA key and an RSA key with exponent 3 are not agent keys.
	weak := mustPEMRSA(t, 1024, 65537)
	if _, err := ParseKey(weak, ""); err == nil {
		t.Fatal("1024-bit RSA accepted")
	}
	if _, err := ParseKey(mustPEMP384(t), ""); err == nil {
		t.Fatal("P-384 accepted")
	}
}

// --- assertions ---

// Known vectors for the other key types: RFC 8037 appendix A.3 for Ed25519; the P-256 one computed
// from RFC 7638 (members in lexicographic order, no whitespace).
func TestThumbprintOtherKeyTypes(t *testing.T) {
	ed := map[string]string{"kty": "OKP", "crv": "Ed25519", "x": "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}
	if got := thumbprint(ed); got != "kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k" {
		t.Fatalf("OKP %s", got)
	}
	ec := map[string]string{"kty": "EC", "crv": "P-256", "x": "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU", "y": "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0"}
	if got := thumbprint(ec); got != "oKIywvGUpTVTyxMQ3bwIIeQUudfr_CkLMjCE19ECD-U" {
		t.Fatalf("EC %s", got)
	}
}

// ES256 signatures are r||s with each half padded to 32 bytes. About 1 in 128 signatures has a
// leading zero in r or s, so a few hundred catch a missing pad.
func TestES256SignaturesAreAlwaysFixedWidthAndVerify(t *testing.T) {
	k := keyFor(t, ES256)
	p := newPlatform(t, k)
	for i := 0; i < 600; i++ {
		sig, err := k.sign([]byte(fmt.Sprint("message ", i)))
		if err != nil || len(sig) != 64 {
			t.Fatalf("signature %d: len %d %v", i, len(sig), err)
		}
		if !p.verifySig("ES256", []byte(fmt.Sprint("message ", i)), sig) {
			t.Fatalf("signature %d does not verify", i)
		}
	}
}

func TestAnRSAKeyWithAnotherExponentIsRefused(t *testing.T) {
	pk, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	pk.E = 3
	if _, err := newKey(pk, "k"); err == nil {
		t.Fatal("exponent 3 accepted")
	}
}

func TestAssertionClaimsAndUniqueness(t *testing.T) {
	for _, alg := range algs {
		k := keyFor(t, alg)
		now := time.Unix(1_800_000_000, 0)
		seen := map[string]bool{}
		for i := 0; i < 50; i++ {
			s, err := clientAssertion(k, testAgentID, "https://p.example/oauth/token", now)
			if err != nil {
				t.Fatal(err)
			}
			parts := strings.Split(s.Reveal(), ".")
			var h struct{ Alg, Typ, Kid string }
			var c struct {
				Iss, Sub, Aud, Jti string
				Iat, Exp           int64
			}
			hb, _ := base64.RawURLEncoding.DecodeString(parts[0])
			cb, _ := base64.RawURLEncoding.DecodeString(parts[1])
			_ = json.Unmarshal(hb, &h)
			_ = json.Unmarshal(cb, &c)
			if h.Alg != string(alg) || h.Kid != k.KID() || h.Typ != "JWT" {
				t.Fatalf("header %+v", h)
			}
			if c.Iss != testAgentID || c.Sub != testAgentID || c.Aud != "https://p.example/oauth/token" || c.Iat != now.Unix() || c.Exp-c.Iat != 60 {
				t.Fatalf("claims %+v", c)
			}
			if c.Jti == "" || seen[c.Jti] {
				t.Fatalf("jti %q repeated or empty", c.Jti)
			}
			seen[c.Jti] = true
		}
	}
	if _, err := clientAssertion(keyFor(t, EdDSA), "", "aud", time.Now()); err == nil {
		t.Fatal("an assertion needs the agent id")
	}
}

// --- the agent's own token ---

func TestMintsWithEveryKeyTypeAndSendsTheResource(t *testing.T) {
	for _, alg := range algs {
		t.Run(string(alg), func(t *testing.T) {
			k := keyFor(t, alg)
			p := newPlatform(t, k)
			a := p.agent(k, WithResource("api-orders"))
			tok, err := a.Token(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			if tok.Reveal() == "" || tok.Scope != "tools.read" {
				t.Fatalf("%+v", tok)
			}
			f := p.tokenForms(grantClientCreds)
			if len(f) != 1 || f[0].Get("resource") != "api-orders" || f[0].Get("client_id") != testAgentID {
				t.Fatalf("%v", f)
			}
			claims := unverified(t, tok.Reveal())
			if claims["aud"] != "api-orders" {
				t.Fatalf("aud %v", claims["aud"])
			}
		})
	}
}

func unverified(t *testing.T, raw string) map[string]any {
	t.Helper()
	b, err := base64.RawURLEncoding.DecodeString(strings.Split(raw, ".")[1])
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	_ = json.Unmarshal(b, &m)
	return m
}

func TestTokenIsCachedSharedAndRenewedBeforeExpiry(t *testing.T) {
	k := keyFor(t, EdDSA)
	p := newPlatform(t, k)
	a := p.agent(k)
	var wg sync.WaitGroup
	for i := 0; i < 30; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := a.Token(context.Background()); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	if n := len(p.tokenForms(grantClientCreds)); n != 1 {
		t.Fatalf("30 concurrent callers cost %d mints, want 1", n)
	}
	p.advance(8 * time.Minute) // 600 s token: still good with 60 s skew
	if _, err := a.Token(context.Background()); err != nil {
		t.Fatal(err)
	}
	if n := len(p.tokenForms(grantClientCreds)); n != 1 {
		t.Fatalf("a token with 2 minutes left must be reused, mints %d", n)
	}
	p.advance(90 * time.Second) // now 30 s from expiry: renew
	if _, err := a.Token(context.Background()); err != nil {
		t.Fatal(err)
	}
	forms := p.tokenForms(grantClientCreds)
	if len(forms) != 2 {
		t.Fatalf("expected a renewal, mints %d", len(forms))
	}
	if forms[0].Get("client_assertion") == forms[1].Get("client_assertion") {
		t.Fatal("every mint signs a fresh assertion")
	}
}

func TestShortLivedTokensStillCacheBriefly(t *testing.T) {
	k := keyFor(t, EdDSA)
	p := newPlatform(t, k)
	p.expiresIn = 30 // shorter than the renewal skew
	a := p.agent(k)
	for i := 0; i < 3; i++ {
		if _, err := a.Token(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	if n := len(p.tokenForms(grantClientCreds)); n != 1 {
		t.Fatalf("a 30 s token is reused inside its first half, mints %d", n)
	}
}

func TestRefusalIsATokenErrorAndNeverRetried(t *testing.T) {
	k := keyFor(t, EdDSA)
	p := newPlatform(t, k)
	other := keyFor(t, ES256)
	a := p.agent(other) // signs with a key the platform does not know
	_, err := a.Token(context.Background())
	var te *TokenError
	if !errors.As(err, &te) || te.Code != CodeInvalidClient || te.Status != 401 {
		t.Fatalf("%v", err)
	}
	if n := len(p.tokenForms(grantClientCreds)); n != 1 {
		t.Fatalf("a refusal is not retried, requests %d", n)
	}
}

func TestTransientFailuresAreRetriedWithAFreshAssertion(t *testing.T) {
	k := keyFor(t, EdDSA)
	p := newPlatform(t, k)
	p.mintStatus = []int{503, 502}
	a := p.agent(k)
	if _, err := a.Token(context.Background()); err != nil {
		t.Fatal(err)
	}
	forms := p.tokenForms(grantClientCreds)
	if len(forms) != 3 {
		t.Fatalf("expected 3 attempts, got %d", len(forms))
	}
	if len(p.slept) != 2 || p.slept[0] != 200*time.Millisecond || p.slept[1] != 400*time.Millisecond {
		t.Fatalf("backoff between attempts: %v", p.slept)
	}
	p2 := newPlatform(t, k)
	p2.mintStatus = []int{503, 503, 503}
	if _, err := p2.agent(k).Token(context.Background()); err == nil {
		t.Fatal("three 503s must fail")
	}
	if n := len(p2.tokenForms(grantClientCreds)); n != mintAttempts {
		t.Fatalf("attempts %d", n)
	}
}

// A fixed assertion works once: this is what x/oauth2/clientcredentials does, and why it fails.
func TestAReusedAssertionIsRefusedSoEveryMintSignsAFreshOne(t *testing.T) {
	k := keyFor(t, EdDSA)
	p := newPlatform(t, k)
	a := p.agent(k)
	if _, err := a.Token(context.Background()); err != nil {
		t.Fatal(err)
	}
	reused := p.tokenForms(grantClientCreds)[0]
	if msg := p.checkAssertion(reused); msg != "jti reused" {
		t.Fatalf("the fake platform must refuse a replay, got %q", msg)
	}
}

func TestContextCancelStopsAMint(t *testing.T) {
	k := keyFor(t, EdDSA)
	p := newPlatform(t, k)
	a := p.agent(k)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := a.Token(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("%v", err)
	}
}

func TestRefusalDescriptionCarriesNoAssertion(t *testing.T) {
	k := keyFor(t, EdDSA)
	p := newPlatform(t, k)
	p.echoAssert = true
	a := p.agent(keyFor(t, ES256))
	_, err := a.Token(context.Background())
	if err == nil {
		t.Fatal("expected a refusal")
	}
	assertClean(t, "mint refusal", err.Error())
}

// --- discovery ---

func TestDiscoveryMustNameTheIssuerAndStayOnItsHost(t *testing.T) {
	k := keyFor(t, EdDSA)
	p := newPlatform(t, k)
	p.issuerClaim = "https://other.example"
	if _, err := p.agent(k).Token(context.Background()); err == nil {
		t.Fatal("metadata naming another issuer must be refused")
	}
	p2 := newPlatform(t, k)
	var hits atomic.Int32
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { hits.Add(1) }))
	defer other.Close()
	p2.tokenHost = other.URL + "/oauth/token" // same scheme, another host
	_, err := p2.agent(k).Token(context.Background())
	if err == nil {
		t.Fatal("a token endpoint on another host would receive the assertion")
	}
	if hits.Load() != 0 || len(p2.tokenForms(grantClientCreds)) != 0 {
		t.Fatal("nothing may be sent to another host")
	}
}

func TestNewValidatesItsArguments(t *testing.T) {
	k := keyFor(t, EdDSA)
	for name, args := range map[string]struct {
		iss, id string
		key     *Key
	}{
		"no issuer":   {"", "a", k},
		"http issuer": {"http://acme.authfi.io", "a", k},
		"query":       {"https://acme.authfi.io?x=1", "a", k},
		"credentials": {"https://u:p@acme.authfi.io", "a", k},
		"no id":       {"https://acme.authfi.io", " ", k},
		"no key":      {"https://acme.authfi.io", "a", nil},
	} {
		if _, err := New(args.iss, args.id, args.key); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	if _, err := New("http://127.0.0.1:9", "a", k); err != nil {
		t.Errorf("loopback http is for local development: %v", err)
	}
}

// --- CIBA ---

func TestCIBAWaitsPollsAndHonoursSlowDown(t *testing.T) {
	k := keyFor(t, EdDSA)
	p := newPlatform(t, k)
	p.cibaAnswers = []string{"pending", "slow_down", "429", "pending", "ok"}
	a := p.agent(k, WithResource("api-orders"))
	req, err := a.RequestUserApproval(context.Background(), "jane@example.com", "Refund order 4411", []string{"orders.refund"}, 2*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if req.Interval != 5*time.Second || req.ApprovalURL == "" || req.Resource != "api-orders" {
		t.Fatalf("%+v", req)
	}
	bc := p.backchannel[0]
	if bc.Get("login_hint") != "jane@example.com" || bc.Get("binding_message") != "Refund order 4411" ||
		bc.Get("scope") != "orders.refund" || bc.Get("requested_expiry") != "120" {
		t.Fatalf("%v", bc)
	}
	d, err := a.AwaitUserToken(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	// first poll after the interval; slow_down and 429 each add five seconds
	want := []time.Duration{5 * time.Second, 5 * time.Second, 10 * time.Second, 15 * time.Second, 15 * time.Second}
	if len(p.slept) != len(want) {
		t.Fatalf("sleeps %v", p.slept)
	}
	for i := range want {
		if p.slept[i] != want[i] {
			t.Fatalf("sleeps %v, want %v", p.slept, want)
		}
	}
	polls := p.tokenForms(grantCIBA)
	jtis := map[string]bool{}
	for _, f := range polls {
		if f.Get("auth_req_id") != "REQ-HANDLE-0001" || f.Get("resource") != "api-orders" {
			t.Fatalf("%v", f)
		}
		jtis[f.Get("client_assertion")] = true
	}
	if len(polls) != 5 || len(jtis) != 5 {
		t.Fatalf("5 polls with 5 distinct assertions, got %d and %d", len(polls), len(jtis))
	}
	if d.Via() != ViaCIBA || d.Subject() != "user:jane@example.com" {
		t.Fatalf("%v", d)
	}
}

func TestCIBADefaultsTheIntervalToFiveSeconds(t *testing.T) {
	k := keyFor(t, EdDSA)
	p := newPlatform(t, k)
	p.noInterval = true
	req, err := p.agent(k).RequestUserApproval(context.Background(), "jane", "msg", nil, 0)
	if err != nil || req.Interval != 5*time.Second {
		t.Fatalf("%+v %v", req, err)
	}
}

func TestApprovalIDIsEscapedInThePath(t *testing.T) {
	k := keyFor(t, EdDSA)
	p := newPlatform(t, k)
	ap, err := p.agent(k).ApprovalStatus(context.Background(), "a?b#c")
	if err != nil || ap.ID != "a?b#c" {
		t.Fatalf("%+v %v", ap, err)
	}
}

func TestCIBAEndStatesReturnAtOnce(t *testing.T) {
	for answer, code := range map[string]string{"denied": CodeAccessDenied, "expired": CodeExpiredToken} {
		k := keyFor(t, EdDSA)
		p := newPlatform(t, k)
		p.cibaAnswers = []string{answer, "ok"}
		a := p.agent(k)
		req, _ := a.RequestUserApproval(context.Background(), "jane", "msg", nil, 0)
		_, err := a.AwaitUserToken(context.Background(), req)
		var te *TokenError
		if !errors.As(err, &te) || te.Code != code {
			t.Fatalf("%s: %v", answer, err)
		}
		if n := len(p.tokenForms(grantCIBA)); n != 1 {
			t.Fatalf("%s: polled %d times after the end state", answer, n)
		}
	}
}

func TestCIBAStopsWhenTheRequestExpiresLocally(t *testing.T) {
	k := keyFor(t, EdDSA)
	p := newPlatform(t, k)
	p.cibaDefault = "pending"
	a := p.agent(k)
	req, _ := a.RequestUserApproval(context.Background(), "jane", "msg", nil, 0)
	_, err := a.AwaitUserToken(context.Background(), req)
	var te *TokenError
	if !errors.As(err, &te) || te.Code != CodeExpiredToken {
		t.Fatalf("%v", err)
	}
	if n := len(p.tokenForms(grantCIBA)); n < 50 || n > 61 {
		t.Fatalf("a 300 s request polled every 5 s is about 59 polls, got %d", n)
	}
}

func TestCIBAContextCancelStopsPolling(t *testing.T) {
	k := keyFor(t, EdDSA)
	p := newPlatform(t, k)
	a := p.agent(k)
	req, _ := a.RequestUserApproval(context.Background(), "jane", "msg", nil, 0)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := a.AwaitUserToken(ctx, req); !errors.Is(err, context.Canceled) {
		t.Fatalf("%v", err)
	}
	if len(p.tokenForms(grantCIBA)) != 0 {
		t.Fatal("no poll after cancel")
	}
}

func TestCIBARequiresWhoAndWhat(t *testing.T) {
	k := keyFor(t, EdDSA)
	p := newPlatform(t, k)
	a := p.agent(k)
	if _, err := a.RequestUserApproval(context.Background(), "", "msg", nil, 0); err == nil {
		t.Fatal("login_hint")
	}
	if _, err := a.RequestUserApproval(context.Background(), "jane", "  ", nil, 0); err == nil {
		t.Fatal("binding_message")
	}
	if len(p.backchannel) != 0 {
		t.Fatal("nothing is sent for an invalid request")
	}
}

func TestCIBAStartIsNeverRetried(t *testing.T) {
	k := keyFor(t, EdDSA)
	p := newPlatform(t, k)
	a := p.agent(keyFor(t, ES256)) // the platform refuses this key with 401
	_, err := a.RequestUserApproval(context.Background(), "jane", "msg", nil, 0)
	if err == nil || len(p.backchannel) != 1 {
		t.Fatalf("%v, requests %d", err, len(p.backchannel))
	}
}

func TestCIBATokenIsNeverRenewed(t *testing.T) {
	k := keyFor(t, EdDSA)
	p := newPlatform(t, k)
	a := p.agent(k)
	req, _ := a.RequestUserApproval(context.Background(), "jane", "msg", nil, 0)
	d, err := a.AwaitUserToken(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := d.Token(context.Background()); err != nil {
		t.Fatal(err)
	}
	before := len(p.forms)
	p.advance(11 * time.Minute)
	_, err = d.Token(context.Background())
	var te *TokenError
	if !errors.As(err, &te) || te.Code != CodeExpiredToken {
		t.Fatalf("%v", err)
	}
	if len(p.forms) != before {
		t.Fatal("a CIBA token must not trigger a request")
	}
}

// --- exchange ---

func TestExchangeUsesTheAgentTokenAsActorAndNoClientAuthentication(t *testing.T) {
	k := keyFor(t, EdDSA)
	p := newPlatform(t, k)
	a := p.agent(k, WithResource("api-orders"))
	d, err := a.Exchange(context.Background(), authfi.NewSecret("person-access-token"), []string{"orders.read"}, "")
	if err != nil {
		t.Fatal(err)
	}
	f := p.tokenForms(grantTokenExchange)[0]
	if f.Get("client_assertion") != "" || f.Get("client_id") != "" {
		t.Fatalf("an exchange must not carry client authentication: %v", f)
	}
	own, _ := a.Token(context.Background())
	if f.Get("actor_token") != own.Reveal() || f.Get("subject_token") != "person-access-token" ||
		f.Get("scope") != "orders.read" || f.Get("resource") != "api-orders" ||
		f.Get("subject_token_type") != accessTokenType || f.Get("actor_token_type") != accessTokenType {
		t.Fatalf("%v", f)
	}
	if d.Via() != ViaExchange || d.Subject() != "user:jane@example.com" {
		t.Fatalf("%v", d)
	}
}

func TestExchangedTokenIsExchangedAgainNearExpiryAndNotBefore(t *testing.T) {
	k := keyFor(t, EdDSA)
	p := newPlatform(t, k)
	a := p.agent(k)
	d, err := a.Exchange(context.Background(), authfi.NewSecret("person"), nil, "")
	if err != nil {
		t.Fatal(err)
	}
	p.advance(5 * time.Minute)
	if _, err := d.Token(context.Background()); err != nil {
		t.Fatal(err)
	}
	if n := len(p.tokenForms(grantTokenExchange)); n != 1 {
		t.Fatalf("exchanges %d", n)
	}
	p.advance(4*time.Minute + 30*time.Second)
	if _, err := d.Token(context.Background()); err != nil {
		t.Fatal(err)
	}
	if n := len(p.tokenForms(grantTokenExchange)); n != 2 {
		t.Fatalf("a token near expiry is exchanged again, exchanges %d", n)
	}
}

func TestExchangeRefusalCarriesNoSubjectToken(t *testing.T) {
	k := keyFor(t, EdDSA)
	p := newPlatform(t, k)
	a := p.agent(k)
	_, err := a.Exchange(context.Background(), authfi.NewSecret("expired-subject"), nil, "")
	var te *TokenError
	if !errors.As(err, &te) || te.Code != CodeInvalidGrant {
		t.Fatalf("%v", err)
	}
	if strings.Contains(err.Error(), "expired-subject") {
		t.Fatalf("the subject token reached the error: %v", err)
	}
	before := len(p.forms)
	if _, err := a.Exchange(context.Background(), authfi.Secret{}, nil, ""); err == nil || len(p.forms) != before {
		t.Fatal("an empty subject token is refused before anything is sent")
	}
}

// --- approvals ---

func TestApprovalStatusAndWait(t *testing.T) {
	k := keyFor(t, EdDSA)
	p := newPlatform(t, k)
	a := p.agent(k)
	ap, err := a.ApprovalStatus(context.Background(), "apr/1 2")
	if err != nil || ap.ID != "apr/1 2" || ap.Status != "approved" {
		t.Fatalf("%+v %v", ap, err)
	}
	own, _ := a.Token(context.Background())
	if p.approvalAuth[0] != "Bearer "+own.Reveal() {
		t.Fatal("the approval is read with the agent's own token")
	}
	p.approvalBody = `{"approval_id":"a","status":"pending"}`
	ctx, cancel := context.WithCancel(context.Background())
	calls := 0
	a.sleep = func(ctx context.Context, d time.Duration) error {
		calls++
		if calls == 3 {
			p.mu.Lock()
			p.approvalBody = `{"approval_id":"a","status":"denied"}`
			p.mu.Unlock()
		}
		return ctx.Err()
	}
	got, err := a.WaitForApproval(ctx, "a", 0)
	cancel()
	if err != nil || got.Status != "denied" || calls != 3 {
		t.Fatalf("%+v %v calls %d", got, err, calls)
	}
}

func TestApprovalStatusNotOffered(t *testing.T) {
	k := keyFor(t, EdDSA)
	p := newPlatform(t, k)
	p.approvalCode = 403
	if _, err := p.agent(k).ApprovalStatus(context.Background(), "a"); !errors.Is(err, ErrApprovalStatusNotOffered) {
		t.Fatalf("%v", err)
	}
	p2 := newPlatform(t, k)
	p2.noAgentCfg = true
	if _, err := p2.agent(k).ApprovalStatus(context.Background(), "a"); !errors.Is(err, ErrApprovalStatusNotOffered) {
		t.Fatalf("%v", err)
	}
	p3 := newPlatform(t, k)
	p3.noAgentCfg = true
	_, err := p3.agent(k).RequestUserApproval(context.Background(), "jane", "msg", nil, 0)
	var te *TokenError
	if !errors.As(err, &te) || te.Code != "unsupported" {
		t.Fatalf("%v", err)
	}
}

func TestWaitForApprovalStopsOnCancel(t *testing.T) {
	k := keyFor(t, EdDSA)
	p := newPlatform(t, k)
	p.approvalBody = `{"approval_id":"a","status":"pending"}`
	a := p.agent(k)
	ctx, cancel := context.WithCancel(context.Background())
	a.sleep = func(ctx context.Context, _ time.Duration) error { cancel(); return ctx.Err() }
	if _, err := a.WaitForApproval(ctx, "a", time.Second); !errors.Is(err, context.Canceled) {
		t.Fatalf("%v", err)
	}
}

// --- oauth2 ---

func TestTokenSourceServesTheCachedToken(t *testing.T) {
	k := keyFor(t, EdDSA)
	p := newPlatform(t, k)
	src := p.agent(k).TokenSource()
	t1, err := src.Token()
	if err != nil {
		t.Fatal(err)
	}
	if t1.Expiry.IsZero() || !t1.Expiry.After(p.clock()) {
		t.Fatal("the oauth2 token carries the expiry")
	}
	t2, _ := src.Token()
	if t1.AccessToken == "" || t1.AccessToken != t2.AccessToken || t1.Type() != "Bearer" || len(p.tokenForms(grantClientCreds)) != 1 {
		t.Fatal("one mint, same token")
	}
}

func TestEndpointsAreCachedForAnHourThenFetchedAgain(t *testing.T) {
	k := keyFor(t, EdDSA)
	p := newPlatform(t, k)
	p.expiresIn = 30
	a := p.agent(k)
	for i := 0; i < 3; i++ {
		p.advance(time.Minute)
		if _, err := a.Token(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	if p.asHits != 1 {
		t.Fatalf("metadata fetched %d times inside an hour, want 1", p.asHits)
	}
	p.advance(time.Hour)
	if _, err := a.Token(context.Background()); err != nil {
		t.Fatal(err)
	}
	if p.asHits != 2 {
		t.Fatalf("metadata fetched %d times after an hour, want 2", p.asHits)
	}
}

func TestAnOversizeReplyIsRefused(t *testing.T) {
	k := keyFor(t, EdDSA)
	p := newPlatform(t, k)
	p.hugeReply = true
	if _, err := p.agent(k).Token(context.Background()); err == nil {
		t.Fatal("a 2 MiB token reply must not be read")
	}
}

func TestApprovalFailureStatusWinsOverAUsableBody(t *testing.T) {
	k := keyFor(t, EdDSA)
	p := newPlatform(t, k)
	p.approvalBody = `{"approval_id":"a","status":"approved"}`
	p.approvalCode = 500
	if ap, err := p.agent(k).ApprovalStatus(context.Background(), "a"); err == nil {
		t.Fatalf("a 500 is not an approval: %+v", ap)
	}
}
