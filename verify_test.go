package authfi

import (
	"context"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestVerifyAcceptsEveryAlgorithm(t *testing.T) {
	f := newFixture(t)
	c := f.client()
	for kid, alg := range map[string]string{"rs1": "RS256", "ps1": "PS256", "es1": "ES256", "ed1": "EdDSA"} {
		t.Run(alg, func(t *testing.T) {
			claims, err := c.VerifyToken(f.mint(tokenSpec{kid: kid}))
			if err != nil {
				t.Fatalf("%s token refused: %v", alg, err)
			}
			if claims.Subject != "usr_123" || claims.TenantID != testTenant || len(claims.Permissions) != 1 {
				t.Fatalf("claims not read: %+v", claims)
			}
			if len(claims.Audience) != 1 || claims.Audience[0] != testAudience {
				t.Fatalf("audience not read: %v", claims.Audience)
			}
		})
	}
}

// An agent token is EdDSA, carries client_id and scope, and a delegated one an act claim.
func TestVerifyAgentAndDelegatedTokens(t *testing.T) {
	f := newFixture(t)
	c := f.client()
	agent := f.mint(tokenSpec{kid: "ed1", claims: map[string]any{"sub": "agt_1", "client_id": "agt_1", "scope": "tools.read"}})
	got, err := c.VerifyToken(agent)
	if err != nil || got.ClientID != "agt_1" || got.Scope != "tools.read" || got.Actor != "" {
		t.Fatalf("agent token: %+v %v", got, err)
	}
	deleg := f.mint(tokenSpec{kid: "ed1", claims: map[string]any{
		"sub": "user:jane", "aud": []string{"other", testAudience}, "act": map[string]any{"sub": "agent:agt_1"}}})
	got, err = c.VerifyToken(deleg)
	if err != nil || got.Actor != "agent:agt_1" || got.Subject != "user:jane" {
		t.Fatalf("delegated token: %+v %v", got, err)
	}
}

func TestVerifyRefusals(t *testing.T) {
	f := newFixture(t)
	c := f.client()
	past := f.clock().Add(-time.Hour).Unix()
	future := f.clock().Add(time.Hour).Unix()
	cases := []struct {
		name string
		spec tokenSpec
		code string
	}{
		{"wrong issuer", tokenSpec{claims: map[string]any{"iss": "https://evil.example"}}, CodeIssuerMismatch},
		{"issuer with trailing slash", tokenSpec{claims: map[string]any{"iss": f.issuer() + "/"}}, CodeIssuerMismatch},
		{"no issuer", tokenSpec{dropClm: []string{"iss"}}, CodeIssuerMismatch},
		{"wrong audience", tokenSpec{claims: map[string]any{"aud": "api-billing"}}, CodeAudienceMismatch},
		{"no audience", tokenSpec{dropClm: []string{"aud"}}, CodeAudienceMismatch},
		{"audience list without ours", tokenSpec{claims: map[string]any{"aud": []string{"a", "b"}}}, CodeAudienceMismatch},
		{"audience is the gateway", tokenSpec{claims: map[string]any{"aud": f.issuer() + "/mcp"}}, CodeAudienceMismatch},
		{"expired", tokenSpec{claims: map[string]any{"exp": past}}, CodeExpired},
		{"no expiry", tokenSpec{dropClm: []string{"exp"}}, CodeExpiryRequired},
		{"not before in the future", tokenSpec{claims: map[string]any{"nbf": future}}, CodeNotYetValid},
		{"issued in the future", tokenSpec{claims: map[string]any{"iat": future}}, CodeNotYetValid},
		{"id token (typ JWT)", tokenSpec{header: map[string]any{"typ": "JWT"}}, CodeTypInvalid},
		{"no typ", tokenSpec{dropHdr: []string{"typ"}}, CodeTypInvalid},
		{"event typ", tokenSpec{header: map[string]any{"typ": "secevent+jwt"}}, CodeTypInvalid},
		{"alg none", tokenSpec{header: map[string]any{"alg": "none"}}, CodeAlgNotAllowed},
		{"alg HS256", tokenSpec{header: map[string]any{"alg": "HS256"}}, CodeAlgNotAllowed},
		{"alg lowercase", tokenSpec{header: map[string]any{"alg": "rs256"}}, CodeAlgNotAllowed},
		{"RS256 header on an EdDSA key", tokenSpec{kid: "ed1", header: map[string]any{"alg": "RS256"}}, CodeAlgKeyMismatch},
		{"EdDSA header on an RSA key", tokenSpec{kid: "rs1", header: map[string]any{"alg": "EdDSA"}}, CodeAlgKeyMismatch},
		{"ES256 header on an RSA key", tokenSpec{kid: "rs1", header: map[string]any{"alg": "ES256"}}, CodeAlgKeyMismatch},
		{"PS256 header on a key published as RS256", tokenSpec{kid: "rs1", header: map[string]any{"alg": "PS256"}}, CodeAlgKeyMismatch},
		{"no kid", tokenSpec{dropHdr: []string{"kid"}}, CodeKeyIDRequired},
		{"unknown kid", tokenSpec{header: map[string]any{"kid": "nope"}}, CodeUnknownKey},
		{"crit header", tokenSpec{header: map[string]any{"crit": []string{"exp"}}}, CodeCritNotSupported},
		{"no subject", tokenSpec{dropClm: []string{"sub"}}, CodeSubjectRequired},
		{"no tenant", tokenSpec{dropClm: []string{"tenant_id"}}, CodeTenantRequired},
		{"another tenant", tokenSpec{claims: map[string]any{"tenant_id": "00000000-0000-0000-0000-000000000000"}}, CodeTenantMismatch},
		{"key-bound token (cnf)", tokenSpec{claims: map[string]any{"cnf": map[string]any{"jkt": "x"}}}, CodeDPoPProofRequired},
		{"mandate-bound token", tokenSpec{claims: map[string]any{"authfi_mandate": "m_1"}}, CodeDPoPProofRequired},
		{"act chain", tokenSpec{claims: map[string]any{"act": map[string]any{"sub": "a", "act": map[string]any{"sub": "b"}}}}, CodeActChainNotAllowed},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := c.VerifyToken(f.mint(tc.spec))
			mustCode(t, err, tc.code)
		})
	}
}

func TestVerifyTypIsCaseInsensitiveAndMayBeAMediaType(t *testing.T) {
	f := newFixture(t)
	c := f.client()
	for _, typ := range []string{"AT+JWT", "application/at+jwt", "Application/AT+JWT"} {
		if _, err := c.VerifyToken(f.mint(tokenSpec{header: map[string]any{"typ": typ}})); err != nil {
			t.Fatalf("typ %q refused: %v", typ, err)
		}
	}
}

func TestVerifyRefusesTamperedAndMalformedTokens(t *testing.T) {
	f := newFixture(t)
	c := f.client()
	good := f.mint(tokenSpec{})
	parts := strings.Split(good, ".")

	other := strings.Split(f.mint(tokenSpec{claims: map[string]any{"sub": "usr_999"}}), ".")
	forgedPayload := parts[0] + "." + other[1] + "." + parts[2]
	for name, tok := range map[string]string{
		"payload swapped":    forgedPayload,
		"signature flipped":  parts[0] + "." + parts[1] + "." + flip(parts[2]),
		"signature stripped": parts[0] + "." + parts[1] + ".",
		"two parts":          parts[0] + "." + parts[1],
		"five parts (JWE)":   good + ".a.b",
		"empty":              "",
		"not base64":         "a!.b!.c!",
		"header not JSON":    b64([]byte("nope")) + "." + parts[1] + "." + parts[2],
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := c.VerifyToken(tok); err == nil {
				t.Fatal("token accepted")
			}
		})
	}
	_, err := c.VerifyToken(forgedPayload)
	mustCode(t, err, CodeSignatureInvalid)

	// Every algorithm refuses a swapped payload and a flipped signature, not only RS256.
	for _, kid := range []string{"rs1", "ps1", "es1", "ed1"} {
		g := strings.Split(f.mint(tokenSpec{kid: kid}), ".")
		o := strings.Split(f.mint(tokenSpec{kid: kid, claims: map[string]any{"sub": "usr_999"}}), ".")
		_, err := c.VerifyToken(g[0] + "." + o[1] + "." + g[2])
		mustCode(t, err, CodeSignatureInvalid)
		_, err = c.VerifyToken(g[0] + "." + g[1] + "." + flip(g[2]))
		if err == nil {
			t.Fatalf("%s: a flipped signature was accepted", kid)
		}
	}

	_, err = c.VerifyToken(strings.Repeat("a", maxTokenBytes+1))
	mustCode(t, err, CodeTooLarge)
}

func flip(sig string) string {
	b := []byte(sig)
	if b[0] == 'A' {
		b[0] = 'B'
	} else {
		b[0] = 'A'
	}
	return string(b)
}

// Keys come from the issuer's key set only: an embedded jwk, a jku and an unknown kid are ignored.
func TestVerifyIgnoresKeysCarriedByTheToken(t *testing.T) {
	f := newFixture(t)
	c := f.client()
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	hdr := map[string]any{"alg": "EdDSA", "typ": "at+jwt", "kid": "attacker",
		"jwk": map[string]string{"kty": "OKP", "crv": "Ed25519", "kid": "attacker", "x": b64(pub)},
		"jku": "https://evil.example/jwks.json"}
	clm := f.goodClaims()
	hj, _ := json.Marshal(hdr)
	cj, _ := json.Marshal(clm)
	signed := b64(hj) + "." + b64(cj)
	tok := signed + "." + b64(ed25519.Sign(priv, []byte(signed)))
	_, err := c.VerifyToken(tok)
	mustCode(t, err, CodeUnknownKey)
}

// The classic confusion: sign HS256 with the public key bytes as the secret.
func TestVerifyRefusesHMACKeyConfusion(t *testing.T) {
	f := newFixture(t)
	c := f.client()
	hj, _ := json.Marshal(map[string]any{"alg": "HS256", "typ": "at+jwt", "kid": "rs1"})
	cj, _ := json.Marshal(f.goodClaims())
	signed := b64(hj) + "." + b64(cj)
	mac := hmac.New(sha256.New, f.keys["rs1"].rsa.N.Bytes())
	mac.Write([]byte(signed))
	_, err := c.VerifyToken(signed + "." + b64(mac.Sum(nil)))
	mustCode(t, err, CodeAlgNotAllowed)
}

// An ES256 signature is exactly r||s, 64 bytes. A longer encoding of the same r and s is not it.
func TestES256SignatureMustBe64Bytes(t *testing.T) {
	f := newFixture(t)
	c := f.client()
	g := strings.Split(f.mint(tokenSpec{kid: "es1"}), ".")
	raw, _ := base64.RawURLEncoding.DecodeString(g[2])
	padded := append(append(append([]byte{}, raw[:32]...), 0x00), raw[32:]...)
	_, err := c.VerifyToken(g[0] + "." + g[1] + "." + b64(padded))
	mustCode(t, err, CodeSignatureInvalid)
}

func TestVerifyLeeway(t *testing.T) {
	f := newFixture(t)
	slightlyExpired := f.mint(tokenSpec{claims: map[string]any{"exp": f.clock().Add(-30 * time.Second).Unix()}})
	if _, err := f.client().VerifyToken(slightlyExpired); err != nil {
		t.Fatalf("a token 30s past exp is inside the default 60s leeway: %v", err)
	}
	_, err := f.client(func(c *Config) { c.Leeway = -1 }).VerifyToken(slightlyExpired)
	mustCode(t, err, CodeExpired)
	longExpired := f.mint(tokenSpec{claims: map[string]any{"exp": f.clock().Add(-2 * time.Minute).Unix()}})
	_, err = f.client().VerifyToken(longExpired)
	mustCode(t, err, CodeExpired)
}

func TestVerifyAcceptsFractionalTimes(t *testing.T) {
	f := newFixture(t)
	tok := f.mint(tokenSpec{claims: map[string]any{"exp": float64(f.clock().Unix()) + 3600.5}})
	if _, err := f.client().VerifyToken(tok); err != nil {
		t.Fatal(err)
	}
}

func TestVerifyWithoutTenantPinAcceptsTheIssuersTenant(t *testing.T) {
	f := newFixture(t)
	c := f.client(func(c *Config) { c.TenantID = "" })
	if _, err := c.VerifyToken(f.mint(tokenSpec{claims: map[string]any{"tenant_id": "any"}})); err != nil {
		t.Fatal(err)
	}
}

func TestConfigurationFailsClosed(t *testing.T) {
	f := newFixture(t)
	tok := f.mint(tokenSpec{})
	cases := map[string]Config{
		"no issuer":                {Audience: []string{testAudience}},
		"no audience":              {Issuer: f.issuer()},
		"empty audience entry":     {Issuer: f.issuer(), Audience: []string{""}},
		"audience is the issuer":   {Issuer: f.issuer(), Audience: []string{f.issuer()}},
		"audience is the gateway":  {Issuer: f.issuer(), Audience: []string{f.issuer() + "/mcp"}},
		"audience is the api host": {Issuer: f.issuer(), APIURL: "https://api.example", Audience: []string{"https://api.example/x"}},
		"console client id":        {Issuer: f.issuer(), Audience: []string{"authfi-console"}},
		"workspace client id":      {Issuer: f.issuer(), Audience: []string{testAudience, "authfi-workspace"}},
		"http issuer off loopback": {Issuer: "http://acme.authfi.io", Audience: []string{testAudience}},
		"issuer with credentials":  {Issuer: "https://u:p@acme.authfi.io", Audience: []string{testAudience}},
		"leeway too large":         {Issuer: f.issuer(), Audience: []string{testAudience}, Leeway: time.Hour},
	}
	for name, cfg := range cases {
		t.Run(name, func(t *testing.T) {
			c := New(cfg)
			c.clock = f.clock
			mustCode(t, c.Validate(), CodeNotConfigured)
			_, err := c.VerifyToken(tok)
			mustCode(t, err, CodeNotConfigured)
		})
	}
}

func TestIssuerTrailingSlashIsTrimmed(t *testing.T) {
	f := newFixture(t)
	c := f.client(func(c *Config) { c.Issuer += "/" })
	if _, err := c.VerifyToken(f.mint(tokenSpec{})); err != nil {
		t.Fatal(err)
	}
}

// --- the key set ---

func TestKeySetIsFetchedOnceForAConcurrentBurst(t *testing.T) {
	f := newFixture(t)
	c := f.client()
	tok := f.mint(tokenSpec{})
	var wg sync.WaitGroup
	for i := 0; i < 40; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := c.VerifyToken(tok); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	if n := f.fetch.Load(); n != 1 {
		t.Fatalf("expected one key set fetch for a burst, got %d", n)
	}
}

// A stream of forged kids must not become a stream of fetches against the issuer.
func TestUnknownKeyIDsDoNotAmplify(t *testing.T) {
	f := newFixture(t)
	c := f.client()
	if _, err := c.VerifyToken(f.mint(tokenSpec{})); err != nil {
		t.Fatal(err)
	}
	before := f.fetch.Load()
	for i := 0; i < 50; i++ {
		f.advance(200 * time.Millisecond) // 10 s in all: still inside the 15 s interval
		_, err := c.VerifyToken(f.mint(tokenSpec{header: map[string]any{"kid": fmt.Sprintf("forged-%d", i)}}))
		mustCode(t, err, CodeUnknownKey)
	}
	if extra := f.fetch.Load() - before; extra > 1 {
		t.Fatalf("50 forged kids cost %d fetches, want at most 1", extra)
	}
}

func TestRotatedKeyIsPickedUpAfterTheRefetchInterval(t *testing.T) {
	f := newFixture(t)
	c := f.client()
	if _, err := c.VerifyToken(f.mint(tokenSpec{})); err != nil {
		t.Fatal(err)
	}
	_, edk, _ := ed25519.GenerateKey(rand.Reader)
	f.add(&signer{kid: "ed2", alg: "EdDSA", ed: edk})
	f.advance(minRefetch + time.Second)
	if _, err := c.VerifyToken(f.mint(tokenSpec{kid: "ed2"})); err != nil {
		t.Fatalf("a key added to the set must verify after one refetch: %v", err)
	}
}

func TestKeySetOutageUsesCachedKeysWithinGraceAndFailsClosedAfter(t *testing.T) {
	f := newFixture(t)
	c := f.client()
	tok := f.mint(tokenSpec{claims: map[string]any{"exp": f.clock().Add(48 * time.Hour).Unix()}})
	if _, err := c.VerifyToken(tok); err != nil {
		t.Fatal(err)
	}
	f.status.Store(500)
	f.advance(c.cfg.JWKSRefresh + time.Minute)
	if _, err := c.VerifyToken(tok); err != nil {
		t.Fatalf("a cached key inside the grace period must keep verifying: %v", err)
	}
	f.advance(staleGrace + time.Minute)
	_, err := c.VerifyToken(tok)
	mustCode(t, err, CodeKeySetUnavailable)
}

func TestKeySetUnavailableOnFirstUseFailsClosed(t *testing.T) {
	f := newFixture(t)
	f.status.Store(503)
	_, err := f.client().VerifyToken(f.mint(tokenSpec{}))
	mustCode(t, err, CodeKeySetUnavailable)
}

func TestKeySetNon200IsRefusedEvenWithAValidBody(t *testing.T) {
	f := newFixture(t)
	f.status.Store(203)
	_, err := f.client().VerifyToken(f.mint(tokenSpec{}))
	mustCode(t, err, CodeKeySetUnavailable)
}

func TestKeySetSkipsUnusableKeys(t *testing.T) {
	sharedRSA()
	body := `{"keys":[
	  {"kty":"RSA","kid":"weak","n":"AQAB","e":"AQAB"},
	  {"kty":"oct","kid":"sym","k":"c2VjcmV0"},
	  {"kty":"OKP","crv":"Ed448","kid":"ed448","x":"AA"},
	  {"kty":"EC","crv":"P-256","kid":"offcurve","x":"AQ","y":"AQ"},
	  {"kty":"RSA","kid":"enc","use":"enc","n":"` + b64(rsaA.N.Bytes()) + `","e":"AQAB"},
	  {"kty":"OKP","crv":"Ed25519","kid":"ok","x":"` + b64(make([]byte, 32)) + `"}]}`
	keys, err := parseKeySet([]byte(body))
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := keys["enc"]; ok {
		t.Fatal("a key for encryption must not verify signatures")
	}
	if len(keys) != 1 || keys["ok"].pub == nil {
		t.Fatalf("only the usable key may load, got %d", len(keys))
	}
}

func TestVerifyContextCancelled(t *testing.T) {
	f := newFixture(t)
	c := f.client()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := c.Verify(ctx, f.mint(tokenSpec{}))
	mustCode(t, err, CodeKeySetUnavailable)
}
