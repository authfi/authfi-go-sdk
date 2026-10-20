package authfi

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// --- redaction through every route ---

func TestSecretsStayHiddenWhenAClientOrSecretSitsInSomeoneElsesStruct(t *testing.T) {
	c := New(secretConfig(""))
	type holder struct {
		cfg    Config
		sec    Secret
		client *Client
	}
	h := holder{cfg: c.cfg, sec: NewSecret(sentinelClientSecret), client: c}
	for _, verb := range allVerbs {
		assertNoSecret(t, "holder "+verb, fmt.Sprintf(verb, h))
		assertNoSecret(t, "&holder "+verb, fmt.Sprintf(verb, &h))
	}
	if c.cfg.ClientSecret != "" || c.cfg.APIKey != "" {
		t.Fatal("the Client keeps no secret in a plain string")
	}
}

func TestSecretIsEmptyAndZeroValue(t *testing.T) {
	var zero Secret
	if !zero.IsEmpty() || zero.Reveal() != "" || !NewSecret("").IsEmpty() || NewSecret("x").IsEmpty() {
		t.Fatal("IsEmpty / Reveal")
	}
	if fmt.Sprintf("%v %s", zero, zero) != " " {
		t.Fatal("an empty secret prints empty")
	}
}

// --- errors never echo the user's own token, whatever its shape ---

func TestOpaqueUserTokenIsScrubbedFromServerEchoes(t *testing.T) {
	const opaque = "opaque-user-token-0123456789"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = fmt.Fprintf(w, "denied for %s", strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "))
	}))
	defer srv.Close()
	c := New(secretConfig(srv.URL))
	_, e1 := c.CloudCredentials(opaque, "gcp", nil)
	_, e2 := c.CloudToken(opaque, "aud", 60)
	for _, err := range []error{e1, e2} {
		if err == nil || strings.Contains(err.Error(), opaque) {
			t.Fatalf("the user's token reached an error: %v", err)
		}
	}
}

func TestServerTextReadsAtMostABoundedAmount(t *testing.T) {
	c := New(secretConfig(""))
	r := &countingReader{}
	_ = c.serverText(r)
	if r.n > maxEchoed*4+1 {
		t.Fatalf("read %d bytes of an endless reply", r.n)
	}
}

type countingReader struct{ n int }

func (c *countingReader) Read(p []byte) (int, error) {
	if c.n > 1<<22 {
		return 0, io.EOF
	}
	c.n += len(p)
	for i := range p {
		p[i] = 'A'
	}
	return len(p), nil
}

func TestCloudCallsReportAReplyWithoutWhatTheyNeed(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte(`{"expires_in":60}`)) }))
	defer srv.Close()
	c := New(secretConfig(srv.URL))
	if tok, err := c.CloudToken("t", "aud", 60); err == nil || tok != "" {
		t.Fatalf("a 200 without a token is an error, got %q %v", tok, err)
	}
	srv2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte(`<html>`)) }))
	defer srv2.Close()
	if _, err := New(secretConfig(srv2.URL)).CloudCredentials("t", "gcp", nil); err == nil {
		t.Fatal("a reply that is not JSON is an error")
	}
}

// A redirect must not carry the client secret or the API key to another host, and is not success.
func TestOutboundCallsDoNotFollowRedirects(t *testing.T) {
	var leaked atomic.Bool
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Client-Secret") != "" || r.Header.Get("X-API-Key") != "" || r.Header.Get("Authorization") != "" {
			leaked.Store(true)
		}
	}))
	defer other.Close()
	redirector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, other.URL+"/steal", http.StatusTemporaryRedirect)
	}))
	defer redirector.Close()
	c := New(secretConfig(redirector.URL))
	c.RegisterPermission("read:users", "")
	if _, err := c.CloudCredentials("t", "gcp", nil); err == nil {
		t.Fatal("a redirect is not a success")
	}
	if _, err := c.CloudToken("t", "aud", 60); err == nil {
		t.Fatal("a redirect is not a success")
	}
	if err := c.Sync(); err == nil {
		t.Fatal("a redirect is not a success")
	}
	if leaked.Load() {
		t.Fatal("a credential followed a redirect to another host")
	}
}

func TestSyncLogsNeverCarryTheAPIKey(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-API-Key") != sentinelAPIKey {
			t.Error("Sync must still send the key it was given")
		}
		_, _ = w.Write([]byte(`{"synced":1,"total":1}`))
	}))
	defer srv.Close()
	var logs bytes.Buffer
	cfg := secretConfig(srv.URL)
	cfg.Logger = slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	c := New(cfg)
	c.RegisterPermission("read:users", "")
	if err := c.Sync(); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(logs.String(), "synced=1") {
		t.Fatalf("Sync logs its result: %q", logs.String())
	}
	assertNoSecret(t, "sync log", logs.String())
}

// --- claims the verifier returns ---

func TestVerifiedClaimsCarryTimesAndSubject(t *testing.T) {
	f := newFixture(t)
	got, err := f.client().VerifyToken(f.mint(tokenSpec{}))
	if err != nil {
		t.Fatal(err)
	}
	if got.ExpiresAt != f.clock().Add(time.Hour).Unix() || got.IssuedAt != f.clock().Unix() || got.Issuer != f.issuer() {
		t.Fatalf("%+v", got)
	}
}

func TestNotBeforeHonoursLeewayBothWays(t *testing.T) {
	f := newFixture(t)
	c := f.client()
	if _, err := c.VerifyToken(f.mint(tokenSpec{claims: map[string]any{"nbf": f.clock().Add(30 * time.Second).Unix()}})); err != nil {
		t.Fatalf("nbf 30s ahead is inside the 60s leeway: %v", err)
	}
	_, err := c.VerifyToken(f.mint(tokenSpec{claims: map[string]any{"nbf": f.clock().Add(90 * time.Second).Unix()}}))
	mustCode(t, err, CodeNotYetValid)
	_, err = c.VerifyToken(f.mint(tokenSpec{claims: map[string]any{"iat": f.clock().Add(90 * time.Second).Unix()}}))
	mustCode(t, err, CodeNotYetValid)
}

func TestNullBindingClaimsAreNotBindings(t *testing.T) {
	f := newFixture(t)
	tok := f.mint(tokenSpec{claims: map[string]any{"cnf": nil, "authfi_mandate": nil, "act": nil}})
	if _, err := f.client().VerifyToken(tok); err != nil {
		t.Fatalf("null claims are absent claims: %v", err)
	}
}

func TestTimesOutsideTheCalendarAreRefusedNotWrapped(t *testing.T) {
	f := newFixture(t)
	c := f.client()
	for name, spec := range map[string]map[string]any{
		"nbf 1e30":      {"nbf": 1e30},
		"nbf 9.3e18":    {"nbf": 9.3e18},
		"iat 9.3e18":    {"iat": 9.3e18},
		"exp 9.3e18":    {"exp": 9.3e18},
		"nbf negative":  {"nbf": -1},
		"exp as string": {"exp": "9999999999"},
	} {
		if _, err := c.VerifyToken(f.mint(tokenSpec{claims: spec})); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}

func TestBase64MustBeStrictInEverySegment(t *testing.T) {
	f := newFixture(t)
	c := f.client()
	g := strings.Split(f.mint(tokenSpec{kid: "ed1"}), ".")
	if _, err := c.VerifyToken(g[0] + "." + g[1] + "." + g[2][:10] + "\n" + g[2][10:]); err == nil {
		t.Fatal("a newline inside the signature must not be skipped")
	}
	if _, err := c.VerifyToken(g[0][:5] + "\r" + g[0][5:] + "." + g[1] + "." + g[2]); err == nil {
		t.Fatal("a carriage return inside the header must not be skipped")
	}
	// A 64-byte signature leaves 4 unused bits in its last character. Setting one is a different
	// string for the same bytes.
	last := g[2][len(g[2])-1]
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
	idx := strings.IndexByte(alphabet, last)
	alt := alphabet[idx|1]
	if alt == last {
		alt = alphabet[idx&^1|2]
	}
	if _, err := c.VerifyToken(g[0] + "." + g[1] + "." + g[2][:len(g[2])-1] + string(alt)); err == nil {
		t.Fatal("a non-canonical signature encoding must be refused")
	}
}

func TestPS256RequiresTheStandardSaltLength(t *testing.T) {
	f := newFixture(t)
	f.keys["ps1"].salt = 64 // not the hash length AuthFI signs with
	_, err := f.client().VerifyToken(f.mint(tokenSpec{kid: "ps1"}))
	mustCode(t, err, CodeSignatureInvalid)
}

// --- the key set under load and failure ---

func TestAnExpiredCacheAndADownIssuerCostOneFetchPerInterval(t *testing.T) {
	f := newFixture(t)
	c := f.client()
	tok := f.mint(tokenSpec{claims: map[string]any{"exp": f.clock().Add(24 * time.Hour).Unix()}})
	if _, err := c.VerifyToken(tok); err != nil {
		t.Fatal(err)
	}
	f.status.Store(500)
	f.advance(c.cfg.JWKSRefresh + time.Second)
	before := f.fetch.Load()
	for i := 0; i < 20; i++ {
		if _, err := c.VerifyToken(tok); err != nil {
			t.Fatalf("a cached key serves during an outage: %v", err)
		}
	}
	if n := f.fetch.Load() - before; n != 1 {
		t.Fatalf("20 requests against a down issuer cost %d fetches, want 1", n)
	}
	f.advance(minRefetch + time.Second)
	_, _ = c.VerifyToken(tok)
	if n := f.fetch.Load() - before; n != 2 {
		t.Fatalf("the next interval allows one more attempt, total %d", n)
	}
}

func TestAColdCacheAndADownIssuerCostOneFetchAndKeepTheReason(t *testing.T) {
	f := newFixture(t)
	f.status.Store(500)
	c := f.client()
	for i := 0; i < 20; i++ {
		_, err := c.VerifyToken(f.mint(tokenSpec{header: map[string]any{"kid": fmt.Sprintf("forged-%d", i)}}))
		mustCode(t, err, CodeKeySetUnavailable)
	}
	if n := f.fetch.Load(); n != 1 {
		t.Fatalf("20 forged kids cost %d fetches, want 1", n)
	}
	f.status.Store(0)
	f.advance(minRefetch + time.Second)
	if _, err := c.VerifyToken(f.mint(tokenSpec{})); err != nil {
		t.Fatalf("the issuer is back: %v", err)
	}
}

func TestACancelledRequestIsNotAnAttemptAgainstTheIssuer(t *testing.T) {
	f := newFixture(t)
	c := f.client()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := c.Verify(ctx, f.mint(tokenSpec{}))
	mustCode(t, err, CodeKeySetUnavailable)
	if _, err := c.VerifyToken(f.mint(tokenSpec{})); err != nil {
		t.Fatalf("the next request must be free to fetch: %v", err)
	}
}

func TestAnEmptyKeySetDoesNotWipeTheCache(t *testing.T) {
	f := newFixture(t)
	c := f.client()
	tok := f.mint(tokenSpec{claims: map[string]any{"exp": f.clock().Add(24 * time.Hour).Unix()}})
	if _, err := c.VerifyToken(tok); err != nil {
		t.Fatal(err)
	}
	f.empty.Store(true)
	f.advance(c.cfg.JWKSRefresh + time.Second)
	if _, err := c.VerifyToken(tok); err != nil {
		t.Fatalf("an empty key set is a failure, not an instruction to forget: %v", err)
	}
}

func TestStaleKeysAreUsedForAnHourPastTheirRefreshTimeAndNoLonger(t *testing.T) {
	f := newFixture(t)
	c := f.client()
	tok := f.mint(tokenSpec{claims: map[string]any{"exp": f.clock().Add(72 * time.Hour).Unix()}})
	if _, err := c.VerifyToken(tok); err != nil {
		t.Fatal(err)
	}
	f.status.Store(500)
	f.advance(5*time.Minute + 59*time.Minute)
	if _, err := c.VerifyToken(tok); err != nil {
		t.Fatalf("59 minutes into the grace: %v", err)
	}
	f.advance(2 * time.Minute)
	_, err := c.VerifyToken(tok)
	mustCode(t, err, CodeKeySetUnavailable)
}

func TestAnOversizeKeySetIsRefused(t *testing.T) {
	f := newFixture(t)
	f.big.Store(true)
	_, err := f.client().VerifyToken(f.mint(tokenSpec{}))
	mustCode(t, err, CodeKeySetUnavailable)
}

func TestKeySetRefusesWeakAndMislabelledKeys(t *testing.T) {
	sharedRSA()
	n1024 := new(big.Int).Lsh(big.NewInt(1), 1023)
	goodN, goodE := b64(rsaA.N.Bytes()), "AQAB"
	ed := b64(make([]byte, 32))
	for name, key := range map[string]string{
		"rsa 1024 bits":       fmt.Sprintf(`{"kty":"RSA","kid":"k","n":%q,"e":%q}`, b64(n1024.Bytes()), goodE),
		"rsa exponent 1":      fmt.Sprintf(`{"kty":"RSA","kid":"k","n":%q,"e":"AQ"}`, goodN),
		"rsa exponent 2":      fmt.Sprintf(`{"kty":"RSA","kid":"k","n":%q,"e":"Ag"}`, goodN),
		"rsa alg HS256":       fmt.Sprintf(`{"kty":"RSA","kid":"k","alg":"HS256","n":%q,"e":%q}`, goodN, goodE),
		"ed25519 31 bytes":    fmt.Sprintf(`{"kty":"OKP","crv":"Ed25519","kid":"k","x":%q}`, b64(make([]byte, 31))),
		"ed25519 33 bytes":    fmt.Sprintf(`{"kty":"OKP","crv":"Ed25519","kid":"k","x":%q}`, b64(make([]byte, 33))),
		"x25519 as ed25519":   fmt.Sprintf(`{"kty":"OKP","crv":"X25519","kid":"k","x":%q}`, ed),
		"ed25519 alg ES256":   fmt.Sprintf(`{"kty":"OKP","crv":"Ed25519","kid":"k","alg":"ES256","x":%q}`, ed),
		"ec alg RS256":        `{"kty":"EC","crv":"P-256","kid":"k","alg":"RS256","x":"AQ","y":"AQ"}`,
		"no kid":              fmt.Sprintf(`{"kty":"OKP","crv":"Ed25519","x":%q}`, ed),
		"use enc":             fmt.Sprintf(`{"kty":"OKP","crv":"Ed25519","kid":"k","use":"enc","x":%q}`, ed),
		"unknown key type":    `{"kty":"oct","kid":"k","k":"AAAA"}`,
		"rsa empty modulus":   `{"kty":"RSA","kid":"k","n":"","e":"AQAB"}`,
		"rsa modulus garbage": `{"kty":"RSA","kid":"k","n":"!!!","e":"AQAB"}`,
	} {
		keys, err := parseKeySet([]byte(`{"keys":[` + key + `]}`))
		if err != nil || len(keys) != 0 {
			t.Errorf("%s: loaded %d keys (%v)", name, len(keys), err)
		}
	}
	// control: the good forms of the same keys load
	for name, key := range map[string]string{
		"rsa": fmt.Sprintf(`{"kty":"RSA","kid":"k","n":%q,"e":%q}`, goodN, goodE),
		"ed":  fmt.Sprintf(`{"kty":"OKP","crv":"Ed25519","kid":"k","x":%q}`, ed),
	} {
		if keys, _ := parseKeySet([]byte(`{"keys":[` + key + `]}`)); len(keys) != 1 {
			t.Errorf("control %s did not load", name)
		}
	}
	if _, err := parseKeySet([]byte(`not json`)); err == nil {
		t.Error("a body that is not JSON")
	}
}

func TestACappedNumberOfKeysLoad(t *testing.T) {
	var sb strings.Builder
	sb.WriteString(`{"keys":[`)
	for i := 0; i < jwksMaxKeys+20; i++ {
		if i > 0 {
			sb.WriteString(",")
		}
		fmt.Fprintf(&sb, `{"kty":"OKP","crv":"Ed25519","kid":"k%d","x":%q}`, i, b64(make([]byte, 32)))
	}
	sb.WriteString(`]}`)
	keys, _ := parseKeySet([]byte(sb.String()))
	if len(keys) != jwksMaxKeys {
		t.Fatalf("loaded %d keys, want the cap of %d", len(keys), jwksMaxKeys)
	}
}

// --- round 2 ---

// A caller that gives up must not make the next caller fetch again: the fetch is not tied to it.
func TestCallersThatGiveUpDoNotMultiplyFetches(t *testing.T) {
	f := newFixture(t)
	f.delay.Store(int64(300 * time.Millisecond))
	c := f.client()
	for i := 0; i < 6; i++ {
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Millisecond)
		_, err := c.Verify(ctx, f.mint(tokenSpec{header: map[string]any{"kid": fmt.Sprintf("forged-%d", i)}}))
		cancel()
		if i < 4 { // the 300 ms fetch is still running
			mustCode(t, err, CodeKeySetUnavailable)
		} else if err == nil {
			t.Fatal("a forged kid must not verify")
		}
	}
	time.Sleep(400 * time.Millisecond)
	if n := f.fetch.Load(); n != 1 {
		t.Fatalf("six callers with 60 ms deadlines cost %d fetches, want 1", n)
	}
	if _, err := c.VerifyToken(f.mint(tokenSpec{})); err != nil {
		t.Fatalf("the fetch finished for the next caller: %v", err)
	}
}

func TestAWaitingCallerLeavesOnItsOwnDeadline(t *testing.T) {
	f := newFixture(t)
	f.delay.Store(int64(1500 * time.Millisecond))
	c := f.client()
	go func() { _, _ = c.VerifyToken(f.mint(tokenSpec{})) }() // starts the slow fetch
	time.Sleep(100 * time.Millisecond)
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, err := c.Verify(ctx, f.mint(tokenSpec{}))
	mustCode(t, err, CodeKeySetUnavailable)
	if took := time.Since(start); took > 700*time.Millisecond {
		t.Fatalf("a caller with a 100 ms deadline waited %s", took)
	}
}

func TestTheFetchHasItsOwnTimeout(t *testing.T) {
	f := newFixture(t)
	f.delay.Store(int64(600 * time.Millisecond))
	c := f.client()
	c.keys.timeout = 50 * time.Millisecond
	start := time.Now()
	_, err := c.VerifyToken(f.mint(tokenSpec{}))
	mustCode(t, err, CodeKeySetUnavailable)
	if time.Since(start) > 400*time.Millisecond {
		t.Fatal("the fetch must give up at its own timeout")
	}
}

func TestASuccessfulFetchClearsTheRememberedFailure(t *testing.T) {
	f := newFixture(t)
	f.status.Store(500)
	c := f.client()
	_, err := c.VerifyToken(f.mint(tokenSpec{}))
	mustCode(t, err, CodeKeySetUnavailable)
	f.status.Store(0)
	f.advance(minRefetch + time.Second)
	if _, err := c.VerifyToken(f.mint(tokenSpec{})); err != nil {
		t.Fatal(err)
	}
	_, err = c.VerifyToken(f.mint(tokenSpec{header: map[string]any{"kid": "forged"}}))
	mustCode(t, err, CodeUnknownKey) // not the old outage
}

func TestStartAndVerifyMayRunTogether(t *testing.T) {
	f := newFixture(t)
	c := f.client()
	tok := f.mint(tokenSpec{})
	done := make(chan struct{})
	for i := 0; i < 8; i++ {
		go func(i int) {
			defer func() { done <- struct{}{} }()
			if i%2 == 0 {
				_ = c.Start()
				return
			}
			_, _ = c.VerifyToken(tok)
		}(i)
	}
	for i := 0; i < 8; i++ {
		<-done
	}
	if n := f.fetch.Load(); n < 1 || n > 2 {
		t.Fatalf("fetches %d", n)
	}
}

func TestSecretEqual(t *testing.T) {
	if !NewSecret("a").Equal(NewSecret("a")) || NewSecret("a").Equal(NewSecret("b")) || NewSecret("a").Equal(Secret{}) || !(Secret{}).Equal(Secret{}) {
		t.Fatal("Equal")
	}
}

func TestBase64SegmentsRejectCRAndLFEverywhere(t *testing.T) {
	f := newFixture(t)
	c := f.client()
	g := strings.Split(f.mint(tokenSpec{kid: "ed1"}), ".")
	for _, ch := range []string{"\r", "\n", "\r\n"} {
		for seg := 0; seg < 3; seg++ {
			p := append([]string(nil), g...)
			p[seg] = p[seg][:8] + ch + p[seg][8:]
			if _, err := c.VerifyToken(strings.Join(p, ".")); err == nil {
				t.Errorf("%q inside segment %d was skipped", ch, seg)
			}
		}
	}
}

// --- the cloud calls, happy path ---

func TestCloudCallsSendTheirCredentialsAndReturnWhatTheyAreGiven(t *testing.T) {
	var seen http.Header
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = r.Header.Clone()
		if strings.HasSuffix(r.URL.Path, "/token") {
			_, _ = w.Write([]byte(`{"token":"oidc-token"}`))
			return
		}
		_, _ = w.Write([]byte(`{"access_key":"AK"}`))
	}))
	defer srv.Close()
	c := New(secretConfig(srv.URL))
	creds, err := c.CloudCredentials("user-token", "aws", map[string]string{"role": "r"})
	if err != nil || creds["access_key"] != "AK" {
		t.Fatalf("%v %v", creds, err)
	}
	if seen.Get("X-Client-Secret") != sentinelClientSecret || seen.Get("X-Client-Id") != "app_1" || seen.Get("Authorization") != "Bearer user-token" {
		t.Fatalf("headers %v", seen)
	}
	tok, err := c.CloudToken("user-token", "aud", 60)
	if err != nil || tok != "oidc-token" {
		t.Fatalf("%q %v", tok, err)
	}
	if seen.Get("X-Client-Secret") != sentinelClientSecret {
		t.Fatal("CloudToken sends the client secret")
	}
	for name, cfg := range map[string]Config{"no secret": {ApplicationID: "a", APIURL: srv.URL}, "no application": {ClientSecret: "s", APIURL: srv.URL}} {
		if _, err := New(cfg).CloudCredentials("t", "aws", nil); err == nil {
			t.Errorf("CloudCredentials with %s", name)
		}
		if _, err := New(cfg).CloudToken("t", "aud", 1); err == nil {
			t.Errorf("CloudToken with %s", name)
		}
	}
}

func TestA3xxWithABodyIsNotASuccess(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusFound)
		_, _ = w.Write([]byte(`{"token":"x","access_key":"y","synced":1,"total":1}`))
	}))
	defer srv.Close()
	c := New(secretConfig(srv.URL))
	c.RegisterPermission("p", "")
	if _, err := c.CloudCredentials("t", "aws", nil); err == nil {
		t.Error("CloudCredentials")
	}
	if tok, err := c.CloudToken("t", "aud", 1); err == nil || tok != "" {
		t.Error("CloudToken")
	}
	if err := c.Sync(); err == nil {
		t.Error("Sync")
	}
}
