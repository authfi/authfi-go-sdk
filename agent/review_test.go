package agent

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	authfi "github.com/authfi/authfi-go-sdk"
)

// --- redirects never carry a credential anywhere ---

func TestATokenEndpointRedirectToAnotherHostGetsNothing(t *testing.T) {
	k := keyFor(t, EdDSA)
	var hits atomic.Int32
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits.Add(1) }))
	defer other.Close()
	p := newPlatform(t, k)
	p.redirectTo = other.URL + "/steal"
	// the default client follows 307 with the body; the Agent must not, whatever client it is given
	for name, a := range map[string]*Agent{"default client": p.agent(k), "caller's client": p.agent(k, WithHTTPClient(&http.Client{}))} {
		_, err := a.Token(context.Background())
		var te *TokenError
		if !errors.As(err, &te) || te.Code != "http_307" {
			t.Fatalf("%s: %v", name, err)
		}
		_, err = a.Exchange(context.Background(), authfi.NewSecret("person"), nil, "")
		if err == nil {
			t.Fatalf("%s: an exchange answered with a redirect is not a success", name)
		}
	}
	if hits.Load() != 0 {
		t.Fatalf("a credential was resent to another host %d times", hits.Load())
	}
}

func TestACIBAStartIsNotResentByARedirect(t *testing.T) {
	k := keyFor(t, EdDSA)
	p := newPlatform(t, k)
	p.cibaRedirect = true
	_, err := p.agent(k).RequestUserApproval(context.Background(), "jane", "msg", nil, 0)
	if err == nil {
		t.Fatal("a redirect is not an approval request")
	}
	if len(p.backchannel) != 1 {
		t.Fatalf("the start request reached the platform %d times, want 1", len(p.backchannel))
	}
}

// --- discovery ---

func TestAFailedAgentConfigurationIsNotCachedAsAbsent(t *testing.T) {
	k := keyFor(t, EdDSA)
	p := newPlatform(t, k)
	p.configStatus = 500
	a := p.agent(k)
	_, err := a.RequestUserApproval(context.Background(), "jane", "msg", nil, 0)
	var te *TokenError
	if !errors.As(err, &te) || te.Code != "discovery_failed" {
		t.Fatalf("an outage is not 'unsupported': %v", err)
	}
	if _, err := a.Token(context.Background()); err != nil {
		t.Fatalf("minting does not depend on the agent configuration: %v", err)
	}
	if _, err := a.ApprovalStatus(context.Background(), "a"); !errors.As(err, &te) || te.Code != "discovery_failed" {
		t.Fatalf("%v", err)
	}
	p.configStatus = 0
	p.advance(2 * time.Minute)
	if _, err := a.RequestUserApproval(context.Background(), "jane", "msg", nil, 0); err != nil {
		t.Fatalf("the configuration is back: %v", err)
	}
}

func TestSameHostChecks(t *testing.T) {
	a, _ := New("https://acme.authfi.io", "a", keyFor(t, EdDSA))
	for raw, ok := range map[string]bool{
		"https://acme.authfi.io/oauth/token":      true,
		"http://acme.authfi.io/oauth/token":       false,
		"https://other.authfi.io/oauth/token":     false,
		"https://acme.authfi.io:8443/oauth/token": false,
		"https://u:p@acme.authfi.io/oauth/token":  false,
		"https://acme.authfi.io/oauth/token#x":    false,
		"":                                        false,
	} {
		if _, err := a.sameHost(raw, "token_endpoint"); (err == nil) != ok {
			t.Errorf("%q: accepted=%v", raw, err == nil)
		}
	}
	if _, err := New("ftp://localhost", "a", keyFor(t, EdDSA)); err == nil {
		t.Error("ftp issuer accepted")
	}
}

// --- errors never hold what the platform echoed ---

func TestAnErrorCodeThatEchoesTheHandleIsNotACode(t *testing.T) {
	k := keyFor(t, EdDSA)
	p := newPlatform(t, k)
	p.cibaAnswers = []string{"echo-handle"}
	a := p.agent(k)
	req, _ := a.RequestUserApproval(context.Background(), "jane", "msg", nil, 0)
	var logs strings.Builder
	a.log = nil
	_, err := a.AwaitUserToken(context.Background(), req)
	var te *TokenError
	if !errors.As(err, &te) || te.Code != "http_400" {
		t.Fatalf("%v", err)
	}
	if strings.Contains(err.Error(), "REQ-HANDLE") || strings.Contains(logs.String(), "REQ-HANDLE") {
		t.Fatal("the handle reached the error")
	}
}

func TestPercentEncodedEchoesOfTheSubjectTokenAreScrubbed(t *testing.T) {
	k := keyFor(t, EdDSA)
	p := newPlatform(t, k)
	_, err := p.agent(k).Exchange(context.Background(), authfi.NewSecret("bad/opaque+subject-token"), nil, "")
	if err == nil {
		t.Fatal("expected a refusal")
	}
	for _, leak := range []string{"bad/opaque+subject-token", url.QueryEscape("bad/opaque+subject-token"), "opaque%2Bsubject"} {
		if strings.Contains(err.Error(), leak) {
			t.Fatalf("%q reached the error: %v", leak, err)
		}
	}
}

// --- numbers the platform sends ---

func TestAnAbsurdLifetimeIsClamped(t *testing.T) {
	k := keyFor(t, EdDSA)
	p := newPlatform(t, k)
	p.expiresIn = 9223372037
	a := p.agent(k)
	tok, err := a.Token(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if tok.Expiry.Before(p.clock()) || tok.Expiry.After(p.clock().Add(400*24*time.Hour)) {
		t.Fatalf("expiry %s", tok.Expiry)
	}
	if _, err := a.Token(context.Background()); err != nil || len(p.tokenForms(grantClientCreds)) != 1 {
		t.Fatalf("a token that never expires is cached: mints %d", len(p.tokenForms(grantClientCreds)))
	}
}

func TestCIBAIntervalIsKeptInSaneBounds(t *testing.T) {
	for name, c := range map[string]struct {
		in   any
		want time.Duration
	}{
		"absent":            {0, 5 * time.Second},
		"negative":          {-3, 5 * time.Second},
		"fraction":          {0.2, time.Second},
		"one second":        {1, time.Second},
		"five minutes":      {300, 300 * time.Second},
		"over five minutes": {600, 300 * time.Second},
		"huge":              {1e30, 300 * time.Second},
	} {
		k := keyFor(t, EdDSA)
		p := newPlatform(t, k)
		p.cibaInterval = c.in
		req, err := p.agent(k).RequestUserApproval(context.Background(), "jane", "msg", nil, 0)
		if err != nil || req.Interval != c.want {
			t.Errorf("%s: interval %v %v, want %s", name, req, err, c.want)
		}
	}
	k := keyFor(t, EdDSA)
	p := newPlatform(t, k)
	p.cibaInterval = 2.5
	req, _ := p.agent(k).RequestUserApproval(context.Background(), "jane", "msg", nil, 0)
	if req.Interval != 2500*time.Millisecond {
		t.Fatalf("a sane interval is honoured: %v", req.Interval)
	}
}

func TestACIBAPollNeverGoesOutAtOrAfterTheRequestsExpiry(t *testing.T) {
	k := keyFor(t, EdDSA)
	p := newPlatform(t, k)
	p.cibaExpires = 12
	p.cibaDefault = "pending"
	a := p.agent(k)
	req, _ := a.RequestUserApproval(context.Background(), "jane", "msg", nil, 0)
	_, err := a.AwaitUserToken(context.Background(), req)
	var te *TokenError
	if !errors.As(err, &te) || te.Code != CodeExpiredToken {
		t.Fatalf("%v", err)
	}
	if n := len(p.tokenForms(grantCIBA)); n != 2 {
		t.Fatalf("polls at 5 s and 10 s only, got %d", n)
	}
}

func TestACIBARequestedExpiryUnderASecondIsOneSecond(t *testing.T) {
	k := keyFor(t, EdDSA)
	p := newPlatform(t, k)
	if _, err := p.agent(k).RequestUserApproval(context.Background(), "jane", "msg", []string{"a.read", "b.write"}, 500*time.Millisecond); err != nil {
		t.Fatal(err)
	}
	bc := p.backchannel[0]
	if bc.Get("requested_expiry") != "1" || bc.Get("scope") != "a.read b.write" {
		t.Fatalf("%v", bc)
	}
}

// --- the delegated token ---

func TestDelegatedTokenWaitsOnItsOwnContextAndKeepsAUsableToken(t *testing.T) {
	var renewals atomic.Int32
	release := make(chan struct{})
	now := time.Now()
	cur := Token{secret: authfi.NewSecret("old"), Expiry: now.Add(30 * time.Second)} // inside the renewal skew, still valid
	d := newDelegated(cur, ViaExchange, func(ctx context.Context) (Token, error) {
		renewals.Add(1)
		select {
		case <-release:
			return Token{}, errors.New("platform down")
		case <-ctx.Done():
			return Token{}, ctx.Err()
		}
	}, func() time.Time { return now })

	first := make(chan Token, 1)
	go func() { tok, _ := d.Token(context.Background()); first <- tok }()
	time.Sleep(100 * time.Millisecond) // the first caller is inside the slow renewal
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	start := time.Now()
	if _, err := d.Token(ctx); !errors.Is(err, context.DeadlineExceeded) || time.Since(start) > time.Second {
		t.Fatalf("a waiting caller leaves on its own deadline: %v after %s", err, time.Since(start))
	}
	close(release)
	if tok := <-first; tok.Reveal() != "old" {
		t.Fatalf("a failed renewal of a still-valid token returns the valid one, got %q", tok.Reveal())
	}
}

func TestDelegatedTokenRenewalIsKept(t *testing.T) {
	k := keyFor(t, EdDSA)
	p := newPlatform(t, k)
	a := p.agent(k)
	d, err := a.Exchange(context.Background(), authfi.NewSecret("person"), nil, "")
	if err != nil {
		t.Fatal(err)
	}
	p.advance(9*time.Minute + 30*time.Second)
	for i := 0; i < 3; i++ {
		if _, err := d.Token(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	if n := len(p.tokenForms(grantTokenExchange)); n != 2 {
		t.Fatalf("one renewal, kept for later calls: exchanges %d", n)
	}
}

func TestAZeroDelegatedTokenIsAnErrorNotAPanic(t *testing.T) {
	var d DelegatedToken
	if _, err := d.Token(context.Background()); err == nil {
		t.Fatal("expected an error")
	}
	var nilD *DelegatedToken
	if _, err := nilD.Token(context.Background()); err == nil {
		t.Fatal("expected an error")
	}
}

func TestLabelSubjectRejectsControlCharacters(t *testing.T) {
	for _, sub := range []string{`a\u001bb`, `a\u0007b`, `a\u007fb`} {
		if got := labelSubject("x." + b64([]byte(`{"sub":"`+sub+`"}`)) + ".y"); got != "" {
			t.Errorf("%q kept", got)
		}
	}
}

// --- approvals ---

func TestApprovalIDsThatWalkThePathAreRefused(t *testing.T) {
	k := keyFor(t, EdDSA)
	p := newPlatform(t, k)
	a := p.agent(k)
	for _, id := range []string{".", ".."} {
		if _, err := a.ApprovalStatus(context.Background(), id); err == nil {
			t.Errorf("%q accepted", id)
		}
	}
	if len(p.approvalAuth) != 0 {
		t.Fatal("nothing is sent for a refused id")
	}
}

func TestAnApprovalEndpointWithoutAnIDSlotIsNotUsed(t *testing.T) {
	k := keyFor(t, EdDSA)
	p := newPlatform(t, k)
	p.approvalNoID = true
	if _, err := p.agent(k).ApprovalStatus(context.Background(), "a"); !errors.Is(err, ErrApprovalStatusNotOffered) {
		t.Fatalf("%v", err)
	}
	if len(p.approvalAuth) != 0 {
		t.Fatal("the agent's token must not go to a fixed URL")
	}
}

// --- limits ---

func TestAReplyLargerThanTheCapIsRefusedEvenWhenItIsValidJSON(t *testing.T) {
	k := keyFor(t, EdDSA)
	p := newPlatform(t, k)
	p.hugeValid = true
	if _, err := p.agent(k).Token(context.Background()); err == nil {
		t.Fatal("a 2 MiB token reply must not be accepted")
	}
}

func TestRSAKeysAboveTheMaximumAreRefused(t *testing.T) {
	if testing.Short() {
		t.Skip("generating a 4160-bit key takes seconds")
	}
	pk, err := rsa.GenerateKey(rand.Reader, 4160)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := newKey(pk, "k"); err == nil {
		t.Fatal("a 4160-bit RSA key accepted")
	}
	small, _ := rsa.GenerateKey(rand.Reader, 2048)
	if _, err := newKey(small, "k"); err != nil {
		t.Fatalf("2048 bits is fine: %v", err)
	}
}

func TestTheAssertionIDIs128BitsOfHex(t *testing.T) {
	s, err := clientAssertion(keyFor(t, EdDSA), "a", "b", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	c := unverified(t, s.Reveal())
	jti, _ := c["jti"].(string)
	if len(jti) != 32 || strings.Trim(jti, "0123456789abcdef") != "" {
		t.Fatalf("jti %q", jti)
	}
}

func TestAKeyPrintsRedactedEvenWhenCopiedByValue(t *testing.T) {
	k := keyFor(t, EdDSA)
	seed := fmt.Sprint([]byte(k.signer.(interface{ Seed() []byte }).Seed()))
	for _, verb := range verbs {
		if out := fmt.Sprintf(verb, *k); strings.Contains(out, seed) || strings.Contains(out, seed[1:20]) {
			t.Errorf("%s of a Key value shows the key: %.80s", verb, out)
		}
	}
}

// --- the transport ---

type bodyCloser struct {
	closed atomic.Bool
}

func (b *bodyCloser) Read([]byte) (int, error) { return 0, errors.New("eof") }
func (b *bodyCloser) Close() error             { b.closed.Store(true); return nil }

func TestTransportClosesTheBodyItDoesNotSendAndStripsOddlyCasedKeyHeaders(t *testing.T) {
	rec := &recorder{}
	rt, _ := Transport(&staticSource{tok: "T"}, rec, "https://acme.authfi.io")
	body := &bodyCloser{}
	req, _ := http.NewRequest("POST", "https://evil.example/", body)
	if _, err := rt.RoundTrip(req); !errors.Is(err, ErrDestinationNotAllowed) || !body.closed.Load() {
		t.Fatal("a body that is not sent is closed")
	}
	body2 := &bodyCloser{}
	rt2, _ := Transport(&staticSource{err: errors.New("no token")}, rec, "https://acme.authfi.io")
	req2, _ := http.NewRequest("POST", "https://acme.authfi.io/", body2)
	if _, err := rt2.RoundTrip(req2); err == nil || !body2.closed.Load() {
		t.Fatal("a body is closed when the token fails")
	}

	req3, _ := http.NewRequest("GET", "https://acme.authfi.io/", nil)
	req3.Header["x-api-key"] = []string{"LEFTOVER"}
	req3.Header["authorization"] = []string{"Bearer other"}
	if _, err := rt.RoundTrip(req3); err != nil {
		t.Fatal(err)
	}
	for k, v := range rec.got.Header {
		if strings.EqualFold(k, "x-api-key") || (strings.EqualFold(k, "authorization") && k != "Authorization") || strings.Contains(strings.Join(v, ""), "LEFTOVER") {
			t.Fatalf("header %s survived: %v", k, v)
		}
	}
	if rec.got.Header.Get("Authorization") != "Bearer T" {
		t.Fatal("the token is set")
	}
}

// --- the gateway's answers ---

func TestAHoldIsAHoldWhateverTheIDLooksLike(t *testing.T) {
	for _, text := range []string{
		"Waiting for approval apr/1+2 (approval_required). A person must approve",
		"  waiting   for approval   APR_9 (APPROVAL_REQUIRED). A person",
		"Waiting for approval apr_1. A person must approve this action in the AuthFI console.",
	} {
		o := ReadResult(ToolResult{IsError: true, Text: text})
		if o.Kind != Held || o.ApprovalID == "" || o.ModelText() != HoldMessage {
			t.Errorf("%q: %+v", text, o)
		}
	}
}

func TestAnErrorThatOnlyStartsWithTheSameWordsIsNotAHold(t *testing.T) {
	for _, text := range []string{
		"Waiting for approval from your manager timed out",
		"waiting for approval service to start: connection refused",
		"Waiting for approval",
		"Waiting for approval failed (timeout)",
		"Waiting for approval from (admin) timed out",
		"Waiting for approval aborted (cancelled)",
	} {
		if o := ReadResult(ToolResult{IsError: true, Text: text}); o.Kind != Result || o.Text != text {
			t.Errorf("%q: %+v", text, o)
		}
	}
	o := ReadResult(ToolResult{IsError: true, Text: "Waiting for approval apr_1. A person must approve this action"})
	if o.Kind != Held || o.ApprovalID != "apr_1" {
		t.Fatalf("trailing punctuation is not part of the id: %+v", o)
	}
}

func TestARefusalNeverCarriesTheApprovalIDInAnyCaseOrCount(t *testing.T) {
	o := ReadResult(ToolResult{IsError: true, Meta: map[string]any{RefusalMeta: map[string]any{
		"code": "denied_APR_9", "reason": "approval apr_9 was denied; see APR_9 and apr_9 again", "approval_id": "apr_9"}}})
	if text := strings.ToLower(o.ModelText() + o.Code + o.Reason); strings.Contains(text, "apr_9") {
		t.Fatalf("%q", o.ModelText())
	}
}

func TestARefusalReasonNeverCarriesTheApprovalID(t *testing.T) {
	o := ReadResult(ToolResult{IsError: true, Meta: map[string]any{RefusalMeta: map[string]any{
		"code": "c", "reason": "approval apr_SECRET was denied", "approval_id": "apr_SECRET"}}})
	if strings.Contains(o.ModelText(), "apr_SECRET") || strings.Contains(o.Reason, "apr_SECRET") {
		t.Fatalf("%q", o.ModelText())
	}
}

func TestACIBAExpiryThatOverflowsIsClamped(t *testing.T) {
	k := keyFor(t, EdDSA)
	p := newPlatform(t, k)
	p.cibaExpires = 9223372037
	req, err := p.agent(k).RequestUserApproval(context.Background(), "jane", "msg", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	if req.ExpiresAt.Before(p.clock()) || req.ExpiresAt.After(p.clock().Add(400*24*time.Hour)) {
		t.Fatalf("expires %s", req.ExpiresAt)
	}
}

func TestAConfigurationOutageDoesNotBlockWhatTheMetadataAlreadyNames(t *testing.T) {
	k := keyFor(t, EdDSA)
	p := newPlatform(t, k)
	p.configStatus = 500
	p.backchannelInMetadata = true
	a := p.agent(k)
	if _, err := a.RequestUserApproval(context.Background(), "jane", "msg", nil, 0); err != nil {
		t.Fatalf("the authorization server metadata names the endpoint: %v", err)
	}
}

func TestAConfigurationOutageIsRetriedAtMostOncePerMinute(t *testing.T) {
	k := keyFor(t, EdDSA)
	p := newPlatform(t, k)
	p.configStatus = 500
	a := p.agent(k)
	for i := 0; i < 20; i++ {
		_, _ = a.ApprovalStatus(context.Background(), "a")
	}
	if p.asHits != 1 {
		t.Fatalf("20 calls during an outage fetched the metadata %d times, want 1", p.asHits)
	}
	p.advance(2 * time.Minute)
	_, _ = a.ApprovalStatus(context.Background(), "a")
	if p.asHits != 2 {
		t.Fatalf("after a minute it tries again: %d", p.asHits)
	}
}

func TestAFailedRenewalIsNotRetriedOnEveryCallAndNeverServesAnExpiredToken(t *testing.T) {
	var renewals atomic.Int32
	now := time.Now()
	clock := func() time.Time { return now }
	cur := Token{secret: authfi.NewSecret("old"), Expiry: now.Add(30 * time.Second)}
	d := newDelegated(cur, ViaExchange, func(ctx context.Context) (Token, error) {
		renewals.Add(1)
		return Token{}, &TokenError{Code: CodeInvalidGrant}
	}, clock)
	for i := 0; i < 10; i++ {
		if tok, err := d.Token(context.Background()); err != nil || tok.Reveal() != "old" {
			t.Fatalf("the valid token is served: %v", err)
		}
	}
	if renewals.Load() != 1 {
		t.Fatalf("10 calls sent %d exchanges, want 1", renewals.Load())
	}
	now = now.Add(31 * time.Second) // past expiry and past the back-off
	_, err := d.Token(context.Background())
	var te *TokenError
	if !errors.As(err, &te) || te.Code != CodeInvalidGrant {
		t.Fatalf("an expired token is never served: %v", err)
	}
	if renewals.Load() != 2 {
		t.Fatalf("the back-off ends: %d", renewals.Load())
	}
	_, err = d.Token(context.Background())
	if err == nil || renewals.Load() != 2 {
		t.Fatalf("and starts again: %v %d", err, renewals.Load())
	}
}

func TestANilHTTPClientOptionIsIgnored(t *testing.T) {
	if _, err := New("https://acme.authfi.io", "a", keyFor(t, EdDSA), WithHTTPClient(nil)); err != nil {
		t.Fatal(err)
	}
}

func TestACIBAExpiryNearMaxInt64IsClamped(t *testing.T) {
	k := keyFor(t, EdDSA)
	p := newPlatform(t, k)
	if _, err := p.agent(k).RequestUserApproval(context.Background(), "jane", "msg", nil, time.Duration(1<<62)); err != nil {
		t.Fatal(err)
	}
	if got := p.backchannel[0].Get("requested_expiry"); got != fmt.Sprint(maxLifetime) {
		t.Fatalf("requested_expiry %s", got)
	}
}

func TestACallerGivingUpDoesNotStartTheRenewalBackoff(t *testing.T) {
	var renewals atomic.Int32
	now := time.Now()
	cur := Token{secret: authfi.NewSecret("old"), Expiry: now.Add(30 * time.Second)}
	d := newDelegated(cur, ViaExchange, func(ctx context.Context) (Token, error) {
		renewals.Add(1)
		<-ctx.Done()
		return Token{}, ctx.Err()
	}, func() time.Time { return now })
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	_, _ = d.Token(ctx)
	_, _ = d.Token(ctx)
	ctx2, cancel2 := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel2()
	_, _ = d.Token(ctx2)
	if renewals.Load() != 3 {
		t.Fatalf("a caller's deadline is not the platform failing: renewals %d, want 3", renewals.Load())
	}
}
