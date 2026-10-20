package agent

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	authfi "github.com/authfi/authfi-go-sdk"
)

func TestParseTokenRefusesIncompleteAnswers(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	for name, body := range map[string]string{
		"no access_token": `{"token_type":"Bearer","expires_in":60}`,
		"not JSON":        `<html>`,
		"MAC token":       `{"access_token":"x","token_type":"mac","expires_in":60}`,
		"no lifetime":     `{"access_token":"x","token_type":"Bearer"}`,
		"negative life":   `{"access_token":"x","token_type":"Bearer","expires_in":-5}`,
	} {
		if _, err := parseToken(200, []byte(body), now); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	tok, err := parseToken(200, []byte(`{"access_token":"x","token_type":"bearer","expires_in":60,"scope":"a b"}`), now)
	if err != nil || tok.Reveal() != "x" || !tok.Expiry.Equal(now.Add(time.Minute)) || tok.Scope != "a b" {
		t.Fatalf("%+v %v", tok, err)
	}
	if _, err := parseToken(201, []byte(`{"access_token":"x","expires_in":60}`), now); err == nil {
		t.Fatal("only 200 is a token answer")
	}
}

func TestTokenFailureKeepsOnlyARegisteredShapedCode(t *testing.T) {
	te := tokenFailure(400, []byte(`{"error":"invalid_grant","error_description":"bad: Bearer abcdefgh12345678"}`), "SECRET-VALUE")
	if te.Code != "invalid_grant" || te.Status != 400 || strings.Contains(te.Description, "abcdefgh") {
		t.Fatalf("%+v", te)
	}
	for _, body := range []string{`not json`, `{"error":"has space"}`, `{"error":"` + strings.Repeat("x", 100) + `"}`, `{"error":"a\"b"}`, `{}`} {
		if got := tokenFailure(502, []byte(body)); got.Code != "http_502" {
			t.Errorf("%q: code %q", body, got.Code)
		}
	}
	if s := (&TokenError{Code: "c", Description: "d"}).Error(); s != "agent: c: d" {
		t.Fatal(s)
	}
	if s := (&TokenError{Code: "c"}).Error(); s != "agent: c" {
		t.Fatal(s)
	}
	if s := (&TokenError{}).Error(); s == "" {
		t.Fatal("an empty TokenError still says something")
	}
	inner := errors.New("inner")
	if !errors.Is(&TokenError{Err: inner}, inner) {
		t.Fatal("Unwrap")
	}
}

func TestLabelSubjectReadsOnlyAShortSingleLineSub(t *testing.T) {
	tok := func(sub string) string {
		return "x." + b64([]byte(`{"sub":"`+sub+`"}`)) + ".y"
	}
	if got := labelSubject(tok("user:jane")); got != "user:jane" {
		t.Fatal(got)
	}
	for name, raw := range map[string]string{"two parts": "a.b", "bad base64": "a.!!.c", "not json": "a." + b64([]byte("x")) + ".c",
		"long": tok(strings.Repeat("a", 300)), "newline": "a." + b64([]byte(`{"sub":"a\nb"}`)) + ".c"} {
		if got := labelSubject(raw); got != "" {
			t.Errorf("%s: %q", name, got)
		}
	}
}

func TestAccessorsAndOptions(t *testing.T) {
	k := keyFor(t, EdDSA)
	p := newPlatform(t, k)
	custom := &http.Client{Timeout: time.Second}
	a := p.agent(k, WithHTTPClient(custom))
	if a.ID() != testAgentID || a.Issuer() != p.issuer() || a.http.Timeout != time.Second {
		t.Fatal("accessors")
	}
	if !strings.Contains(a.GoString(), testAgentID) || strings.Contains(a.GoString(), "PRIVATE") {
		t.Fatal(a.GoString())
	}
	for _, s := range []string{k.GoString(), (Token{}).GoString()} {
		if s == "" {
			t.Fatal("GoString")
		}
	}
}

func TestDelegatedTokenSourceAndGoString(t *testing.T) {
	k := keyFor(t, EdDSA)
	p := newPlatform(t, k)
	a := p.agent(k)
	d, err := a.Exchange(context.Background(), authfi.NewSecret("person"), nil, "")
	if err != nil {
		t.Fatal(err)
	}
	tok, err := d.TokenSource().Token()
	if err != nil || tok.AccessToken == "" {
		t.Fatalf("%v", err)
	}
	if strings.Contains(d.GoString(), tok.AccessToken) || !strings.Contains(d.GoString(), ViaExchange) {
		t.Fatal(d.GoString())
	}
	if (&CIBARequest{}).GoString() == "" {
		t.Fatal("CIBARequest GoString")
	}
}

func TestAwaitUserTokenNeedsARequest(t *testing.T) {
	k := keyFor(t, EdDSA)
	p := newPlatform(t, k)
	a := p.agent(k)
	if _, err := a.AwaitUserToken(context.Background(), nil); err == nil {
		t.Fatal("nil request")
	}
	if _, err := a.AwaitUserToken(context.Background(), &CIBARequest{}); err == nil {
		t.Fatal("empty request")
	}
}

func TestRequestUserApprovalRejectsNegativeExpiryAndBadAnswers(t *testing.T) {
	k := keyFor(t, EdDSA)
	p := newPlatform(t, k)
	a := p.agent(k)
	if _, err := a.RequestUserApproval(context.Background(), "jane", "msg", nil, -time.Second); err == nil {
		t.Fatal("negative expiry")
	}
	if len(p.backchannel) != 0 {
		t.Fatal("nothing sent")
	}
}

func TestApprovalIDIsRequiredAndAnswersAreChecked(t *testing.T) {
	k := keyFor(t, EdDSA)
	p := newPlatform(t, k)
	a := p.agent(k)
	if _, err := a.ApprovalStatus(context.Background(), " "); err == nil {
		t.Fatal("empty id")
	}
	p.approvalBody = `{"status":"approved"}`
	if _, err := a.ApprovalStatus(context.Background(), "a"); err == nil {
		t.Fatal("an answer without approval_id")
	}
	p.approvalBody = `{"error":"nope"}`
	p.approvalCode = 500
	if _, err := a.ApprovalStatus(context.Background(), "a"); err == nil {
		t.Fatal("a 500")
	}
	if !(Approval{}).Pending() || !(Approval{Status: "pending"}).Pending() || (Approval{Status: "approved"}).Pending() {
		t.Fatal("Pending")
	}
}
