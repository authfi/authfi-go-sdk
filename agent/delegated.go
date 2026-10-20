package agent

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	authfi "github.com/authfi/authfi-go-sdk"
	"golang.org/x/oauth2"
)

// How a delegated token came about.
const (
	ViaCIBA     = "ciba"
	ViaExchange = "exchange"
)

// CIBARequest is a pending request for a person's approval. The handle is a bearer value and is
// held as a Secret.
type CIBARequest struct {
	authReqID authfi.Secret
	// ExpiresAt is when the platform stops waiting for the person.
	ExpiresAt time.Time
	// Interval is how often the platform wants to be polled.
	Interval time.Duration
	// ApprovalURL, when the platform sends one, is where the person can approve.
	ApprovalURL string
	// Resource, when set, is the API the resulting token is for. Default: the agent's resource.
	Resource string
}

func (r *CIBARequest) String() string {
	return fmt.Sprintf("agent.CIBARequest(expires=%s, interval=%s)", r.ExpiresAt.UTC().Format(time.RFC3339), r.Interval)
}
func (r *CIBARequest) GoString() string           { return r.String() }
func (r *CIBARequest) Format(f fmt.State, _ rune) { _, _ = io.WriteString(f, r.String()) }
func (r *CIBARequest) LogValue() slog.Value       { return slog.StringValue(r.String()) }
func (r *CIBARequest) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		ExpiresAt   time.Time `json:"expires_at"`
		ApprovalURL string    `json:"approval_url,omitempty"`
	}{r.ExpiresAt, r.ApprovalURL})
}

// RequestUserApproval asks a person to approve the agent acting for them (OpenID CIBA, poll
// mode). loginHint says which person; bindingMessage is what they read on their own device
// ("Refund order 4411"), so both are required. scope is what the agent will do. expiry is how
// long to wait; zero leaves it to the platform.
//
// The request creates state at the platform, so it is never sent twice.
func (a *Agent) RequestUserApproval(ctx context.Context, loginHint, bindingMessage string, scope []string, expiry time.Duration) (*CIBARequest, error) {
	if strings.TrimSpace(loginHint) == "" {
		return nil, errors.New("agent: loginHint is required: the platform must know which person to ask")
	}
	if strings.TrimSpace(bindingMessage) == "" {
		return nil, errors.New("agent: bindingMessage is required: it is what the person reads before approving")
	}
	if expiry < 0 {
		return nil, errors.New("agent: expiry must not be negative")
	}
	ep, err := a.endpoints(ctx)
	if err != nil {
		return nil, &TokenError{Code: "discovery_failed", Description: authfi.Scrub(err.Error()), Err: err}
	}
	if ep.configErr != nil {
		return nil, &TokenError{Code: "discovery_failed", Description: authfi.Scrub(ep.configErr.Error()), Err: ep.configErr}
	}
	if ep.backchannel == "" {
		return nil, &TokenError{Code: "unsupported", Description: "this project offers no user approval (CIBA) to agents"}
	}
	fields := url.Values{"login_hint": {strings.TrimSpace(loginHint)}, "binding_message": {strings.TrimSpace(bindingMessage)}}
	if len(scope) > 0 {
		fields.Set("scope", strings.Join(scope, " "))
	}
	if expiry > 0 {
		secs := int((expiry + time.Second - 1) / time.Second) // rounded up: under a second is not "none"
		fields.Set("requested_expiry", fmt.Sprint(secs))
	}
	form, assertion, err := a.authForm(ep.token, fields)
	if err != nil {
		return nil, err
	}
	r, err := a.postForm(ctx, ep.backchannel, form)
	if err != nil {
		return nil, &TokenError{Code: "unreachable", Description: authfi.Scrub(err.Error(), assertion.Reveal()), Err: err}
	}
	if r.status != http.StatusOK {
		te := tokenFailure(r.status, r.body, assertion.Reveal())
		a.logRefusal("ciba", te)
		return nil, te
	}
	var body struct {
		AuthReqID   string  `json:"auth_req_id"`
		ExpiresIn   int64   `json:"expires_in"`
		Interval    float64 `json:"interval"`
		ApprovalURL string  `json:"approval_url"`
	}
	if json.Unmarshal(r.body, &body) != nil || body.AuthReqID == "" {
		return nil, &TokenError{Code: "invalid_response", Description: "the CIBA endpoint answered no auth_req_id", Status: r.status}
	}
	if body.ExpiresIn <= 0 {
		body.ExpiresIn = 300
	}
	if body.ExpiresIn > maxLifetime {
		body.ExpiresIn = maxLifetime
	}
	interval := defaultInterval
	if body.Interval >= 1 && body.Interval <= 300 { // under a second would be a hot loop; over five minutes is nonsense
		interval = time.Duration(body.Interval * float64(time.Second))
	}
	return &CIBARequest{
		authReqID:   authfi.NewSecret(body.AuthReqID),
		ExpiresAt:   a.now().Add(time.Duration(body.ExpiresIn) * time.Second),
		Interval:    interval,
		ApprovalURL: body.ApprovalURL,
		Resource:    a.resource,
	}, nil
}

// AwaitUserToken polls until the person decides and returns the token whose subject is the person
// and whose actor is this agent. It waits Interval before the first poll, signs a fresh assertion
// for every poll, adds five seconds on slow_down (and on an HTTP 429), and keeps waiting on
// authorization_pending. access_denied, expired_token, invalid_grant and every other refusal
// return at once as a *TokenError. A cancelled ctx returns ctx.Err(); the request stays open at
// the platform.
//
// The token is never renewed: the approval was for it. After expiry, Token returns expired_token.
func (a *Agent) AwaitUserToken(ctx context.Context, req *CIBARequest) (*DelegatedToken, error) {
	if req == nil || req.authReqID.IsEmpty() {
		return nil, errors.New("agent: a CIBARequest from RequestUserApproval is required")
	}
	ep, err := a.endpoints(ctx)
	if err != nil {
		return nil, &TokenError{Code: "discovery_failed", Description: authfi.Scrub(err.Error()), Err: err}
	}
	wait := req.Interval
	if wait <= 0 {
		wait = defaultInterval
	}
	for {
		if !a.now().Add(wait).Before(req.ExpiresAt) {
			return nil, &TokenError{Code: CodeExpiredToken, Description: "the person did not decide in time"}
		}
		if err := a.sleep(ctx, wait); err != nil {
			return nil, err
		}
		fields := url.Values{"grant_type": {grantCIBA}, "auth_req_id": {req.authReqID.Reveal()}}
		if req.Resource != "" {
			fields.Set("resource", req.Resource)
		}
		form, assertion, err := a.authForm(ep.token, fields)
		if err != nil {
			return nil, err
		}
		r, err := a.postForm(ctx, ep.token, form)
		if err != nil {
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			return nil, &TokenError{Code: "unreachable", Description: authfi.Scrub(err.Error(), assertion.Reveal(), req.authReqID.Reveal()), Err: err}
		}
		if r.status == http.StatusOK {
			tok, err := parseToken(r.status, r.body, a.now(), assertion.Reveal(), req.authReqID.Reveal())
			if err != nil {
				return nil, err
			}
			return newDelegated(tok, ViaCIBA, nil, a.now), nil
		}
		te := tokenFailure(r.status, r.body, assertion.Reveal(), req.authReqID.Reveal())
		switch {
		case te.Code == CodeSlowDown || r.status == http.StatusTooManyRequests:
			wait += slowDownStep
		case te.Code == CodeAuthorizationPending:
		default:
			a.logRefusal("ciba_poll", te)
			return nil, te
		}
	}
}

// Exchange trades a person's access token for a token whose subject is that person and whose
// actor is this agent (RFC 8693). The agent authenticates with its own current token as
// actor_token, so the request carries no client assertion. scope and resource narrow the result.
//
// The exchange creates state at the platform, so it is never sent twice. The result is renewed by
// exchanging again for as long as subject stays valid.
func (a *Agent) Exchange(ctx context.Context, subject authfi.Secret, scope []string, resource string) (*DelegatedToken, error) {
	if subject.IsEmpty() {
		return nil, errors.New("agent: the person's token is required")
	}
	if resource == "" {
		resource = a.resource
	}
	exchange := func(ctx context.Context) (Token, error) {
		ep, err := a.endpoints(ctx)
		if err != nil {
			return Token{}, &TokenError{Code: "discovery_failed", Description: authfi.Scrub(err.Error()), Err: err}
		}
		own, err := a.Token(ctx)
		if err != nil {
			return Token{}, err
		}
		form := url.Values{
			"grant_type":         {grantTokenExchange},
			"subject_token":      {subject.Reveal()},
			"subject_token_type": {accessTokenType},
			"actor_token":        {own.Reveal()},
			"actor_token_type":   {accessTokenType},
		}
		if len(scope) > 0 {
			form.Set("scope", strings.Join(scope, " "))
		}
		if resource != "" {
			form.Set("resource", resource)
		}
		r, err := a.postForm(ctx, ep.token, form)
		if err != nil {
			if ctx.Err() != nil {
				return Token{}, ctx.Err()
			}
			return Token{}, &TokenError{Code: "unreachable", Description: authfi.Scrub(err.Error(), subject.Reveal(), own.Reveal()), Err: err}
		}
		tok, err := parseToken(r.status, r.body, a.now(), subject.Reveal(), own.Reveal())
		if err != nil {
			a.logRefusal("token_exchange", err)
		}
		return tok, err
	}
	tok, err := exchange(ctx)
	if err != nil {
		return nil, err
	}
	return newDelegated(tok, ViaExchange, exchange, a.now), nil
}

// DelegatedToken is a token for a person's delegation to this agent. It prints redacted.
type DelegatedToken struct {
	sem     chan struct{} // one-slot lock that a context can leave
	cur     Token
	via     string
	subject string
	renew   func(context.Context) (Token, error)
	now     func() time.Time
}

func newDelegated(t Token, via string, renew func(context.Context) (Token, error), now func() time.Time) *DelegatedToken {
	return &DelegatedToken{sem: make(chan struct{}, 1), cur: t, via: via, renew: renew, now: now, subject: labelSubject(t.Reveal())}
}

// Via is ViaCIBA or ViaExchange.
func (d *DelegatedToken) Via() string { return d.via }

// Subject is the person the token is for, read from the token for display. It is a label, not a
// verified claim: deciding is the resource server's job.
func (d *DelegatedToken) Subject() string { return d.subject }

// Token returns the current token. An exchanged token is exchanged again within a minute of
// expiry; a CIBA token is not renewed, and Token returns expired_token once it has run out.
func (d *DelegatedToken) Token(ctx context.Context) (Token, error) {
	if d == nil || d.sem == nil {
		return Token{}, errors.New("agent: a DelegatedToken comes from AwaitUserToken or Exchange")
	}
	if err := acquire(ctx, d.sem); err != nil {
		return Token{}, err
	}
	defer func() { <-d.sem }()
	if d.cur.valid(d.now(), renewSkew) {
		return d.cur, nil
	}
	if d.renew == nil {
		if d.cur.valid(d.now(), 0) {
			return d.cur, nil
		}
		return Token{}, &TokenError{Code: CodeExpiredToken, Description: "the person's approval has run out: ask again"}
	}
	t, err := d.renew(ctx)
	if err != nil {
		if d.cur.valid(d.now(), 0) {
			return d.cur, nil // the old token still works; the caller meets the refusal when it runs out
		}
		return Token{}, err
	}
	d.cur = t
	return t, nil
}

// TokenSource is the delegated token as an oauth2.TokenSource.
func (d *DelegatedToken) TokenSource() oauth2.TokenSource { return tokenSource{d.Token} }

func (d *DelegatedToken) String() string {
	return fmt.Sprintf("agent.DelegatedToken(via=%s, subject=%s)", d.via, d.subject)
}
func (d *DelegatedToken) GoString() string           { return d.String() }
func (d *DelegatedToken) Format(f fmt.State, _ rune) { _, _ = io.WriteString(f, d.String()) }
func (d *DelegatedToken) LogValue() slog.Value       { return slog.StringValue(d.String()) }
func (d *DelegatedToken) MarshalJSON() ([]byte, error) {
	return json.Marshal(map[string]string{"via": d.via, "subject": d.subject})
}

// labelSubject reads sub from a token WITHOUT checking its signature, only to label a token this
// SDK just received from the platform.
func labelSubject(raw string) string {
	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		return ""
	}
	b, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return ""
	}
	var c struct {
		Sub string `json:"sub"`
	}
	if json.Unmarshal(b, &c) != nil || len(c.Sub) > 256 {
		return ""
	}
	for _, r := range c.Sub {
		if r < 0x20 || r == 0x7f {
			return "" // a label that reaches a log or a terminal carries no control characters
		}
	}
	return c.Sub
}
