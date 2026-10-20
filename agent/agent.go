package agent

import (
	"context"
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

const (
	assertionType      = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
	grantClientCreds   = "client_credentials"
	grantCIBA          = "urn:openid:params:grant-type:ciba"
	grantTokenExchange = "urn:ietf:params:oauth:grant-type:token-exchange"
	accessTokenType    = "urn:ietf:params:oauth:token-type:access_token"

	renewSkew       = 60 * time.Second
	endpointsTTL    = time.Hour
	maxReply        = 1 << 20
	defaultInterval = 5 * time.Second
	slowDownStep    = 5 * time.Second
	mintAttempts    = 3
)

// Agent is one agent of one project: its key, and the tokens the platform mints for it. It is safe
// for concurrent use; concurrent callers share one mint. It prints redacted.
type Agent struct {
	issuer   string
	id       string
	key      *Key
	http     *http.Client
	resource string
	log      *slog.Logger

	now   func() time.Time
	sleep func(context.Context, time.Duration) error

	sem      chan struct{} // guards the cached token: a one-slot lock that a context can leave
	cached   Token
	renewAt  time.Time
	discSem  chan struct{}
	disc     discovered
	discTime time.Time
}

type discovered struct {
	token       string
	backchannel string
	approval    string
}

// Option configures New.
type Option func(*Agent)

// WithHTTPClient sets the client used for every request. Default: a client with a 30 s timeout.
func WithHTTPClient(c *http.Client) Option { return func(a *Agent) { a.http = c } }

// WithResource sets what the agent's own token is for (RFC 8707): the client id of the API it
// calls. Without it the token is for the AuthFI gateway.
func WithResource(resource string) Option { return func(a *Agent) { a.resource = resource } }

// WithLogger receives one line per mint and per refusal. No token, assertion or key is logged.
func WithLogger(l *slog.Logger) Option { return func(a *Agent) { a.log = l } }

// New makes the agent agentID of the project at issuer. issuer is the project's own issuer, for
// example https://acme.authfi.io: there is no platform default, because an agent signs for the
// issuer it is given. Nothing is fetched until the first call.
func New(issuer, agentID string, key *Key, opts ...Option) (*Agent, error) {
	issuer = strings.TrimRight(strings.TrimSpace(issuer), "/")
	if err := checkOrigin(issuer); err != nil {
		return nil, fmt.Errorf("agent: issuer: %w", err)
	}
	if strings.TrimSpace(agentID) == "" {
		return nil, errors.New("agent: the agent id is required")
	}
	if key == nil {
		return nil, errors.New("agent: the key is required")
	}
	a := &Agent{
		issuer: issuer, id: agentID, key: key,
		http:    &http.Client{Timeout: 30 * time.Second},
		now:     time.Now,
		sleep:   sleepCtx,
		sem:     make(chan struct{}, 1),
		discSem: make(chan struct{}, 1),
	}
	for _, o := range opts {
		o(a)
	}
	return a, nil
}

// ID is the agent id.
func (a *Agent) ID() string { return a.id }

// Issuer is the project issuer.
func (a *Agent) Issuer() string { return a.issuer }

func checkOrigin(raw string) error {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return errors.New("must be an absolute URL without credentials, query or fragment")
	}
	if u.Scheme == "https" {
		return nil
	}
	if h := u.Hostname(); u.Scheme == "http" && (h == "localhost" || h == "127.0.0.1" || h == "::1") {
		return nil
	}
	return errors.New("must use https")
}

func sleepCtx(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func acquire(ctx context.Context, sem chan struct{}) error {
	select {
	case sem <- struct{}{}:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// --- discovery ---

// endpoints returns the endpoints the project publishes. They must sit on the issuer's own host:
// an assertion is a credential, and a discovery document must not be able to redirect it.
func (a *Agent) endpoints(ctx context.Context) (discovered, error) {
	if err := acquire(ctx, a.discSem); err != nil {
		return discovered{}, err
	}
	defer func() { <-a.discSem }()
	if a.disc.token != "" && a.now().Sub(a.discTime) < endpointsTTL {
		return a.disc, nil
	}
	var as struct {
		Issuer      string `json:"issuer"`
		Token       string `json:"token_endpoint"`
		Backchannel string `json:"backchannel_authentication_endpoint"`
	}
	if err := a.getJSON(ctx, a.issuer+"/.well-known/oauth-authorization-server", "", &as); err != nil {
		return discovered{}, fmt.Errorf("agent: discovery: %w", err)
	}
	if strings.TrimRight(as.Issuer, "/") != a.issuer {
		return discovered{}, errors.New("agent: discovery: the metadata names another issuer")
	}
	d := discovered{backchannel: as.Backchannel}
	var err error
	if d.token, err = a.sameHost(as.Token, "token_endpoint"); err != nil {
		return discovered{}, err
	}
	var ac struct {
		Backchannel string `json:"backchannel_authentication_endpoint"`
		Endpoints   struct {
			Approval string `json:"approval"`
		} `json:"endpoints"`
	}
	// The agent configuration is optional: a project without it has no approvals for agents.
	if err := a.getJSON(ctx, a.issuer+"/.well-known/agent-configuration", "", &ac); err == nil {
		if d.backchannel == "" {
			d.backchannel = ac.Backchannel
		}
		d.approval = ac.Endpoints.Approval
	}
	if d.backchannel != "" {
		if d.backchannel, err = a.sameHost(d.backchannel, "backchannel_authentication_endpoint"); err != nil {
			return discovered{}, err
		}
	}
	if d.approval != "" {
		if d.approval, err = a.sameHost(d.approval, "approval endpoint"); err != nil {
			return discovered{}, err
		}
	}
	a.disc, a.discTime = d, a.now()
	return d, nil
}

func (a *Agent) sameHost(raw, what string) (string, error) {
	u, err := url.Parse(raw)
	base, _ := url.Parse(a.issuer)
	if raw == "" || err != nil || u.Scheme != base.Scheme || u.Host != base.Host {
		return "", fmt.Errorf("agent: discovery: %s is missing or not on the issuer's host", what)
	}
	return raw, nil
}

// --- HTTP ---

type reply struct {
	status int
	body   []byte
}

func (a *Agent) do(req *http.Request) (reply, error) {
	req.Header.Set("Accept", "application/json")
	resp, err := a.http.Do(req)
	if err != nil {
		return reply{}, scrubbedNetError(err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxReply+1))
	if err != nil || len(body) > maxReply {
		return reply{}, errors.New("the reply could not be read")
	}
	return reply{status: resp.StatusCode, body: body}, nil
}

// scrubbedNetError keeps the failure and drops the URL, which may carry a query a caller built.
func scrubbedNetError(err error) error {
	var ue *url.Error
	if errors.As(err, &ue) {
		return fmt.Errorf("%s: %w", ue.Op, ue.Err)
	}
	return err
}

func (a *Agent) getJSON(ctx context.Context, rawURL, bearer string, into any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return errors.New("bad URL")
	}
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	r, err := a.do(req)
	if err != nil {
		return err
	}
	if r.status != http.StatusOK {
		return fmt.Errorf("HTTP %d", r.status)
	}
	if err := json.Unmarshal(r.body, into); err != nil {
		return errors.New("the reply is not JSON")
	}
	return nil
}

func (a *Agent) postForm(ctx context.Context, endpoint string, form url.Values) (reply, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return reply{}, errors.New("bad URL")
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return a.do(req)
}

// authForm is a form with the agent's client authentication in it: a fresh assertion for audience.
func (a *Agent) authForm(audience string, fields url.Values) (url.Values, authfi.Secret, error) {
	as, err := clientAssertion(a.key, a.id, audience, a.now())
	if err != nil {
		return nil, authfi.Secret{}, err
	}
	form := url.Values{"client_id": {a.id}, "client_assertion_type": {assertionType}, "client_assertion": {as.Reveal()}}
	for k, v := range fields {
		form[k] = v
	}
	return form, as, nil
}

func (a *Agent) logRefusal(what string, err error) {
	var te *TokenError
	if a.log != nil && errors.As(err, &te) {
		a.log.Warn("agent: refused", "agent", a.id, "request", what, "code", te.Code, "status", te.Status)
	}
}

// --- the agent's own token ---

// Token returns the agent's own token, minting a new one when none is cached or it is within a
// minute of expiry. Each mint signs a fresh assertion. A refusal is a *TokenError and is not
// retried; a network failure is retried twice.
func (a *Agent) Token(ctx context.Context) (Token, error) {
	if err := acquire(ctx, a.sem); err != nil {
		return Token{}, err
	}
	defer func() { <-a.sem }()
	if !a.cached.secret.IsEmpty() && a.now().Before(a.renewAt) {
		return a.cached, nil
	}
	tok, err := a.mint(ctx)
	if err != nil {
		a.logRefusal("client_credentials", err)
		return Token{}, err
	}
	skew := renewSkew
	if life := tok.Expiry.Sub(a.now()); life/2 < skew {
		skew = life / 2
	}
	a.cached, a.renewAt = tok, tok.Expiry.Add(-skew)
	if a.log != nil {
		a.log.Info("agent: token minted", "agent", a.id, "expires", tok.Expiry.UTC().Format(time.RFC3339))
	}
	return tok, nil
}

func (a *Agent) mint(ctx context.Context) (Token, error) {
	ep, err := a.endpoints(ctx)
	if err != nil {
		return Token{}, &TokenError{Code: "discovery_failed", Description: authfi.Scrub(err.Error()), Err: err}
	}
	var last error
	for attempt := 0; attempt < mintAttempts; attempt++ {
		if attempt > 0 {
			if err := a.sleep(ctx, time.Duration(attempt)*200*time.Millisecond); err != nil {
				return Token{}, err
			}
		}
		fields := url.Values{"grant_type": {grantClientCreds}}
		if a.resource != "" {
			fields.Set("resource", a.resource)
		}
		form, assertion, err := a.authForm(ep.token, fields)
		if err != nil {
			return Token{}, err
		}
		r, err := a.postForm(ctx, ep.token, form)
		if err != nil {
			if ctx.Err() != nil {
				return Token{}, ctx.Err()
			}
			last = &TokenError{Code: "unreachable", Description: authfi.Scrub(err.Error(), assertion.Reveal()), Err: err}
			continue
		}
		if r.status == 502 || r.status == 503 || r.status == 504 {
			last = tokenFailure(r.status, r.body, assertion.Reveal())
			continue
		}
		return parseToken(r.status, r.body, a.now(), assertion.Reveal())
	}
	return Token{}, last
}

// TokenSource is the agent's own token as an oauth2.TokenSource, for libraries that take one. It
// mints on demand with a 30 s deadline per call.
func (a *Agent) TokenSource() oauth2.TokenSource { return tokenSource{a.Token} }

type tokenSource struct {
	get func(context.Context) (Token, error)
}

func (s tokenSource) Token() (*oauth2.Token, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	t, err := s.get(ctx)
	if err != nil {
		return nil, err
	}
	return &oauth2.Token{AccessToken: t.Reveal(), TokenType: "Bearer", Expiry: t.Expiry}, nil
}

func (a *Agent) String() string {
	return fmt.Sprintf("agent.Agent(issuer=%s, id=%s, key=%s)", a.issuer, a.id, a.key)
}
func (a *Agent) GoString() string           { return a.String() }
func (a *Agent) Format(f fmt.State, _ rune) { _, _ = io.WriteString(f, a.String()) }
func (a *Agent) LogValue() slog.Value       { return slog.StringValue(a.String()) }
func (a *Agent) MarshalJSON() ([]byte, error) {
	return json.Marshal(map[string]string{"issuer": a.issuer, "id": a.id})
}
