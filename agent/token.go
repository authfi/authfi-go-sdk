package agent

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"time"

	authfi "github.com/authfi/authfi-go-sdk"
)

// assertionLifetime is how long a client assertion lives. The platform refuses one that claims
// more than five minutes.
const assertionLifetime = 60 * time.Second

// maxLifetime bounds a lifetime or an interval a server sends, in seconds.
const maxLifetime = 365 * 24 * 3600

// clientAssertion is an RFC 7523 section 2.2 assertion: iss and sub are the client, aud is the
// endpoint that checks it, jti is fresh. It is a bearer credential for its lifetime, so one is
// signed per request and never kept.
func clientAssertion(k *Key, clientID, audience string, now time.Time) (authfi.Secret, error) {
	if clientID == "" || audience == "" {
		return authfi.Secret{}, errors.New("agent: an assertion needs the agent id and the audience")
	}
	var jti [16]byte
	if _, err := rand.Read(jti[:]); err != nil {
		return authfi.Secret{}, errors.New("agent: no randomness for the assertion id")
	}
	iat := now.Unix()
	header, _ := json.Marshal(map[string]string{"alg": string(k.alg), "typ": "JWT", "kid": k.kid})
	claims, _ := json.Marshal(map[string]any{
		"iss": clientID, "sub": clientID, "aud": audience,
		"jti": hex.EncodeToString(jti[:]), "iat": iat, "exp": iat + int64(assertionLifetime/time.Second),
	})
	signed := b64(header) + "." + b64(claims)
	sig, err := k.sign([]byte(signed))
	if err != nil {
		return authfi.Secret{}, errors.New("agent: the assertion could not be signed")
	}
	return authfi.NewSecret(signed + "." + b64(sig)), nil
}

// OAuth error codes a caller may branch on.
const (
	CodeAuthorizationPending = "authorization_pending"
	CodeSlowDown             = "slow_down"
	CodeAccessDenied         = "access_denied"
	CodeExpiredToken         = "expired_token"
	CodeInvalidGrant         = "invalid_grant"
	CodeInvalidClient        = "invalid_client"
	CodeInvalidTarget        = "invalid_target"
)

// TokenError is the platform's refusal of a token request, or a failure to reach it. Description
// is scrubbed of anything token-shaped. A refusal is never retried.
type TokenError struct {
	Code        string
	Description string
	Status      int
	Err         error
}

func (e *TokenError) Error() string {
	switch {
	case e.Description != "":
		return fmt.Sprintf("agent: %s: %s", e.Code, e.Description)
	case e.Code != "":
		return "agent: " + e.Code
	}
	return "agent: token request failed"
}

func (e *TokenError) Unwrap() error { return e.Err }

// Token is an access token with its expiry. It prints redacted; Reveal is the one place the
// value leaves, such as an HTTP header.
type Token struct {
	secret authfi.Secret
	// Expiry is when the token stops being valid.
	Expiry time.Time
	// Scope is what the platform granted, space separated.
	Scope string
}

// Reveal returns the access token.
func (t Token) Reveal() string { return t.secret.Reveal() }

// valid reports whether the token is set and not within skew of its expiry at now.
func (t Token) valid(now time.Time, skew time.Duration) bool {
	return !t.secret.IsEmpty() && now.Add(skew).Before(t.Expiry)
}

func (t Token) String() string {
	return fmt.Sprintf("agent.Token(expires=%s)", t.Expiry.UTC().Format(time.RFC3339))
}
func (t Token) GoString() string           { return t.String() }
func (t Token) Format(f fmt.State, _ rune) { _, _ = io.WriteString(f, t.String()) }
func (t Token) LogValue() slog.Value       { return slog.StringValue(t.String()) }
func (t Token) MarshalText() ([]byte, error) {
	return []byte(t.String()), nil
}
func (t Token) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Expiry time.Time `json:"expiry"`
		Scope  string    `json:"scope,omitempty"`
	}{t.Expiry, t.Scope})
}

type tokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int64  `json:"expires_in"`
	Scope       string `json:"scope"`
}

// parseToken reads a token endpoint answer. A token with no lifetime is refused: it could never
// be renewed on time.
func parseToken(status int, body []byte, now time.Time, secrets ...string) (Token, error) {
	if status != 200 {
		return Token{}, tokenFailure(status, body, secrets...)
	}
	var r tokenResponse
	if err := json.Unmarshal(body, &r); err != nil || r.AccessToken == "" {
		return Token{}, &TokenError{Code: "invalid_response", Description: "the token endpoint answered no access_token", Status: status}
	}
	if t := strings.ToLower(r.TokenType); t != "" && t != "bearer" {
		return Token{}, &TokenError{Code: "invalid_response", Description: "the token endpoint answered a token type other than Bearer", Status: status}
	}
	if r.ExpiresIn <= 0 {
		return Token{}, &TokenError{Code: "invalid_response", Description: "the token endpoint answered no lifetime", Status: status}
	}
	if r.ExpiresIn > maxLifetime {
		r.ExpiresIn = maxLifetime // a lifetime past this overflows time.Duration, and no token lives a year
	}
	return Token{
		secret: authfi.NewSecret(r.AccessToken),
		Expiry: now.Add(time.Duration(r.ExpiresIn) * time.Second),
		Scope:  r.Scope,
	}, nil
}

// tokenFailure turns an error answer into a TokenError. Only the registered error code and a
// scrubbed description are kept.
func tokenFailure(status int, body []byte, secrets ...string) *TokenError {
	var e struct {
		Code        string `json:"error"`
		Description string `json:"error_description"`
	}
	_ = json.Unmarshal(body, &e)
	code := e.Code
	// The code is a short token by the OAuth rules. One that has anything else in it, or that held a
	// secret the server echoed, is not a code.
	if code == "" || len(code) > 64 || strings.ContainsAny(code, " \t\r\n\"") || authfi.Scrub(code, secrets...) != code {
		code = fmt.Sprintf("http_%d", status)
	}
	return &TokenError{Code: code, Description: authfi.Scrub(e.Description, secrets...), Status: status}
}
