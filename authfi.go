// Package authfi verifies the access tokens a project's AuthFI issuer mints, and guards Go
// HTTP handlers with them.
//
// Usage:
//
//	auth := authfi.New(authfi.Config{
//	    Issuer:   "https://acme.authfi.io",     // the project issuer
//	    Audience: []string{"my-api-client-id"}, // required: the client id of this API
//	})
//
//	// chi router
//	r.With(auth.Require("read:users")).Get("/api/users", handler)
//
//	// net/http
//	http.Handle("/api/users", auth.Require("read:users")(handler))
//
// The keys are read from the issuer's key set. Person, agent, CIBA and delegated tokens all
// verify; an ID token is refused as an access token.
package authfi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"
)

// Config configures a Client. It holds secrets (ClientSecret, APIKey), so it prints redacted when
// printed as a Config, in JSON and in slog. New moves the secrets into the Client as Secret values
// and keeps no copy of them in a string, so printing a Client by any route shows none.
type Config struct {
	// Issuer is the project issuer, for example https://acme.authfi.io. Required to verify tokens.
	Issuer string
	// Audience is the client id of this API. A token must name one of these in aud. Required:
	// there is no way to skip the check, and AuthFI's own audiences (the issuer, anything under
	// it, authfi-console, authfi-workspace) are refused.
	Audience []string
	// TenantID, when set, must equal the tenant_id of every token. Set it; a server that trusts
	// more than one issuer cannot leave it out.
	TenantID string
	// Leeway is the clock skew allowed on exp, nbf and iat. Zero means 60 s, negative means none,
	// and the most is 300 s.
	Leeway time.Duration
	// Revocations, when set, makes Verify refuse a token whose subject (or, on a delegated token,
	// actor) was revoked after the token was issued. Feed it with a Receiver (NewReceiver) or
	// with Revoke. Without it no revocation is checked.
	Revocations *RevocationStore
	// HTTPClient fetches the key set of the issuer. Default: a client with a 10 s timeout.
	HTTPClient *http.Client
	// Logger receives refusal codes (never a token). Default: no logging.
	Logger *slog.Logger

	Tenant        string
	APIKey        string // Deprecated: AuthFI does not issue API keys. Used only by Sync.
	APIURL        string // Deprecated: used only by Sync, CloudCredentials and CloudToken. Default: https://api.authfi.io
	ApplicationID string // client_id of your application
	ClientSecret  string // client_secret: required for cloud identity
	AutoSync      bool
	JWKSRefresh   time.Duration // default: 5 min
}

// Client verifies tokens and guards handlers. It prints redacted.
type Client struct {
	cfg          Config // ClientSecret and APIKey are blank here; see clientSecret and apiKey
	clientSecret Secret
	apiKey       Secret
	api          *http.Client // management and cloud calls: a redirect is an error, not a hop
	cfgErr       error
	permissions  map[string]*string // name → description
	mu           sync.Mutex
	keys         *keySet
	clock        func() time.Time // tests only
}

type Claims struct {
	Subject       string   `json:"sub"`
	Email         string   `json:"email"`
	EmailVerified bool     `json:"email_verified"`
	Name          string   `json:"name"`
	Roles         []string `json:"roles"`
	Permissions   []string `json:"permissions"`
	TenantID      string   `json:"tenant_id"`
	OrgID         string   `json:"org_id"`
	OrgSlug       string   `json:"org_slug"`
	OrgRole       string   `json:"org_role"`
	IssuedAt      int64    `json:"iat"`
	ExpiresAt     int64    `json:"exp"`
	Issuer        string   `json:"iss"`

	// Set by Verify.
	Audience []string `json:"-"`
	Actor    string   `json:"-"` // act.sub: who acts for Subject, on a delegated token
	ClientID string   `json:"client_id"`
	Scope    string   `json:"scope"`
	JTI      string   `json:"jti"`
}

type contextKey struct{}

// New builds a Client. A configuration that verification cannot run with (no Issuer, no Audience,
// an AuthFI audience) is not a panic: every verification then fails closed with the reason, and
// Validate returns it.
func New(cfg Config) *Client {
	if cfg.APIURL == "" {
		cfg.APIURL = "https://api.authfi.io"
	}
	if cfg.JWKSRefresh == 0 {
		cfg.JWKSRefresh = 5 * time.Minute
	}
	if cfg.HTTPClient == nil {
		cfg.HTTPClient = &http.Client{Timeout: jwksFetchTimeout}
	}
	c := &Client{
		cfg: cfg, clientSecret: NewSecret(cfg.ClientSecret), apiKey: NewSecret(cfg.APIKey),
		permissions: make(map[string]*string),
		api: &http.Client{
			Timeout:       30 * time.Second,
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
	}
	c.cfg.ClientSecret, c.cfg.APIKey = "", ""
	c.cfgErr = checkConfig(c.cfg)
	c.keys = &keySet{
		url:     trimIssuer(cfg.Issuer) + jwksPath,
		ttl:     cfg.JWKSRefresh,
		timeout: jwksFetchTimeout,
		client:  cfg.HTTPClient,
		now:     c.now,
	}
	return c
}

// Validate returns why this Client cannot verify tokens, or nil.
func (c *Client) Validate() error { return c.cfgErr }

// Require returns middleware that validates JWT and checks all listed permissions.
func (c *Client) Require(permissions ...string) func(http.Handler) http.Handler {
	// Register for auto-sync
	for _, p := range permissions {
		c.RegisterPermission(p, "")
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			claims, err := c.authenticate(r)
			if err != nil {
				writeAuthError(w, err)
				return
			}

			userPerms := toSet(claims.Permissions)
			for _, required := range permissions {
				if !userPerms[required] {
					writeJSON(w, http.StatusForbidden, map[string]string{"error": "insufficient permissions", "missing": required})
					return
				}
			}

			ctx := context.WithValue(r.Context(), contextKey{}, claims)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// RequireRole returns middleware that validates JWT and checks for any listed role.
func (c *Client) RequireRole(roles ...string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			claims, err := c.authenticate(r)
			if err != nil {
				writeAuthError(w, err)
				return
			}

			userRoles := toSet(claims.Roles)
			found := false
			for _, role := range roles {
				if userRoles[role] {
					found = true
					break
				}
			}
			if !found {
				writeJSON(w, http.StatusForbidden, map[string]string{"error": "insufficient role"})
				return
			}

			ctx := context.WithValue(r.Context(), contextKey{}, claims)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// Authenticate returns middleware that validates JWT without permission checks.
func (c *Client) Authenticate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		claims, err := c.authenticate(r)
		if err != nil {
			writeAuthError(w, err)
			return
		}
		ctx := context.WithValue(r.Context(), contextKey{}, claims)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// GetUser extracts claims from request context (set by middleware).
func GetUser(ctx context.Context) *Claims {
	claims, _ := ctx.Value(contextKey{}).(*Claims)
	return claims
}

// RegisterPermission registers a permission for auto-sync.
func (c *Client) RegisterPermission(name, description string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if description != "" {
		c.permissions[name] = &description
	} else if _, exists := c.permissions[name]; !exists {
		c.permissions[name] = nil
	}
}

// Start pre-fetches JWKS and syncs permissions.
func (c *Client) Start() error {
	if c.cfgErr != nil {
		return c.cfgErr
	}
	ctx, cancel := context.WithTimeout(context.Background(), jwksFetchTimeout)
	defer cancel()
	if err := c.keys.load(ctx); err != nil {
		return fmt.Errorf("authfi: JWKS fetch failed: %w", err)
	}

	if c.cfg.AutoSync {
		return c.Sync()
	}
	return nil
}

// Sync pushes registered permissions to AuthFI.
func (c *Client) Sync() error {
	c.mu.Lock()
	if len(c.permissions) == 0 {
		c.mu.Unlock()
		return nil
	}

	type perm struct {
		Name        string  `json:"name"`
		Description *string `json:"description,omitempty"`
	}
	perms := make([]perm, 0, len(c.permissions))
	for name, desc := range c.permissions {
		perms = append(perms, perm{Name: name, Description: desc})
	}
	c.mu.Unlock()

	body := map[string]interface{}{"permissions": perms}
	if c.cfg.ApplicationID != "" {
		body["application_id"] = c.cfg.ApplicationID
	}

	data, _ := json.Marshal(body)
	url := fmt.Sprintf("%s/%s/v1/permissions/sync", c.cfg.APIURL, c.cfg.Tenant)
	req, _ := http.NewRequest("PUT", url, bytes.NewReader(data))
	req.Header.Set("X-API-Key", c.apiKey.Reveal())
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.api.Do(req)
	if err != nil {
		return fmt.Errorf("authfi: sync failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("authfi: sync failed (%d): %s", resp.StatusCode, c.serverText(resp.Body))
	}

	var result struct{ Synced, Total int }
	json.NewDecoder(resp.Body).Decode(&result)
	if c.cfg.Logger != nil {
		c.cfg.Logger.Info("authfi: permissions synced", "synced", result.Synced, "total", result.Total)
	}
	return nil
}

// CloudCredentials gets cloud provider credentials using an AuthFI user token.
// Requires ApplicationID and ClientSecret in Config — cloud credentials are scoped
// per application so each app can only access the cloud resources its IAM role permits.
func (c *Client) CloudCredentials(userToken, provider string, opts map[string]string) (map[string]interface{}, error) {
	if c.cfg.ApplicationID == "" || c.clientSecret.IsEmpty() {
		return nil, fmt.Errorf("authfi: ApplicationID and ClientSecret required for cloud credentials")
	}

	body := map[string]interface{}{
		"provider": provider,
		"ttl":      900,
	}
	for k, v := range opts {
		body[k] = v
	}

	data, _ := json.Marshal(body)
	authURL := fmt.Sprintf("%s/%s/v1/credentials", c.cfg.APIURL, c.cfg.Tenant)
	req, _ := http.NewRequest("POST", authURL, bytes.NewReader(data))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+userToken)
	req.Header.Set("X-Client-ID", c.cfg.ApplicationID)
	req.Header.Set("X-Client-Secret", c.clientSecret.Reveal())

	resp, err := c.api.Do(req)
	if err != nil {
		return nil, fmt.Errorf("cloud credentials request failed: %s", Scrub(err.Error(), c.clientSecret.Reveal(), userToken))
	}
	defer resp.Body.Close()

	if resp.StatusCode/100 != 2 {
		return nil, fmt.Errorf("cloud credentials failed (%d): %s", resp.StatusCode, c.serverText(resp.Body, userToken))
	}

	var result map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("cloud credentials failed: the reply is not JSON")
	}
	return result, nil
}

// CloudToken gets a raw OIDC token for manual federation.
// Requires ApplicationID and ClientSecret in Config.
func (c *Client) CloudToken(userToken, audience string, ttl int) (string, error) {
	if c.cfg.ApplicationID == "" || c.clientSecret.IsEmpty() {
		return "", fmt.Errorf("authfi: ApplicationID and ClientSecret required for cloud token")
	}

	body, _ := json.Marshal(map[string]interface{}{"audience": audience, "ttl": ttl})
	authURL := fmt.Sprintf("%s/%s/v1/credentials/token", c.cfg.APIURL, c.cfg.Tenant)
	req, _ := http.NewRequest("POST", authURL, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+userToken)
	req.Header.Set("X-Client-ID", c.cfg.ApplicationID)
	req.Header.Set("X-Client-Secret", c.clientSecret.Reveal())

	resp, err := c.api.Do(req)
	if err != nil {
		return "", fmt.Errorf("cloud token request failed: %s", Scrub(err.Error(), c.clientSecret.Reveal(), userToken))
	}
	defer resp.Body.Close()

	if resp.StatusCode/100 != 2 {
		return "", fmt.Errorf("cloud token failed (%d): %s", resp.StatusCode, c.serverText(resp.Body, userToken))
	}
	var result struct {
		Token string `json:"token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil || result.Token == "" {
		return "", fmt.Errorf("cloud token failed: the reply holds no token")
	}
	return result.Token, nil
}

// serverText reads a bounded part of a server reply for an error, with every secret this client
// holds scrubbed out of it.
func (c *Client) serverText(body io.Reader, extra ...string) string {
	b, _ := io.ReadAll(io.LimitReader(body, maxEchoed*4))
	return Scrub(string(b), append([]string{c.clientSecret.Reveal(), c.apiKey.Reveal()}, extra...)...)
}

// String, GoString and Format print the issuer and the client id and nothing secret.
func (c Config) String() string {
	return fmt.Sprintf("authfi.Config{Issuer:%q Audience:%q Tenant:%q ApplicationID:%q}", c.Issuer, c.Audience, c.Tenant, c.ApplicationID)
}
func (c Config) GoString() string           { return c.String() }
func (c Config) Format(f fmt.State, _ rune) { _, _ = io.WriteString(f, c.String()) }
func (c Config) LogValue() slog.Value {
	return slog.GroupValue(slog.String("issuer", c.Issuer), slog.String("tenant", c.Tenant), slog.String("application_id", c.ApplicationID))
}

// MarshalJSON leaves every secret out.
func (c Config) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Issuer        string   `json:"issuer"`
		Audience      []string `json:"audience"`
		TenantID      string   `json:"tenant_id,omitempty"`
		Tenant        string   `json:"tenant,omitempty"`
		ApplicationID string   `json:"application_id,omitempty"`
	}{c.Issuer, c.Audience, c.TenantID, c.Tenant, c.ApplicationID})
}

func (c *Client) String() string               { return "authfi.Client{" + c.cfg.String() + "}" }
func (c *Client) GoString() string             { return c.String() }
func (c *Client) Format(f fmt.State, _ rune)   { _, _ = io.WriteString(f, c.String()) }
func (c *Client) MarshalJSON() ([]byte, error) { return c.cfg.MarshalJSON() }

func (c *Client) authenticate(r *http.Request) (*Claims, error) {
	scheme, token, ok := strings.Cut(strings.TrimSpace(r.Header.Get("Authorization")), " ")
	if !ok || !strings.EqualFold(scheme, "Bearer") || strings.TrimSpace(token) == "" {
		return nil, refuse(CodeMissingBearer, "send the access token as Authorization: Bearer <token>")
	}
	return c.Verify(r.Context(), strings.TrimSpace(token))
}

// writeAuthError answers 401, or 503 when verification cannot run, with a JSON body holding only
// the refusal code.
func writeAuthError(w http.ResponseWriter, err error) {
	code, status := CodeMalformed, http.StatusUnauthorized
	var e *Error
	if errors.As(err, &e) {
		code = e.Code
		if code == CodeKeySetUnavailable || code == CodeNotConfigured {
			status = http.StatusServiceUnavailable
		}
	}
	if status == http.StatusUnauthorized {
		w.Header().Set("WWW-Authenticate", `Bearer error="invalid_token"`)
	}
	writeJSON(w, status, map[string]string{"error": code})
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

// --- helpers ---

func toSet(s []string) map[string]bool {
	m := make(map[string]bool, len(s))
	for _, v := range s {
		m[v] = true
	}
	return m
}
