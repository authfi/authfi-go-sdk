package authfi

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"sync"
	"time"
)

// AgentTokenMode says what is checked on an agent token.
type AgentTokenMode string

const (
	// AgentEnforce refuses an agent token without a valid DPoP proof and a proven custody chain. The
	// default: the zero value of Config.AgentTokens.
	AgentEnforce AgentTokenMode = "enforce"
	// AgentWatch runs the same checks, accepts the token when one fails and logs the code once per
	// key and reason window. For a rollout.
	AgentWatch AgentTokenMode = "watch"
	// AgentOff skips the checks that are only for agent tokens. It has to be asked for.
	AgentOff AgentTokenMode = "off"
)

const (
	agentIDPrefix = "agt_"
	// watchWindow is how long a watch-mode refusal of one key for one reason is logged only once.
	watchWindow = time.Minute
	maxWatched  = 1024
)

func (m AgentTokenMode) mode() AgentTokenMode {
	if m == "" {
		return AgentEnforce
	}
	return m
}

// checkAgentConfig validates the settings the agent-token checks depend on.
func checkAgentConfig(cfg Config) error {
	switch cfg.AgentTokens.mode() {
	case AgentEnforce, AgentWatch, AgentOff:
	default:
		return refuse(CodeNotConfigured, "AgentTokens is enforce, watch or off")
	}
	if cfg.NonceKey != nil && len(cfg.NonceKey) < minNonceKeyLen {
		return refuse(CodeNotConfigured, "NonceKey must be at least %d bytes", minNonceKeyLen)
	}
	if _, err := parsePins(cfg.RootPins); err != nil {
		return refuse(CodeNotConfigured, "RootPins: %v", err)
	}
	if cfg.PublicURL != "" {
		if err := checkIssuerURL(cfg.PublicURL); err != nil {
			return refuse(CodeNotConfigured, "PublicURL must be an absolute https URL without query or fragment")
		}
	}
	return nil
}

// isAgentToken reports whether the token is an agent's: an agent id (agt_, any case, spaces
// around ignored) as subject, client, authorized party or agent_id, or an act claim.
func isAgentToken(w *wireClaims) bool {
	for _, id := range []string{w.Subject, w.ClientID, w.Azp, w.AgentID} {
		if strings.HasPrefix(strings.ToLower(strings.TrimSpace(id)), agentIDPrefix) {
			return true
		}
	}
	return present(w.Act)
}

// newProofRequest takes from r what a proof is checked against.
func newProofRequest(r *http.Request) proofRequest {
	return proofRequest{
		method: r.Method, host: r.Host, requestURI: r.RequestURI, path: r.URL.EscapedPath(), tls: r.TLS != nil,
		proofs: r.Header.Values(headerDPoP), forwardedHost: r.Header.Values("X-Forwarded-Host"),
		forwardedProto: r.Header.Values("X-Forwarded-Proto"),
	}
}

// cnfJKT is cnf.jkt, or "" when the token carries none.
func cnfJKT(raw json.RawMessage) string {
	var cnf struct {
		JKT string `json:"jkt"`
	}
	if json.Unmarshal(raw, &cnf) != nil {
		return ""
	}
	return cnf.JKT
}

// presented is a token as the caller sent it: the header, the key that verified it and, for a
// request, the request and the Authorization scheme it came with.
type presented struct {
	token  string
	header tokenHeader
	key    verifyKey
	req    *http.Request // nil for Verify
	scheme string
}

// checkBinding applies the sender-constraint rules of a verified token: a token bound to a key
// needs a DPoP proof for that key, and an agent token also needs its signing key's custody chain.
func (c *Client) checkBinding(ctx context.Context, w *wireClaims, p presented) error {
	agent := isAgentToken(w)
	bound := present(w.Cnf) || present(w.Mandate)
	mode := c.cfg.AgentTokens.mode()
	checked := agent && mode != AgentOff // the agent-only checks run
	if !bound && !checked {
		if p.scheme == schemeDPoP {
			return refuse(CodeMalformed, "the token is not bound to a key: send it as Authorization: Bearer")
		}
		return nil
	}
	err := c.proveBinding(ctx, w, p, agent, checked)
	if err == nil {
		return nil
	}
	if checked && mode == AgentWatch {
		c.watched(p.header.Kid, err)
		return nil
	}
	return err
}

func (c *Client) proveBinding(ctx context.Context, w *wireClaims, p presented, agent, chain bool) error {
	if p.req == nil {
		if agent {
			return refuse(CodeAgentNeedsRequest, "an agent token is verified with the request it came on: use VerifyRequest or Require")
		}
		return refuse(CodeDPoPProofRequired, "the token is bound to a key and cannot be used as a bearer")
	}
	if p.scheme != schemeDPoP {
		return refuse(CodeDPoPProofRequired, "a token bound to a key is sent as Authorization: DPoP")
	}
	jkt := cnfJKT(w.Cnf)
	if jkt == "" {
		return refuse(CodeDPoPProofRequired, "an agent token must be bound to a key (cnf.jkt)")
	}
	proof, perr := verifyProof(newProofRequest(p.req), p.token, proofEnv{now: c.now(), nonces: c.nonces,
		publicURL: c.cfg.PublicURL, trustForwarded: c.cfg.TrustForwarded})
	if perr != nil {
		return perr
	}
	if subtle.ConstantTimeCompare([]byte(proof.thumbprint), []byte(jkt)) != 1 {
		return refuse(CodeDPoPKeyMismatch, "the DPoP proof key is not the key the token is bound to")
	}
	if chain {
		if cerr := c.chain.check(p.key.pub, p.key.x5c, p.key.x5t, p.header.X5tS256, c.now()); cerr != nil {
			return cerr
		}
	}
	// The proof id is spent last: a request that failed any other check does not use it up.
	fresh, err := c.replay.Claim(ctx, proof.id, proof.until)
	switch {
	case errors.Is(err, ErrReplayGuardFull):
		return refuse(CodeDPoPReplayGuardFull, "the replay guard holds too many DPoP proofs")
	case err != nil:
		return refuse(CodeDPoPReplayUnavailable, "the replay guard could not record the DPoP proof")
	case !fresh:
		return refuse(CodeDPoPReplayed, "the DPoP proof was already used")
	}
	return nil
}

// watchLog remembers which key and reason were logged lately, so watch mode logs each once a window.
type watchLog struct {
	mu   sync.Mutex
	seen map[string]time.Time
}

func (c *Client) watched(kid string, err error) {
	code := CodeMalformed
	var e *Error
	if errors.As(err, &e) {
		code = e.Code
	}
	if c.cfg.Logger == nil || !c.watch.firstInWindow(kid+"|"+code, c.now()) {
		return
	}
	c.cfg.Logger.Warn("authfi: agent token accepted in watch mode", "code", code)
}

func (l *watchLog) firstInWindow(key string, now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if at, ok := l.seen[key]; ok && now.Sub(at) < watchWindow {
		return false
	}
	if len(l.seen) >= maxWatched {
		l.seen = map[string]time.Time{}
	}
	l.seen[key] = now
	return true
}

// VerifyRequest verifies the access token on r. It reads Authorization: Bearer for a plain token
// and Authorization: DPoP plus the DPoP header for a token bound to a key, which is every agent
// token unless Config.AgentTokens is off. Forwarding headers are read for the proof's URL only when
// Config.TrustForwarded is set.
func (c *Client) VerifyRequest(r *http.Request) (*Claims, error) {
	if r == nil {
		return nil, refuse(CodeMissingBearer, "no request")
	}
	scheme, token, err := authorization(r)
	if err != nil {
		c.logRefusal(err)
		return nil, err
	}
	claims, err := c.verifyWith(r.Context(), token, r, scheme)
	c.logRefusal(err)
	return claims, err
}

// authorization reads the one Authorization header: scheme Bearer or DPoP, and a token.
func authorization(r *http.Request) (scheme, token string, err error) {
	values := r.Header.Values("Authorization")
	if len(values) != 1 {
		return "", "", refuse(CodeMissingBearer, "send the access token as Authorization: Bearer <token> or DPoP <token>")
	}
	s, t, ok := strings.Cut(strings.TrimSpace(values[0]), " ")
	t = strings.TrimSpace(t)
	switch {
	case !ok || t == "":
	case strings.EqualFold(s, "Bearer"):
		return "Bearer", t, nil
	case strings.EqualFold(s, schemeDPoP):
		return schemeDPoP, t, nil
	}
	return "", "", refuse(CodeMissingBearer, "send the access token as Authorization: Bearer <token> or DPoP <token>")
}

func (c *Client) logRefusal(err error) {
	if err == nil || c.cfg.Logger == nil {
		return
	}
	code, ref := CodeMalformed, ""
	var e *Error
	if errors.As(err, &e) {
		code, ref = e.Code, e.Ref
	}
	c.cfg.Logger.Debug("authfi: token refused", "code", code, "ref", ref)
}

// challenge is the WWW-Authenticate value for a refusal code: a DPoP challenge for the DPoP and
// agent-token codes, a Bearer one otherwise.
func challenge(code string) string {
	switch {
	case code == CodeDPoPNonce:
		return `DPoP algs="EdDSA ES256 PS256", error="use_dpop_nonce"`
	case strings.HasPrefix(code, "dpop_"), strings.HasPrefix(code, "chain_"), code == CodeDPoPProofRequired, code == CodeAgentNeedsRequest:
		return `DPoP algs="EdDSA ES256 PS256", error="invalid_dpop_proof"`
	}
	return `Bearer error="invalid_token"`
}
