package agent

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	authfi "github.com/authfi/authfi-go-sdk"
)

// INSTANCE SIGN-IN
//
// An agent bound to a workload holds no long-lived secret. Each execution (an instance) makes a key in
// memory, shows the platform where it runs (Evidence), receives an attestation (15 minutes at most) and
// presents it at the token endpoint with a proof of the same key and a DPoP proof. The token is bound to
// the instance key, so every call carries Authorization: DPoP and a fresh proof: use DPoPTransport.
//
//	ev := agent.KubernetesEvidence("")
//	cfg := agent.Configuration{Version: 3, Digest: "sha256:..."}
//	a, err := agent.NewInstance("https://acme.authfi.io", "agt_...", ev, cfg)
//	rt, err := a.DPoPTransport(nil, "https://api.example.com")
//
// The instance key is made on the first sign-in (or the first DPoPTransport), never at New, so a
// process snapshot taken before that holds no key to clone.

const (
	attestPath    = "/apis/regional/v1/ai/agents/attest"
	challengePath = attestPath + "/challenge"

	typAttestation = "oauth-client-attestation+jwt"
	typPoP         = "oauth-client-attestation-pop+jwt"
	typProof       = "authfi-instance-proof+jwt"

	headerAttestation = "OAuth-Client-Attestation"
	headerPoP         = "OAuth-Client-Attestation-PoP"

	// maxAttestationLifetime is the longest the platform signs an attestation for.
	maxAttestationLifetime = 900
	popLifetime            = 60
)

var (
	instanceIDRE  = regexp.MustCompile(`^inst_[0-9a-f]{32}$`)
	imageDigestRE = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
)

// Configuration names the approved configuration an instance runs: the version of the agent's
// configuration and the digest of the profile it runs. The platform attests no instance without one.
// The zero value is not a configuration.
type Configuration struct {
	Version int
	Digest  string

	observe bool
}

// ObserveConfiguration asks to be admitted naming no version, so that what the instance does can be
// observed and a version approved from it. The platform admits this only while a person has an
// observation window open for the agent, and an instance admitted this way cannot ask a person or
// act for one. It is never the default: an instance that names nothing is refused before anything
// is sent.
func ObserveConfiguration() Configuration { return Configuration{observe: true} }

// IsObserve reports whether c asks to be observed.
func (c Configuration) IsObserve() bool { return c.observe }

func (c Configuration) validate() error {
	switch {
	case c.observe && (c.Version != 0 || c.Digest != ""):
		return errors.New("agent: an instance runs an approved version or asks to be observed, not both")
	case c.observe:
		return nil
	case c.Version < 1 || !strings.HasPrefix(c.Digest, "sha256:") || len(c.Digest) == len("sha256:"):
		return errors.New("agent: an instance runs one approved configuration: set Configuration{Version, Digest} " +
			"(the approved version number and sha256:<hex>), or use ObserveConfiguration while a person is " +
			"observing the agent. The platform attests no instance without one")
	}
	return nil
}

// WithImageDigest states the digest (sha256:<64 hex>) of the image the instance executes. Optional.
func WithImageDigest(digest string) Option { return func(a *Agent) { a.imageDigest = digest } }

// WithAPIOrigin sets where the project's machine APIs are served, for a project on a custom domain.
// Default: the issuer's origin.
func WithAPIOrigin(origin string) Option { return func(a *Agent) { a.apiOrigin = origin } }

// instance is the state of an agent that signs in by attestation.
type instance struct {
	evidence Evidence
	cfg      Configuration

	mu  sync.Mutex // guards key and att
	key *Key
	att *attestation
}

// attestation is a platform-signed statement that this instance, with this key, is the agent's.
type attestation struct {
	token      authfi.Secret
	instanceID string
	expires    time.Time
	jkt        string
}

// NewInstance makes the agent agentID of the project at issuer, signing in as an instance of it:
// evidence shows where it runs and cfg is the approved configuration it executes. Nothing is
// fetched, and no key is made, until the first call. The result is an *Agent: Token, TokenSource and
// DPoPTransport work as for a key-file agent. WithDPoP is refused: an instance's token is bound to
// its own key.
//
// Acting for a person (RequestUserApproval, Exchange) is not yet available to an instance and
// returns a *TokenError with code "not_supported".
func NewInstance(issuer, agentID string, ev Evidence, cfg Configuration, opts ...Option) (*Agent, error) {
	if ev == nil {
		return nil, errors.New("agent: the evidence is required: KubernetesEvidence or DeviceEvidence")
	}
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	base, err := newAgent(issuer, agentID, opts...)
	if err != nil {
		return nil, err
	}
	base.inst = &instance{evidence: ev, cfg: cfg}
	switch {
	case base.dpop != nil:
		return nil, errors.New("agent: WithDPoP does not apply to an instance: its token is bound to its own key")
	case base.imageDigest != "" && !imageDigestRE.MatchString(base.imageDigest):
		return nil, errors.New("agent: the image digest is sha256: and 64 lowercase hex digits")
	case base.apiOrigin != "":
		base.apiOrigin = strings.TrimRight(strings.TrimSpace(base.apiOrigin), "/")
		if err := checkOrigin(base.apiOrigin); err != nil {
			return nil, fmt.Errorf("agent: api origin: %w", err)
		}
	}
	return base, nil
}

// NewInstanceFromEnv makes the instance the environment describes, or says what is missing.
//
//	AUTHFI_ISSUER               the project's own address (required)
//	AUTHFI_AGENT_ID             agt_... (required)
//	AUTHFI_DEVICE_KEY_FILE      the device key the agent was bound with (device evidence), with
//	AUTHFI_DEVICE_KEY_KID       its key id (optional)
//	AUTHFI_SERVICE_ACCOUNT_TOKEN_FILE  where the projected token is (default KubernetesTokenPath)
//	AUTHFI_CONFIG_VERSION, AUTHFI_CONFIG_DIGEST  the approved configuration this instance runs
//	AUTHFI_CONFIG_OBSERVE=1     instead of the two above, to be observed
//	AUTHFI_IMAGE_DIGEST         the image digest (optional)
//	AUTHFI_API_ORIGIN           where machine APIs are served (optional)
//	AUTHFI_AGENT_RESOURCE       the API the agent's token is for (optional)
//
// Device evidence is used when AUTHFI_DEVICE_KEY_FILE is set, even if a Kubernetes token is also
// there (the Python SDK has the same order); else the Kubernetes token when its file is there.
// Options are applied after the environment, so an option overrides the variable that names the same
// setting.
func NewInstanceFromEnv(opts ...Option) (*Agent, error) {
	return newInstanceFromLookup(os.Getenv, fileExists, opts...)
}

func fileExists(path string) bool {
	st, err := os.Stat(path)
	return err == nil && st.Mode().IsRegular()
}

func newInstanceFromLookup(get func(string) string, exists func(string) bool, opts ...Option) (*Agent, error) {
	env := func(k string) string { return strings.TrimSpace(get(k)) }
	issuer, agentID := env("AUTHFI_ISSUER"), env("AUTHFI_AGENT_ID")
	if issuer == "" {
		return nil, errors.New("agent: AUTHFI_ISSUER is not set: set it to your project's own address, for example https://acme.authfi.io")
	}
	if agentID == "" {
		return nil, errors.New("agent: AUTHFI_AGENT_ID is required (agt_...)")
	}
	var ev Evidence
	switch device, named := env("AUTHFI_DEVICE_KEY_FILE"), env("AUTHFI_SERVICE_ACCOUNT_TOKEN_FILE"); {
	case device != "":
		key, err := LoadKey(device, env("AUTHFI_DEVICE_KEY_KID"))
		if err != nil {
			return nil, fmt.Errorf("agent: cannot use the device key in AUTHFI_DEVICE_KEY_FILE: %w", err)
		}
		if ev, err = DeviceEvidence(key); err != nil {
			return nil, err
		}
	case named != "" || exists(KubernetesTokenPath):
		ev = KubernetesEvidence(named)
	default:
		return nil, fmt.Errorf("agent: this agent shows no evidence of where it runs: on Kubernetes project a "+
			"service-account token at %s (or name it in AUTHFI_SERVICE_ACCOUNT_TOKEN_FILE); on a device set AUTHFI_DEVICE_KEY_FILE",
			KubernetesTokenPath)
	}
	cfg, err := configurationFrom(env)
	if err != nil {
		return nil, err
	}
	var extra []Option
	if v := env("AUTHFI_IMAGE_DIGEST"); v != "" {
		extra = append(extra, WithImageDigest(v))
	}
	if v := env("AUTHFI_API_ORIGIN"); v != "" {
		extra = append(extra, WithAPIOrigin(v))
	}
	if v := env("AUTHFI_AGENT_RESOURCE"); v != "" {
		extra = append(extra, WithResource(v))
	}
	return NewInstance(issuer, agentID, ev, cfg, append(extra, opts...)...)
}

func configurationFrom(env func(string) string) (Configuration, error) {
	version, digest := env("AUTHFI_CONFIG_VERSION"), env("AUTHFI_CONFIG_DIGEST")
	switch raw := strings.ToLower(env("AUTHFI_CONFIG_OBSERVE")); raw {
	case "", "0", "false":
	case "1", "true":
		if version != "" || digest != "" {
			return Configuration{}, errors.New("agent: an instance runs an approved version or asks to be observed, not both: " +
				"unset AUTHFI_CONFIG_OBSERVE, or unset AUTHFI_CONFIG_VERSION and AUTHFI_CONFIG_DIGEST")
		}
		return ObserveConfiguration(), nil
	default:
		return Configuration{}, fmt.Errorf("agent: AUTHFI_CONFIG_OBSERVE is 1 to be observed, or unset; got %q", raw)
	}
	n, err := strconv.Atoi(version)
	if err != nil || n < 1 || !strings.HasPrefix(digest, "sha256:") {
		return Configuration{}, fmt.Errorf("agent: AUTHFI_CONFIG_VERSION is the approved version number and "+
			"AUTHFI_CONFIG_DIGEST is sha256:<hex>; got %q and %q. A new agent that a person is observing asks for "+
			"that with AUTHFI_CONFIG_OBSERVE=1", version, digest)
	}
	return Configuration{Version: n, Digest: digest}, nil
}

// InstanceID is the id the platform gave this instance, once it has signed in; empty before.
func (a *Agent) InstanceID() string {
	if a.inst == nil {
		return ""
	}
	a.inst.mu.Lock()
	defer a.inst.mu.Unlock()
	if a.inst.att == nil {
		return ""
	}
	return a.inst.att.instanceID
}

// instanceKey is the instance's key, made on first use.
func (in *instance) instanceKey() (*Key, error) {
	in.mu.Lock()
	defer in.mu.Unlock()
	if in.key == nil {
		k, err := GenerateKey(EdDSA, "")
		if err != nil {
			return nil, err
		}
		in.key = k
	}
	return in.key, nil
}

// dpopKey is the key tokens are bound to: the instance's own, or the one given to WithDPoP.
func (a *Agent) dpopKey() (*Key, error) {
	if a.inst != nil {
		return a.inst.instanceKey()
	}
	return a.dpop, nil
}

func (a *Agent) machineOrigin() string {
	if a.apiOrigin != "" {
		return a.apiOrigin
	}
	return issuerOrigin(a.issuer)
}

// errInstanceNoAssertion is what an instance answers where an agent key would sign a client assertion.
var errInstanceNoAssertion = &TokenError{
	Code: "not_supported",
	Description: "an instance holds no agent key, so it signs no client assertion: it authenticates with its " +
		"attestation and its DPoP-bound token. Acting for a person is not yet available to an instance",
}

// held returns the attestation when it has more than skew left and is for the current key.
func (in *instance) held(now time.Time, skew time.Duration) *attestation {
	in.mu.Lock()
	defer in.mu.Unlock()
	if in.att != nil && in.key != nil && in.att.jkt == in.key.Thumbprint() && in.att.expires.Sub(now) > skew {
		return in.att
	}
	return nil
}

// attested returns the instance's attestation, asking the platform for a new one (challenge, evidence,
// attest) when none is held or it has less than a minute left. The attest request is never sent
// again once it may have arrived: its evidence works once. The caller holds the agent's token lock.
func (a *Agent) attested(ctx context.Context) (*attestation, error) {
	in := a.inst
	key, err := in.instanceKey()
	if err != nil {
		return nil, &TokenError{Code: "attestation_failed", Description: "the instance key could not be made", Err: err}
	}
	if held := in.held(a.now(), renewSkew); held != nil {
		return held, nil
	}
	origin := a.machineOrigin()
	nonce, err := a.challenge(ctx, origin)
	if err != nil {
		return nil, err
	}
	jkt := key.Thumbprint()
	now := a.now()
	ev, err := in.evidence.evidence(ctx, evidenceInput{Nonce: nonce, AgentID: a.id, InstanceKeyJkt: jkt, Issuer: a.issuer, Now: now})
	if err != nil {
		return nil, &TokenError{Code: "evidence_unavailable", Description: authfi.Scrub(err.Error()), Err: err}
	}
	jti, err := randomID()
	if err != nil {
		return nil, &TokenError{Code: "attestation_failed", Description: err.Error(), Err: err}
	}
	proof, err := key.signJWT(typProof, map[string]any{
		"nonce": nonce, "agent_id": a.id, "aud": a.issuer, "iat": now.Unix(), "jti": jti,
	})
	if err != nil {
		return nil, &TokenError{Code: "attestation_failed", Description: "the instance proof could not be signed", Err: err}
	}
	body := map[string]any{
		"agent_id":     a.id,
		"evidence":     map[string]string{"kind": in.evidence.Kind(), "token": ev},
		"instance_key": key.PublicJWK(),
		"config":       map[string]any{"version": in.cfg.Version, "digest": in.cfg.Digest},
		"proof":        proof,
	}
	if a.imageDigest != "" {
		body["image_digest"] = a.imageDigest
	}
	secrets := []string{ev, proof, nonce}
	r, err := a.postJSON(ctx, origin+attestPath, body)
	if err != nil {
		return nil, &TokenError{Code: "unreachable", Description: authfi.Scrub(err.Error(), secrets...), Err: err}
	}
	if r.status != http.StatusOK {
		return nil, a.attestFailure(r, secrets)
	}
	att, perr := parseAttestation(r.body, a.id, jkt, a.now())
	if perr != nil {
		return nil, &TokenError{Code: "invalid_response", Description: authfi.Scrub(perr.Error(), secrets...), Status: r.status}
	}
	in.mu.Lock()
	in.att = att
	in.mu.Unlock()
	if a.log != nil {
		a.log.Info("agent: instance attested", "agent", a.id, "instance", att.instanceID,
			"expires", att.expires.UTC().Format(time.RFC3339))
	}
	return att, nil
}

func (a *Agent) challenge(ctx context.Context, origin string) (string, error) {
	r, err := a.postJSON(ctx, origin+challengePath, map[string]any{})
	if err != nil {
		return "", &TokenError{Code: "unreachable", Description: authfi.Scrub(err.Error()), Err: err}
	}
	if r.status != http.StatusOK {
		return "", a.attestFailure(r, nil)
	}
	var c struct {
		Nonce string `json:"nonce"`
	}
	if json.Unmarshal(r.body, &c) != nil || c.Nonce == "" {
		return "", &TokenError{Code: "invalid_response", Description: "the attestation challenge answered no nonce", Status: r.status}
	}
	return c.Nonce, nil
}

func (a *Agent) postJSON(ctx context.Context, endpoint string, body any) (reply, error) {
	raw, err := json.Marshal(body)
	if err != nil {
		return reply{}, errors.New("the request could not be encoded")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(raw))
	if err != nil {
		return reply{}, errors.New("bad URL")
	}
	req.Header.Set("Content-Type", "application/json")
	return a.do(req)
}

// What the person reading a refusal can do. The attest route gives every failed sign-in the same 401
// (it must not say which agents exist, what they are bound to, or which part of the evidence was wrong),
// so these cannot name the cause: the reason is on the project's audit tape as agent.attest.refused.
const (
	hintRefused = "The platform refuses every failed sign-in the same way. Its reason is on the audit tape " +
		"(agent.attest.refused): the binding of the agent's workload, the evidence kind, a service-account token " +
		"used once or older than 600 seconds, the approved configuration version and digest, and a pod the cluster " +
		"does not report running are the causes to check."
	hintObserve = "This instance asked to be observed, which the platform admits only while a person has an observation " +
		"window open for the agent: ask a person to open one in the console, or set AUTHFI_CONFIG_VERSION and " +
		"AUTHFI_CONFIG_DIGEST. The platform's own reason is on the audit tape (agent.attest.refused)."
	hintUnavailable = "The platform could not decide just now. Sign in again: the SDK asks for a new challenge, and a " +
		"service-account token that may have been spent needs the pod to have rotated to a fresh one."
)

// attestFailure is the platform's refusal of a challenge or an attest, with what to check.
func (a *Agent) attestFailure(r reply, secrets []string) *TokenError {
	te := tokenFailure(r.status, r.body, secrets...)
	hint := ""
	switch r.status {
	case http.StatusUnauthorized:
		hint = hintRefused
		if a.inst != nil && a.inst.cfg.IsObserve() {
			hint = hintObserve
		}
		te.Code = "attestation_refused"
	case http.StatusServiceUnavailable:
		hint, te.Code = hintUnavailable, "attestation_unavailable"
	}
	if hint != "" {
		if te.Description != "" {
			te.Description += ". "
		}
		te.Description += hint
	}
	return te
}

// parseAttestation takes the checks a client can make: the attestation names this agent and this
// instance key, an instance id, and a lifetime within the cap. The platform's signature is the
// platform's to prove, at the token endpoint.
func parseAttestation(body []byte, agentID, jkt string, now time.Time) (*attestation, error) {
	var resp struct {
		Attestation string `json:"attestation"`
	}
	if json.Unmarshal(body, &resp) != nil || resp.Attestation == "" {
		return nil, errors.New("the attest route answered no attestation")
	}
	header, claims, err := jwtParts(resp.Attestation)
	if err != nil {
		return nil, errors.New("the attestation is not a JWT")
	}
	if typ, _ := header["typ"].(string); typ != typAttestation {
		return nil, fmt.Errorf("the attestation has typ %q, not %s", typ, typAttestation)
	}
	if sub, _ := claims["sub"].(string); sub != agentID {
		return nil, fmt.Errorf("the attestation is for %q, not %s", sub, agentID)
	}
	if got := cnfThumbprint(claims["cnf"]); got != jkt {
		return nil, errors.New("the attestation is bound to a different key than this instance's")
	}
	var instID string
	if inst, ok := claims["authfi_instance"].(map[string]any); ok {
		instID, _ = inst["instance_id"].(string)
	}
	if !instanceIDRE.MatchString(instID) {
		return nil, errors.New("the attestation names no instance_id (inst_ and 32 hex digits)")
	}
	iat, ok1 := claims["iat"].(float64)
	exp, ok2 := claims["exp"].(float64)
	switch {
	case !ok1 || !ok2:
		return nil, errors.New("the attestation has no lifetime")
	case exp-iat > maxAttestationLifetime:
		return nil, fmt.Errorf("the attestation lives longer than %d seconds", maxAttestationLifetime)
	case !now.Before(time.Unix(int64(exp), 0)):
		return nil, errors.New("the attestation has already expired (is the clock right?)")
	case time.Unix(int64(exp), 0).Sub(now) <= renewSkew:
		// Held with a minute or less left it would be renewed on every call.
		return nil, errors.New("the attestation has a minute or less left (is the clock right?)")
	}
	return &attestation{token: authfi.NewSecret(resp.Attestation), instanceID: instID, expires: time.Unix(int64(exp), 0), jkt: jkt}, nil
}

// cnfThumbprint is the RFC 7638 thumbprint of cnf.jwk, or "" for anything that is not a key this SDK makes.
func cnfThumbprint(cnf any) string {
	m, ok := cnf.(map[string]any)
	if !ok {
		return ""
	}
	raw, ok := m["jwk"].(map[string]any)
	if !ok {
		return ""
	}
	jwk := map[string]string{}
	for _, name := range []string{"kty", "crv", "x", "y", "n", "e"} {
		if v, ok := raw[name].(string); ok {
			jwk[name] = v
		}
	}
	need := map[string][]string{"OKP": {"crv", "x"}, "EC": {"crv", "x", "y"}, "RSA": {"n", "e"}}[jwk["kty"]]
	if need == nil {
		return ""
	}
	for _, n := range need {
		if jwk[n] == "" {
			return ""
		}
	}
	return thumbprint(jwk)
}

// postInstanceToken sends a client_credentials request authenticated by the held attestation, a proof
// of the instance key and a DPoP proof. The proofs are made fresh for each call.
func (a *Agent) postInstanceToken(ctx context.Context, endpoint string, fields url.Values) (reply, error) {
	in := a.inst
	att := in.held(a.now(), 0)
	if att == nil {
		return reply{}, errors.New("the instance has no valid attestation")
	}
	key, err := in.instanceKey()
	if err != nil {
		return reply{}, err
	}
	form := url.Values{"client_id": {a.id}}
	for k, v := range fields {
		form[k] = v
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return reply{}, errors.New("bad URL")
	}
	now := a.now()
	jti, err := randomID()
	if err != nil {
		return reply{}, err
	}
	pop, err := key.signJWT(typPoP, map[string]any{
		"iss": a.id, "aud": a.issuer, "jti": jti, "iat": now.Unix(), "exp": now.Unix() + popLifetime,
	})
	if err != nil {
		return reply{}, errors.New("agent: the attestation proof could not be signed")
	}
	dpop, err := key.dpopProof(http.MethodPost, proofURL(req.URL), "", a.getNonce(), now)
	if err != nil {
		return reply{}, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set(headerAttestation, att.token.Reveal())
	req.Header.Set(headerPoP, pop)
	req.Header.Set(headerDPoP, dpop)
	return a.do(req)
}

func randomID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", errors.New("agent: no randomness for the proof id")
	}
	return hex.EncodeToString(b[:]), nil
}

// signJWT signs a compact JWT of the given typ with the key.
func (k *Key) signJWT(typ string, claims map[string]any) (string, error) {
	header, _ := json.Marshal(map[string]string{"alg": string(k.alg), "typ": typ})
	body, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	signed := b64(header) + "." + b64(body)
	sig, err := k.sign([]byte(signed))
	if err != nil {
		return "", errors.New("agent: the JWT could not be signed")
	}
	return signed + "." + b64(sig), nil
}

// dpopBound reports whether this agent's tokens are DPoP-bound: an instance's always are.
func (a *Agent) dpopBound() bool { return a.inst != nil || a.dpop != nil }
