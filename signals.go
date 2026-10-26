package authfi

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Event types a Receiver acts on. They are the exact strings the transmitter sends.
const (
	EventSessionRevoked       = "https://schemas.openid.net/secevent/caep/event-type/session-revoked"
	EventTokenClaimsChange    = "https://schemas.openid.net/secevent/caep/event-type/token-claims-change"
	EventAccountPurged        = "https://schemas.openid.net/secevent/risc/event-type/account-purged"
	EventCredentialCompromise = "https://schemas.openid.net/secevent/risc/event-type/credential-compromise"
)

const (
	setTyp         = "secevent+jwt"
	setContentType = "application/secevent+jwt"
	maxSubjectLen  = 512
	maxJTILen      = 256
	maxStreamReply = 64 << 10
)

// RFC 8935 section 2.4 error codes.
const (
	errInvalidRequest   = "invalid_request"
	errInvalidKey       = "invalid_key"
	errInvalidIssuer    = "invalid_issuer"
	errInvalidAudience  = "invalid_audience"
	errAuthnFailed      = "authentication_failed"
	errTemporarilyAbort = "temporarily_unavailable"
)

// Signal is one accepted event, handed to ReceiverConfig.OnSignal after it took effect.
type Signal struct {
	// Event is the event type URI.
	Event string
	// Subject is the subject the event is about, for example "agent:agt_123".
	Subject string
	// JTI is the id of the SET that carried it.
	JTI string
	// IssuedAt is the iat of the SET: the instant before which the subject's tokens are dead,
	// when Revoked.
	IssuedAt time.Time
	// Revoked is true when the event withdrew the subject's access and the store now refuses
	// its tokens issued at or before IssuedAt.
	Revoked bool
	// Resumed is true for a token-claims-change event saying the subject was resumed. It does not
	// lift a revocation: tokens issued after the revocation are accepted without it, and tokens
	// from before stay refused.
	Resumed bool
}

// ReceiverConfig configures a Receiver.
type ReceiverConfig struct {
	// Audience is the audience of your stream, the value you registered as the stream's audience.
	// Required. It is not the audience of your API.
	Audience string
	// AuthToken, when set, is the bearer the transmitter must present on every push, the
	// auth_token you registered with the stream. The signature of the SET is checked either way.
	AuthToken Secret
	// OnSignal, when set, is called once for each accepted event after the store was updated. It
	// runs on the request goroutine: keep it short. A panic in it is recovered and logged.
	OnSignal func(Signal)
}

// Receiver is an http.Handler for the Shared Signals push delivery of RFC 8935. Mount it at the
// endpoint you registered with the stream.
type Receiver struct {
	c      *Client
	cfg    ReceiverConfig
	token  [sha256.Size]byte
	hasTok bool
	seen   *seenSet
	store  *RevocationStore
}

// NewReceiver builds a Receiver that records revocations in Config.Revocations, so the same Client
// refuses the tokens they cover. It fails closed: no store, no audience, or a Client that cannot
// verify (see Validate) is an error and no handler.
func (c *Client) NewReceiver(cfg ReceiverConfig) (*Receiver, error) {
	if c.cfgErr != nil {
		return nil, c.cfgErr
	}
	if c.cfg.Revocations == nil {
		return nil, refuse(CodeNotConfigured, "Config.Revocations is required: the store a Receiver records revocations in and Verify reads")
	}
	if strings.TrimSpace(cfg.Audience) == "" {
		return nil, refuse(CodeNotConfigured, "ReceiverConfig.Audience is required: the audience your stream was registered with")
	}
	r := &Receiver{c: c, cfg: cfg, store: c.cfg.Revocations}
	r.seen = newSeenSet(r.store.max, r.store.life)
	if !cfg.AuthToken.IsEmpty() {
		r.token, r.hasTok = sha256.Sum256([]byte(cfg.AuthToken.Reveal())), true
	}
	return r, nil
}

// ServeHTTP answers 202 for an accepted SET, 400 with {"err","description"} for one it refuses
// (RFC 8935 section 2.4), 401 for a push without the configured bearer, 405 for any method but
// POST and 503 when the issuer's keys cannot be read, which makes the transmitter retry. Nothing
// is recorded unless the SET passed every check.
func (r *Receiver) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method_not_allowed"})
		return
	}
	if r.hasTok && !r.bearerOK(req) {
		r.log("push refused", "code", "bearer")
		w.Header().Set("WWW-Authenticate", `Bearer error="invalid_token"`)
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
		return
	}
	if mt, _, err := mime.ParseMediaType(req.Header.Get("Content-Type")); err != nil || mt != setContentType {
		r.refuse(w, http.StatusBadRequest, errInvalidRequest, "the content type must be "+setContentType)
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, req.Body, maxTokenBytes))
	if err != nil {
		r.refuse(w, http.StatusBadRequest, errInvalidRequest, "the body could not be read or is too large")
		return
	}
	status, code, desc := r.accept(req.Context(), strings.TrimSpace(string(body)))
	if code != "" {
		r.refuse(w, status, code, desc)
		return
	}
	w.WriteHeader(http.StatusAccepted)
}

func (r *Receiver) bearerOK(req *http.Request) bool {
	scheme, tok, ok := strings.Cut(strings.TrimSpace(req.Header.Get("Authorization")), " ")
	if !ok || !strings.EqualFold(scheme, "Bearer") {
		return false
	}
	got := sha256.Sum256([]byte(strings.TrimSpace(tok)))
	return subtle.ConstantTimeCompare(got[:], r.token[:]) == 1
}

func (r *Receiver) refuse(w http.ResponseWriter, status int, code, desc string) {
	r.log("SET refused", "code", code, "reason", desc)
	if status == http.StatusServiceUnavailable {
		w.Header().Set("Retry-After", "5")
	}
	writeJSON(w, status, map[string]string{"err": code, "description": desc})
}

func (r *Receiver) log(msg string, kv ...any) {
	if l := r.c.cfg.Logger; l != nil {
		l.Warn("authfi: receiver: "+msg, kv...)
	}
}

// setClaims is the payload of a SET as the transmitter writes it.
type setClaims struct {
	Iss    string                     `json:"iss"`
	Jti    string                     `json:"jti"`
	Iat    *numericDate               `json:"iat"`
	Exp    *numericDate               `json:"exp"`
	Aud    audience                   `json:"aud"`
	SubID  *subjectID                 `json:"sub_id"`
	Events map[string]json.RawMessage `json:"events"`
}

type subjectID struct {
	Format string `json:"format"`
	ID     string `json:"id"`
	Iss    string `json:"iss"`
	Sub    string `json:"sub"`
}

// accept runs every check and, only if all pass, applies the SET. It returns an RFC 8935 error
// code, or "" for accepted.
func (r *Receiver) accept(ctx context.Context, token string) (status int, code, desc string) {
	payload, err := r.c.verifyCompact(ctx, token, setTyp)
	if err != nil {
		return verifyFailure(err)
	}
	var cl setClaims
	if err := json.Unmarshal(payload, &cl); err != nil {
		return http.StatusBadRequest, errInvalidRequest, "the SET payload is not a JSON object of the expected shape"
	}
	if cl.Iss != trimIssuer(r.c.cfg.Issuer) {
		return http.StatusBadRequest, errInvalidIssuer, "the SET was not issued by this project"
	}
	if !intersects(cl.Aud, []string{r.cfg.Audience}) {
		return http.StatusBadRequest, errInvalidAudience, "the SET is not for this stream"
	}
	if cl.Jti == "" || len(cl.Jti) > maxJTILen {
		return http.StatusBadRequest, errInvalidRequest, "the SET has no usable jti"
	}
	now, leeway := r.c.now(), r.c.leeway()
	if cl.Iat == nil {
		return http.StatusBadRequest, errInvalidRequest, "the SET has no iat"
	}
	iat := cl.Iat.time()
	if now.Add(leeway).Before(iat) {
		return http.StatusBadRequest, errInvalidRequest, "the SET was issued in the future"
	}
	if !now.Before(iat.Add(r.store.life)) {
		return http.StatusBadRequest, errInvalidRequest, "the SET is older than any token it could affect"
	}
	if cl.Exp != nil && !now.Before(cl.Exp.time().Add(leeway)) {
		return http.StatusBadRequest, errInvalidRequest, "the SET has expired"
	}
	subject, ok := cl.subject(r.c.cfg.Issuer)
	if !ok {
		return http.StatusBadRequest, errInvalidRequest, "the SET names no usable subject"
	}
	if len(cl.Events) == 0 {
		return http.StatusBadRequest, errInvalidRequest, "the SET carries no events"
	}
	for _, ev := range cl.Events {
		if !bytes.HasPrefix(bytes.TrimSpace(ev), []byte("{")) {
			return http.StatusBadRequest, errInvalidRequest, "an event of the SET is not an object"
		}
	}

	if !r.seen.claim(cl.Jti, now) {
		return 0, "", "" // a retry of a SET already applied: accepted again, applied once
	}
	r.apply(cl, subject, iat)
	return 0, "", ""
}

// apply records the revocations in a SET that passed every check, and calls the hook.
func (r *Receiver) apply(cl setClaims, subject string, iat time.Time) {
	for ev, raw := range cl.Events {
		sig := Signal{Event: ev, Subject: subject, JTI: cl.Jti, IssuedAt: iat}
		switch ev {
		case EventSessionRevoked, EventAccountPurged, EventCredentialCompromise:
			sig.Revoked = true
			if n := r.store.Revoke(subject, iat); n > 0 {
				r.log("revocation store is full; the oldest revocations were folded into a floor", "dropped", n)
			}
		case EventTokenClaimsChange:
			var detail struct {
				Resumed bool `json:"resumed"`
			}
			_ = json.Unmarshal(raw, &detail)
			sig.Resumed = detail.Resumed
		default:
			r.info("SET event ignored: not an event this receiver acts on", "event", ev)
			continue
		}
		r.info("SET accepted", "event", ev, "subject", subject, "jti", cl.Jti)
		r.hook(sig)
	}
}

func (r *Receiver) info(msg string, kv ...any) {
	if l := r.c.cfg.Logger; l != nil {
		l.Info("authfi: receiver: "+msg, kv...)
	}
}

func (r *Receiver) hook(s Signal) {
	if r.cfg.OnSignal == nil {
		return
	}
	defer func() {
		if p := recover(); p != nil {
			r.log("OnSignal panicked; the revocation stands", "event", s.Event)
		}
	}()
	r.cfg.OnSignal(s)
}

// subject reads sub_id in the two formats the platform and the specification use.
func (cl setClaims) subject(issuer string) (string, bool) {
	s := cl.SubID
	if s == nil {
		return "", false
	}
	var out string
	switch s.Format {
	case "opaque":
		out = s.ID
	case "iss_sub":
		if s.Iss != trimIssuer(issuer) {
			return "", false
		}
		out = s.Sub
	}
	if out == "" || len(out) > maxSubjectLen {
		return "", false
	}
	return out, true
}

// verifyFailure maps a refusal of the JWS layer to RFC 8935 section 2.4. A key set that cannot be
// read is not the sender's fault: it is 503 so the transmitter keeps the SET and retries.
func verifyFailure(err error) (int, string, string) {
	var e *Error
	if !errors.As(err, &e) {
		return http.StatusServiceUnavailable, errTemporarilyAbort, "the SET could not be checked now"
	}
	switch e.Code {
	case CodeKeySetUnavailable, CodeNotConfigured:
		return http.StatusServiceUnavailable, errTemporarilyAbort, "the issuer's keys could not be read"
	case CodeSignatureInvalid:
		return http.StatusBadRequest, errAuthnFailed, "the signature does not verify"
	case CodeUnknownKey, CodeKeyIDRequired, CodeAlgNotAllowed, CodeAlgKeyMismatch, CodeCritNotSupported:
		return http.StatusBadRequest, errInvalidKey, "the key or algorithm of the SET is not accepted"
	}
	return http.StatusBadRequest, errInvalidRequest, "the SET is not a well-formed " + setTyp
}

// --- stream registration ---

// StreamRequest is a receiver to register with the transmitter.
type StreamRequest struct {
	// Audience is your identifier for the stream. It comes back in the aud of every SET, and a
	// Receiver built with the same value accepts them. Required.
	Audience string
	// EndpointURL is where SETs are POSTed: the public https URL your Receiver is mounted at.
	EndpointURL string
	// AuthToken, when set, is sent back as the bearer on every push. Pass the same value in
	// ReceiverConfig.AuthToken.
	AuthToken Secret
	// Events are the event types to receive. Empty means all of them.
	Events []string
}

// Stream is a registered stream as the transmitter reports it.
type Stream struct {
	ID          string   `json:"id"`
	Audience    string   `json:"audience"`
	EndpointURL string   `json:"endpoint_url"`
	Status      string   `json:"status"`
	Events      []string `json:"events_requested"`
}

// RegisterStream registers a push stream with the project's transmitter: it reads the issuer's
// /.well-known/ssf-configuration, and POSTs the registration to the configuration_endpoint it
// names, with bearer as the Authorization header. The endpoint must sit on the issuer's own host,
// because bearer is a credential and a discovery document must not be able to redirect it.
func (c *Client) RegisterStream(ctx context.Context, bearer Secret, req StreamRequest) (*Stream, error) {
	if c.cfgErr != nil {
		return nil, c.cfgErr
	}
	if bearer.IsEmpty() {
		return nil, errors.New("authfi: RegisterStream needs the bearer token that may register streams")
	}
	if strings.TrimSpace(req.Audience) == "" {
		return nil, errors.New("authfi: StreamRequest.Audience is required")
	}
	if u, err := url.Parse(req.EndpointURL); err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil {
		return nil, errors.New("authfi: StreamRequest.EndpointURL must be an https URL")
	}
	secrets := []string{bearer.Reveal(), req.AuthToken.Reveal()}
	issuer := trimIssuer(c.cfg.Issuer)

	var meta struct {
		Issuer string `json:"issuer"`
		Config string `json:"configuration_endpoint"`
	}
	if err := c.getJSONBounded(ctx, issuer+"/.well-known/ssf-configuration", &meta, secrets); err != nil {
		return nil, fmt.Errorf("authfi: stream discovery: %w", err)
	}
	if trimIssuer(meta.Issuer) != issuer {
		return nil, errors.New("authfi: stream discovery: the metadata names another issuer")
	}
	if !sameOrigin(meta.Config, issuer) {
		return nil, errors.New("authfi: stream discovery: configuration_endpoint is missing or not on the issuer's host")
	}

	payload := map[string]any{"audience": req.Audience, "endpoint_url": req.EndpointURL}
	if !req.AuthToken.IsEmpty() {
		payload["auth_token"] = req.AuthToken.Reveal()
	}
	if len(req.Events) > 0 {
		payload["events_requested"] = req.Events
	}
	data, _ := json.Marshal(payload)
	hreq, err := http.NewRequestWithContext(ctx, http.MethodPost, meta.Config, bytes.NewReader(data))
	if err != nil {
		return nil, errors.New("authfi: stream registration: bad URL")
	}
	hreq.Header.Set("Content-Type", "application/json")
	hreq.Header.Set("Accept", "application/json")
	hreq.Header.Set("Authorization", "Bearer "+bearer.Reveal())
	resp, err := c.api.Do(hreq)
	if err != nil {
		return nil, fmt.Errorf("authfi: stream registration failed: %s", Scrub(err.Error(), secrets...))
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, maxStreamReply))
	if resp.StatusCode/100 != 2 {
		return nil, fmt.Errorf("authfi: stream registration refused (%d): %s", resp.StatusCode, Scrub(string(body), secrets...))
	}
	var out struct {
		Data Stream `json:"data"`
	}
	if err := json.Unmarshal(body, &out); err != nil || out.Data.ID == "" {
		return nil, errors.New("authfi: stream registration: the reply holds no stream")
	}
	return &out.Data, nil
}

func (c *Client) getJSONBounded(ctx context.Context, rawURL string, into any, secrets []string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return errors.New("bad URL")
	}
	req.Header.Set("Accept", "application/json")
	resp, err := c.api.Do(req)
	if err != nil {
		return errors.New(Scrub(err.Error(), secrets...))
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, maxStreamReply))
	if err := json.Unmarshal(body, into); err != nil {
		return errors.New("the reply is not JSON")
	}
	return nil
}

// sameOrigin reports whether raw is an absolute URL with the scheme and host of base.
func sameOrigin(raw, base string) bool {
	u, err := url.Parse(raw)
	b, berr := url.Parse(base)
	return err == nil && berr == nil && raw != "" && u.Scheme == b.Scheme && u.Host == b.Host && u.User == nil && u.Fragment == ""
}
