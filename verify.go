package authfi

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
	"net/http"
	"strings"
	"time"
)

const (
	maxTokenBytes  = 16 << 10
	defaultLeeway  = 60 * time.Second
	maxLeeway      = 300 * time.Second
	accessTokenTyp = "at+jwt"
)

// firstPartyAudiences are AuthFI's own client ids. A token minted for one of them is for AuthFI,
// not for a customer's API, and must never be accepted there.
var firstPartyAudiences = map[string]bool{"authfi-console": true, "authfi-workspace": true}

// checkConfig validates what verification depends on. New runs it once and keeps the result, so
// every verification fails closed with it.
func checkConfig(cfg Config) error {
	if cfg.Issuer == "" {
		return refuse(CodeNotConfigured, "Issuer is required: the project issuer, for example https://acme.authfi.io")
	}
	if err := checkIssuerURL(cfg.Issuer); err != nil {
		return err
	}
	if len(cfg.Audience) == 0 {
		return refuse(CodeNotConfigured, "Audience is required: the client id of your API. There is no way to skip the audience check")
	}
	issuer := trimIssuer(cfg.Issuer)
	api := trimIssuer(cfg.APIURL)
	for _, a := range cfg.Audience {
		switch {
		case strings.TrimSpace(a) == "":
			return refuse(CodeNotConfigured, "Audience contains an empty value")
		case a == issuer || strings.HasPrefix(a, issuer+"/"),
			api != "" && (a == api || strings.HasPrefix(a, api+"/")),
			firstPartyAudiences[a]:
			return refuse(CodeNotConfigured, "Audience %q is an AuthFI audience; mint the token with resource=<the client id of your API> and verify that audience", a)
		}
	}
	if cfg.Leeway > maxLeeway {
		return refuse(CodeNotConfigured, "Leeway is at most %s", maxLeeway)
	}
	return checkAgentConfig(cfg)
}

func (c *Client) leeway() time.Duration {
	switch {
	case c.cfg.Leeway == 0:
		return defaultLeeway
	case c.cfg.Leeway < 0:
		return 0
	}
	return c.cfg.Leeway
}

// VerifyToken verifies an access token against the project issuer. See Verify.
func (c *Client) VerifyToken(token string) (*Claims, error) {
	return c.Verify(context.Background(), token)
}

// Verify checks that token is an access token this project issued for this API, and returns its
// claims. Every rule fails closed:
//
//   - the token is a compact JWS of three parts, at most 16 KiB;
//   - alg is RS256, PS256, ES256 or EdDSA and is one the issuer's key named by kid may use;
//     none and HS* are refused, and keys never come from the token;
//   - typ is at+jwt, which refuses an ID token, a transaction token and an event as a bearer;
//   - iss equals Issuer, aud includes one of Audience, exp is present and in the future;
//   - sub and tenant_id are present, and tenant_id equals TenantID when that is set;
//   - a delegation chain (an act inside an act) is refused;
//   - a token bound to a key (cnf, authfi_mandate) and an agent token (agt_ subject or client, or an
//     act claim) are refused here, since a proof needs the request: use VerifyRequest or Require.
//     The refusal of an agent token is CodeAgentNeedsRequest, unless Config.AgentTokens is off.
//
// The error is an *Error whose Code names the rule; its text holds nothing from the token.
func (c *Client) Verify(ctx context.Context, token string) (*Claims, error) {
	claims, err := c.verifyWith(ctx, token, nil, "")
	c.logRefusal(err)
	return claims, err
}

// tokenHeader is the JOSE header of an access token or a Security Event Token.
type tokenHeader struct {
	Alg     string          `json:"alg"`
	Kid     string          `json:"kid"`
	Typ     string          `json:"typ"`
	Crit    json.RawMessage `json:"crit"`
	X5tS256 string          `json:"x5t#S256"`
}

// verifyWith verifies token. r and scheme are the request it came on and its Authorization scheme,
// or nil and "" when there is none. Revocation is checked before the binding (DPoP, the key's chain): a
// withdrawn subject or actor is refused as token_revoked wherever the token is presented, which is the
// answer a kill switch owes, and the check reads nothing but the claims.
func (c *Client) verifyWith(ctx context.Context, token string, r *http.Request, scheme string) (*Claims, error) {
	if c.cfgErr != nil {
		return nil, c.cfgErr
	}
	payload, header, key, err := c.verifyCompact(ctx, token, accessTokenTyp)
	if err != nil {
		return nil, err
	}
	var w wireClaims
	if err := json.Unmarshal(payload, &w); err != nil {
		return nil, refuse(CodeMalformed, "the token payload is not valid")
	}
	claims, err := c.checkClaims(&w)
	if err != nil {
		return nil, err
	}
	if err := c.checkRevoked(claims); err != nil {
		return nil, err
	}
	if err := c.checkBinding(ctx, &w, presented{token: token, header: header, key: key, req: r, scheme: scheme}); err != nil {
		return nil, err
	}
	return claims, nil
}

// verifyCompact checks the structure and the signature of a compact JWS: size, three parts, an
// allowed alg, no critical extensions, the media type wantTyp, a kid, and a signature by the
// issuer's key of that kid that is allowed to use that alg. It returns the decoded payload, the header
// and the key, and reads nothing from the payload. Access tokens and Security Event Tokens both pass
// through it, so the two cannot drift apart on what a valid signature is.
func (c *Client) verifyCompact(ctx context.Context, token, wantTyp string) ([]byte, tokenHeader, verifyKey, error) {
	var header tokenHeader
	var none verifyKey
	if len(token) > maxTokenBytes {
		return nil, header, none, refuse(CodeTooLarge, "the token is larger than %d bytes", maxTokenBytes)
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, header, none, refuse(CodeMalformed, "a token is three dot-separated parts")
	}
	if err := decodeSegment(parts[0], &header); err != nil {
		return nil, header, none, refuse(CodeMalformed, "the token header is not valid")
	}
	switch header.Alg {
	case "RS256", "PS256", "ES256", "EdDSA":
	default:
		return nil, header, none, refuse(CodeAlgNotAllowed, "the algorithm of the token is not accepted")
	}
	if present(header.Crit) {
		return nil, header, none, refuse(CodeCritNotSupported, "the token carries critical header extensions this SDK does not understand")
	}
	if typ := strings.TrimPrefix(strings.ToLower(header.Typ), "application/"); typ != wantTyp {
		return nil, header, none, refuse(CodeTypInvalid, "the token is not of the expected type (typ must be %s)", wantTyp)
	}
	if header.Kid == "" {
		return nil, header, none, refuse(CodeKeyIDRequired, "the token names no signing key")
	}
	sig, err := decodeB64(parts[2])
	if err != nil || len(sig) == 0 {
		return nil, header, none, refuse(CodeMalformed, "the token signature is not valid")
	}

	key, err := c.keys.get(ctx, header.Kid)
	if err != nil {
		return nil, header, none, err
	}
	if !key.allows(header.Alg) {
		return nil, header, none, refuse(CodeAlgKeyMismatch, "the algorithm of the token does not match its signing key")
	}
	if !verifySignature(header.Alg, key.pub, []byte(parts[0]+"."+parts[1]), sig) {
		return nil, header, none, refuse(CodeSignatureInvalid, "the token signature does not verify")
	}
	payload, err := decodeB64(parts[1])
	if err != nil {
		return nil, header, none, refuse(CodeMalformed, "the token payload is not valid")
	}
	return payload, header, key, nil
}

func verifySignature(alg string, pub any, signed, sig []byte) bool {
	switch alg {
	case "RS256", "PS256":
		k, ok := pub.(*rsa.PublicKey)
		if !ok {
			return false
		}
		h := sha256.Sum256(signed)
		if alg == "RS256" {
			return rsa.VerifyPKCS1v15(k, crypto.SHA256, h[:], sig) == nil
		}
		return rsa.VerifyPSS(k, crypto.SHA256, h[:], sig, &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash}) == nil
	case "ES256":
		k, ok := pub.(*ecdsa.PublicKey)
		if !ok || len(sig) != 64 {
			return false
		}
		h := sha256.Sum256(signed)
		return ecdsa.Verify(k, h[:], new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:]))
	case "EdDSA":
		k, ok := pub.(ed25519.PublicKey)
		return ok && len(sig) == ed25519.SignatureSize && ed25519.Verify(k, signed, sig)
	}
	return false
}

// decodeB64 decodes base64url without padding, strictly: the Go decoder skips CR and LF, which would
// let two different strings stand for one signature, and Strict refuses non-zero trailing bits.
func decodeB64(seg string) ([]byte, error) {
	if strings.ContainsAny(seg, "\r\n") {
		return nil, errors.New("not base64url")
	}
	return base64.RawURLEncoding.Strict().DecodeString(seg)
}

func decodeSegment(seg string, into any) error {
	raw, err := decodeB64(seg)
	if err != nil {
		return err
	}
	return json.Unmarshal(raw, into)
}

func (c *Client) checkClaims(w *wireClaims) (*Claims, error) {
	now, leeway := c.now(), c.leeway()
	if w.Issuer != trimIssuer(c.cfg.Issuer) {
		return nil, refuse(CodeIssuerMismatch, "the token was not issued by this project")
	}
	if w.Exp == nil {
		return nil, refuse(CodeExpiryRequired, "the token has no expiry")
	}
	if !now.Before(w.Exp.time().Add(leeway)) {
		return nil, refuse(CodeExpired, "the token has expired")
	}
	if w.Nbf != nil && now.Add(leeway).Before(w.Nbf.time()) {
		return nil, refuse(CodeNotYetValid, "the token is not valid yet")
	}
	if w.Iat != nil && now.Add(leeway).Before(w.Iat.time()) {
		return nil, refuse(CodeNotYetValid, "the token was issued in the future")
	}
	if !intersects(w.Audience, c.cfg.Audience) {
		return nil, refuse(CodeAudienceMismatch, "the token is not for this API")
	}
	if w.Subject == "" {
		return nil, refuse(CodeSubjectRequired, "the token has no subject")
	}
	if w.TenantID == "" {
		return nil, refuse(CodeTenantRequired, "the token names no tenant")
	}
	if c.cfg.TenantID != "" && w.TenantID != c.cfg.TenantID {
		return nil, refuse(CodeTenantMismatch, "the token belongs to another tenant")
	}
	var actor string
	if present(w.Act) {
		var a struct {
			Sub string          `json:"sub"`
			Act json.RawMessage `json:"act"`
		}
		if json.Unmarshal(w.Act, &a) != nil {
			return nil, refuse(CodeMalformed, "the act claim of the token is not valid")
		}
		if present(a.Act) {
			return nil, refuse(CodeActChainNotAllowed, "a delegation chain is not supported")
		}
		actor = a.Sub
	}
	out := w.Claims
	out.Audience = []string(w.Audience)
	out.ExpiresAt = w.Exp.unix()
	out.IssuedAt = 0
	if w.Iat != nil {
		out.IssuedAt = w.Iat.unix()
	}
	out.Actor = actor
	return &out, nil
}

func (c *Client) now() time.Time {
	if c.clock != nil {
		return c.clock()
	}
	return time.Now()
}

func present(raw json.RawMessage) bool { return len(raw) > 0 && string(raw) != "null" }

func intersects(have audience, want []string) bool {
	for _, h := range have {
		for _, w := range want {
			if h != "" && h == w {
				return true
			}
		}
	}
	return false
}

// wireClaims is the payload as sent: the audience as a string or a list, times as JSON numbers.
// The embedded Claims is filled from the same JSON; the fields below shadow its time and audience.
type wireClaims struct {
	Claims
	Audience audience        `json:"aud"`
	Exp      *numericDate    `json:"exp"`
	Nbf      *numericDate    `json:"nbf"`
	Iat      *numericDate    `json:"iat"`
	Act      json.RawMessage `json:"act"`
	Cnf      json.RawMessage `json:"cnf"`
	Mandate  json.RawMessage `json:"authfi_mandate"`
}

type audience []string

func (a *audience) UnmarshalJSON(b []byte) error {
	var one string
	if json.Unmarshal(b, &one) == nil {
		*a = audience{one}
		return nil
	}
	var many []string
	if err := json.Unmarshal(b, &many); err != nil {
		return err
	}
	*a = audience(many)
	return nil
}

// numericDate is a JSON number of seconds; a fractional value is allowed (RFC 7519 section 2).
// Values outside the years 1970 to 9999 are refused: beyond them int64 conversion wraps, and a
// far-future nbf or iat would read as the past.
type numericDate float64

const maxNumericDate = 253402300799 // 9999-12-31T23:59:59Z

func (d *numericDate) UnmarshalJSON(b []byte) error {
	var f float64
	if err := json.Unmarshal(b, &f); err != nil {
		return err
	}
	if f < 0 || f > maxNumericDate || f != f {
		return errors.New("time out of range")
	}
	*d = numericDate(f)
	return nil
}

func (d numericDate) time() time.Time {
	sec := float64(d)
	whole := int64(sec)
	return time.Unix(whole, int64((sec-float64(whole))*1e9))
}

func (d numericDate) unix() int64 { return int64(d) }
