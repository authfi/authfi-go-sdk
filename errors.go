package authfi

import "fmt"

// Refusal codes. They are the kernel's names where the kernel has one, so a log line on the
// resource server and one from the platform read the same.
const (
	CodeNotConfigured      = "sdk_not_configured"
	CodeMalformed          = "token_malformed"
	CodeTooLarge           = "token_too_large"
	CodeAlgNotAllowed      = "token_alg_not_allowed"
	CodeKeyIDRequired      = "token_kid_required"
	CodeCritNotSupported   = "token_crit_not_supported"
	CodeTypInvalid         = "token_typ_invalid"
	CodeUnknownKey         = "token_unknown_key"
	CodeAlgKeyMismatch     = "token_alg_key_mismatch"
	CodeSignatureInvalid   = "token_signature_invalid"
	CodeIssuerMismatch     = "token_issuer_mismatch"
	CodeAudienceMismatch   = "token_audience_mismatch"
	CodeExpired            = "token_expired"
	CodeExpiryRequired     = "token_exp_required"
	CodeNotYetValid        = "token_not_yet_valid"
	CodeSubjectRequired    = "token_sub_required"
	CodeTenantRequired     = "token_tenant_required"
	CodeTenantMismatch     = "token_tenant_not_issuers"
	CodeDPoPProofRequired  = "token_dpop_proof_required"
	CodeActChainNotAllowed = "token_act_chain_unsupported"
	CodeKeySetUnavailable  = "jwks_unavailable"
	CodeMissingBearer      = "missing_authorization"
	CodeRevoked            = "token_revoked"
	CodeIssuedAtRequired   = "token_iat_required"
)

// Error is a refusal or failure with a stable Code. Use errors.As to read it. Its text never
// contains a token, a signature or a secret.
type Error struct {
	Code    string
	Message string
	Err     error
	// Ref is the reference of the decision behind the refusal: for token_revoked, the jti of the
	// Security Event Token that withdrew the subject. Empty when there is none.
	Ref string
}

func (e *Error) Error() string {
	text := "authfi: " + e.Code
	if e.Message != "" {
		text = fmt.Sprintf("authfi: %s: %s", e.Code, e.Message)
	}
	if e.Ref != "" {
		text += " (ref " + e.Ref + ")"
	}
	return text
}

func (e *Error) Unwrap() error { return e.Err }

func refuse(code, format string, args ...any) *Error {
	return &Error{Code: code, Message: fmt.Sprintf(format, args...)}
}
