package authfi

import (
	"fmt"
	"log/slog"
	"regexp"
	"strings"
)

// redacted is what every secret-holding type prints, under every fmt verb, in JSON and in logs.
const redacted = "[redacted]"

// Secret holds a token, a client secret or any other value that must not reach a log, an error
// or a serialised form by accident. The only way out is Reveal, a name that shows up in review.
//
// The value sits behind a pointer on purpose: fmt cannot call Format on a Secret that is an
// unexported field of someone else's struct, and would print a string held directly. A pointer
// prints as an address.
type Secret struct{ p *string }

// NewSecret wraps v. An empty v is an empty Secret.
func NewSecret(v string) Secret {
	if v == "" {
		return Secret{}
	}
	return Secret{p: &v}
}

// Reveal returns the value. Call it at the one place the value leaves, such as an HTTP header.
func (s Secret) Reveal() string {
	if s.p == nil {
		return ""
	}
	return *s.p
}

// IsEmpty reports whether no value is held.
func (s Secret) IsEmpty() bool { return s.p == nil }

func (s Secret) String() string   { return redactedIfSet(s.Reveal()) }
func (s Secret) GoString() string { return "authfi.Secret(" + redactedIfSet(s.Reveal()) + ")" }

// Format redacts under every verb, including %x and %d, which would otherwise print the bytes.
func (s Secret) Format(f fmt.State, _ rune) { _, _ = f.Write([]byte(redactedIfSet(s.Reveal()))) }

func (s Secret) MarshalJSON() ([]byte, error) {
	return []byte(`"` + redactedIfSet(s.Reveal()) + `"`), nil
}
func (s Secret) MarshalText() ([]byte, error) { return []byte(redactedIfSet(s.Reveal())), nil }
func (s Secret) LogValue() slog.Value         { return slog.StringValue(redactedIfSet(s.Reveal())) }

func redactedIfSet(v string) string {
	if v == "" {
		return ""
	}
	return redacted
}

var (
	jwtShape    = regexp.MustCompile(`eyJ[A-Za-z0-9_-]{2,}\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*`)
	bearerShape = regexp.MustCompile(`(?i)\b(bearer|dpop)\s+[A-Za-z0-9._~+/=-]{8,}`)
)

// maxEchoed bounds how much of a server's reply an error may carry.
const maxEchoed = 512

// Scrub returns text safe to put in an error or a log line: every known secret value replaced,
// JWT-shaped and "Bearer ..." strings replaced as a second net, and the length bounded. Use it on
// anything a server sent back, because a misbehaving server can echo what it was given.
func Scrub(text string, secrets ...string) string {
	for _, s := range secrets {
		if len(s) >= 4 {
			text = strings.ReplaceAll(text, s, redacted)
		}
	}
	text = jwtShape.ReplaceAllString(text, redacted)
	text = bearerShape.ReplaceAllString(text, "$1 "+redacted)
	if len(text) > maxEchoed {
		text = text[:maxEchoed] + "..."
	}
	return text
}
