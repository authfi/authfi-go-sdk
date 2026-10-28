package authfi

// See the note in dpop.go: this file holds no secret and reads nothing of Config.

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"
	"sync"
	"time"
)

// The AuthFI certificate policies (IANA PEN 67322). A signing key whose certificate states .1.1
// (HSM custody) or .1.2 (HSM resident) is held in AuthFI custody; .1.3 is for keys their subject holds.
const (
	policyHSMCustody  = "1.3.6.1.4.1.67322.1.1"
	policyHSMResident = "1.3.6.1.4.1.67322.1.2"
	policySubjectHeld = "1.3.6.1.4.1.67322.1.3"
	policyArc         = "1.3.6.1.4.1.67322.1."

	// DefaultRootPin is the SHA-256 of the SubjectPublicKeyInfo of AuthFI Root CA R1. It is compiled
	// in and never read from the key set being checked.
	DefaultRootPin = "b060083465bf0e9239a37f12a5e294a8c219f6b7d81563f4509c984b83ca6332"

	chainRefresh   = 10 * time.Minute
	maxChainCached = 4096
)

var tokenPolicies = []string{policyHSMCustody, policyHSMResident}

// parsePins reads SHA-256 hashes in hex, with or without colons. None given means the default pin.
func parsePins(pins []string) ([][32]byte, error) {
	if len(pins) == 0 {
		pins = []string{DefaultRootPin}
	}
	out := make([][32]byte, 0, len(pins))
	for _, p := range pins {
		b, err := hex.DecodeString(strings.ReplaceAll(strings.TrimSpace(p), ":", ""))
		if err != nil || len(b) != 32 {
			return nil, fmt.Errorf("a root pin is a SHA-256 in hex")
		}
		var pin [32]byte
		copy(pin[:], b)
		out = append(out, pin)
	}
	return out, nil
}

// chainVerifier proves that a published signing key is held in AuthFI custody: its x5c chains to a
// pinned root and the certificate states a custody policy. Path validation is cached per chain; the
// match between key and certificate is checked on every call.
type chainVerifier struct {
	pins [][32]byte

	mu    sync.Mutex
	cache map[[32]byte]chainEntry
}

type chainEntry struct {
	chain   [32]byte // hash of every published certificate, so another path to the same leaf revalidates
	leaf    *x509.Certificate
	expires time.Time
}

func newChainVerifier(pins [][32]byte) *chainVerifier {
	return &chainVerifier{pins: pins, cache: map[[32]byte]chainEntry{}}
}

// check proves that the key that verified a token is certified by x5c and the chain reaches a pinned
// root. jwkThumb is the x5t#S256 the key set publishes and tokenThumb the one in the token header;
// each, when present, must be the leaf's thumbprint.
func (v *chainVerifier) check(pub any, x5c []string, jwkThumb, tokenThumb string, now time.Time) *Error {
	if len(x5c) == 0 {
		return refuse(CodeChainNotProven, "the signing key publishes no certificate chain")
	}
	want, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return refuse(CodeChainNotProven, "the signing key cannot be compared with its certificate")
	}
	e, perr := v.proven(x5c, now)
	if perr != nil {
		return perr
	}
	if now.Before(e.leaf.NotBefore) || now.After(e.leaf.NotAfter) {
		return refuse(CodeChainNotProven, "the signing certificate is not valid now")
	}
	if !bytes.Equal(e.leaf.RawSubjectPublicKeyInfo, want) {
		return refuse(CodeChainNotProven, "the certificate certifies another key")
	}
	thumb := thumbprintS256(e.leaf.Raw)
	if jwkThumb != "" && jwkThumb != thumb {
		return refuse(CodeChainNotProven, "the key's x5t#S256 names another certificate")
	}
	if tokenThumb != "" && tokenThumb != thumb {
		return refuse(CodeChainNotProven, "the token's x5t#S256 names another certificate")
	}
	return nil
}

// proven returns the cached proof of x5c, or validates it.
func (v *chainVerifier) proven(x5c []string, now time.Time) (chainEntry, *Error) {
	leafDER, err := base64.StdEncoding.DecodeString(x5c[0])
	if err != nil {
		return chainEntry{}, refuse(CodeChainNotProven, "the signing certificate is not base64")
	}
	leafSum := sha256.Sum256(leafDER)
	h := sha256.New()
	for _, c := range x5c {
		h.Write([]byte(c))
		h.Write([]byte{0})
	}
	var chain [32]byte
	copy(chain[:], h.Sum(nil))

	v.mu.Lock()
	e, ok := v.cache[leafSum]
	v.mu.Unlock()
	if ok && e.chain == chain && now.Before(e.expires) {
		return e, nil
	}
	leaf, expires, verr := v.validate(x5c, now)
	if verr != nil {
		return chainEntry{}, verr
	}
	e = chainEntry{chain: chain, leaf: leaf, expires: expires}
	v.mu.Lock()
	if len(v.cache) >= maxChainCached {
		v.cache = map[[32]byte]chainEntry{}
	}
	v.cache[leafSum] = e
	v.mu.Unlock()
	return e, nil
}

// validate runs the full path validation. It returns the leaf and when the proof lapses.
func (v *chainVerifier) validate(x5c []string, now time.Time) (*x509.Certificate, time.Time, *Error) {
	certs := make([]*x509.Certificate, 0, len(x5c))
	for _, b := range x5c {
		der, err := base64.StdEncoding.DecodeString(b)
		if err != nil {
			return nil, time.Time{}, refuse(CodeChainNotProven, "a published certificate is not base64")
		}
		c, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, time.Time{}, refuse(CodeChainNotProven, "a published certificate does not parse")
		}
		certs = append(certs, c)
	}
	leaf := certs[0]
	if leaf.IsCA || leaf.KeyUsage&x509.KeyUsageDigitalSignature == 0 {
		return nil, time.Time{}, refuse(CodeChainNotProven, "the signing certificate is a CA or cannot sign")
	}
	anchor := v.anchorFor(certs)
	if anchor == nil {
		return nil, time.Time{}, refuse(CodeChainPin, "the chain does not reach a pinned root")
	}
	if !statesAny(leaf, tokenPolicies) {
		return nil, time.Time{}, refuse(CodeChainPolicy, "the signing certificate states no AuthFI custody policy")
	}
	if statesOID(leaf, policySubjectHeld) {
		return nil, time.Time{}, refuse(CodeChainPolicy, "the signing certificate also states the subject-held key policy")
	}
	roots, inter := x509.NewCertPool(), x509.NewCertPool()
	roots.AddCert(anchor)
	for _, c := range certs[1:] {
		if !c.Equal(anchor) {
			inter.AddCert(c)
		}
	}
	chains, err := leaf.Verify(x509.VerifyOptions{Roots: roots, Intermediates: inter, CurrentTime: now,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}})
	if err != nil {
		return nil, time.Time{}, refuse(CodeChainNotProven, "the certificate chain does not validate")
	}
	var lastErr *Error
	for _, path := range chains {
		if lastErr = v.checkPath(path); lastErr != nil {
			continue
		}
		expires := now.Add(chainRefresh)
		for _, c := range path {
			if c.NotAfter.Before(expires) {
				expires = c.NotAfter
			}
		}
		return leaf, expires, nil
	}
	return nil, time.Time{}, lastErr
}

// checkPath applies the pin and policy rules to one built path, leaf first and root last.
func (v *chainVerifier) checkPath(path []*x509.Certificate) *Error {
	if len(path) < 2 {
		return refuse(CodeChainNotProven, "the chain has no CA")
	}
	if !v.pinned(path[len(path)-1]) {
		return refuse(CodeChainPin, "the chain does not end at a pinned root")
	}
	for _, ca := range path[1 : len(path)-1] {
		if !statesAny(ca, tokenPolicies) {
			return refuse(CodeChainPolicy, "a CA of the chain states no AuthFI custody policy")
		}
		if statesOID(ca, policySubjectHeld) {
			return refuse(CodeChainPolicy, "a CA of the chain also states the subject-held key policy")
		}
	}
	return nil
}

// anchorFor returns the root: a certificate of the x5c that is self-signed, a CA, and whose key is
// pinned. A root carried by the key set is only a container for the pinned key; one not signed by
// that key could give it validity and constraints of its own.
func (v *chainVerifier) anchorFor(certs []*x509.Certificate) *x509.Certificate {
	for _, c := range certs[1:] {
		if v.pinned(c) && c.IsCA && c.CheckSignatureFrom(c) == nil {
			return c
		}
	}
	return nil
}

func (v *chainVerifier) pinned(c *x509.Certificate) bool {
	sum := sha256.Sum256(c.RawSubjectPublicKeyInfo)
	for _, p := range v.pins {
		if p == sum {
			return true
		}
	}
	return false
}

func statesAny(c *x509.Certificate, oids []string) bool {
	for _, o := range oids {
		if statesOID(c, o) {
			return true
		}
	}
	return false
}

func statesOID(c *x509.Certificate, oid string) bool {
	for _, p := range c.PolicyIdentifiers {
		if p.String() == oid {
			return true
		}
	}
	return false
}

// thumbprintS256 is a certificate's x5t#S256: the base64url SHA-256 of its DER.
func thumbprintS256(der []byte) string {
	sum := sha256.Sum256(der)
	return base64URL(sum[:])
}
