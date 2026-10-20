// Package agent is the agent side of the AuthFI Go SDK: an agent's own key and token, acting for
// a person through CIBA or token exchange, an http.RoundTripper that sends the current token only
// where it may go, and a reader for the gateway's answers.
//
// An agent authenticates by signing a short assertion with a key that never leaves the process
// (private_key_jwt, RFC 7523). There is no secret to leak: the key, every token and every
// assertion print redacted under every fmt verb, in JSON and in slog, and never appear in an
// error.
package agent

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"os"
	"runtime"
)

// Algorithm is a JWS algorithm an agent key signs with.
type Algorithm string

// The algorithms the platform accepts for an agent's key. EdDSA is the default.
const (
	EdDSA Algorithm = "EdDSA"
	ES256 Algorithm = "ES256"
	PS256 Algorithm = "PS256"
)

const (
	rsaMinBits       = 2048
	rsaMaxBits       = 4096
	rsaGeneratedBits = 3072
	rsaExponent      = 65537
)

// Key is an agent's private key. There is no method that returns the private key as a value:
// WriteFile is the one way out. It prints as agent.Key(kid=..., alg=...).
type Key struct {
	alg    Algorithm
	kid    string
	signer crypto.Signer
}

// GenerateKey makes a new key. kid is the key id registered with the public half; when empty it is
// the RFC 7638 thumbprint of the public key.
func GenerateKey(alg Algorithm, kid string) (*Key, error) {
	var s crypto.Signer
	var err error
	switch alg {
	case EdDSA:
		_, s, err = ed25519.GenerateKey(rand.Reader)
	case ES256:
		s, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	case PS256:
		s, err = rsa.GenerateKey(rand.Reader, rsaGeneratedBits)
	default:
		return nil, fmt.Errorf("agent: unsupported algorithm %q: use EdDSA, ES256 or PS256", alg)
	}
	if err != nil {
		return nil, fmt.Errorf("agent: generate key: %w", err)
	}
	return newKey(s, kid)
}

// ParseKey reads a PEM private key (PKCS#8, SEC1 EC or PKCS#1 RSA). The algorithm follows the
// key: Ed25519 signs EdDSA, P-256 signs ES256, RSA of 2048 to 4096 bits with exponent 65537
// signs PS256. kid as in GenerateKey.
func ParseKey(pemBytes []byte, kid string) (*Key, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, errors.New("agent: the key is not PEM")
	}
	var parsed any
	var err error
	switch block.Type {
	case "PRIVATE KEY":
		parsed, err = x509.ParsePKCS8PrivateKey(block.Bytes)
	case "EC PRIVATE KEY":
		parsed, err = x509.ParseECPrivateKey(block.Bytes)
	case "RSA PRIVATE KEY":
		parsed, err = x509.ParsePKCS1PrivateKey(block.Bytes)
	default:
		return nil, fmt.Errorf("agent: unsupported PEM block %q", block.Type)
	}
	if err != nil {
		return nil, errors.New("agent: the key could not be parsed")
	}
	s, ok := parsed.(crypto.Signer)
	if !ok {
		return nil, errors.New("agent: the key cannot sign")
	}
	return newKey(s, kid)
}

// LoadKey reads a PEM private key from path. On Linux and macOS it refuses a file readable by
// group or others, and names the chmod; Windows ACLs are not checked. kid as in GenerateKey.
func LoadKey(path, kid string) (*Key, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("agent: cannot read the key file: %w", errors.Unwrap(err))
	}
	if runtime.GOOS != "windows" && info.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("agent: the key file %s is readable by group or others (mode %04o): run chmod 600 on it", path, info.Mode().Perm())
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("agent: cannot read the key file: %w", errors.Unwrap(err))
	}
	return ParseKey(b, kid)
}

func newKey(s crypto.Signer, kid string) (*Key, error) {
	k := &Key{signer: s}
	switch pk := s.(type) {
	case ed25519.PrivateKey:
		k.alg = EdDSA
	case *ecdsa.PrivateKey:
		if pk.Curve != elliptic.P256() {
			return nil, errors.New("agent: an EC key must be on P-256 (ES256)")
		}
		k.alg = ES256
	case *rsa.PrivateKey:
		if bits := pk.N.BitLen(); bits < rsaMinBits || bits > rsaMaxBits {
			return nil, fmt.Errorf("agent: an RSA key must be %d to %d bits, this one is %d", rsaMinBits, rsaMaxBits, bits)
		}
		if pk.E != rsaExponent {
			return nil, errors.New("agent: an RSA key must use exponent 65537")
		}
		k.alg = PS256
	default:
		return nil, errors.New("agent: the key must be Ed25519, P-256 or RSA")
	}
	if kid == "" {
		kid = thumbprint(k.PublicJWK())
	}
	k.kid = kid
	return k, nil
}

// KID is the key id the assertion header names.
func (k *Key) KID() string { return k.kid }

// Alg is the algorithm the key signs with.
func (k *Key) Alg() Algorithm { return k.alg }

// PublicJWK is the public half, in the form registered in the console.
func (k *Key) PublicJWK() map[string]string {
	switch pub := k.signer.Public().(type) {
	case ed25519.PublicKey:
		return map[string]string{"kty": "OKP", "crv": "Ed25519", "x": b64(pub)}
	case *ecdsa.PublicKey:
		return map[string]string{"kty": "EC", "crv": "P-256",
			"x": b64(pub.X.FillBytes(make([]byte, 32))), "y": b64(pub.Y.FillBytes(make([]byte, 32)))}
	case *rsa.PublicKey:
		return map[string]string{"kty": "RSA", "n": b64(pub.N.Bytes()), "e": b64(big.NewInt(int64(pub.E)).Bytes())}
	}
	return nil
}

// WriteFile writes the private key as PKCS#8 PEM to a new file readable by its owner only. It
// refuses to overwrite.
func (k *Key) WriteFile(path string) error {
	der, err := x509.MarshalPKCS8PrivateKey(k.signer)
	if err != nil {
		return errors.New("agent: the key could not be encoded")
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("agent: cannot create the key file: %w", errors.Unwrap(err))
	}
	if _, err := f.Write(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})); err != nil {
		_ = f.Close()
		_ = os.Remove(path)
		return errors.New("agent: cannot write the key file")
	}
	return f.Close()
}

func (k *Key) sign(data []byte) ([]byte, error) {
	switch k.alg {
	case EdDSA:
		return k.signer.Sign(rand.Reader, data, crypto.Hash(0))
	case ES256:
		h := sha256.Sum256(data)
		r, s, err := ecdsa.Sign(rand.Reader, k.signer.(*ecdsa.PrivateKey), h[:])
		if err != nil {
			return nil, err
		}
		out := make([]byte, 64)
		r.FillBytes(out[:32])
		s.FillBytes(out[32:])
		return out, nil
	default:
		h := sha256.Sum256(data)
		return k.signer.Sign(rand.Reader, h[:], &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: crypto.SHA256})
	}
}

func (k Key) String() string               { return fmt.Sprintf("agent.Key(kid=%s, alg=%s)", k.kid, k.alg) }
func (k Key) GoString() string             { return k.String() }
func (k Key) Format(f fmt.State, _ rune)   { _, _ = io.WriteString(f, k.String()) }
func (k Key) LogValue() slog.Value         { return slog.StringValue(k.String()) }
func (k Key) MarshalText() ([]byte, error) { return []byte(k.String()), nil }
func (k Key) MarshalJSON() ([]byte, error) {
	return []byte(fmt.Sprintf(`{"kid":%q,"alg":%q}`, k.kid, k.alg)), nil
}

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// thumbprint is the RFC 7638 SHA-256 thumbprint: the required members in lexicographic order.
func thumbprint(jwk map[string]string) string {
	var canonical string
	switch jwk["kty"] {
	case "OKP":
		canonical = fmt.Sprintf(`{"crv":%q,"kty":"OKP","x":%q}`, jwk["crv"], jwk["x"])
	case "EC":
		canonical = fmt.Sprintf(`{"crv":%q,"kty":"EC","x":%q,"y":%q}`, jwk["crv"], jwk["x"], jwk["y"])
	default:
		canonical = fmt.Sprintf(`{"e":%q,"kty":"RSA","n":%q}`, jwk["e"], jwk["n"])
	}
	sum := sha256.Sum256([]byte(canonical))
	return b64(sum[:])
}
