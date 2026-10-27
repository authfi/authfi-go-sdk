package agent

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"sync"
	"time"

	"golang.org/x/oauth2"
)

const (
	headerDPoP      = "DPoP"
	headerDPoPNonce = "DPoP-Nonce"
	maxNonces       = 64
)

// Thumbprint is the RFC 7638 SHA-256 thumbprint of the public key: the cnf.jkt a token bound to
// this key carries.
func (k *Key) Thumbprint() string { return thumbprint(k.PublicJWK()) }

// dpopProof builds a DPoP proof (RFC 9449) for one request: htm and htu name it, ath binds it to
// accessToken when there is one, and nonce echoes a server nonce.
func (k *Key) dpopProof(method, htu, accessToken, nonce string, now time.Time) (string, error) {
	var jti [16]byte
	if _, err := rand.Read(jti[:]); err != nil {
		return "", errors.New("agent: no randomness for the DPoP proof id")
	}
	claims := map[string]any{"jti": hex.EncodeToString(jti[:]), "htm": method, "htu": htu, "iat": now.Unix()}
	if accessToken != "" {
		sum := sha256.Sum256([]byte(accessToken))
		claims["ath"] = b64(sum[:])
	}
	if nonce != "" {
		claims["nonce"] = nonce
	}
	header, _ := json.Marshal(map[string]any{"typ": "dpop+jwt", "alg": string(k.alg), "jwk": k.PublicJWK()})
	body, _ := json.Marshal(claims)
	signed := b64(header) + "." + b64(body)
	sig, err := k.sign([]byte(signed))
	if err != nil {
		return "", errors.New("agent: the DPoP proof could not be signed")
	}
	return signed + "." + b64(sig), nil
}

// proofURL is the htu of a request: scheme, host and path, without query or fragment.
func proofURL(u *url.URL) string {
	c := url.URL{Scheme: u.Scheme, Host: u.Host, Path: u.Path, RawPath: u.RawPath}
	return c.String()
}

// nonces remembers the latest DPoP nonce each origin sent.
type nonces struct {
	mu sync.Mutex
	by map[string]string
}

func (n *nonces) get(origin string) string {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.by[origin]
}

func (n *nonces) set(origin, nonce string) {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.by == nil || len(n.by) >= maxNonces {
		n.by = map[string]string{}
	}
	n.by[origin] = nonce
}

// WithDPoP makes every token request carry a DPoP proof for key, so the platform binds the token to
// that key (cnf.jkt). A resource server that checks agent tokens requires it: use the same key in
// DPoPTransport. Use a key made for this, not the key that signs the agent's assertion.
func WithDPoP(key *Key) Option { return func(a *Agent) { a.dpop = key } }

// DPoPTransport is Transport for a token bound to key: each request carries Authorization: DPoP and
// a fresh proof of key for that request, and a server nonce the resource asks for is echoed once.
// key must be the key the token was bound to (see WithDPoP). sendTo is as for Transport.
func DPoPTransport(src oauth2.TokenSource, key *Key, base http.RoundTripper, sendTo ...string) (http.RoundTripper, error) {
	if key == nil {
		return nil, errors.New("agent: a DPoP key is required")
	}
	rt, err := Transport(src, base, sendTo...)
	if err != nil {
		return nil, err
	}
	t := rt.(*transport)
	t.dpop, t.nonces = key, &nonces{}
	return t, nil
}

// DPoPTransport is the agent's transport for a resource that requires DPoP: its token, bound by
// WithDPoP, sent with a proof per request.
func (a *Agent) DPoPTransport(base http.RoundTripper, sendTo ...string) (http.RoundTripper, error) {
	if a.dpop == nil {
		return nil, errors.New("agent: WithDPoP is required to use DPoPTransport")
	}
	return DPoPTransport(a.TokenSource(), a.dpop, base, sendTo...)
}
