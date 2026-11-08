package agent

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
)

// Evidence is what an instance shows to prove where it runs. Each kind matches the kind of workload
// binding the agent was registered with: the platform refuses evidence of another kind.
//
// Make one with KubernetesEvidence or DeviceEvidence. An Evidence is made for one nonce, one agent
// and one instance key: it cannot be reused for another attestation.
type Evidence interface {
	// Kind is the binding kind this evidence proves: "k8s" or "device".
	Kind() string
	// evidence makes the proof for one attestation. Only this package implements it, so a new kind
	// is a new proof the platform has a verifier for, never a free-form string.
	evidence(ctx context.Context, in evidenceInput) (string, error)
}

// evidenceInput is everything an evidence may bind itself to.
type evidenceInput struct {
	Nonce          string
	AgentID        string
	InstanceKeyJkt string
	Issuer         string
	Now            time.Time
}

const (
	// KubernetesTokenPath is where Kubernetes projects the pod's service-account token by default.
	KubernetesTokenPath = "/var/run/secrets/kubernetes.io/serviceaccount/token"

	// deviceMessagePrefix domain-separates the device's signature from anything else the key could sign.
	deviceMessagePrefix = "authfi-agent-attest\n"

	kindKubernetes = "k8s"
	kindDevice     = "device"

	maxEvidenceFile = 16 << 10

	// maxKubernetesTokenLifetime is the longest service-account token the platform accepts, in seconds.
	maxKubernetesTokenLifetime = 600
)

// bindingMessage is the exact bytes a device key signs: the server nonce, the agent the instance
// attests as and the thumbprint of the instance key. Binding the instance key means a captured
// signature cannot be spent for an attestation that names another key. The platform checks these
// exact bytes (agent-identity internal/service/attest, DeviceMessage).
func bindingMessage(nonce, agentID, instanceKeyJkt string) []byte {
	return []byte(deviceMessagePrefix + nonce + "\n" + agentID + "\n" + instanceKeyJkt)
}

// --- Kubernetes ---

// errEvidenceNotRotated marks evidence that cannot be remade yet because the kubelet has not rotated
// the file. It is not a refusal by the platform: nothing was decided, so a still-valid token may be
// used meanwhile.
var errEvidenceNotRotated = errors.New("evidence not rotated")

type kubernetesEvidence struct {
	path string

	mu   sync.Mutex
	last string // the token used last: a service-account token works once
}

// KubernetesEvidence is the pod's projected service-account token, read from path at the time of each
// sign-in (empty path means KubernetesTokenPath). Project it with audience set to the project's
// origin and expirationSeconds: 600, so the kubelet renews it before the next attestation is due.
// The token works once; the SDK refuses to present the same one twice. A token counts as used when
// it is handed to the sign-in, so a connection that fails after the send leaves the sign-in
// blocked until the kubelet rotates the file (up to about 8 minutes): the platform may have seen it.
func KubernetesEvidence(path string) Evidence {
	if strings.TrimSpace(path) == "" {
		path = KubernetesTokenPath
	}
	return &kubernetesEvidence{path: path}
}

func (k *kubernetesEvidence) Kind() string { return kindKubernetes }

func (k *kubernetesEvidence) evidence(_ context.Context, in evidenceInput) (string, error) {
	token, err := readSmallFile(k.path)
	if err != nil {
		return "", fmt.Errorf("agent: cannot read the service-account token %s (%w): on Kubernetes project one there "+
			"(audience %s, expirationSeconds 600), or name where it is", k.path, err, issuerOrigin(in.Issuer))
	}
	if token == "" {
		return "", fmt.Errorf("agent: the service-account token file %s is empty", k.path)
	}
	claims, err := jwtClaims(token)
	if err != nil {
		return "", fmt.Errorf("agent: %s does not hold a service-account JWT", k.path)
	}
	if !audienceHas(claims["aud"], issuerOrigin(in.Issuer), in.Issuer) {
		return "", fmt.Errorf("agent: the service-account token in %s is not for %s: project one with audience %s",
			k.path, issuerOrigin(in.Issuer), issuerOrigin(in.Issuer))
	}
	if exp, ok := claims["exp"].(float64); ok && !in.Now.Before(time.Unix(int64(exp), 0)) {
		return "", fmt.Errorf("agent: the service-account token in %s has expired: project it with expirationSeconds 600 "+
			"so the kubelet renews it", k.path)
	}
	// The platform refuses a token that lives longer than 600 seconds (token_lifetime_too_long).
	if iat, ok := claims["iat"].(float64); ok {
		if exp, ok := claims["exp"].(float64); ok && exp-iat > maxKubernetesTokenLifetime {
			return "", fmt.Errorf("agent: the service-account token in %s lives %d seconds and the platform accepts at most %d: "+
				"project it with expirationSeconds: 600", k.path, int64(exp-iat), maxKubernetesTokenLifetime)
		}
	}
	k.mu.Lock()
	defer k.mu.Unlock()
	if token == k.last {
		return "", fmt.Errorf("agent: the service-account token in %s has not rotated since the last sign-in tried it, and it "+
			"works once (a sign-in that failed after sending it may have spent it): project it with expirationSeconds: 600 "+
			"so the kubelet renews it every 8 minutes: %w", k.path, errEvidenceNotRotated)
	}
	k.last = token
	return token, nil
}

// --- device ---

type deviceEvidence struct{ key *Key }

// DeviceEvidence is a signature by the device key the agent was bound to, over the nonce, the agent
// and the instance key. The device key signs only that; it is never sent.
func DeviceEvidence(key *Key) (Evidence, error) {
	if key == nil {
		return nil, errors.New("agent: the device key is required")
	}
	return deviceEvidence{key: key}, nil
}

func (deviceEvidence) Kind() string { return kindDevice }

func (d deviceEvidence) evidence(_ context.Context, in evidenceInput) (string, error) {
	sig, err := d.key.sign(bindingMessage(in.Nonce, in.AgentID, in.InstanceKeyJkt))
	if err != nil {
		return "", errors.New("agent: the device key could not sign the evidence")
	}
	return b64(sig), nil
}

// --- helpers ---

func readSmallFile(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", errors.Unwrap(err)
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, maxEvidenceFile+1))
	if err != nil {
		return "", errors.New("the file could not be read")
	}
	if len(b) > maxEvidenceFile {
		return "", errors.New("file is too large")
	}
	return strings.TrimSpace(string(b)), nil
}

// jwtClaims reads the claims of a compact JWT without verifying it. It is for the checks a client
// makes on a token it was given, never for trusting one.
func jwtClaims(raw string) (map[string]any, error) {
	_, claims, err := jwtParts(raw)
	return claims, err
}

func jwtParts(raw string) (header, claims map[string]any, err error) {
	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		return nil, nil, errors.New("not a compact JWT")
	}
	for i, dst := range []*map[string]any{&header, &claims} {
		b, derr := base64.RawURLEncoding.DecodeString(strings.TrimRight(parts[i], "="))
		if derr != nil {
			return nil, nil, errors.New("not base64url")
		}
		if json.Unmarshal(b, dst) != nil {
			return nil, nil, errors.New("not JSON")
		}
	}
	return header, claims, nil
}

func audienceHas(aud any, accepted ...string) bool {
	has := func(s string) bool {
		for _, a := range accepted {
			if s == a {
				return true
			}
		}
		return false
	}
	switch v := aud.(type) {
	case string:
		return has(v)
	case []any:
		for _, e := range v {
			if s, ok := e.(string); ok && has(s) {
				return true
			}
		}
	}
	return false
}

func issuerOrigin(issuer string) string {
	u, err := url.Parse(issuer)
	if err != nil || u.Host == "" {
		return issuer
	}
	return u.Scheme + "://" + u.Host
}
