package agent

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	authfi "github.com/authfi/authfi-go-sdk"
)

// writeToken writes a projected service-account token for the platform's issuer and returns its path.
func writeToken(t *testing.T, p *instPlatform, n string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "token")
	rewriteToken(t, p, path, n)
	return path
}

func rewriteToken(t *testing.T, p *instPlatform, path, n string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(p.k8sToken(p.issuer(), 10*time.Minute, n)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
}

func mustToken(t *testing.T, a *Agent) Token {
	t.Helper()
	tok, err := a.Token(context.Background())
	if err != nil {
		t.Fatalf("Token: %v", err)
	}
	return tok
}

func tokenErr(t *testing.T, a *Agent) *TokenError {
	t.Helper()
	_, err := a.Token(context.Background())
	var te *TokenError
	if !errors.As(err, &te) {
		t.Fatalf("want a *TokenError, got %v", err)
	}
	return te
}

// --- the happy path, and what it proves ---

func TestKubernetesInstanceSignsInAndBindsTheTokenToItsOwnKey(t *testing.T) {
	p := newInstPlatform(t)
	path := writeToken(t, p, "a")
	a := p.instanceWith(KubernetesEvidence(path))

	if a.inst.key != nil {
		t.Fatal("the instance key must not exist before the first sign-in (a snapshot must hold none)")
	}
	if p.requests() != 0 {
		t.Fatal("New fetches nothing")
	}
	tok := mustToken(t, a)
	if tok.Reveal() == "" || a.InstanceID() == "" || !instanceIDRE.MatchString(a.InstanceID()) {
		t.Fatalf("token %v instance %q", tok, a.InstanceID())
	}
	if got := p.issuedTokens[tok.Reveal()]; got != a.inst.key.Thumbprint() {
		t.Fatalf("token bound to %q, instance key is %q", got, a.inst.key.Thumbprint())
	}
	body := p.attests[0]
	ev := body["evidence"].(map[string]any)
	if ev["kind"] != "k8s" || ev["token"] == "" {
		t.Fatalf("evidence %v", ev)
	}
	if _, has := body["image_digest"]; has {
		t.Fatal("no image digest was given")
	}
	form := p.tokenReqs[0].form
	if form.Get("client_assertion") != "" || form.Get("client_id") != testInstAgent {
		t.Fatalf("a bound agent sends no assertion: %v", form)
	}
}

func TestAWarmInstanceDoesNoNetworkWorkWhileTheTokenIsValid(t *testing.T) {
	p := newInstPlatform(t)
	a := p.instanceWith(KubernetesEvidence(writeToken(t, p, "a")))
	first := mustToken(t, a)
	n := p.requests()
	for i := 0; i < 5; i++ {
		if got := mustToken(t, a); got.Reveal() != first.Reveal() {
			t.Fatal("a valid token is reused")
		}
	}
	if p.requests() != n {
		t.Fatalf("warm calls made %d requests", p.requests()-n)
	}
}

func TestConcurrentCallersShareOneSignIn(t *testing.T) {
	p := newInstPlatform(t)
	a := p.instanceWith(KubernetesEvidence(writeToken(t, p, "a")))
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := a.Token(context.Background()); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	if c, at, tk := p.count("POST "+challengePath), p.count("POST "+attestPath), p.count("POST /oauth/token"); c != 1 || at != 1 || tk != 1 {
		t.Fatalf("challenge %d attest %d token %d", c, at, tk)
	}
}

func TestTheAttestationIsRenewedBeforeItEndsWithANewNonceAndNewEvidence(t *testing.T) {
	p := newInstPlatform(t)
	path := writeToken(t, p, "a")
	a := p.instanceWith(KubernetesEvidence(path))
	mustToken(t, a)
	first := a.inst.att

	// The access token (600 s) is renewed first and the attestation (900 s) is still good: no new attest.
	p.advance(560 * time.Second)
	mustToken(t, a)
	if p.count("POST "+attestPath) != 1 || a.inst.att != first {
		t.Fatal("the attestation still had more than a minute: it is kept")
	}
	// The attestation (900 s) has ended by the time the access token is due again: a new one, from a
	// rotated token, with a new nonce.
	p.advance(540 * time.Second)
	rewriteToken(t, p, path, "b")
	mustToken(t, a)
	if p.count("POST "+attestPath) != 2 {
		t.Fatalf("attests %d", p.count("POST "+attestPath))
	}
	n1 := p.attests[0]["proof"].(string)
	n2 := p.attests[1]["proof"].(string)
	_, c1, _ := jwtParts(n1)
	_, c2, _ := jwtParts(n2)
	if c1["nonce"] == c2["nonce"] || c1["jti"] == c2["jti"] {
		t.Fatal("every attestation uses its own nonce and proof id")
	}
	if a.inst.att == first || a.InstanceID() == "" {
		t.Fatal("the new attestation is held")
	}
}

func TestAnAttestationWithAMinuteLeftIsNotUsedForANewToken(t *testing.T) {
	p := newInstPlatform(t)
	p.tokenTTL = 900 // renewed 60 s before it ends, when the attestation of the same age has 60 s left
	path := writeToken(t, p, "a")
	a := p.instanceWith(KubernetesEvidence(path))
	mustToken(t, a)
	p.advance(841 * time.Second)
	rewriteToken(t, p, path, "b")
	mustToken(t, a)
	if p.count("POST "+attestPath) != 2 {
		t.Fatalf("attests %d: an attestation with under a minute left is not presented", p.count("POST "+attestPath))
	}
}

func TestADPoPNonceTheTokenEndpointWantsIsEchoedOnce(t *testing.T) {
	p := newInstPlatform(t)
	p.requireNonce = true
	a := p.instanceWith(KubernetesEvidence(writeToken(t, p, "a")))
	mustToken(t, a)
	if len(p.tokenReqs) != 2 || p.count("POST "+attestPath) != 1 {
		t.Fatalf("token requests %d attests %d", len(p.tokenReqs), p.count("POST "+attestPath))
	}
	if p.tokenReqs[0].header.Get(headerPoP) == p.tokenReqs[1].header.Get(headerPoP) {
		t.Fatal("the proof of possession is new for each request (its jti is single use)")
	}
}

func TestAnAttestRequestIsNeverSentAgain(t *testing.T) {
	p := newInstPlatform(t)
	p.attestStatus = http.StatusServiceUnavailable
	a := p.instanceWith(KubernetesEvidence(writeToken(t, p, "a")))
	te := tokenErr(t, a)
	if te.Code != "attestation_unavailable" || te.Status != 503 || !strings.Contains(te.Description, "Sign in again") {
		t.Fatalf("%+v", te)
	}
	if p.count("POST "+attestPath) != 1 || len(p.tokenReqs) != 0 {
		t.Fatalf("attests %d token requests %d: the evidence works once, so nothing is resent", p.count("POST "+attestPath), len(p.tokenReqs))
	}
}

// --- device evidence ---

func TestDeviceInstanceSignsInWithEveryKeyAlgorithm(t *testing.T) {
	for _, alg := range algs {
		t.Run(string(alg), func(t *testing.T) {
			p := newInstPlatform(t)
			dev := keyFor(t, alg)
			p.kind, p.deviceJWK, p.deviceAlg = kindDevice, dev.PublicJWK(), alg
			ev, err := DeviceEvidence(dev)
			if err != nil {
				t.Fatal(err)
			}
			a := p.instanceWith(ev)
			mustToken(t, a)
			if p.attests[0]["evidence"].(map[string]any)["kind"] != "device" {
				t.Fatal("device evidence")
			}
		})
	}
}

func TestAnotherDeviceKeysSignatureIsRefusedAndNeverLeaksTheEvidence(t *testing.T) {
	p := newInstPlatform(t)
	bound := keyFor(t, ES256)
	p.kind, p.deviceJWK, p.deviceAlg = kindDevice, bound.PublicJWK(), ES256
	ev, _ := DeviceEvidence(keyFor(t, ES256)) // a different device
	a := p.instanceWith(ev)
	te := tokenErr(t, a)
	if te.Code != "attestation_refused" || te.Status != 401 {
		t.Fatalf("%+v", te)
	}
	sent := p.attests[0]["evidence"].(map[string]any)["token"].(string)
	if strings.Contains(te.Error(), sent) {
		t.Fatal("the error repeats the evidence")
	}
	if len(p.tokenReqs) != 0 {
		t.Fatal("no token is asked for after a refused attestation")
	}
}

func TestDeviceEvidenceSignsTheNonceTheAgentAndTheInstanceKeyAndNothingElse(t *testing.T) {
	dev := keyFor(t, EdDSA)
	ev, _ := DeviceEvidence(dev)
	in := evidenceInput{Nonce: "n1", AgentID: "agt_x", InstanceKeyJkt: "jkt1"}
	sig, err := ev.evidence(context.Background(), in)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := base64.RawURLEncoding.DecodeString(sig)
	if !verifyRaw(dev.PublicJWK(), EdDSA, []byte("authfi-agent-attest\nn1\nagt_x\njkt1"), raw) {
		t.Fatal("the device signs exactly the platform's message")
	}
	for _, other := range []evidenceInput{{Nonce: "n2", AgentID: "agt_x", InstanceKeyJkt: "jkt1"}, {Nonce: "n1", AgentID: "agt_y", InstanceKeyJkt: "jkt1"}, {Nonce: "n1", AgentID: "agt_x", InstanceKeyJkt: "jkt2"}} {
		if verifyRaw(dev.PublicJWK(), EdDSA, bindingMessage(other.Nonce, other.AgentID, other.InstanceKeyJkt), raw) {
			t.Fatalf("the signature must bind the nonce, the agent and the key: %+v", other)
		}
	}
}

func TestEvidenceOfTheWrongKindIsRefused(t *testing.T) {
	p := newInstPlatform(t)
	dev := keyFor(t, EdDSA)
	p.kind = kindKubernetes // the agent is bound to a cluster
	ev, _ := DeviceEvidence(dev)
	te := tokenErr(t, p.instanceWith(ev))
	if te.Code != "attestation_refused" || !strings.Contains(p.refusals[0], "binding k8s") {
		t.Fatalf("%+v %v", te, p.refusals)
	}
}

// --- Kubernetes evidence the SDK refuses itself ---

func TestKubernetesTokenForAnotherAudienceIsNotSent(t *testing.T) {
	p := newInstPlatform(t)
	path := filepath.Join(t.TempDir(), "token")
	_ = os.WriteFile(path, []byte(p.k8sToken("https://kubernetes.default.svc", time.Hour, "x")), 0o600)
	te := tokenErr(t, p.instanceWith(KubernetesEvidence(path)))
	if te.Code != "evidence_unavailable" || !strings.Contains(te.Description, "audience "+p.issuer()) {
		t.Fatalf("%+v", te)
	}
	if p.count("POST "+attestPath) != 0 {
		t.Fatal("a token for the wrong audience is not sent")
	}
}

func TestKubernetesTokenThatHasNotRotatedIsNotPresentedTwice(t *testing.T) {
	p := newInstPlatform(t)
	path := filepath.Join(t.TempDir(), "token")
	_ = os.WriteFile(path, []byte(p.k8sToken(p.issuer(), 3*time.Hour, "long")), 0o600)
	a := p.instanceWith(KubernetesEvidence(path))
	mustToken(t, a)
	p.advance(15 * time.Minute) // the attestation is due again, the kubelet has not rotated the file
	te := tokenErr(t, a)
	if te.Code != "evidence_unavailable" || !strings.Contains(te.Description, "has not rotated") {
		t.Fatalf("%+v", te)
	}
	if p.count("POST "+attestPath) != 1 {
		t.Fatal("a spent service-account token is not sent again")
	}
}

func TestKubernetesTokenThatIsMissingEmptyExpiredOrNotAJWT(t *testing.T) {
	p := newInstPlatform(t)
	dir := t.TempDir()
	write := func(name, content string) string {
		path := filepath.Join(dir, name)
		_ = os.WriteFile(path, []byte(content), 0o600)
		return path
	}
	cases := map[string]struct{ path, want string }{
		"missing":   {filepath.Join(dir, "nope"), "cannot read the service-account token"},
		"empty":     {write("empty", "  \n"), "is empty"},
		"not a jwt": {write("junk", "not-a-token"), "does not hold a service-account JWT"},
		"expired":   {write("old", p.k8sToken(p.issuer(), -time.Minute, "o")), "has expired"},
		"too large": {write("big", strings.Repeat("a", maxEvidenceFile+1)), "cannot read the service-account token"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			te := tokenErr(t, p.instanceWith(KubernetesEvidence(c.path)))
			if te.Code != "evidence_unavailable" || !strings.Contains(te.Description, c.want) {
				t.Fatalf("%+v", te)
			}
		})
	}
	if p.count("POST "+attestPath) != 0 {
		t.Fatal("no bad evidence reaches the platform")
	}
}

// --- an attestation the SDK will not hold ---

func TestAnAttestationThatIsNotThisInstancesIsRefused(t *testing.T) {
	cases := map[string]struct {
		claims func(map[string]any)
		header func(map[string]any)
		want   string
	}{
		"another agent": {claims: func(c map[string]any) { c["sub"] = "agt_other" }, want: "is for"},
		"another key": {claims: func(c map[string]any) {
			c["cnf"] = map[string]any{"jwk": map[string]any{"kty": "OKP", "crv": "Ed25519", "x": "AAAA"}}
		}, want: "different key"},
		"no key":           {claims: func(c map[string]any) { delete(c, "cnf") }, want: "different key"},
		"wrong typ":        {header: func(h map[string]any) { h["typ"] = "JWT" }, want: "typ"},
		"no instance id":   {claims: func(c map[string]any) { c["authfi_instance"] = map[string]any{} }, want: "instance_id"},
		"bad instance id":  {claims: func(c map[string]any) { c["authfi_instance"] = map[string]any{"instance_id": "inst_XYZ"} }, want: "instance_id"},
		"too long":         {claims: func(c map[string]any) { c["exp"] = c["iat"].(int64) + 901 }, want: "longer than 900"},
		"no lifetime":      {claims: func(c map[string]any) { delete(c, "exp") }, want: "no lifetime"},
		"already expired":  {claims: func(c map[string]any) { c["exp"] = c["iat"].(int64) - 1 }, want: "expired"},
		"expiry is a text": {claims: func(c map[string]any) { c["exp"] = "soon" }, want: "no lifetime"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			p := newInstPlatform(t)
			p.mutate, p.mutateHeader = c.claims, c.header
			if p.mutate == nil {
				p.mutate = func(map[string]any) {}
			}
			te := tokenErr(t, p.instanceWith(KubernetesEvidence(writeToken(t, p, "a"))))
			if te.Code != "invalid_response" || !strings.Contains(te.Description, c.want) {
				t.Fatalf("%+v", te)
			}
			if len(p.tokenReqs) != 0 {
				t.Fatal("an attestation that fails the client's checks is not presented")
			}
		})
	}
}

func TestRefusalsKeepEverySecretOutOfTheErrorAndTheLog(t *testing.T) {
	p := newInstPlatform(t)
	var logs bytes.Buffer
	a := p.instanceWith(KubernetesEvidence(writeToken(t, p, "a")), WithLogger(slog.New(slog.NewTextHandler(&logs, nil))))
	tok := mustToken(t, a)
	att := a.inst.att.token.Reveal()
	for name, s := range map[string]string{"access token": tok.Reveal(), "attestation": att} {
		for _, shown := range []string{a.String(), logs.String(), stringOf(a), stringOf(tok)} {
			if strings.Contains(shown, s) {
				t.Fatalf("the %s is shown: %s", name, shown)
			}
		}
	}
	if !strings.Contains(logs.String(), "instance attested") {
		t.Fatalf("one line per attestation: %s", logs.String())
	}
}

func stringOf(v any) string { return strings.TrimSpace(fmt.Sprint(v)) }

func TestAPlatformThatEchoesTheEvidenceDoesNotGetItBackInTheError(t *testing.T) {
	p := newInstPlatform(t)
	path := writeToken(t, p, "a")
	raw, _ := os.ReadFile(path)
	echoed := strings.TrimSpace(string(raw))
	p.extraAttest = func(w http.ResponseWriter) bool {
		writeJSONTest(w, 401, map[string]string{"error": "unauthorized", "error_description": "bad evidence " + echoed})
		return true
	}
	te := tokenErr(t, p.instanceWith(KubernetesEvidence(path)))
	if strings.Contains(te.Error(), echoed) || strings.Contains(te.Error(), echoed[:20]) {
		t.Fatalf("the evidence is in the error: %s", te)
	}
}

func TestAnObservedInstanceIsToldWhatToDoWhenRefused(t *testing.T) {
	p := newInstPlatform(t) // no observation window is open
	a, err := NewInstance(p.issuer(), testInstAgent, KubernetesEvidence(writeToken(t, p, "a")), ObserveConfiguration())
	if err != nil {
		t.Fatal(err)
	}
	a.now = p.clock
	te := tokenErr(t, a)
	if te.Code != "attestation_refused" || !strings.Contains(te.Description, "observation window") {
		t.Fatalf("%+v", te)
	}
	cfg := p.attests[0]["config"].(map[string]any)
	if cfg["version"].(float64) != 0 || cfg["digest"] != "" {
		t.Fatalf("an observed instance names no version: %v", cfg)
	}

	p.observeOpen = true
	rewriteToken(t, p, a.inst.evidence.(*kubernetesEvidence).path, "b")
	mustToken(t, a)
}

func TestAnUnapprovedConfigurationIsRefusedByThePlatform(t *testing.T) {
	p := newInstPlatform(t)
	a, _ := NewInstance(p.issuer(), testInstAgent, KubernetesEvidence(writeToken(t, p, "a")), Configuration{Version: 2, Digest: testCfgDigest})
	a.now = p.clock
	if te := tokenErr(t, a); te.Code != "attestation_refused" || !strings.Contains(p.refusals[0], "not approved") {
		t.Fatalf("%+v %v", te, p.refusals)
	}
}

// --- construction ---

func TestNewInstanceRefusesWhatCannotSignIn(t *testing.T) {
	ev := KubernetesEvidence("")
	good := Configuration{Version: 1, Digest: testCfgDigest}
	dev, _ := DeviceEvidence(keyFor(t, EdDSA))
	_ = dev
	cases := map[string]func() error{
		"no evidence":        func() error { _, err := NewInstance("https://a.authfi.io", "agt_1", nil, good); return err },
		"zero configuration": func() error { _, err := NewInstance("https://a.authfi.io", "agt_1", ev, Configuration{}); return err },
		"version zero": func() error {
			_, err := NewInstance("https://a.authfi.io", "agt_1", ev, Configuration{Digest: testCfgDigest})
			return err
		},
		"no digest": func() error {
			_, err := NewInstance("https://a.authfi.io", "agt_1", ev, Configuration{Version: 1})
			return err
		},
		"digest not sha256": func() error {
			_, err := NewInstance("https://a.authfi.io", "agt_1", ev, Configuration{Version: 1, Digest: "md5:ab"})
			return err
		},
		"observe with a version": func() error {
			c := ObserveConfiguration()
			c.Version = 2
			_, err := NewInstance("https://a.authfi.io", "agt_1", ev, c)
			return err
		},
		"http issuer": func() error { _, err := NewInstance("http://a.authfi.io", "agt_1", ev, good); return err },
		"no agent id": func() error { _, err := NewInstance("https://a.authfi.io", " ", ev, good); return err },
		"with DPoP": func() error {
			_, err := NewInstance("https://a.authfi.io", "agt_1", ev, good, WithDPoP(keyFor(t, EdDSA)))
			return err
		},
		"bad image": func() error {
			_, err := NewInstance("https://a.authfi.io", "agt_1", ev, good, WithImageDigest("sha256:abc"))
			return err
		},
		"bad api host": func() error {
			_, err := NewInstance("https://a.authfi.io", "agt_1", ev, good, WithAPIOrigin("http://evil.example"))
			return err
		},
	}
	for name, f := range cases {
		t.Run(name, func(t *testing.T) {
			if f() == nil {
				t.Fatal("must be refused")
			}
		})
	}
	if _, err := NewInstance("https://a.authfi.io", "agt_1", ev, good, WithImageDigest("sha256:"+strings.Repeat("a", 64))); err != nil {
		t.Fatal(err)
	}
	if _, err := DeviceEvidence(nil); err == nil {
		t.Fatal("a device evidence needs a key")
	}
}

func TestTheImageDigestAndAPIOriginAreUsed(t *testing.T) {
	p := newInstPlatform(t)
	digest := "sha256:" + strings.Repeat("b", 64)
	a := p.instanceWith(KubernetesEvidence(writeToken(t, p, "a")), WithImageDigest(digest), WithAPIOrigin(p.issuer()+"/"))
	mustToken(t, a)
	if p.attests[0]["image_digest"] != digest {
		t.Fatalf("%v", p.attests[0])
	}
}

func TestAnInstanceDoesNotActForAPersonYetAndSaysSo(t *testing.T) {
	p := newInstPlatform(t)
	a := p.instanceWith(KubernetesEvidence(writeToken(t, p, "a")))
	_, err := a.RequestUserApproval(context.Background(), "ann@example.com", "Refund order 4411", nil, 0)
	var te *TokenError
	if !errors.As(err, &te) || te.Code != "not_supported" {
		t.Fatalf("%v", err)
	}
	if _, err := a.Exchange(context.Background(), authfi.NewSecret("subject-token-123"), nil, ""); !errors.As(err, &te) || te.Code != "not_supported" {
		t.Fatalf("%v", err)
	}
	for _, l := range p.log {
		if strings.Contains(l, "ciba") || strings.Contains(l, "token") {
			t.Fatalf("nothing is sent for an assertion an instance cannot sign: %v", p.log)
		}
	}
}

// --- the environment ---

func envOf(m map[string]string) func(string) string { return func(k string) string { return m[k] } }

func TestInstanceFromTheEnvironment(t *testing.T) {
	p := newInstPlatform(t)
	tokenPath := writeToken(t, p, "a")
	base := map[string]string{
		"AUTHFI_ISSUER": p.issuer(), "AUTHFI_AGENT_ID": testInstAgent, "AUTHFI_SERVICE_ACCOUNT_TOKEN_FILE": tokenPath,
		"AUTHFI_CONFIG_VERSION": "3", "AUTHFI_CONFIG_DIGEST": testCfgDigest,
	}
	none := func(string) bool { return false }
	with := func(over map[string]string) map[string]string {
		m := map[string]string{}
		for k, v := range base {
			m[k] = v
		}
		for k, v := range over {
			if v == "-" {
				delete(m, k)
			} else {
				m[k] = v
			}
		}
		return m
	}

	a, err := newInstanceFromLookup(envOf(base), none)
	if err != nil {
		t.Fatal(err)
	}
	a.now = p.clock
	mustToken(t, a)

	devPath := filepath.Join(t.TempDir(), "device.pem")
	dev := keyFor(t, ES256)
	if err := dev.WriteFile(devPath); err != nil {
		t.Fatal(err)
	}
	d, err := newInstanceFromLookup(envOf(with(map[string]string{"AUTHFI_DEVICE_KEY_FILE": devPath, "AUTHFI_DEVICE_KEY_KID": "dk1"})), none)
	if err != nil || d.inst.evidence.Kind() != kindDevice {
		t.Fatalf("%v %v", d, err)
	}
	if o, err := newInstanceFromLookup(envOf(with(map[string]string{"AUTHFI_CONFIG_VERSION": "-", "AUTHFI_CONFIG_DIGEST": "-", "AUTHFI_CONFIG_OBSERVE": "1"})), none); err != nil || !o.inst.cfg.IsObserve() {
		t.Fatalf("%v %v", o, err)
	}
	if k, err := newInstanceFromLookup(envOf(with(map[string]string{"AUTHFI_SERVICE_ACCOUNT_TOKEN_FILE": "-"})), func(path string) bool { return path == KubernetesTokenPath }); err != nil || k.inst.evidence.(*kubernetesEvidence).path != KubernetesTokenPath {
		t.Fatalf("%v %v", k, err)
	}

	bad := map[string]map[string]string{
		"no issuer":                  with(map[string]string{"AUTHFI_ISSUER": "-"}),
		"no agent":                   with(map[string]string{"AUTHFI_AGENT_ID": "-"}),
		"no evidence":                with(map[string]string{"AUTHFI_SERVICE_ACCOUNT_TOKEN_FILE": "-"}),
		"no configuration":           with(map[string]string{"AUTHFI_CONFIG_VERSION": "-", "AUTHFI_CONFIG_DIGEST": "-"}),
		"version not a number":       with(map[string]string{"AUTHFI_CONFIG_VERSION": "three"}),
		"digest not sha256":          with(map[string]string{"AUTHFI_CONFIG_DIGEST": "abc"}),
		"observe and a version":      with(map[string]string{"AUTHFI_CONFIG_OBSERVE": "1"}),
		"observe is not a boolean":   with(map[string]string{"AUTHFI_CONFIG_OBSERVE": "maybe"}),
		"device key missing":         with(map[string]string{"AUTHFI_DEVICE_KEY_FILE": filepath.Join(t.TempDir(), "gone.pem")}),
		"bad image digest":           with(map[string]string{"AUTHFI_IMAGE_DIGEST": "latest"}),
		"api origin is not an https": with(map[string]string{"AUTHFI_API_ORIGIN": "http://evil.example"}),
	}
	for name, env := range bad {
		t.Run(name, func(t *testing.T) {
			if a, err := newInstanceFromLookup(envOf(env), none); err == nil {
				t.Fatalf("must be refused, got %v", a)
			}
		})
	}
}

// --- DPoP on the resource ---

func TestTheInstanceTokenIsSentWithAProofOfTheInstanceKey(t *testing.T) {
	p := newInstPlatform(t)
	a := p.instanceWith(KubernetesEvidence(writeToken(t, p, "a")))

	var got struct {
		auth, proof string
		jkt         string
	}
	res := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got.auth, got.proof = r.Header.Get("Authorization"), r.Header.Get("DPoP")
		h, c, _ := jwtParts(got.proof)
		jwk := map[string]string{}
		for k, v := range h["jwk"].(map[string]any) {
			jwk[k] = v.(string)
		}
		got.jkt = thumbprint(jwk)
		if !verifyJWT(got.proof, jwk, h["alg"].(string)) || c["htm"] != "GET" {
			w.WriteHeader(401)
			return
		}
		w.WriteHeader(200)
	}))
	defer res.Close()

	rt, err := a.DPoPTransport(res.Client().Transport, res.URL)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := (&http.Client{Transport: rt}).Get(res.URL + "/things")
	if err != nil || resp.StatusCode != 200 {
		t.Fatalf("%v %v", resp, err)
	}
	tok := mustToken(t, a)
	if got.auth != "DPoP "+tok.Reveal() {
		t.Fatalf("scheme: %q", strings.SplitN(got.auth, " ", 2)[0])
	}
	if got.jkt != p.issuedTokens[tok.Reveal()] || got.jkt != a.inst.key.Thumbprint() {
		t.Fatal("the resource proof is by the key the token is bound to")
	}
}

func TestTheInstanceKeyIsMadeOnceEvenWhenTheTransportComesFirst(t *testing.T) {
	p := newInstPlatform(t)
	a := p.instanceWith(KubernetesEvidence(writeToken(t, p, "a")))
	if _, err := a.DPoPTransport(nil, "https://api.example.com"); err != nil {
		t.Fatal(err)
	}
	k := a.inst.key
	if k == nil {
		t.Fatal("the transport needs the key")
	}
	mustToken(t, a)
	if a.inst.key != k {
		t.Fatal("one instance, one key")
	}
}

func TestAnInstanceHasNoStaticKeyToPrint(t *testing.T) {
	p := newInstPlatform(t)
	a := p.instanceWith(KubernetesEvidence(writeToken(t, p, "a")))
	for _, s := range []string{a.String(), stringOf(a)} {
		if !strings.Contains(s, "instance=k8s") || strings.Contains(s, "key=") {
			t.Fatal(s)
		}
	}
}
