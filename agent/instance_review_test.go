package agent

import (
	"bytes"
	"context"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Tests added after the independent review of the instance sign-in.

// A service-account token that lives longer than the platform accepts is named before it is sent.
func TestKubernetesTokenThatLivesLongerThanThePlatformAcceptsIsNamedBeforeSending(t *testing.T) {
	p := newInstPlatform(t)
	path := filepath.Join(t.TempDir(), "token")
	_ = os.WriteFile(path, []byte(p.k8sToken(p.issuer(), 3*time.Hour, "long")), 0o600)
	te := tokenErr(t, p.instanceWith(KubernetesEvidence(path)))
	if te.Code != "evidence_unavailable" || !strings.Contains(te.Description, "expirationSeconds: 600") ||
		!strings.Contains(te.Description, "at most 600") {
		t.Fatalf("%+v", te)
	}
	if p.count("POST "+attestPath) != 0 {
		t.Fatal("a token the platform would refuse is not sent")
	}
}

// A connection that fails after the token was handed to the attest may have spent it: the sign-in
// stays blocked until the kubelet rotates the file, and says so.
func TestKubernetesTokenIsCountedUsedWhenTheAttestFailsAfterSending(t *testing.T) {
	p := newInstPlatform(t)
	path := writeToken(t, p, "once")
	a := p.instanceWith(KubernetesEvidence(path))
	p.script(func() {
		p.extraAttest = func(w http.ResponseWriter) bool {
			hj, _ := w.(http.Hijacker)
			c, _, _ := hj.Hijack()
			_ = c.Close() // the request arrived; the reply never does
			return true
		}
	})
	if te := tokenErr(t, a); te.Code != "unreachable" {
		t.Fatalf("%+v", te)
	}
	p.script(func() { p.extraAttest = nil })
	te := tokenErr(t, a)
	if te.Code != "evidence_not_rotated" || !strings.Contains(te.Description, "may have spent it") {
		t.Fatalf("%+v", te)
	}
	rewriteToken(t, p, path, "rotated")
	mustToken(t, a) // the kubelet rotated the file: the sign-in works again
}

// A token endpoint that refuses after a good attest, and echoes everything it was shown, gets none of
// it back in the error or the log.
func TestATokenRefusalAfterAGoodAttestKeepsEveryProofOutOfTheErrorAndTheLog(t *testing.T) {
	for _, c := range []struct {
		status int
		code   string
	}{{401, "invalid_client"}, {400, "invalid_dpop_proof"}} {
		t.Run(c.code, func(t *testing.T) {
			p := newInstPlatform(t)
			var logs bytes.Buffer
			var shown []string
			p.extraToken = func(w http.ResponseWriter, r *http.Request) bool {
				shown = []string{r.Header.Get(headerAttestation), r.Header.Get(headerPoP), r.Header.Get(headerDPoP)}
				writeJSONTest(w, c.status, map[string]string{"error": c.code,
					"error_description": "bad " + strings.Join(shown, " and ")})
				return true
			}
			a := p.instanceWith(KubernetesEvidence(writeToken(t, p, "a")), WithLogger(slog.New(slog.NewTextHandler(&logs, nil))))
			te := tokenErr(t, a)
			if te.Code != c.code || te.Status != c.status {
				t.Fatalf("%+v", te)
			}
			if len(shown) != 3 || shown[0] == "" || shown[1] == "" || shown[2] == "" {
				t.Fatalf("the token request carried %v", shown)
			}
			for _, s := range shown {
				for _, out := range []string{te.Error(), te.Description, logs.String()} {
					if strings.Contains(out, s) || strings.Contains(out, s[:30]) {
						t.Fatalf("a proof is shown: %s", out)
					}
				}
			}
			if p.count("POST "+attestPath) != 1 {
				t.Fatalf("a refusal does not attest again: %d attests", p.count("POST "+attestPath))
			}
			if c.status == 400 && len(p.tokenReqs) != 1 {
				t.Fatalf("a refusal is not retried: %d token requests", len(p.tokenReqs))
			}
		})
	}
}

// Each token retry is a new request: the proof of possession is single use on the platform, so a
// retry that reused one would be refused. The attestation is not asked for again.
func TestTokenEndpointRetriesCarryNewProofsAndDoNotAttestAgain(t *testing.T) {
	p := newInstPlatform(t)
	p.tokenStatuses = []int{503, 503}
	a := p.instanceWith(KubernetesEvidence(writeToken(t, p, "a")))
	mustToken(t, a)
	if p.count("POST "+attestPath) != 1 || len(p.tokenReqs) != 3 {
		t.Fatalf("%d attests, %d token requests", p.count("POST "+attestPath), len(p.tokenReqs))
	}
	pops, dpops := map[string]bool{}, map[string]bool{}
	for _, r := range p.tokenReqs {
		_, pc, _ := jwtParts(r.header.Get(headerPoP))
		_, dc, _ := jwtParts(r.header.Get(headerDPoP))
		pops[pc["jti"].(string)], dpops[dc["jti"].(string)] = true, true
	}
	if len(pops) != 3 || len(dpops) != 3 {
		t.Fatalf("%d distinct PoP ids and %d DPoP ids over 3 requests", len(pops), len(dpops))
	}
}

func TestAChallengeThatFailsIsReportedAndLeavesTheKubernetesTokenUnspent(t *testing.T) {
	cases := map[string]struct {
		answer func(w http.ResponseWriter) bool
		code   string
		want   string
	}{
		"unavailable": {func(w http.ResponseWriter) bool {
			writeJSONTest(w, 503, map[string]string{"error": "temporarily_unavailable"})
			return true
		}, "attestation_unavailable", "Sign in again"},
		"refused": {func(w http.ResponseWriter) bool {
			writeJSONTest(w, 401, map[string]string{"error": "unauthorized"})
			return true
		}, "attestation_refused", "audit tape"},
		"no nonce": {func(w http.ResponseWriter) bool { writeJSONTest(w, 200, map[string]string{}); return true },
			"invalid_response", "no nonce"},
		"not json": {func(w http.ResponseWriter) bool { _, _ = w.Write([]byte("<html>")); return true },
			"invalid_response", "no nonce"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			p := newInstPlatform(t)
			a := p.instanceWith(KubernetesEvidence(writeToken(t, p, "a")))
			p.extraChallenge = c.answer
			te := tokenErr(t, a)
			if te.Code != c.code || !strings.Contains(te.Description, c.want) {
				t.Fatalf("%+v", te)
			}
			if p.count("POST "+attestPath) != 0 {
				t.Fatal("nothing is attested without a nonce")
			}
			p.extraChallenge = nil
			mustToken(t, a) // the same token file: it was never handed to an attest
		})
	}
}

// A still-valid token is used while the platform cannot be reached, and never after a refusal.
func TestARenewalThatCannotReachThePlatformKeepsTheTokenUntilItExpires(t *testing.T) {
	p := newInstPlatform(t)
	var logs bytes.Buffer
	a := p.instanceWith(KubernetesEvidence(writeToken(t, p, "a")), WithLogger(slog.New(slog.NewTextHandler(&logs, nil))))
	first := mustToken(t, a)

	p.advance(time.Duration(p.tokenTTL-30) * time.Second) // inside the renewal minute, the token still good
	p.tokenStatuses = []int{503, 503, 503}
	got, err := a.Token(context.Background())
	if err != nil || got.Reveal() != first.Reveal() {
		t.Fatalf("the still-valid token is used when the platform answers 503: %v %v", got, err)
	}
	if !strings.Contains(logs.String(), "using the token until it expires") {
		t.Fatalf("a warning is logged: %s", logs.String())
	}
	n := len(p.tokenReqs)
	if _, err := a.Token(context.Background()); err != nil || len(p.tokenReqs) != n {
		t.Fatalf("the next call does not hammer the platform: %v, %d new requests", err, len(p.tokenReqs)-n)
	}

	p.advance(graceRetry) // the retry is due; the platform is back
	if again := mustToken(t, a); again.Reveal() == first.Reveal() {
		t.Fatal("a renewal that can be made is made")
	}
}

func TestARenewalThatIsRefusedIsNotSoftenedAndNeitherIsAnExpiredToken(t *testing.T) {
	p := newInstPlatform(t)
	a := p.instanceWith(KubernetesEvidence(writeToken(t, p, "a")))
	mustToken(t, a)
	p.advance(time.Duration(p.tokenTTL-30) * time.Second)
	p.extraToken = func(w http.ResponseWriter, _ *http.Request) bool {
		writeJSONTest(w, 401, map[string]string{"error": "invalid_client"})
		return true
	}
	if te := tokenErr(t, a); te.Code != "invalid_client" {
		t.Fatalf("a revoked agent learns of it at once, not at expiry: %+v", te)
	}

	p.extraToken = nil
	b := p.instanceWith(KubernetesEvidence(writeToken(t, p, "b")))
	mustToken(t, b)
	p.advance(time.Duration(p.tokenTTL+1) * time.Second)
	p.tokenStatuses = []int{503, 503, 503}
	if te := tokenErr(t, b); te.Status != 503 {
		t.Fatalf("an expired token is not kept: %+v", te)
	}
}

// An attestation held with a minute or less left would be renewed on every call.
func TestAnAttestationWithAMinuteOrLessLeftIsNotHeld(t *testing.T) {
	p := newInstPlatform(t)
	p.attestTTL = 60
	te := tokenErr(t, p.instanceWith(KubernetesEvidence(writeToken(t, p, "a"))))
	if te.Code != "invalid_response" || !strings.Contains(te.Description, "a minute or less") {
		t.Fatalf("%+v", te)
	}
	if len(p.tokenReqs) != 0 {
		t.Fatal("it is not presented")
	}
}

func TestOptionsOverrideTheEnvironment(t *testing.T) {
	env := map[string]string{
		"AUTHFI_ISSUER": "https://acme.authfi.io", "AUTHFI_AGENT_ID": "agt_1",
		"AUTHFI_CONFIG_VERSION": "1", "AUTHFI_CONFIG_DIGEST": testCfgDigest,
		"AUTHFI_API_ORIGIN": "https://api.from-env.example", "AUTHFI_AGENT_RESOURCE": "https://res.from-env.example",
		"AUTHFI_IMAGE_DIGEST": "sha256:" + strings.Repeat("a", 64),
	}
	a, err := newInstanceFromLookup(func(k string) string { return env[k] }, func(string) bool { return true },
		WithAPIOrigin("https://api.from-option.example"), WithResource("https://res.from-option.example"),
		WithImageDigest("sha256:"+strings.Repeat("b", 64)))
	if err != nil {
		t.Fatal(err)
	}
	if a.apiOrigin != "https://api.from-option.example" || a.resource != "https://res.from-option.example" ||
		a.imageDigest != "sha256:"+strings.Repeat("b", 64) {
		t.Fatalf("the options did not win: %q %q %q", a.apiOrigin, a.resource, a.imageDigest)
	}
}

// Same order as the Python SDK, until AUTHFI_EVIDENCE (step 2) makes a conflict a start-up error.
func TestADeviceKeyWinsOverAKubernetesTokenWhenBothArePresent(t *testing.T) {
	keyPath := filepath.Join(t.TempDir(), "device.json")
	if err := keyFor(t, EdDSA).WriteFile(keyPath); err != nil {
		t.Fatal(err)
	}
	env := map[string]string{"AUTHFI_ISSUER": "https://acme.authfi.io", "AUTHFI_AGENT_ID": "agt_1",
		"AUTHFI_CONFIG_VERSION": "1", "AUTHFI_CONFIG_DIGEST": testCfgDigest, "AUTHFI_DEVICE_KEY_FILE": keyPath}
	a, err := newInstanceFromLookup(func(k string) string { return env[k] }, func(string) bool { return true })
	if err != nil {
		t.Fatal(err)
	}
	if a.inst.evidence.Kind() != kindDevice {
		t.Fatalf("evidence kind %s", a.inst.evidence.Kind())
	}
}

// The grace for a still-valid token and the used-once rule for the Kubernetes token work together:
// an attest that fails after it was sent, in the minute the token is due, must not leave the caller
// with an error while the old access token is still good.
func TestAnAttestDroppedInTheRenewalMinuteKeepsTheTokenWhileTheServiceAccountTokenIsNotRotated(t *testing.T) {
	p := newInstPlatform(t)
	path := writeToken(t, p, "a")
	a := p.instanceWith(KubernetesEvidence(path))
	mustToken(t, a)
	p.advance(540 * time.Second) // the token is renewed on the held attestation
	rewriteToken(t, p, path, "b")
	second := mustToken(t, a)
	// The attestation (900 s) ends before the second token (600 s) is renewed: both are due together.
	p.advance(time.Duration(p.tokenTTL-60) * time.Second)
	rewriteToken(t, p, path, "c")
	p.script(func() {
		p.extraAttest = func(w http.ResponseWriter) bool {
			hj, _ := w.(http.Hijacker)
			c, _, _ := hj.Hijack()
			_ = c.Close() // the request arrived; the reply never does
			return true
		}
	})
	got, err := a.Token(context.Background())
	if err != nil || got.Reveal() != second.Reveal() {
		t.Fatalf("the still-valid token is used when the attest cannot be completed: %v", err)
	}
	p.script(func() { p.extraAttest = nil })
	p.advance(graceRetry) // the platform is back; the file has not rotated since "c" was sent
	got, err = a.Token(context.Background())
	if err != nil || got.Reveal() != second.Reveal() {
		t.Fatalf("an unrotated service-account token is a wait, not a failure, while the token is good: %v", err)
	}
	rewriteToken(t, p, path, "d") // the kubelet rotates the file
	p.advance(graceRetry)
	if renewed := mustToken(t, a); renewed.Reveal() == second.Reveal() {
		t.Fatal("a renewal that can be made is made")
	}
}

// The same wait does not outlive the token, and a refusal in that minute is not softened.
func TestAnUnrotatedServiceAccountTokenIsNotKeptPastExpiryAndARefusedAttestIsNotSoftened(t *testing.T) {
	setup := func() (*instPlatform, *Agent, Token, string) {
		p := newInstPlatform(t)
		path := writeToken(t, p, "a")
		a := p.instanceWith(KubernetesEvidence(path))
		mustToken(t, a)
		p.advance(540 * time.Second)
		rewriteToken(t, p, path, "b")
		second := mustToken(t, a)
		p.advance(time.Duration(p.tokenTTL-60) * time.Second)
		rewriteToken(t, p, path, "c")
		return p, a, second, path
	}

	p, a, _, _ := setup()
	p.script(func() {
		p.extraAttest = func(w http.ResponseWriter) bool {
			writeJSONTest(w, 401, map[string]string{"error": "unauthorized"})
			return true
		}
	})
	if te := tokenErr(t, a); te.Status != 401 {
		t.Fatalf("a refused attest is told at once: %+v", te)
	}

	p, a, _, _ = setup()
	p.script(func() {
		p.extraAttest = func(w http.ResponseWriter) bool {
			hj, _ := w.(http.Hijacker)
			c, _, _ := hj.Hijack()
			_ = c.Close()
			return true
		}
	})
	mustToken(t, a) // held
	p.script(func() { p.extraAttest = nil })
	p.advance(61 * time.Second) // past the token's end
	if te := tokenErr(t, a); te.Code != "evidence_not_rotated" {
		t.Fatalf("an expired token is not kept: %+v", te)
	}
}
