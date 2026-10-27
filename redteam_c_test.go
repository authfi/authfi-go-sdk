package authfi

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"
)

// The kill-switch corpus (track C, invariant I7): attacks on the revocation receiver and the store,
// shared with the Node SDK as testdata/corpus-C-containment.json. Each case names a scenario below
// by its id and states the stable result. A case this file has no scenario for, or a scenario the
// file has no case for, fails the test, so the corpus and the code cannot drift apart.

type corpusCase struct {
	ID           string `json:"id"`
	Component    string `json:"component"`
	Kind         string `json:"kind"`
	ExpectCode   string `json:"expect_code"`
	ExpectAccept bool   `json:"expect_accept"`
	ExpectRef    bool   `json:"expect_ref"`
	Why          string `json:"why"`
}

// rtResult is what a scenario observed: a stable refusal code (the receiver's RFC 8935 error or the
// SDK's refusal code), or accepted. ref is the decision reference the refusal carried (I1).
type rtResult struct {
	code     string
	accepted bool
	ref      string
	wantRef  string
}

func rtPush(w *httptest.ResponseRecorder) rtResult {
	if w.Code == http.StatusAccepted {
		return rtResult{accepted: true}
	}
	var b struct {
		Err string `json:"err"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &b)
	return rtResult{code: b.Err}
}

func rtVerify(g *rig, tok string) rtResult {
	err := g.verify(tok)
	if err == nil {
		return rtResult{accepted: true}
	}
	var e *Error
	if !errors.As(err, &e) {
		return rtResult{code: "not_an_authfi_error"}
	}
	return rtResult{code: e.Code, ref: e.Ref}
}

func rtRevokeSET(g *rig) (set, jti string) {
	c := g.f.goodSET(evSessionRevoked, nil)
	return g.f.mintSET(setSpec{claims: c}), c["jti"].(string)
}

var redteamScenarios = map[string]func(t *testing.T) rtResult{
	"set-forged-signature": func(t *testing.T) rtResult {
		g := newRig(t)
		set := g.f.mintSET(setSpec{})
		i := strings.LastIndex(set, ".")
		return rtPush(g.push(set[:i+1] + flip(set[i+1:])))
	},
	"set-other-aud": func(t *testing.T) rtResult {
		g := newRig(t)
		c := g.f.goodSET(evSessionRevoked, nil)
		c["aud"] = "another-stream"
		return rtPush(g.push(g.f.mintSET(setSpec{claims: c})))
	},
	"set-other-iss": func(t *testing.T) rtResult {
		g := newRig(t)
		c := g.f.goodSET(evSessionRevoked, nil)
		c["iss"] = "https://another-project.example"
		return rtPush(g.push(g.f.mintSET(setSpec{claims: c})))
	},
	"set-replayed-jti": func(t *testing.T) rtResult {
		g := newRig(t)
		set, _ := rtRevokeSET(g)
		for i := 0; i < 3; i++ {
			if r := rtPush(g.push(set)); !r.accepted {
				return r
			}
		}
		if len(g.signals()) != 1 {
			return rtResult{code: "applied_more_than_once"}
		}
		return rtResult{accepted: true}
	},
	"set-expired": func(t *testing.T) rtResult {
		g := newRig(t)
		c := g.f.goodSET(evSessionRevoked, nil)
		c["exp"] = g.f.clock().Add(-10 * time.Minute).Unix()
		return rtPush(g.push(g.f.mintSET(setSpec{claims: c})))
	},
	"set-alg-none": func(t *testing.T) rtResult {
		g := newRig(t)
		return rtPush(g.push(g.f.mintSET(setSpec{header: map[string]any{"alg": "none"}})))
	},
	"set-alg-hs256-confusion": func(t *testing.T) rtResult {
		g := newRig(t)
		return rtPush(g.push(g.f.mintSET(setSpec{header: map[string]any{"alg": "HS256"}})))
	},
	"set-alg-key-mismatch": func(t *testing.T) rtResult {
		g := newRig(t)
		return rtPush(g.push(g.f.mintSET(setSpec{header: map[string]any{"alg": "RS256"}})))
	},
	"set-kid-not-in-jwks": func(t *testing.T) rtResult {
		g := newRig(t)
		return rtPush(g.push(g.f.mintSET(setSpec{header: map[string]any{"kid": "not-in-the-key-set"}})))
	},
	"token-issued-before-revocation": func(t *testing.T) rtResult {
		g := newRig(t)
		tok := g.tokenFor(testAgentSubject, g.f.clock().Add(-10*time.Second), nil)
		set, jti := rtRevokeSET(g)
		if r := rtPush(g.push(set)); !r.accepted {
			return r
		}
		r := rtVerify(g, tok)
		r.wantRef = jti
		return r
	},
	"token-issued-same-second": func(t *testing.T) rtResult {
		g := newRig(t)
		tok := g.tokenFor(testAgentSubject, g.f.clock(), nil)
		set, jti := rtRevokeSET(g)
		if r := rtPush(g.push(set)); !r.accepted {
			return r
		}
		r := rtVerify(g, tok)
		r.wantRef = jti
		return r
	},
	"token-issued-after-revocation-resume": func(t *testing.T) rtResult {
		g := newRig(t)
		old := g.tokenFor(testAgentSubject, g.f.clock().Add(-10*time.Second), nil)
		set, _ := rtRevokeSET(g)
		g.push(set)
		g.f.advance(2 * time.Second)
		g.push(g.f.mintSET(setSpec{claims: g.f.goodSET(evClaimsChange, map[string]any{"resumed": true})}))
		if r := rtVerify(g, old); r.code != CodeRevoked {
			return rtResult{code: "old_token_not_refused"}
		}
		return rtVerify(g, g.tokenFor(testAgentSubject, g.f.clock(), nil))
	},
	"token-delegated-actor-revoked": func(t *testing.T) rtResult {
		g := newRig(t)
		tok := g.tokenFor("usr_7", g.f.clock().Add(-10*time.Second), map[string]any{"act": map[string]any{"sub": testAgentSubject}})
		set, jti := rtRevokeSET(g)
		g.push(set)
		r := rtVerify(g, tok)
		r.wantRef = jti
		return r
	},
	"subject-case-variant": func(t *testing.T) rtResult {
		g := newRig(t)
		set, _ := rtRevokeSET(g)
		g.push(set)
		return rtVerify(g, g.tokenFor("AGENT:AGT_42", g.f.clock().Add(-10*time.Second), nil))
	},
	"subject-prefix-missing": func(t *testing.T) rtResult {
		g := newRig(t)
		c := g.f.goodSET(evSessionRevoked, nil)
		c["sub_id"] = map[string]any{"format": "opaque", "id": "agt_42"}
		g.push(g.f.mintSET(setSpec{claims: c}))
		return rtVerify(g, g.tokenFor(testAgentSubject, g.f.clock().Add(-10*time.Second), nil))
	},
	"body-oversize": func(t *testing.T) rtResult {
		g := newRig(t)
		return rtPush(g.push(strings.Repeat("a", 64<<10)))
	},
	"content-type-wrong": func(t *testing.T) rtResult {
		g := newRig(t)
		set, _ := rtRevokeSET(g)
		return rtPush(g.push(set, func(r *http.Request) { r.Header.Set("Content-Type", "application/json") }))
	},
	"flood-past-store-cap": func(t *testing.T) rtResult {
		g := newRig(t)
		small := NewRevocationStore(RevocationOptions{MaxEntries: 20})
		small.now = g.f.clock
		g.c = g.f.client(func(c *Config) { c.Revocations = small })
		now := g.f.clock()
		tok := g.tokenFor("agent:agt_first", now.Add(-10*time.Second), nil)
		small.RevokeRef("agent:agt_first", now, "jti-first")
		for i := 0; i < 60; i++ { // far past the cap, each newer than the first
			small.RevokeRef("agent:flood_"+itoa(i), now.Add(time.Duration(i+1)*time.Second), "jti-flood-"+itoa(i))
		}
		if small.Len() > 20 {
			return rtResult{code: "store_over_cap"}
		}
		return rtVerify(g, tok)
	},
}

func TestRedTeamCorpusC(t *testing.T) {
	raw, err := os.ReadFile("testdata/corpus-C-containment.json")
	if err != nil {
		t.Fatal(err)
	}
	var corpus struct {
		Track     string       `json:"track"`
		Invariant string       `json:"invariant"`
		Cases     []corpusCase `json:"cases"`
	}
	if err := json.Unmarshal(raw, &corpus); err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for _, tc := range corpus.Cases {
		if !strings.Contains(tc.Component, "go-sdk") {
			continue
		}
		if tc.Kind != "revocation_scenario" {
			t.Fatalf("%s: kind %q is not one this harness can run", tc.ID, tc.Kind)
		}
		run, ok := redteamScenarios[tc.ID]
		if !ok {
			t.Fatalf("%s: no scenario with this id; add it or the case is not tested", tc.ID)
		}
		if tc.ExpectCode == "" && !tc.ExpectAccept {
			t.Fatalf("%s: the case states neither expect_code nor expect_accept", tc.ID)
		}
		seen[tc.ID] = true
		t.Run(tc.ID, func(t *testing.T) {
			got := run(t)
			if tc.ExpectAccept && !got.accepted {
				t.Fatalf("want accepted, got %q (%s)", got.code, tc.Why)
			}
			if tc.ExpectCode != "" && got.code != tc.ExpectCode {
				t.Fatalf("want %q, got %q accepted=%v (%s)", tc.ExpectCode, got.code, got.accepted, tc.Why)
			}
			if tc.ExpectRef {
				// I1: the refusal names the SET that decided it.
				if got.ref == "" || (got.wantRef != "" && got.ref != got.wantRef) {
					t.Fatalf("the refusal must carry the revoking SET's jti %q, got ref %q", got.wantRef, got.ref)
				}
			}
		})
	}
	for id := range redteamScenarios {
		if !seen[id] {
			t.Errorf("scenario %s has no case in the corpus", id)
		}
	}
}
