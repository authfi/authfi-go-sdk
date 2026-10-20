//go:build live

// Package live_test runs the SDK against a real AuthFI project. It is skipped unless
// AUTHFI_LIVE_ISSUER and AUTHFI_LIVE_DIR are set, and needs the tag: go test -tags live ./live.
//
// AUTHFI_LIVE_DIR holds files a harness wrote for a probe operator of a test project (never
// production, never a real person): console-token, person-access, person-id, app-client-id and
// operator-email. Every object the test registers is removed when it ends. Nothing secret is printed.
package live_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	authfi "github.com/authfi/authfi-go-sdk"
	"github.com/authfi/authfi-go-sdk/agent"
)

var (
	issuer = os.Getenv("AUTHFI_LIVE_ISSUER")
	dir    = os.Getenv("AUTHFI_LIVE_DIR")
	tenant = os.Getenv("AUTHFI_LIVE_TENANT")
	run    = fmt.Sprint(time.Now().Unix() % 100000)
)

func file(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(dir, name))
	if err != nil {
		t.Fatalf("harness file %s: %v", name, err)
	}
	return strings.TrimSpace(string(b))
}

func gql(t *testing.T, query string, vars map[string]any) map[string]any {
	t.Helper()
	body, _ := json.Marshal(map[string]any{"query": query, "variables": vars})
	req, _ := http.NewRequest("POST", issuer+"/graphql", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+file(t, "console-token"))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	var out struct {
		Data   map[string]any `json:"data"`
		Errors []any          `json:"errors"`
	}
	_ = json.Unmarshal(raw, &out)
	if resp.StatusCode != 200 || len(out.Errors) > 0 {
		t.Fatalf("console API %d: %.200s", resp.StatusCode, authfi.Scrub(string(raw)))
	}
	return out.Data
}

func header(tok string) map[string]any {
	var h map[string]any
	b, _ := base64.RawURLEncoding.DecodeString(strings.Split(tok, ".")[0])
	_ = json.Unmarshal(b, &h)
	return h
}

func claims(tok string) map[string]any {
	var c map[string]any
	b, _ := base64.RawURLEncoding.DecodeString(strings.Split(tok, ".")[1])
	_ = json.Unmarshal(b, &c)
	return c
}

func code(err error) string {
	var e *authfi.Error
	if errors.As(err, &e) {
		return e.Code
	}
	return fmt.Sprintf("(not an *authfi.Error: %T)", err)
}

func TestLive(t *testing.T) {
	if issuer == "" || dir == "" {
		t.Skip("AUTHFI_LIVE_ISSUER and AUTHFI_LIVE_DIR are not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()
	clientID := file(t, "app-client-id")

	// The verifier of an API whose client id is clientID, pinned to the test tenant.
	api := authfi.New(authfi.Config{Issuer: issuer, Audience: []string{clientID}, TenantID: tenant})
	if err := api.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}

	t.Run("an RS256 user token verifies", func(t *testing.T) {
		tok := file(t, "person-access")
		c, err := api.Verify(ctx, tok)
		if err != nil {
			t.Fatalf("refused: %v", err)
		}
		h := header(tok)
		t.Logf("VERIFIED alg=%v typ=%v sub=%s aud=%v tenant=%s", h["alg"], h["typ"], c.Subject, c.Audience, c.TenantID)
		if h["alg"] != "RS256" {
			t.Fatalf("expected an RS256 user token, got %v", h["alg"])
		}
	})

	t.Run("the ID token is refused as an access token", func(t *testing.T) {
		tok := file(t, "person-id")
		_, err := api.Verify(ctx, tok)
		t.Logf("REFUSED id token (alg=%v typ=%v): %s", header(tok)["alg"], header(tok)["typ"], code(err))
		if code(err) != authfi.CodeTypInvalid {
			t.Fatalf("got %v", err)
		}
	})

	t.Run("a console token is for AuthFI, not for this API", func(t *testing.T) {
		_, err := api.Verify(ctx, file(t, "console-token"))
		t.Logf("REFUSED console token: %s", code(err))
		if code(err) != authfi.CodeAudienceMismatch {
			t.Fatalf("got %v", err)
		}
	})

	t.Run("a tampered user token and another tenant are refused", func(t *testing.T) {
		parts := strings.Split(file(t, "person-access"), ".")
		c := claims(strings.Join(parts, "."))
		c["sub"] = "someone-else"
		pb, _ := json.Marshal(c)
		_, err := api.Verify(ctx, parts[0]+"."+base64.RawURLEncoding.EncodeToString(pb)+"."+parts[2])
		t.Logf("REFUSED tampered payload: %s", code(err))
		if code(err) != authfi.CodeSignatureInvalid {
			t.Fatalf("got %v", err)
		}
		other := authfi.New(authfi.Config{Issuer: issuer, Audience: []string{clientID}, TenantID: "00000000-0000-0000-0000-000000000000"})
		_, err = other.Verify(ctx, file(t, "person-access"))
		t.Logf("REFUSED wrong tenant pin: %s", code(err))
		if code(err) != authfi.CodeTenantMismatch {
			t.Fatalf("got %v", err)
		}
	})

	// --- the agent ---
	key, err := agent.GenerateKey(agent.EdDSA, "sdk-live-go-"+run)
	if err != nil {
		t.Fatal(err)
	}
	jwk, _ := json.Marshal(key.PublicJWK())
	me := gql(t, "{ me { id email } }", nil)["me"].(map[string]any)
	reg := gql(t, "mutation($i:RegisterAgentInput!){ registerAgent(input:$i){ id } }", map[string]any{"i": map[string]any{
		"name": "sdk-live-go-" + run, "type": "delegated", "publicJwk": string(jwk), "jwkKid": key.KID(), "ownerUserId": me["id"]}})
	agentID := reg["registerAgent"].(map[string]any)["id"].(string)
	t.Cleanup(func() {
		gql(t, "mutation($id:ID!){ deleteAgent(id:$id) }", map[string]any{"id": agentID})
		t.Logf("CLEANUP agent %s deleted", agentID)
	})
	t.Logf("registered agent %s (kid %s, alg %s)", agentID, key.KID(), key.Alg())

	ag, err := agent.New(issuer, agentID, key, agent.WithResource(clientID))
	if err != nil {
		t.Fatal(err)
	}

	t.Run("an EdDSA agent token verifies", func(t *testing.T) {
		tok, err := ag.Token(ctx)
		if err != nil {
			t.Fatalf("mint: %v", err)
		}
		c, err := api.Verify(ctx, tok.Reveal())
		if err != nil {
			t.Fatalf("refused: %v", err)
		}
		h := header(tok.Reveal())
		t.Logf("VERIFIED agent token alg=%v typ=%v sub=%s client_id=%s aud=%v scope=%q", h["alg"], h["typ"], c.Subject, c.ClientID, c.Audience, c.Scope)
		if h["alg"] != "EdDSA" {
			t.Fatalf("expected EdDSA, got %v", h["alg"])
		}
		again, _ := ag.Token(ctx)
		if again.Reveal() != tok.Reveal() {
			t.Fatal("the token is cached")
		}
	})

	t.Run("the gateway token is not accepted by an API", func(t *testing.T) {
		gw, err := agent.New(issuer, agentID, key)
		if err != nil {
			t.Fatal(err)
		}
		tok, err := gw.Token(ctx)
		if err != nil {
			t.Fatalf("mint: %v", err)
		}
		_, err = api.Verify(ctx, tok.Reveal())
		t.Logf("REFUSED gateway-audience agent token (aud=%v): %s", claims(tok.Reveal())["aud"], code(err))
		if code(err) != authfi.CodeAudienceMismatch {
			t.Fatalf("got %v", err)
		}
		bad := authfi.New(authfi.Config{Issuer: issuer, Audience: []string{issuer + "/mcp"}})
		t.Logf("REFUSED configuring the gateway as an audience: %s", code(bad.Validate()))
		if code(bad.Validate()) != authfi.CodeNotConfigured {
			t.Fatal("the gateway audience must be refused")
		}
	})

	t.Run("a key the project never registered is refused", func(t *testing.T) {
		impostorKey, _ := agent.GenerateKey(agent.EdDSA, key.KID())
		impostor, _ := agent.New(issuer, agentID, impostorKey)
		_, err := impostor.Token(ctx)
		var te *agent.TokenError
		if !errors.As(err, &te) {
			t.Fatalf("got %v", err)
		}
		t.Logf("REFUSED impostor key: %s (HTTP %d)", te.Code, te.Status)
	})

	t.Run("a person's token is exchanged for a delegated token", func(t *testing.T) {
		d, err := ag.Exchange(ctx, authfi.NewSecret(file(t, "person-access")), nil, clientID)
		if err != nil {
			var te *agent.TokenError
			if errors.As(err, &te) {
				t.Logf("EXCHANGE refused: %s %s (HTTP %d)", te.Code, te.Description, te.Status)
			}
			t.Fatalf("exchange: %v", err)
		}
		tok, _ := d.Token(ctx)
		c, err := api.Verify(ctx, tok.Reveal())
		if err != nil {
			t.Fatalf("delegated token refused: %v", err)
		}
		t.Logf("VERIFIED delegated token alg=%v sub=%s actor=%s via=%s", header(tok.Reveal())["alg"], c.Subject, c.Actor, d.Via())
		if c.Actor == "" {
			t.Fatal("a delegated token names its actor")
		}
	})

	t.Run("a CIBA approval yields a delegated token", func(t *testing.T) {
		req, err := ag.RequestUserApproval(ctx, file(t, "operator-email"), "Refund order 4411 (sdk live test)", nil, 2*time.Minute)
		if err != nil {
			var te *agent.TokenError
			if errors.As(err, &te) {
				t.Logf("CIBA request refused: %s %s (HTTP %d)", te.Code, te.Description, te.Status)
			}
			t.Fatalf("request: %v", err)
		}
		t.Logf("CIBA requested, interval %s", req.Interval)
		go func() {
			for i := 0; i < 20; i++ {
				time.Sleep(time.Second)
				list := gql(t, "{ myAgentRequests { authReqId agentId status bindingMessage } }", nil)["myAgentRequests"].([]any)
				for _, r := range list {
					m := r.(map[string]any)
					if m["agentId"] == agentID && m["status"] == "pending" {
						gql(t, "mutation($a:ID!){ decideMyAgentRequest(authReqId:$a, decision:APPROVE){ status } }", map[string]any{"a": m["authReqId"]})
						t.Logf("the operator approved %q", m["bindingMessage"])
						return
					}
				}
			}
		}()
		d, err := ag.AwaitUserToken(ctx, req)
		if err != nil {
			var te *agent.TokenError
			if errors.As(err, &te) {
				t.Logf("CIBA poll refused: %s %s (HTTP %d)", te.Code, te.Description, te.Status)
			}
			t.Fatalf("await: %v", err)
		}
		tok, _ := d.Token(ctx)
		h := header(tok.Reveal())
		t.Logf("CIBA token alg=%v sub=%s act=%v aud=%v", h["alg"], claims(tok.Reveal())["sub"], claims(tok.Reveal())["act"], claims(tok.Reveal())["aud"])
	})
}
