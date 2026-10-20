package agent

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log/slog"
	"strings"
	"testing"

	authfi "github.com/authfi/authfi-go-sdk"
)

var verbs = []string{"%v", "%+v", "%#v", "%s", "%q", "%x", "%X", "%d"}

// sentinels collects every secret value a test has seen, so output can be searched for all of them.
type sentinels []string

func (s *sentinels) add(v ...string) { *s = append(*s, v...) }

func (s sentinels) clean(t *testing.T, where, out string) {
	t.Helper()
	for _, v := range s {
		if v != "" && strings.Contains(out, v) {
			t.Errorf("%s leaks a secret (%d bytes of it): %.120s", where, len(v), out)
		}
	}
}

// assertClean is for tests that only know the generic shapes: a JWT or a bearer string.
func assertClean(t *testing.T, where, out string) {
	t.Helper()
	if strings.Contains(out, "eyJ") || strings.Contains(strings.ToLower(out), "bearer ey") {
		t.Errorf("%s holds a JWT-shaped value: %s", where, out)
	}
	if strings.Contains(out, "REQ-HANDLE") {
		t.Errorf("%s holds a CIBA handle", where)
	}
}

func mustPEMRSA(t *testing.T, bits, e int) []byte {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		t.Fatal(err)
	}
	if e != 65537 {
		t.Skip("custom exponents are not generated here")
	}
	der, _ := x509.MarshalPKCS8PrivateKey(k)
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
}

func mustPEMP384(t *testing.T) []byte {
	t.Helper()
	k, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	der, _ := x509.MarshalPKCS8PrivateKey(k)
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
}

// Everything that holds a key, a token, an assertion or a handle prints redacted, whatever the verb.
func TestNothingSecretPrintsOrSerialises(t *testing.T) {
	k := keyFor(t, EdDSA)
	p := newPlatform(t, k)
	var secrets sentinels
	var logs bytes.Buffer
	a := p.agent(k, WithLogger(slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug}))))

	own, err := a.Token(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	req, err := a.RequestUserApproval(context.Background(), "jane", "msg", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	deleg, err := a.AwaitUserToken(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	dt, _ := deleg.Token(context.Background())
	ex, err := a.Exchange(context.Background(), authfi.NewSecret("PERSON-TOKEN-SENTINEL"), nil, "")
	if err != nil {
		t.Fatal(err)
	}
	et, _ := ex.Token(context.Background())

	secrets.add(own.Reveal(), dt.Reveal(), et.Reveal(), "REQ-HANDLE-0001", "PERSON-TOKEN-SENTINEL")
	for _, f := range p.forms {
		secrets.add(f.Get("client_assertion"))
	}
	der, _ := x509.MarshalPKCS8PrivateKey(k.signer)
	secrets.add(string(der), fmt.Sprintf("%x", der))
	seed := k.signer.(ed25519.PrivateKey)
	secrets.add(string(seed), fmt.Sprintf("%x", []byte(seed)), fmt.Sprint([]byte(seed)), fmt.Sprintf("%v", seed), fmt.Sprintf("%x", []byte(seed[:32])), fmt.Sprint([]byte(seed[:32])))
	for _, part := range strings.Split(own.Reveal(), ".") {
		if len(part) > 20 {
			secrets.add(part)
		}
	}

	things := map[string]any{"Key": k, "Token": own, "*Token": &own, "Agent": a, "CIBARequest": req, "DelegatedToken": deleg, "ExchangedToken": ex,
		"[]Token": []Token{own, dt}, "map": map[string]*DelegatedToken{"d": deleg}}
	for name, v := range things {
		for _, verb := range verbs {
			secrets.clean(t, name+" "+verb, fmt.Sprintf(verb, v))
		}
		secrets.clean(t, name+" Sprint", fmt.Sprint(v))
		b, err := json.Marshal(v)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		secrets.clean(t, name+" json", string(b))
		var buf bytes.Buffer
		slog.New(slog.NewJSONHandler(&buf, nil)).Info("x", "v", v)
		secrets.clean(t, name+" slog json", buf.String())
		buf.Reset()
		slog.New(slog.NewTextHandler(&buf, nil)).Info("x", slog.Any("v", v))
		secrets.clean(t, name+" slog text", buf.String())
	}
	secrets.clean(t, "the agent's own log", logs.String())
	if logs.Len() == 0 {
		t.Fatal("the agent logs its mints")
	}
	tx, _ := own.MarshalText()
	secrets.clean(t, "Token text", string(tx))
}

func TestErrorsFromARefusingPlatformCarryNoSecret(t *testing.T) {
	k := keyFor(t, EdDSA)
	p := newPlatform(t, k)
	p.echoAssert = true
	var secrets sentinels
	good := p.agent(k)
	req, _ := good.RequestUserApproval(context.Background(), "jane", "msg", nil, 0)
	secrets.add("REQ-HANDLE-0001")

	wrong := p.agent(keyFor(t, ES256))
	_, e1 := wrong.Token(context.Background())
	_, e2 := wrong.RequestUserApproval(context.Background(), "jane", "msg", nil, 0)
	_, e3 := wrong.AwaitUserToken(context.Background(), req)
	_, e4 := wrong.Exchange(context.Background(), authfi.NewSecret("expired-subject"), nil, "")
	secrets.add("expired-subject")
	for i, err := range []error{e1, e2, e3, e4} {
		if err == nil {
			t.Fatalf("error %d: expected a refusal", i+1)
		}
		for _, f := range p.forms {
			secrets.add(f.Get("client_assertion"))
		}
		for _, f := range p.backchannel {
			secrets.add(f.Get("client_assertion"))
		}
		for _, verb := range verbs {
			secrets.clean(t, fmt.Sprintf("error %d %s", i+1, verb), fmt.Sprintf(verb, err))
		}
		assertClean(t, fmt.Sprintf("error %d", i+1), err.Error())
	}
}

func TestUnreachablePlatformErrorHasNoURLQuery(t *testing.T) {
	k := keyFor(t, EdDSA)
	a, err := New("http://127.0.0.1:1", testAgentID, k)
	if err != nil {
		t.Fatal(err)
	}
	_, err = a.Token(context.Background())
	if err == nil {
		t.Fatal("expected a failure")
	}
	assertClean(t, "unreachable", err.Error())
	if strings.Contains(err.Error(), "http://") || strings.Contains(err.Error(), "/.well-known") {
		t.Fatalf("the request URL is not part of the error: %v", err)
	}
}
