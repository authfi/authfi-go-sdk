package authfi

import (
	"go/ast"
	"go/parser"
	"go/token"
	"testing"
)

// The DPoP and chain verification files must hold no secret and read nothing of Config, so they can
// be published on their own.
func TestProofAndChainFilesAreSeparable(t *testing.T) {
	banned := map[string]bool{
		"clientSecret": true, "apiKey": true, "ClientSecret": true, "APIKey": true,
		"Secret": true, "NewSecret": true, "Reveal": true, "Config": true, "cfg": true, "Client": true,
	}
	for _, file := range []string{"dpop.go", "chain.go"} {
		f, err := parser.ParseFile(token.NewFileSet(), file, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		ast.Inspect(f, func(n ast.Node) bool {
			if id, ok := n.(*ast.Ident); ok && banned[id.Name] {
				t.Errorf("%s uses %s: the proof and chain code must not depend on the client or its secrets", file, id.Name)
			}
			return true
		})
	}
}

func TestSeparabilityTestSeesAViolation(t *testing.T) {
	f, err := parser.ParseFile(token.NewFileSet(), "x.go", "package p\nfunc f(c Client) { _ = c.clientSecret }", 0)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	ast.Inspect(f, func(n ast.Node) bool {
		if id, ok := n.(*ast.Ident); ok && (id.Name == "clientSecret" || id.Name == "Client") {
			found = true
		}
		return true
	})
	if !found {
		t.Fatal("the scan does not see identifiers")
	}
}
