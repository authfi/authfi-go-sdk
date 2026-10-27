package authfi

import (
	"go/ast"
	"go/parser"
	"go/token"
	"strconv"
	"testing"
)

// The DPoP and chain verification files must hold no secret, read nothing of Config, and reach for
// neither the environment, the file system nor the network, so they can be published on their own.
var (
	bannedIdents = map[string]bool{
		"clientSecret": true, "apiKey": true, "ClientSecret": true, "APIKey": true,
		"Secret": true, "NewSecret": true, "Reveal": true, "Config": true, "cfg": true, "Client": true,
	}
	bannedImports = map[string]bool{"os": true, "syscall": true, "os/exec": true, "net/http": true, "net": true, "io/ioutil": true}
)

// separabilityViolations lists what src uses that the proof and chain code must not.
func separabilityViolations(t *testing.T, name string, src any) []string {
	t.Helper()
	f, err := parser.ParseFile(token.NewFileSet(), name, src, 0)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, imp := range f.Imports {
		if path, _ := strconv.Unquote(imp.Path.Value); bannedImports[path] {
			out = append(out, "import "+path)
		}
	}
	ast.Inspect(f, func(n ast.Node) bool {
		if id, ok := n.(*ast.Ident); ok && bannedIdents[id.Name] {
			out = append(out, "identifier "+id.Name)
		}
		return true
	})
	return out
}

func TestProofAndChainFilesAreSeparable(t *testing.T) {
	for _, file := range []string{"dpop.go", "chain.go"} {
		for _, v := range separabilityViolations(t, file, nil) {
			t.Errorf("%s uses %s: the proof and chain code must not depend on the client, its secrets, the environment or the network", file, v)
		}
	}
}

func TestSeparabilityScanSeesALeak(t *testing.T) {
	leak := "package p\nimport \"os\"\nvar leak = os.Getenv(\"AUTHFI_CLIENT_SECRET\")\n"
	if v := separabilityViolations(t, "x.go", leak); len(v) != 1 || v[0] != "import os" {
		t.Fatalf("an os import is a violation: %v", v)
	}
	for _, src := range []string{
		"package p\nimport \"net/http\"\nvar _ http.Client\n",
		"package p\nimport \"syscall\"\nvar _ = syscall.Getpid\n",
		"package p\nimport \"os/exec\"\nvar _ = exec.Command\n",
		"package p\nfunc f(c Client) { _ = c.clientSecret }\n",
	} {
		if len(separabilityViolations(t, "x.go", src)) == 0 {
			t.Errorf("not seen: %s", src)
		}
	}
	if v := separabilityViolations(t, "x.go", "package p\nimport \"strings\"\nvar _ = strings.ToLower\n"); len(v) != 0 {
		t.Fatalf("control: %v", v)
	}
}
