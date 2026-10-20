# AuthFI Go SDK

Official Go SDK for [AuthFI](https://authfi.io) — the identity control plane.

## Install

```bash
go get github.com/authfi/authfi-go-sdk
```

## Quick Start

```go
package main

import (
    "net/http"
    authfi "github.com/authfi/authfi-go-sdk"
)

func main() {
    auth := authfi.New(authfi.Config{
        Issuer:   "https://acme.authfi.io",     // your project's issuer
        Audience: []string{"my-api-client-id"}, // required: the client id of this API
        TenantID: "your-tenant-id",             // recommended: pin the tenant
    })
    if err := auth.Start(); err != nil { // pre-fetches the issuer's key set, and checks the config
        panic(err)
    }

    // chi / gorilla / net/http: permission middleware
    http.Handle("/api/users", auth.Require("read:users")(usersHandler))

    // Role middleware
    http.Handle("/admin", auth.RequireRole("admin")(adminHandler))

    http.ListenAndServe(":8080", nil)
}

func usersHandler(w http.ResponseWriter, r *http.Request) {
    user := authfi.GetUser(r.Context())
    // user.Subject, user.Email, user.Roles, user.Permissions
}
```

## What is verified

`VerifyToken` (and the middleware) accept an access token only when all of these hold:

- it is signed with RS256, PS256, ES256 or EdDSA by a key in the issuer's key set, and the algorithm is the one that key is for (person, agent, CIBA and delegated tokens all verify);
- `typ` is `at+jwt`, so an ID token is refused as an access token;
- `iss` is the configured issuer and `aud` includes one of the configured audiences. The audience is required, and AuthFI's own audiences (the issuer, anything under it, `authfi-console`, `authfi-workspace`) are refused: mint the token for your API with `resource=<your API's client id>`;
- `exp` is present and in the future, with 60 seconds of leeway (`Config.Leeway`), and `nbf` and `iat` hold;
- `sub` and `tenant_id` are present, and `tenant_id` equals `TenantID` when you set it;
- it is not bound to a key (`cnf`, `authfi_mandate`) and carries no delegation chain.

A refusal is an `*authfi.Error`; read `Code` with `errors.As`. Nothing from the token is in the message.

## Secrets

A `Config` prints the issuer and the client id and nothing else (under every `fmt` verb, in JSON and in `slog`), and `New` moves `ClientSecret` and `APIKey` into the `Client` as `authfi.Secret` values, so printing a `Client` by any route shows none of them. `fmt` cannot call a `String` method on an unexported field of your own struct, so a `Config` that you embed that way prints its plain fields: keep secrets in the environment or in an `authfi.Secret` (`authfi.NewSecret`, read with `Reveal`).

Errors that carry a server's reply have every secret and every JWT-shaped string removed (`authfi.Scrub`) and are bounded in length. Calls to the management and cloud routes do not follow redirects, so a credential cannot be sent on to another host.

## Features

- Key-set caching: one fetch for a burst of requests, one refetch per 15 seconds for an unknown key id, cached keys kept for an hour if the issuer is unreachable
- `Require("read:users")` middleware: permission checks
- `RequireRole("admin")` middleware: role-based access
- `Authenticate` middleware: token only, no permission check
- Cloud credentials (GCP/AWS/Azure/OCI)
- Verification uses the standard library only; the `agent` package adds `golang.org/x/oauth2` and the OpenTelemetry trace API

## Agents

`github.com/authfi/authfi-go-sdk/agent` is the agent side: an agent signs a short assertion with its own key (Ed25519 by default, ES256 and PS256 too), gets its own token, and acts for a person through CIBA or token exchange.

```go
key, _ := agent.LoadKey("/run/secrets/agent.key", "") // refuses a file others can read
a, _ := agent.New("https://acme.authfi.io", "agt_...", key, agent.WithResource("my-api-client-id"))

tok, err := a.Token(ctx) // cached, renewed a minute before expiry, a fresh assertion per mint

// For a person, with their approval on their own device:
req, _ := a.RequestUserApproval(ctx, "jane@acme.com", "Refund order 4411", []string{"orders.refund"}, 2*time.Minute)
delegated, err := a.AwaitUserToken(ctx, req) // honours slow_down; a denial returns at once

// Or from a token your user already holds:
delegated, err := a.Exchange(ctx, authfi.NewSecret(userToken), nil, "my-api-client-id")

// Any http.Client (the Anthropic Go SDK, LangChainGo, the MCP Go SDK) can use the current token,
// sent only to the origins you name:
rt, _ := agent.Transport(a.TokenSource(), nil, "https://acme.authfi.io")
client := &http.Client{Transport: rt}
```

The key, every token, every assertion and the CIBA handle print redacted and never appear in an error. `agent.ReadResult` reads the gateway's answer to a tool call as a result, a refusal or a hold, and `agent.WithApproval` sends a held call again once a person has decided.

A refusal is a `*agent.TokenError` with the OAuth `Code` (`invalid_client`, `access_denied`, `expired_token`, ...) and is not retried. A network failure while minting is retried twice with a fresh assertion; a request that creates state (CIBA, exchange) is never sent twice. `LoadKey` checks file modes on Linux and macOS only.

## Cloud Credentials

```go
creds, err := auth.CloudCredentials(userToken, "gcp", map[string]string{
    "project": "my-project",
})
```

## Running Tests

```bash
go test -v ./...
```

## License

MIT
