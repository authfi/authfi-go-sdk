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
- a token bound to a key (`cnf`, `authfi_mandate`) comes with a DPoP proof for that key, and an agent token also passes the checks in [Agent tokens](#agent-tokens); a delegation chain (an `act` inside an `act`) is refused.
- with `Config.Revocations` set, neither its subject nor its actor was revoked after it was issued (see Revocation).

A refusal is an `*authfi.Error`; read `Code` with `errors.As`. Nothing from the token is in the message.

## Agent tokens

An agent token has an `agt_` subject or `client_id`, or an `act` claim. For these the SDK checks, by default, what a bearer check cannot:

1. **Proof of possession (RFC 9449).** The token carries `cnf.jkt` and arrives as `Authorization: DPoP <token>` with exactly one `DPoP` header: a `dpop+jwt` proof signed with EdDSA, ES256 or PS256 by the key whose thumbprint is `cnf.jkt`, naming this request's method and URL (`htm`, `htu`), issued within the last 60 seconds (5 s of clock skew ahead), carrying the hash of this token (`ath`), and never seen before for that key (`jti`).
2. **Custody of the signing key.** The key set's `x5c` chain certifies the key that signed the token, `x5t#S256` in the token header and the key set equals that certificate, the chain ends at a root pinned by the SHA-256 of its public key (AuthFI Root CA R1 by default), the certificate states AuthFI policy `1.3.6.1.4.1.67322.1.1` or `.1.2`, every CA between states one of them, and the leaf is a signing certificate, not a CA.

A person's bearer token is verified exactly as before. Use `VerifyRequest(r)` or the middleware (`Require`, `RequireRole`, `Authenticate`): they read both schemes. `Verify(ctx, token)` has no request to hold a proof against and refuses an agent token with `agent_token_needs_request`.

| `Config` field | Meaning |
|---|---|
| `AgentTokens` | `AgentEnforce` (the zero value) refuses an agent token that fails a check; `AgentWatch` accepts it and logs the refusal code once per key and reason a minute; `AgentOff` skips the agent checks and has to be set explicitly. A token bound to a key always needs its proof. |
| `PublicURL` | The URL clients call, for example `https://api.acme.com` (a path prefix is allowed). The proof's `htu` must match it plus the request path. Without it the request's own `Host` and TLS state are used. |
| `TrustForwarded` | Read `X-Forwarded-Host` and `X-Forwarded-Proto` for the URL. Off by default; set it only behind a proxy that overwrites both. |
| `ReplayGuard` | Where seen proofs are kept (`Claim(ctx, id, until) (fresh bool, err error)`). The default is bounded and lives in the process, so it is right for one replica: with several replicas give them one shared store. |
| `NonceKey` | 32 or more bytes shared by every replica. Turns on server nonces: a proof without a current one is refused with `dpop_nonce`, the middleware answers with a `DPoP-Nonce` header and `WWW-Authenticate: DPoP error="use_dpop_nonce"`. |
| `RootPins` | Hex SHA-256 of the root public keys a chain may end at, replacing the default (`authfi.DefaultRootPin`). For a private region. |

The resource server:

```go
auth := authfi.New(authfi.Config{
    Issuer:    "https://acme.authfi.io",
    Audience:  []string{"orders-api-client-id"},
    PublicURL: "https://api.acme.com",
})
http.Handle("/orders", auth.Require("read:orders")(ordersHandler))
```

An agent built with the `agent` package calls it. `WithDPoP` binds the agent's token to a key made for this, and `DPoPTransport` sends `Authorization: DPoP` and a fresh proof with every request (a server nonce the API asks for is echoed once):

```go
dpopKey, _ := agent.GenerateKey(agent.ES256, "")
a, _ := agent.New("https://acme.authfi.io", "agt_...", key,
    agent.WithResource("orders-api-client-id"), agent.WithDPoP(dpopKey))
rt, _ := a.DPoPTransport(nil, "https://api.acme.com")
resp, err := (&http.Client{Transport: rt}).Get("https://api.acme.com/orders")
```

The refusal codes are `dpop_missing`, `dpop_multiple`, `dpop_malformed`, `dpop_type`, `dpop_alg`, `dpop_signature`, `dpop_method`, `dpop_url`, `dpop_iat`, `dpop_ath`, `dpop_replayed`, `dpop_key_mismatch`, `dpop_nonce`, `dpop_replay_unavailable`, `chain_not_proven`, `chain_policy`, `chain_pin` and `agent_token_needs_request`. None carries anything from the token or the proof.

## Secrets

A `Config` prints the issuer and the client id and nothing else (under every `fmt` verb, in JSON and in `slog`), and `New` moves `ClientSecret` and `APIKey` into the `Client` as `authfi.Secret` values, so printing a `Client` by any route shows none of them. `fmt` cannot call a `String` method on an unexported field of your own struct, so a `Config` that you embed that way prints its plain fields: keep secrets in the environment or in an `authfi.Secret` (`authfi.NewSecret`, read with `Reveal`).

Errors that carry a server's reply have every secret and every JWT-shaped string removed (`authfi.Scrub`) and are bounded in length. Calls to the management and cloud routes do not follow redirects, so a credential cannot be sent on to another host.

## Features

- Key-set caching: one fetch for a burst of requests, one refetch per 15 seconds for an unknown key id, cached keys kept for an hour if the issuer is unreachable
- `Require("read:users")` middleware: permission checks
- `RequireRole("admin")` middleware: role-based access
- `Authenticate` middleware: token only, no permission check
- `Receiver`: Shared Signals push receiver and `RevocationStore`, so a revoked agent is refused at once (see Revocation)
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

## Revocation: stop an agent's tokens the moment AuthFI withdraws it

Access tokens verify offline, so a revoked or suspended agent keeps working until its token expires, unless AuthFI tells you. AuthFI sends a signed Shared Signals event (RFC 8935 push) when an agent is revoked, suspended or deleted. A `Receiver` takes it and your `Client` refuses the agent's earlier tokens at once.

```go
store := authfi.NewRevocationStore(authfi.RevocationOptions{
    TokenLifetime: 24 * time.Hour, // at least the longest token you accept
})
auth := authfi.New(authfi.Config{
    Issuer:      "https://acme.authfi.io",
    Audience:    []string{"my-api-client-id"},
    Revocations: store, // Verify and the middleware now check revocations
})
recv, err := auth.NewReceiver(authfi.ReceiverConfig{
    Audience:  "my-stream",                        // the audience you registered the stream with
    AuthToken: authfi.NewSecret(pushBearer),       // optional: the bearer AuthFI sends on each push
    OnSignal:  func(s authfi.Signal) { log.Printf("%s %s", s.Event, s.Subject) },
})
http.Handle("/ssf/push", recv) // the https URL you register as the stream endpoint
```

What the receiver does, in order, and what it refuses:

- POST with `Content-Type: application/secevent+jwt`, at most 16 KiB; any other method is 405. If you set `AuthToken`, the push must carry that bearer (401 otherwise).
- The SET is a JWS signed by a key in the project's key set (the one that verifies agent tokens), with `typ` `secevent+jwt`. `none` and HMAC are refused. AuthFI treats a 400 as final and stops the stream, so a condition that can heal answers 503 and AuthFI retries: a key that is not in the key set yet (a rotation), a key set that cannot be read, or an `iat` more than 60 seconds ahead of this server's clock.
- `iss` is the configured issuer, `aud` includes your stream audience, `jti` and `iat` are present, `iat` is present, `exp` (if present) has not passed, `sub_id` names the subject, `events` holds objects.
- Accepted: `202`. Refused: `400` with `{"err": ..., "description": ...}` where `err` is `invalid_request`, `invalid_key`, `invalid_issuer`, `invalid_audience` or `authentication_failed`. Nothing is recorded for a refused SET.
- A SET older than any token it could affect (`TokenLifetime` plus the clock leeway) is answered `202` and not applied.
- A `jti` seen before is answered `202` and applied once, so AuthFI can retry a push whose answer was lost. The set of seen ids is bounded.

`session-revoked`, `account-purged` and `credential-compromise` revoke the subject: tokens issued at or before the SET's `iat` are refused with code `token_revoked`, and a token issued after it is accepted. A delegated token is refused when its actor (`act.sub`) is revoked. With `Revocations` set, a token with no `iat` is refused (`token_iat_required`). `token-claims-change` with `resumed: true` reaches `OnSignal` with `Resumed` set and changes nothing else: a resumed agent mints a new token, which is newer than the revocation.

A refused token's `*authfi.Error` carries the jti of the revoking SET in `Ref` (and in the debug log line), so a refusal can be traced to the event that caused it. `store.Revoke(subject, notBefore)`, `store.RevokeRef(subject, notBefore, ref)` and `store.IsRevoked(subject, issuedAt)` are there for your own use. The store holds at most `MaxEntries` subjects (default 100,000) and forgets a revocation once it is older than `TokenLifetime` plus the clock leeway. `Verify` refuses a token that lives longer than `TokenLifetime` (code `sdk_not_configured`, HTTP 503 from the middleware): raise `TokenLifetime` to your longest token lifetime. When it is full it drops the oldest revocations and refuses every token issued before the newest one it dropped, whatever its subject, until that time passes `TokenLifetime`: a full store costs some holders a new token and never lets a revoked one through.

Subjects match exactly: `agent:agt_42` is not `AGENT:AGT_42` and not a bare `agt_42`. AuthFI always sends the `agent:<id>` form.

To register the stream from code, `auth.RegisterStream(ctx, bearer, authfi.StreamRequest{Audience: "my-stream", EndpointURL: "https://api.example.com/ssf/push", AuthToken: pushBearer})` reads the issuer's `/.well-known/ssf-configuration` and posts the registration to the `configuration_endpoint` it names, which must be on the issuer's host. The bearer is a credential allowed to register streams.

The store lives in memory. A restart empties it, so until the tokens issued before the restart expire, a revoked agent is accepted again; a replica only learns of revocations pushed to its own endpoint. Run one stream per process and keep the token lifetime short.

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
