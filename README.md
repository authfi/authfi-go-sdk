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
        Tenant:   "acme",
        APIKey:   "sk_live_...",
        AutoSync: true,
    })

    // chi / gorilla / net/http — permission middleware
    http.Handle("/api/users", auth.Require("read:users")(usersHandler))

    // Role middleware
    http.Handle("/admin", auth.RequireRole("admin")(adminHandler))

    // Start — pre-fetches JWKS + syncs permissions
    auth.Start()
    http.ListenAndServe(":8080", nil)
}

func usersHandler(w http.ResponseWriter, r *http.Request) {
    user := authfi.GetUser(r.Context())
    // user.Subject, user.Email, user.Roles, user.Permissions
}
```

## Features

- JWKS + RS256 token verification with caching
- `Require("read:users")` middleware — permission checks
- `RequireRole("admin")` middleware — role-based access
- `Authenticate` middleware — JWT only, no permission check
- Permission auto-sync on `Start()`
- Cloud credentials (GCP/AWS/Azure/OCI)
- Zero external dependencies — stdlib only

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

20 unit tests covering token verification, middleware, permissions, roles, and sync.

## License

MIT
