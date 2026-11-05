# Changelog

All notable changes to this module. It follows [Semantic Versioning](https://semver.org): before 1.0 a minor
version may break, but only with an entry here. The module is versioned by git tag (`go get
github.com/authfi/authfi-go-sdk@v0.2.0`).

## 0.2.0

The first tagged version. Earlier commits were consumed by pseudo-version.

### Added

- **Strict access-token verification** for RS256, PS256, ES256 and EdDSA tokens: `typ` must be `at+jwt`, and `iss`,
  a required audience that is never AuthFI's own, `exp`, `sub` and the tenant are checked. ID tokens are refused.
  The issuer's key set is cached with a rate limit and a single in-flight fetch.
- **The `agent` package** for AI agents: the agent's own key (EdDSA, ES256 or PS256) and token with a fresh
  assertion per mint, CIBA, RFC 8693 token exchange, approval status, a `Transport` that sends the token only to
  the origins you name and never follows a redirect with a credential, and a reader for the gateway's answers.
- **Verification of agent tokens**: DPoP proofs (RFC 9449) and the AuthFI certificate chain of the signing key are
  verified by default. The proof replay guard is bounded per proof key, and a full guard answers
  `dpop_replay_guard_full`.
- **Revocation**: a Shared Signals push receiver (RFC 8935) and a bounded revocation store wired into `Verify`, so
  a token of an agent that AuthFI has withdrawn is refused at once instead of when it expires.
- **`agent.Spotlight`** marks a tool result as data, with its source and a fresh random id the content cannot
  forge, so a model can tell a tool's data from an instruction.

### Changed

- Every secret in `Config`, `Client`, errors and logs is redacted.
- Go 1.21 or later is required.
