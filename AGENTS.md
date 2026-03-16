# AGENTS.md — Caddy Policy Engine

## Project Overview

Caddy v2 HTTP middleware plugin (`http.handlers.policy_engine`) that evaluates
allow/block/honeypot/rate_limit policy rules. Single Go package (`package policyengine`)
with no subdirectories. Built as a Caddy plugin via xcaddy.

## Build & Test Commands

```bash
# Run all tests with race detection (canonical command)
go test -race -count=1 ./...

# Run a single test by name
go test -race -count=1 -run TestCondition_Eq_Match ./...

# Run tests matching a prefix (e.g. all rate limit tests)
go test -race -count=1 -run TestZone ./...

# Run benchmarks (Aho-Corasick)
go test -bench=BenchmarkAC -benchmem ./...

# Build with xcaddy (produces a caddy binary with this plugin)
xcaddy build --with github.com/erfianugrah/caddy-policy-engine

# Format code
gofmt -w .

# Vet
go vet ./...
```

There is no Makefile, no CI/CD pipeline, and no linter configuration file.
Always run tests with `-race -count=1`. The `-count=1` disables test caching.

## Project Structure

All source lives in the repository root as a single flat Go package:

| File | Purpose |
|---|---|
| `policyengine.go` | Core engine: types, compilation, matching, ServeHTTP, hot-reload |
| `ratelimit.go` | Sliding window rate limiting with sharded counters |
| `ahocorasick.go` | Aho-Corasick multi-pattern substring matcher |
| `transforms.go` | CRS-compatible transform functions (lowercase, urlDecode, etc.) |
| `responseheaders.go` | CSP, security headers, CORS, ResponseWriter wrapper |
| `*_test.go` | Corresponding test files (white-box, same package) |

## Dependencies

Only two direct dependencies:
- `github.com/caddyserver/caddy/v2` — Caddy framework
- `go.uber.org/zap` — Structured logging

Notable indirect dependency used in source:
- `github.com/corazawaf/libinjection-go` — SQLi/XSS detection operators

All core algorithms (Aho-Corasick, transforms, rate limiter) are self-contained
with zero third-party dependencies.

## Code Style Guidelines

### Imports

Three groups separated by blank lines, each alphabetically sorted:
1. Standard library (`fmt`, `net/http`, `sync`, etc.)
2. Third-party (`github.com/caddyserver/caddy/v2`, `go.uber.org/zap`)
3. Internal (N/A — single package project)

Use named imports only when necessary:
```go
libinjection "github.com/corazawaf/libinjection-go"
```

### Naming Conventions

- **Exported types**: PascalCase — `PolicyEngine`, `PolicyRule`, `RateLimitConfig`
- **Unexported types**: camelCase — `compiledRule`, `compiledCondition`, `parsedBody`
- **Constants**: camelCase — `defaultBodyMaxSize`, `maxRegexLen`, `numShards`
- **Variables**: Short contextual abbreviations — `pe` (PolicyEngine), `cr` (compiledRule), `cc` (compiledCondition), `pb` (parsedBody), `rls` (rateLimitState)
- **Test functions**: `Test<Subject>_<Scenario>` — e.g., `TestCondition_Eq_Match`, `TestZone_AllowUnderLimit`

### Types and Structs

- All exported struct fields carry `json:"snake_case,omitempty"` tags.
- Each user-facing config type has a "compiled" counterpart created at provision time
  (e.g., `PolicyRule` -> `compiledRule`, `PolicyCondition` -> `compiledCondition`,
  `WafConfig` -> `compiledWafConfig`). Pre-process everything at load time for O(1)
  runtime lookups.
- Interface compliance assertions go at the bottom of the file:
  ```go
  var _ caddy.Module = (*PolicyEngine)(nil)
  ```

### Error Handling

- Always wrap errors with `fmt.Errorf("context: %w", err)`.
- Error messages include the function/operation context:
  `"compiling rules: %w"`, `"parsing CIDR %q: %w"`, `"condition %s %s: %w"`.
- No sentinel error variables — errors are constructed inline.
- Check errors immediately on the next line; never defer error checking.
- Graceful degradation on startup: missing rules file logs a warning and starts
  with empty rules rather than failing fatally.
- In tests, use `t.Fatal(err)` or `t.Fatalf(...)` for immediate failure.

### Concurrency

- `sync.RWMutex` (as pointer) protects hot-reload: write lock during reload,
  read lock during request serving.
- Sharded mutexes in the rate limiter (`numShards = 16`).
- `sync.Pool` for response body buffer reuse.
- Channel-based goroutine lifecycle: `stopPoll`/`stopSweep` channels with
  `close()` for graceful shutdown.

### Code Organization

- Section separators use ASCII art headers:
  ```go
  // ─── Section Name ──────────────────────────────────────────────
  ```
- Every file starts with a package-level doc comment explaining its purpose.
- Doc comments on all exported and most unexported functions.
- Extensive inline comments for non-obvious logic (CRS semantics, Coraza
  compatibility, algorithm explanations).

### Formatting

- Standard `gofmt` formatting. No custom linter configuration.
- No line length limit beyond what gofmt produces naturally.

## Testing Conventions

- All tests are **white-box** (same `package policyengine`), accessing unexported symbols.
- Uses only the standard `testing` package — no testify, gomock, or other frameworks.
- Test helpers defined in `policyengine_test.go`:
  - `testContext()` — creates a `caddy.Context`
  - `mustProvision(t, pe)` — provisions a PolicyEngine, fails on error
  - `makeRequest(method, path, remoteAddr)` — builds `*http.Request` with Caddy vars
  - `makeRequestWithHeaders(method, path, remoteAddr, headers)` — same with headers
  - `writeTempRulesFile(t, rules)` — writes temp JSON rules file, returns path
  - `newTestPolicyEngine(t, rules)` — compiles rules into a fully initialized engine
  - `nextHandler` — mock handler that records whether `ServeHTTP` was called
- Tests are designed to run with the `-race` flag.
- Test data is constructed inline or via temp files; there is no fixtures directory.

## Caddy Plugin Interfaces

This module implements:
- `caddy.Module` (CaddyModule)
- `caddy.Provisioner` (Provision)
- `caddy.Validator` (Validate)
- `caddy.CleanerUpper` (Cleanup)
- `caddyhttp.MiddlewareHandler` (ServeHTTP)
- `caddyfile.Unmarshaler` (UnmarshalCaddyfile)

When adding new functionality, ensure the appropriate Caddy interface is
satisfied and add an interface assertion at the bottom of the file.
