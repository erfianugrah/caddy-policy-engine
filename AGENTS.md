# AGENTS.md — Caddy Policy Engine

## Project Overview

Caddy v2 HTTP middleware plugin (`http.handlers.policy_engine`) that IS the WAF —
evaluating allow/block/challenge/skip/rate_limit/detect/response_header policy rules
through a 7-pass priority pipeline. Includes a JA4 TLS fingerprinting listener wrapper
(`caddy.listeners.ja4`), a SHA-256 hashcash proof-of-work challenge system with 6-layer
bot scoring, session tracking via service worker + page-level collector, and a JTI
denylist for retrospective cookie invalidation.

Single Go package (`package policyengine`) with no subdirectories. Built as a Caddy
plugin via xcaddy. **Coraza has been removed** — this plugin replaces it entirely.

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

| File | Lines | Purpose |
|---|---|---|
| `policyengine.go` | ~4419 | Core engine: types, compilation, 7-pass evaluation, ServeHTTP, hot-reload, field extraction, operators, CRS protocol enforcement |
| `challenge.go` | ~1120 | PoW challenge system: interstitial, verification, 6-layer bot scoring, adaptive difficulty, HMAC cookies, session tracking, JTI denylist |
| `ratelimit.go` | ~606 | Sliding window rate limiting with 16-shard concurrent counters |
| `transforms.go` | ~820 | CRS-compatible transform functions (21 transforms matching ModSecurity `t:xxx`) |
| `responseheaders.go` | ~804 | CSP, security headers, CORS, ResponseWriter wrapper |
| `ja4.go` | ~431 | JA4 TLS fingerprint computation: ClientHello parser, hash computation |
| `ja4_listener.go` | ~152 | `caddy.ListenerWrapper` module for JA4 — intercepts connections pre-TLS |
| `ja4_registry.go` | ~28 | Thread-safe JA4 fingerprint store (`sync.Map`) keyed by remote address |
| `ahocorasick.go` | ~172 | Aho-Corasick multi-pattern substring matcher for `phrase_match` operator |
| `policyengine_test.go` | ~7698 | Core engine tests |
| `challenge_test.go` | ~1278 | Challenge system tests |
| `ratelimit_test.go` | ~1217 | Rate limiter tests |
| `transforms_test.go` | ~951 | Transform function tests |
| `responseheaders_test.go` | ~2054 | Response header tests |
| `ja4_test.go` | ~398 | JA4 fingerprint tests |
| `ahocorasick_test.go` | ~374 | Aho-Corasick tests |

### Embedded Files (5)

| File | Purpose |
|---|---|
| `challenge.html` | PoW interstitial HTML template (served to challenged clients) |
| `challenge.js` | Client-side PoW solver + bot signal collector (inline in HTML) |
| `challenge-worker.js` | Web Worker for parallel SHA-256 hashing (`/.well-known/policy-challenge/worker.js`) |
| `session-sw.js` | Service Worker for cross-navigation session tracking (`/.well-known/policy-challenge/session-sw.js`) |
| `session-collector.js` | Page-level behavioral collector injected via `sessionCollectorWriter` into HTML responses |

## Rule Types and Evaluation Pipeline

7 rule types evaluated in a strict priority-band order:

| Pass | Priority Band | Type | Action |
|---|---|---|---|
| 1 | 50–99 | `allow` | Short-circuit: skip remaining passes, pass to next handler |
| 2 | 100–149 | `block` | Return 403 Forbidden |
| 3 | 150–199 | `challenge` | Verify PoW cookie or serve interstitial |
| 4 | 200–299 | `skip` | Set skip flags for downstream phases (detect, rate_limit, block, challenge) |
| 5 | 300–399 | `rate_limit` | Sliding window counter; 429 on exceed or log_only |
| 6 | 400–499 | `detect` | Anomaly scoring (inbound + outbound); block if threshold exceeded |
| 7 | 500–599 | `response_header` | Inject CSP, security headers, CORS on the response |

Within each band, rules are sorted by priority (ascending), then by rule ID for
deterministic tie-breaking.

### CRS Protocol Enforcement

`WafConfig` carries CRS extended settings for protocol enforcement. These are
checked before the main rule loop in `ServeHTTP` via `enforceProtocolLimits()`.
Violations produce synthetic detect rule matches with CRITICAL severity (+5 score)
using original CRS rule IDs for event correlation.

| Setting | CRS Rule | Description |
|---------|----------|-------------|
| `allowed_methods` | 911100 | Space-separated HTTP methods (e.g., "GET HEAD POST") |
| `allowed_http_versions` | 920430 | Space-separated versions (e.g., "HTTP/1.1 HTTP/2.0") |
| `max_num_args` | 920380 | Max argument count (0 = unlimited) |
| `arg_name_length` | 920360 | Max argument name length (0 = unlimited) |
| `arg_length` | 920370 | Max argument value length (0 = unlimited) |
| `total_arg_length` | 920390 | Max combined query string length (0 = unlimited) |
| `max_file_size` | 920400 | Max individual upload size (0 = unlimited, not yet enforced) |
| `combined_file_sizes` | 920410 | Max combined upload size (0 = unlimited, not yet enforced) |

All settings support per-service overrides via `WafServiceConfig`. Zero/empty = not
enforced (permissive default). Settings flow from wafctl dashboard → `waf-config.json`
→ `policy-rules.json` `waf_config` section → plugin `compileWafConfig()`.

## Dependencies

Three direct dependencies:
- `github.com/caddyserver/caddy/v2` — Caddy framework
- `go.uber.org/zap` — Structured logging
- `github.com/corazawaf/libinjection-go` — SQLi/XSS detection operators (`detect_sqli`/`detect_xss`)

All core algorithms (Aho-Corasick, transforms, rate limiter, JA4 parser, challenge
system, bot scoring) are self-contained with zero third-party dependencies.

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

- **Exported types**: PascalCase — `PolicyEngine`, `PolicyRule`, `RateLimitConfig`, `JA4ListenerWrapper`, `ChallengeConfig`
- **Unexported types**: camelCase — `compiledRule`, `compiledCondition`, `parsedBody`, `compiledChallengeConfig`, `botSignals`, `botBehavior`
- **Constants**: camelCase — `defaultBodyMaxSize`, `maxRegexLen`, `numShards`, `hashesPerCoreMs`, `timingScorePenalty`
- **Variables**: Short contextual abbreviations — `pe` (PolicyEngine), `cr` (compiledRule), `cc` (compiledCondition), `pb` (parsedBody), `rls` (rateLimitState)
- **Test functions**: `Test<Subject>_<Scenario>` — e.g., `TestCondition_Eq_Match`, `TestZone_AllowUnderLimit`

### Types and Structs

- All exported struct fields carry `json:"snake_case,omitempty"` tags.
- Each user-facing config type has a "compiled" counterpart created at provision time
  (e.g., `PolicyRule` -> `compiledRule`, `PolicyCondition` -> `compiledCondition`,
  `ChallengeConfig` -> `compiledChallengeConfig`). Pre-process everything at load time
  for O(1) runtime lookups.
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
- `sync.Map` in `ja4Registry` for lock-free JA4 fingerprint storage.
- Channel-based goroutine lifecycle: `stopPoll`/`stopSweep` channels with
  `close()` for graceful shutdown.

### Code Organization

- Section separators use ASCII art headers:
  ```go
  // ─── Section Name ──────────────────────────────────────────────
  ```
- Every file starts with a package-level doc comment explaining its purpose.
- Doc comments on all exported and most unexported functions.
- Extensive inline comments for non-obvious logic (CRS semantics, algorithm
  explanations, bot scoring rationale).

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

### PolicyEngine (`http.handlers.policy_engine`)

This module implements:
- `caddy.Module` (CaddyModule)
- `caddy.Provisioner` (Provision)
- `caddy.Validator` (Validate)
- `caddy.CleanerUpper` (Cleanup)
- `caddyhttp.MiddlewareHandler` (ServeHTTP)
- `caddyfile.Unmarshaler` (UnmarshalCaddyfile)

### JA4ListenerWrapper (`caddy.listeners.ja4`)

This module implements:
- `caddy.Module` (CaddyModule)
- `caddy.Provisioner` (Provision)
- `caddy.ListenerWrapper` (WrapListener)
- `caddyfile.Unmarshaler` (UnmarshalCaddyfile)

When adding new functionality, ensure the appropriate Caddy interface is
satisfied and add an interface assertion at the bottom of the relevant file.

## Challenge System Patterns

### PoW Flow

1. Client hits a challenge rule → `serveChallengeInterstitial()` serves embedded HTML
2. Client-side JS spawns Web Worker, performs SHA-256 hashcash PoW
3. JS collects bot signals (13 probes) + behavioral data during solve
4. Client POSTs solution to `/.well-known/policy-challenge/verify`
5. Server validates: HMAC, PoW hash, timing, then runs 6-layer bot scoring
6. If score < 70: HMAC-signed cookie issued, client redirected to original URL
7. Subsequent requests: `validateChallengeCookie()` checks cookie validity

### Adaptive Difficulty

- `preSignalScore(r)` runs at challenge-serve time (L1/L2/partial-L5 only)
- `selectDifficulty(r, min, max)` maps score linearly to [min, max] range
- Score 0 → min difficulty, score >= 70 → max difficulty
- Static fallback: when min == max == 0, uses `challenge_difficulty` field

### 6-Layer Bot Scoring (`scoreBotSignals`)

| Layer | Source | Signals |
|---|---|---|
| L1 | TLS fingerprint (JA4) | Non-browser ALPN, TLS 1.2-only |
| L2 | HTTP headers | Missing Sec-Fetch-*, Accept-Language, Client Hints |
| L3 | JS probes (13) | webdriver, CDC markers, WebGL renderer+MaxTex, audio, speech voices, permissions timing, languages, chrome.runtime, platform, memory, touch, screen |
| L4 | Behavioral (5) | Mouse/key/scroll events, first interaction timing, worker variance |
| L5 | Spatial | Mobile UA vs touch/screen, platform vs UA cross-check, Chrome UA vs JA4 |
| L6 | Timing | PoW solve time vs expected minimum (`minSolveMs`) |

### Session Tracking

- `session-sw.js`: Service Worker intercepts navigation requests, sends beacons
- `session-collector.js`: Injected into HTML responses via `sessionCollectorWriter`
  (wraps `http.ResponseWriter`, injects `<script>` before `</body>`)
- Beacons POST to `/.well-known/policy-challenge/session` → logged as Caddy variables
- JTI denylist: `jti-denylist.json` written by wafctl, polled by plugin, enables
  retrospective cookie invalidation

### Challenge Variables Set

- `policy_engine.action`: `challenge_issued`, `challenge_bypassed`, `challenge_passed`, `challenge_failed`, `session_beacon`
- `policy_engine.challenge_fail_reason`: `missing_fields`, `bad_input`, `payload_expired`, `hmac_invalid`, `bad_pow`, `timing_hard`, `bot_score`
- `policy_engine.challenge_difficulty`, `policy_engine.challenge_pre_score`, `policy_engine.challenge_elapsed_ms`, `policy_engine.challenge_bot_score`
- `policy_engine.session_beacon`, `policy_engine.session_jti`

## JA4 Patterns

### Architecture

- `ja4_listener.go`: Caddy `ListenerWrapper` — wraps the TCP listener before TLS handshake
- `ja4.go`: Hand-rolled ClientHello binary parser (zero deps), full FoxIO JA4 spec
- `ja4_registry.go`: Global `sync.Map` store keyed by `remoteAddr`, cleaned up on `Close()`
- `ja4_test.go`: Tests with real captured ClientHello packets

### Data Flow

1. `ja4Listener.Accept()` → reads first bytes of TCP connection
2. `readClientHello()` → binary parse of TLS record + ClientHello message
3. `parseClientHello()` → extracts cipher suites, extensions, SNI, ALPN, sig algs
4. `computeJA4()` → constructs JA4 fingerprint string (protocol, version, cipher count, ext count, ALPN, ciphers hash, extensions hash)
5. `ja4Registry.Set(addr, ja4)` → stored for request lifetime
6. `extractField(cc, r, pb)` case `"ja4"` → reads from registry
7. `ja4Conn.Close()` → `ja4Registry.Delete(addr)` cleanup

### Key Design Decisions

- `rewindConn` replays buffered bytes so TLS handshake proceeds normally after ClientHello capture
- GREASE values filtered per spec
- SHA-256 truncated to 12 hex chars for hash sections
