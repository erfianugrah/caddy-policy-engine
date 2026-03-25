package policyengine

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	_ "embed"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"go.uber.org/zap"
)

//go:embed challenge.html
var challengeHTMLTemplate string

//go:embed challenge.js
var challengeJS string

//go:embed challenge-worker.js
var challengeWorkerJS string

//go:embed session-sw.js
var sessionSWJS string

//go:embed session-collector.js
var sessionCollectorJS string

// ─── Types ──────────────────────────────────────────────────────────

// ChallengeConfig is the per-rule challenge configuration in policy-rules.json.
type ChallengeConfig struct {
	Difficulty    int    `json:"difficulty"`               // Leading hex zeros in SHA-256 (1-16)
	MinDifficulty int    `json:"min_difficulty,omitempty"` // Adaptive: minimum difficulty (1-16)
	MaxDifficulty int    `json:"max_difficulty,omitempty"` // Adaptive: maximum difficulty (1-16)
	Algorithm     string `json:"algorithm"`                // "fast" or "slow"
	TTLSeconds    int    `json:"ttl_seconds"`              // Cookie lifetime in seconds
	BindIP        bool   `json:"bind_ip"`                  // Bind cookie to client IP
	BindJA4       bool   `json:"bind_ja4,omitempty"`       // Bind cookie to JA4 TLS fingerprint
}

// ChallengeGlobalConfig holds global challenge settings in policy-rules.json.
type ChallengeGlobalConfig struct {
	HMACKey string `json:"hmac_key,omitempty"` // Hex-encoded 32-byte HMAC-SHA256 key
}

// compiledChallengeConfig is the pre-compiled form of ChallengeConfig.
type compiledChallengeConfig struct {
	difficulty    int // static difficulty (used when min == max)
	minDifficulty int // adaptive: minimum difficulty
	maxDifficulty int // adaptive: maximum difficulty
	algorithm     string
	ttl           time.Duration
	bindIP        bool
	bindJA4       bool
	cookieName    string
}

// challengePayload is the JSON payload embedded in the interstitial page
// and submitted back during verification.
type challengePayload struct {
	RandomData  string `json:"random_data"`
	Difficulty  int    `json:"difficulty"`
	Algorithm   string `json:"algorithm"`
	HMAC        string `json:"hmac"`
	OriginalURL string `json:"original_url"`
	Timestamp   string `json:"timestamp"`
}

// challengeCookiePayload is the signed cookie content.
type challengeCookiePayload struct {
	Jti   string `json:"jti"`           // Unique token ID (16 hex chars)
	Sub   string `json:"sub,omitempty"` // Client IP (if bind_ip)
	Aud   string `json:"aud"`           // Service hostname
	Iat   int64  `json:"iat"`           // Issued at (unix timestamp)
	Exp   int64  `json:"exp"`           // Expires at (unix timestamp)
	Dif   int    `json:"dif"`           // Difficulty solved at
	Score int    `json:"scr"`           // Bot score at time of issuance (0-100)
	Ja4   string `json:"ja4,omitempty"` // JA4 TLS fingerprint (if bind_ja4)
}

// ─── Worker JS Serving ──────────────────────────────────────────────

// serveChallengeWorkerJS serves the Web Worker JS file at
// /.well-known/policy-challenge/worker.js. Served with aggressive caching
// since the content is deterministic (changes only on plugin binary update).
func (pe *PolicyEngine) serveChallengeWorkerJS(w http.ResponseWriter, r *http.Request) error {
	w.Header().Set("Content-Type", "application/javascript; charset=utf-8")
	w.Header().Set("Cache-Control", "public, max-age=86400, immutable")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(challengeWorkerJS))
	return nil
}

// serveSessionSW serves the session tracking service worker at
// /.well-known/policy-challenge/session-sw.js. The Service-Worker-Allowed
// header permits registration with origin-wide scope (the script path is
// under /.well-known/ which is more restrictive than /).
func (pe *PolicyEngine) serveSessionSW(w http.ResponseWriter, r *http.Request) error {
	w.Header().Set("Content-Type", "application/javascript; charset=utf-8")
	w.Header().Set("Cache-Control", "public, max-age=86400, immutable")
	w.Header().Set("Service-Worker-Allowed", "/")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(sessionSWJS))
	return nil
}

// handleSessionBeacon accepts POST beacons from the session service worker
// and page-level collector at /.well-known/policy-challenge/session.
// The beacon JSON is logged via Caddy variables for downstream processing
// by wafctl. Returns 204 No Content (per Beacon API spec recommendation).
func (pe *PolicyEngine) handleSessionBeacon(w http.ResponseWriter, r *http.Request) error {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return nil
	}

	// Read beacon body (limited to 64KB to prevent abuse).
	body := make([]byte, 0, 4096)
	buf := make([]byte, 4096)
	total := 0
	for {
		n, err := r.Body.Read(buf)
		if n > 0 {
			total += n
			if total > 65536 {
				w.WriteHeader(http.StatusRequestEntityTooLarge)
				return nil
			}
			body = append(body, buf[:n]...)
		}
		if err != nil {
			break
		}
	}

	if len(body) > 0 {
		// Extract JTI from the challenge cookie for session correlation.
		host := stripPort(r.Host)
		cookieName := challengeCookieName(host)
		jti := ""
		if cookie, err := r.Cookie(cookieName); err == nil && cookie.Value != "" {
			parts := strings.SplitN(cookie.Value, ".", 2)
			if len(parts) == 2 {
				if payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[0]); err == nil {
					var cp struct {
						Jti string `json:"jti"`
					}
					if json.Unmarshal(payloadBytes, &cp) == nil {
						jti = cp.Jti
					}
				}
			}
		}

		// Log the session beacon data as Caddy variables for access log capture.
		caddyhttp.SetVar(r.Context(), "policy_engine.session_beacon", string(body))
		caddyhttp.SetVar(r.Context(), "policy_engine.session_jti", jti)
		caddyhttp.SetVar(r.Context(), "policy_engine.action", "session_beacon")

		pe.logger.Debug("session beacon received",
			zap.String("jti", jti),
			zap.Int("body_bytes", len(body)),
			zap.String("client_ip", clientIP(r)))
	}

	w.WriteHeader(http.StatusNoContent)
	return nil
}

// ─── Timing Validation ──────────────────────────────────────────────

const (
	// hashesPerCoreMs is a generous upper bound for WebCrypto SHA-256
	// hashes per core per millisecond. Real browsers typically achieve
	// 20-40; we use 50 to avoid false positives on fast hardware.
	hashesPerCoreMs = 50

	// timingSafetyFactor allows 3.3x faster than the expected average,
	// accounting for variance in hash distribution and system load.
	timingSafetyFactor = 0.3

	// timingScorePenalty is the bot score added when elapsed time is
	// below the expected minimum but above the hard-reject threshold.
	timingScorePenalty = 40
)

// minSolveMs computes the minimum expected solve time in milliseconds
// for a given difficulty and core count. This is the floor below which
// a solution is suspiciously fast.
//
// Formula: (2^(difficulty*4)) / (cores * hashesPerCoreMs) * safetyFactor
//
// Cores are clamped to [1, 256] to prevent division tricks.
func minSolveMs(difficulty, cores int) int {
	if cores < 1 {
		cores = 1
	}
	if cores > 256 {
		cores = 256
	}
	if difficulty < 1 {
		difficulty = 1
	}
	if difficulty > 16 {
		difficulty = 16
	}

	// Expected iterations = 16^difficulty = 2^(difficulty*4).
	expectedIters := math.Pow(2, float64(difficulty*4))

	// Minimum time = expected iters / (cores * hashes/core/ms) * safety factor.
	minMs := (expectedIters / float64(cores*hashesPerCoreMs)) * timingSafetyFactor

	// Floor at 0 — difficulty 1 with many cores can produce sub-millisecond.
	if minMs < 0 {
		minMs = 0
	}

	return int(minMs)
}

// ─── Bot Signal Scoring ─────────────────────────────────────────────

// botSignals is the parsed client-side environment probe data.
type botSignals struct {
	Webdriver      int     `json:"wd"`                  // 1 = navigator.webdriver true
	CDCPresent     int     `json:"cdc"`                 // 1 = ChromeDriver markers found
	ChromeRuntime  int     `json:"cr"`                  // 1 = window.chrome.runtime present
	PluginCount    int     `json:"plg"`                 // navigator.plugins.length
	LanguageCount  int     `json:"lang"`                // navigator.languages.length
	SpeechVoices   int     `json:"sv"`                  // speechSynthesis voices count
	WebGLRenderer  string  `json:"wglr"`                // UNMASKED_RENDERER_WEBGL
	WebGLMaxTex    int     `json:"wglMaxTex,omitempty"` // MAX_TEXTURE_SIZE
	AudioHash      int     `json:"audioHash,omitempty"` // OfflineAudioContext fingerprint
	Cores          int     `json:"cores"`
	Memory         float64 `json:"mem"`
	TouchPoints    int     `json:"touch"`
	Platform       string  `json:"plt"`
	ScreenWidth    int     `json:"sw"`
	ScreenHeight   int     `json:"sh"`
	PermissionTime float64 `json:"pt"` // ms for permissions.query
}

// botBehavior is the parsed behavioral data collected during PoW.
type botBehavior struct {
	MouseEvents      int     `json:"me"`
	KeyEvents        int     `json:"ke"`
	FocusChanges     int     `json:"fc"`
	ScrollEvents     int     `json:"se"`
	FirstInteraction int     `json:"fi"`  // ms from page load, -1 = none
	WorkerVariance   float64 `json:"wtv"` // stddev of worker progress intervals
	Duration         int     `json:"dur"` // total challenge duration ms
}

// preSignalScore computes a bot score from signals available before the
// interstitial is served — Layers 1 (JA4/TLS), 2 (HTTP headers), and
// 5 (spatial inconsistency, UA-only subset). This runs at challenge-serve
// time to drive adaptive difficulty selection.
//
// Layer 5 here only uses UA-based checks that don't require JS probes
// (touch points and screen width come from JS, so they're excluded).
// The full L5 check runs later in scoreBotSignals when JS data is available.
func preSignalScore(r *http.Request) int {
	score := 0

	// ── Layer 1: TLS fingerprint (JA4) ────────────────────────────
	ja4 := ja4Registry.Get(r.RemoteAddr)
	if ja4 != "" {
		parts := strings.SplitN(ja4, "_", 2)
		if len(parts) >= 1 && len(parts[0]) >= 10 {
			a := parts[0]
			alpn := a[8:10]
			if alpn == "00" {
				score += 25
			}
			if a[1:3] == "12" {
				score += 10
			}
		}
	}

	// ── Layer 2: HTTP header analysis ─────────────────────────────
	if r.Header.Get("Sec-Fetch-Site") == "" && r.Header.Get("Sec-Fetch-Mode") == "" {
		score += 20
	}
	if r.Header.Get("Accept-Language") == "" {
		score += 10
	}
	ua := r.Header.Get("User-Agent")
	isChromeLikeUA := strings.Contains(ua, "Chrome/") || strings.Contains(ua, "Chromium/")
	if isChromeLikeUA && r.Header.Get("Sec-CH-UA") == "" {
		score += 15
	}

	// ── Layer 5 (partial): UA-only spatial checks ─────────────────
	// Chrome UA but JA4 is non-browser TLS stack — no JS needed.
	if isChromeLikeUA && ja4 != "" {
		parts := strings.SplitN(ja4, "_", 2)
		if len(parts) >= 1 && len(parts[0]) >= 10 {
			alpn := parts[0][8:10]
			if alpn == "00" || alpn == "h1" {
				score += 35
			}
		}
	}

	if score > 100 {
		score = 100
	}
	return score
}

// selectDifficulty picks a PoW difficulty from [min, max] based on the
// pre-signal score of the incoming request. Score 0 → min, score >= 70 → max.
func selectDifficulty(r *http.Request, min, max int) int {
	if min >= max {
		return min
	}
	score := preSignalScore(r)
	if score >= 70 {
		return max
	}
	if score <= 0 {
		return min
	}
	// Linear interpolation: score/70 * (max-min) + min.
	return min + (score*(max-min)+69)/70 // integer ceil division
}

// scoreBotSignals parses the signals and behavior JSON from the challenge
// submission, combines with JA4 TLS fingerprint and HTTP header analysis,
// and returns a bot score (0-100).
//
// elapsedMs is the client-reported solve time; difficulty is the PoW difficulty.
// These are used for timing-based scoring: if the solve was suspiciously fast
// relative to the expected minimum (based on difficulty and reported core count),
// a penalty is applied. Pass elapsedMs < 0 to skip timing scoring.
//
// Layers:
//
//	L1 — TLS fingerprint (JA4) — non-browser TLS stacks
//	L2 — HTTP headers — missing Sec-Fetch-*, inconsistent Client Hints
//	L3 — JS environment probes — webdriver, plugins, WebGL, canvas, permissions
//	L4 — Behavioral signals — mouse, keyboard, scroll, worker timing
//	L5 — Spatial inconsistency — cross-referencing UA, JA4, and JS signals
//	L6 — Timing validation — suspiciously fast PoW solutions
func scoreBotSignals(signalsJSON, behaviorJSON string, r *http.Request, logger *zap.Logger, elapsedMs, difficulty int) int {
	var sig botSignals
	var beh botBehavior

	if signalsJSON != "" {
		if err := json.Unmarshal([]byte(signalsJSON), &sig); err != nil {
			logger.Debug("challenge: failed to parse signals", zap.Error(err))
			return 0 // fail open — can't score without signals
		}
	} else {
		return 0 // no signals submitted — fail open
	}

	if behaviorJSON != "" {
		json.Unmarshal([]byte(behaviorJSON), &beh) // best-effort
	}

	// Start with L1/L2/partial-L5 from preSignalScore.
	score := preSignalScore(r)

	ua := r.Header.Get("User-Agent")

	// ── Layer 3: JS environment probes ────────────────────────────
	if sig.Webdriver == 1 {
		score += 90 // navigator.webdriver = true
	}
	if sig.CDCPresent == 1 {
		score += 95 // ChromeDriver/Puppeteer markers in DOM
	}
	if strings.Contains(sig.WebGLRenderer, "SwiftShader") {
		score += 85
	}
	if sig.WebGLMaxTex > 0 && sig.WebGLMaxTex <= 8192 && !strings.Contains(sig.WebGLRenderer, "SwiftShader") {
		score += 60 // small GPU texture limit without SwiftShader — virtual GPU
	}
	if sig.AudioHash == 0 && sig.PluginCount > 0 {
		score += 15 // audio API failed but plugins present — inconsistent
	}
	if sig.PluginCount == 0 {
		score += 30
	}
	if sig.SpeechVoices == 0 {
		score += 20
	}
	if sig.PermissionTime >= 0 && sig.PermissionTime < 0.5 {
		score += 30 // permissions.query too fast — no real permission store
	}
	if sig.LanguageCount <= 1 {
		score += 10
	}
	if sig.ChromeRuntime == 0 {
		score += 15
	}
	// Server-class memory: >= 32GB is unusual for a consumer browser.
	// VPS instances running headless Chrome farms typically report high RAM.
	if sig.Memory >= 32 {
		score += 15
	}

	// ── Layer 4: Behavioral signals ───────────────────────────────
	if beh.Duration > 2000 && beh.MouseEvents == 0 && beh.KeyEvents == 0 && beh.ScrollEvents == 0 {
		score += 15 // no interaction during long challenge — likely automated
	}
	// Worker timing variance: truly deterministic execution (stddev < 0.5ms)
	// over a meaningful duration indicates a controlled environment. Real
	// browsers have OS scheduling jitter that produces higher variance.
	if beh.WorkerVariance >= 0 && beh.WorkerVariance < 0.5 && beh.Duration > 1000 {
		score += 20
	}
	// Positive signal: organic mouse activity with early first interaction
	// indicates a real human. Subtract a small amount to reduce false positives
	// for legitimate browsers that happen to trigger minor red flags.
	if beh.MouseEvents >= 5 && beh.FirstInteraction > 0 && beh.FirstInteraction < 2000 {
		score -= 10
		if score < 0 {
			score = 0
		}
	}

	// ── Layer 5 (full): Spatial inconsistency with JS signals ─────
	// The partial L5 check (Chrome UA + JA4) already ran in preSignalScore.
	// Here we add the JS-dependent checks.
	uaLower := strings.ToLower(ua)
	isMobileUA := strings.Contains(uaLower, "mobile") ||
		strings.Contains(uaLower, "android") ||
		strings.Contains(uaLower, "iphone")
	if isMobileUA && sig.TouchPoints == 0 {
		score += 40 // mobile UA but no touch support
	}
	if isMobileUA && sig.ScreenWidth > 2000 {
		score += 30 // mobile UA but desktop screen resolution
	}
	// Platform vs UA cross-check: "Win32" platform with non-Windows UA
	// or "Linux" platform with Windows UA indicates UA spoofing.
	if sig.Platform != "" {
		pltLower := strings.ToLower(sig.Platform)
		isWinPlatform := strings.Contains(pltLower, "win")
		isLinuxPlatform := strings.Contains(pltLower, "linux")
		isMacPlatform := strings.Contains(pltLower, "mac")
		uaClaimsWindows := strings.Contains(uaLower, "windows")
		uaClaimsMac := strings.Contains(uaLower, "macintosh") || strings.Contains(uaLower, "mac os")
		uaClaimsLinux := strings.Contains(uaLower, "linux") || strings.Contains(uaLower, "android")
		// Platform says Windows but UA says Mac/Linux (or vice versa).
		if isWinPlatform && !uaClaimsWindows && (uaClaimsMac || uaClaimsLinux) {
			score += 30
		}
		if isMacPlatform && !uaClaimsMac && (uaClaimsWindows || uaClaimsLinux) {
			score += 30
		}
		if isLinuxPlatform && !uaClaimsLinux && (uaClaimsWindows || uaClaimsMac) {
			score += 30
		}
	}

	// ── Layer 6: Timing validation ───────────────────────────────
	if elapsedMs >= 0 && difficulty >= 1 {
		cores := sig.Cores
		if cores < 1 {
			cores = 1
		}
		floor := minSolveMs(difficulty, cores)
		if floor > 0 && elapsedMs < floor {
			score += timingScorePenalty
			logger.Debug("challenge: suspicious solve timing",
				zap.Int("elapsed_ms", elapsedMs),
				zap.Int("floor_ms", floor),
				zap.Int("cores", cores),
				zap.Int("difficulty", difficulty))
		}
	}

	// Cap at 100.
	if score > 100 {
		score = 100
	}

	ja4 := ja4Registry.Get(r.RemoteAddr)
	logger.Debug("challenge bot score",
		zap.Int("score", score),
		zap.String("ja4", ja4),
		zap.Int("webdriver", sig.Webdriver),
		zap.Int("plugins", sig.PluginCount),
		zap.String("webgl", sig.WebGLRenderer),
		zap.Float64("perm_timing", sig.PermissionTime),
		zap.Int("mouse_events", beh.MouseEvents),
		zap.Float64("worker_variance", beh.WorkerVariance),
		zap.Bool("has_sec_fetch", r.Header.Get("Sec-Fetch-Site") != ""),
		zap.Bool("mobile_ua", isMobileUA),
		zap.Int("touch_points", sig.TouchPoints),
		zap.String("platform", sig.Platform),
		zap.Float64("memory_gb", sig.Memory),
		zap.Int("elapsed_ms", elapsedMs))

	return score
}

// ─── Cookie Name ────────────────────────────────────────────────────

// challengeCookieName computes a per-service cookie name from the service hostname.
func challengeCookieName(service string) string {
	h := sha256.Sum256([]byte(service))
	return "__pc_" + hex.EncodeToString(h[:4])
}

// ─── HMAC Key Provisioning ──────────────────────────────────────────

// provisionChallengeKey sets up the HMAC key from the loaded config or env.
func (pe *PolicyEngine) provisionChallengeKey(globalCfg *ChallengeGlobalConfig) {
	if globalCfg != nil && globalCfg.HMACKey != "" {
		if key, err := hex.DecodeString(globalCfg.HMACKey); err == nil && len(key) == 32 {
			pe.challengeHMACKey = key
			pe.logger.Info("challenge HMAC key loaded from config")
			return
		}
		pe.logger.Warn("invalid challenge HMAC key in config, generating ephemeral key")
	}

	// Generate ephemeral key (invalidated on restart).
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		pe.logger.Error("failed to generate challenge HMAC key", zap.Error(err))
		return
	}
	pe.challengeHMACKey = key
	pe.logger.Warn("using ephemeral challenge HMAC key (cookies invalidated on restart)")
}

// ─── Cookie Validation ──────────────────────────────────────────────

// validateChallengeCookie checks for a valid signed challenge cookie.
// Returns true if the client has already solved a challenge for this host.
func (pe *PolicyEngine) validateChallengeCookie(r *http.Request) bool {
	if len(pe.challengeHMACKey) == 0 {
		return false
	}

	host := stripPort(r.Host)
	expectedName := challengeCookieName(host)

	cookie, err := r.Cookie(expectedName)
	if err != nil || cookie.Value == "" {
		return false
	}

	// Token format: base64url(payload).base64url(signature)
	parts := strings.SplitN(cookie.Value, ".", 2)
	if len(parts) != 2 {
		return false
	}

	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return false
	}
	sigBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return false
	}

	// Verify HMAC.
	mac := hmac.New(sha256.New, pe.challengeHMACKey)
	mac.Write([]byte(parts[0]))
	expected := mac.Sum(nil)
	if subtle.ConstantTimeCompare(sigBytes, expected) != 1 {
		return false
	}

	// Decode and validate payload.
	var payload challengeCookiePayload
	if err := json.Unmarshal(payloadBytes, &payload); err != nil {
		return false
	}

	// Check expiry.
	if time.Now().Unix() > payload.Exp {
		return false
	}

	// Check audience (service).
	if payload.Aud != host {
		return false
	}

	// Check IP binding (if enabled for the matching rule, we don't know here —
	// so we check if Sub is non-empty, meaning binding was active when issued).
	if payload.Sub != "" && payload.Sub != clientIP(r) {
		return false
	}

	// Check JA4 binding (if enabled at issuance time, Ja4 will be non-empty).
	// If the client's current TLS fingerprint doesn't match the one stored in
	// the cookie, the cookie was likely replayed from a different TLS stack.
	if payload.Ja4 != "" {
		currentJA4 := ja4Registry.Get(r.RemoteAddr)
		if currentJA4 != payload.Ja4 {
			return false
		}
	}

	return true
}

// ─── Interstitial Serving ───────────────────────────────────────────

// serveChallengeInterstitial generates and serves the PoW interstitial page.
func (pe *PolicyEngine) serveChallengeInterstitial(w http.ResponseWriter, r *http.Request, cfg *compiledChallengeConfig) error {
	// Select difficulty adaptively based on pre-signal scoring.
	difficulty := selectDifficulty(r, cfg.minDifficulty, cfg.maxDifficulty)

	// Log the selected difficulty and pre-signal score for analytics.
	caddyhttp.SetVar(r.Context(), "policy_engine.challenge_difficulty", strconv.Itoa(difficulty))
	caddyhttp.SetVar(r.Context(), "policy_engine.challenge_pre_score", strconv.Itoa(preSignalScore(r)))

	// Generate random data (64 bytes → 128 hex chars, matching Anubis).
	randomBytes := make([]byte, 64)
	if _, err := rand.Read(randomBytes); err != nil {
		pe.logger.Error("failed to generate challenge nonce", zap.Error(err))
		return caddyhttp.Error(http.StatusInternalServerError, nil)
	}
	randomData := hex.EncodeToString(randomBytes)
	now := time.Now().UTC()

	// Build the challenge payload that will be HMAC'd and embedded.
	// When JA4 binding is enabled, include the TLS fingerprint in the
	// HMAC so the challenge can only be verified from the same TLS stack.
	payloadStr := fmt.Sprintf("%s|%d|%d", randomData, difficulty, now.Unix())
	if cfg.bindJA4 {
		if ja4 := ja4Registry.Get(r.RemoteAddr); ja4 != "" {
			payloadStr += "|" + ja4
		}
	}
	mac := hmac.New(sha256.New, pe.challengeHMACKey)
	mac.Write([]byte(payloadStr))
	payloadHMAC := hex.EncodeToString(mac.Sum(nil))

	originalURL := r.URL.String()

	challengeData := challengePayload{
		RandomData:  randomData,
		Difficulty:  difficulty,
		Algorithm:   cfg.algorithm,
		HMAC:        payloadHMAC,
		OriginalURL: originalURL,
		Timestamp:   strconv.FormatInt(now.Unix(), 10),
	}

	dataJSON, err := json.Marshal(challengeData)
	if err != nil {
		return caddyhttp.Error(http.StatusInternalServerError, nil)
	}

	// Build the page by replacing template placeholders.
	page := challengeHTMLTemplate
	page = strings.Replace(page, "{{CHALLENGE_DATA}}", string(dataJSON), 1)
	page = strings.Replace(page, "{{CHALLENGE_JS}}", challengeJS, 1)

	// Serve — return 200 to fool status-checking bots (same as Anubis).
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("X-Robots-Tag", "noindex, nofollow")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(page))
	return nil
}

// ─── PoW Verification Endpoint ──────────────────────────────────────

// handleChallengeVerify handles POST /.well-known/policy-challenge/verify.
// It validates the PoW solution and issues a signed cookie on success.
func (pe *PolicyEngine) handleChallengeVerify(w http.ResponseWriter, r *http.Request) error {
	if r.Method != http.MethodPost {
		return caddyhttp.Error(http.StatusMethodNotAllowed, nil)
	}

	if err := r.ParseForm(); err != nil {
		return caddyhttp.Error(http.StatusBadRequest, nil)
	}

	randomData := r.FormValue("random_data")
	nonceStr := r.FormValue("nonce")
	response := r.FormValue("response")
	submittedHMAC := r.FormValue("hmac")
	difficultyStr := r.FormValue("difficulty")
	timestampStr := r.FormValue("timestamp")
	originalURL := r.FormValue("original_url")

	if randomData == "" || nonceStr == "" || response == "" || submittedHMAC == "" || difficultyStr == "" || timestampStr == "" {
		pe.logger.Info("challenge verify: missing fields",
			zap.String("client_ip", clientIP(r)))
		caddyhttp.SetVar(r.Context(), "policy_engine.action", "challenge_failed")
		caddyhttp.SetVar(r.Context(), "policy_engine.challenge_fail_reason", "missing_fields")
		return caddyhttp.Error(http.StatusForbidden, nil)
	}

	difficulty, err := strconv.Atoi(difficultyStr)
	if err != nil || difficulty < 1 || difficulty > 16 {
		caddyhttp.SetVar(r.Context(), "policy_engine.action", "challenge_failed")
		caddyhttp.SetVar(r.Context(), "policy_engine.challenge_fail_reason", "bad_input")
		return caddyhttp.Error(http.StatusForbidden, nil)
	}

	nonce, err := strconv.Atoi(nonceStr)
	if err != nil {
		caddyhttp.SetVar(r.Context(), "policy_engine.action", "challenge_failed")
		caddyhttp.SetVar(r.Context(), "policy_engine.challenge_fail_reason", "bad_input")
		return caddyhttp.Error(http.StatusForbidden, nil)
	}

	timestamp, err := strconv.ParseInt(timestampStr, 10, 64)
	if err != nil {
		caddyhttp.SetVar(r.Context(), "policy_engine.action", "challenge_failed")
		caddyhttp.SetVar(r.Context(), "policy_engine.challenge_fail_reason", "bad_input")
		return caddyhttp.Error(http.StatusForbidden, nil)
	}

	// Check timestamp freshness (5-minute window).
	if time.Now().Unix()-timestamp > 300 {
		pe.logger.Info("challenge verify: expired",
			zap.String("client_ip", clientIP(r)),
			zap.Int64("timestamp", timestamp))
		caddyhttp.SetVar(r.Context(), "policy_engine.action", "challenge_failed")
		caddyhttp.SetVar(r.Context(), "policy_engine.challenge_fail_reason", "payload_expired")
		return caddyhttp.Error(http.StatusForbidden, nil)
	}

	// Look up the matching challenge rule to get config (JA4 binding,
	// TTL, bind_ip). We need bindJA4 before HMAC verification because
	// the JA4 fingerprint is part of the HMAC input when enabled.
	host := stripPort(r.Host)
	cookieName := challengeCookieName(host)
	bindJA4 := true  // default
	ttl := time.Hour // default
	bindIP := true   // default
	pe.mu.RLock()
	for _, cr := range pe.rules {
		if cr.rule.Type == "challenge" && cr.challengeConfig != nil {
			if cr.challengeConfig.cookieName == cookieName {
				bindJA4 = cr.challengeConfig.bindJA4
				ttl = cr.challengeConfig.ttl
				bindIP = cr.challengeConfig.bindIP
				break
			}
		}
	}
	pe.mu.RUnlock()

	// Verify HMAC of the challenge payload (prevents tampering).
	// When JA4 binding is enabled, the JA4 fingerprint was included in
	// the HMAC at interstitial-serve time, so we must include it here too.
	payloadStr := fmt.Sprintf("%s|%d|%d", randomData, difficulty, timestamp)
	ja4 := ""
	if bindJA4 {
		ja4 = ja4Registry.Get(r.RemoteAddr)
		if ja4 != "" {
			payloadStr += "|" + ja4
		}
	}
	mac := hmac.New(sha256.New, pe.challengeHMACKey)
	mac.Write([]byte(payloadStr))
	expectedHMAC := hex.EncodeToString(mac.Sum(nil))
	if subtle.ConstantTimeCompare([]byte(submittedHMAC), []byte(expectedHMAC)) != 1 {
		pe.logger.Info("challenge verify: HMAC mismatch",
			zap.String("client_ip", clientIP(r)),
			zap.Bool("bind_ja4", bindJA4),
			zap.String("ja4", ja4))
		caddyhttp.SetVar(r.Context(), "policy_engine.action", "challenge_failed")
		caddyhttp.SetVar(r.Context(), "policy_engine.challenge_fail_reason", "hmac_invalid")
		return caddyhttp.Error(http.StatusForbidden, nil)
	}

	// Recompute SHA-256(randomData + nonce) — server NEVER trusts client hash.
	calcString := fmt.Sprintf("%s%d", randomData, nonce)
	hash := sha256.Sum256([]byte(calcString))
	calculated := hex.EncodeToString(hash[:])

	// Constant-time compare with submitted hash.
	if subtle.ConstantTimeCompare([]byte(response), []byte(calculated)) != 1 {
		pe.logger.Info("challenge verify: hash mismatch",
			zap.String("client_ip", clientIP(r)),
			zap.String("expected", calculated),
			zap.String("got", response))
		caddyhttp.SetVar(r.Context(), "policy_engine.action", "challenge_failed")
		caddyhttp.SetVar(r.Context(), "policy_engine.challenge_fail_reason", "bad_pow")
		return caddyhttp.Error(http.StatusForbidden, nil)
	}

	// Verify leading zeros.
	if !strings.HasPrefix(calculated, strings.Repeat("0", difficulty)) {
		pe.logger.Info("challenge verify: insufficient leading zeros",
			zap.String("client_ip", clientIP(r)),
			zap.Int("difficulty", difficulty),
			zap.String("hash", calculated))
		caddyhttp.SetVar(r.Context(), "policy_engine.action", "challenge_failed")
		caddyhttp.SetVar(r.Context(), "policy_engine.challenge_fail_reason", "bad_pow")
		return caddyhttp.Error(http.StatusForbidden, nil)
	}

	// ── Timing validation ───────────────────────────────────────────
	// Parse elapsed_ms (client-reported solve time) and validate against
	// the expected minimum for this difficulty and core count.
	elapsedMs := -1 // negative = not submitted, skip timing checks
	if ems := r.FormValue("elapsed_ms"); ems != "" {
		if v, err := strconv.Atoi(ems); err == nil {
			elapsedMs = v
		}
	}

	// Log elapsed_ms and difficulty for analytics.
	if elapsedMs >= 0 {
		caddyhttp.SetVar(r.Context(), "policy_engine.challenge_elapsed_ms", strconv.Itoa(elapsedMs))
	}
	caddyhttp.SetVar(r.Context(), "policy_engine.challenge_difficulty", strconv.Itoa(difficulty))
	caddyhttp.SetVar(r.Context(), "policy_engine.challenge_pre_score", strconv.Itoa(preSignalScore(r)))

	// Parse core count from signals JSON for timing validation.
	// We read it here (before scoreBotSignals) so we can do the
	// hard-reject check independently of the soft scoring.
	signalCores := 1
	if signalsJSON := r.FormValue("signals"); signalsJSON != "" {
		var sigPeek struct {
			Cores int `json:"cores"`
		}
		if json.Unmarshal([]byte(signalsJSON), &sigPeek) == nil && sigPeek.Cores > 0 {
			signalCores = sigPeek.Cores
		}
	}

	// Hard reject: elapsed time below 1/3 of the floor is physically
	// impossible — indicates pre-computation or hash table lookup.
	if elapsedMs >= 0 {
		floor := minSolveMs(difficulty, signalCores)
		hardRejectFloor := floor / 3
		if hardRejectFloor > 0 && elapsedMs < hardRejectFloor {
			pe.logger.Info("challenge rejected: impossibly fast solve",
				zap.String("client_ip", clientIP(r)),
				zap.Int("elapsed_ms", elapsedMs),
				zap.Int("floor_ms", floor),
				zap.Int("hard_reject_floor_ms", hardRejectFloor),
				zap.Int("cores", signalCores),
				zap.Int("difficulty", difficulty))
			caddyhttp.SetVar(r.Context(), "policy_engine.action", "challenge_failed")
			caddyhttp.SetVar(r.Context(), "policy_engine.challenge_fail_reason", "timing_hard")
			return caddyhttp.Error(http.StatusForbidden, nil)
		}
	}

	// ── Bot signal scoring ──────────────────────────────────────────
	// Parse client-side environment probes and behavioral signals.
	// Compute a weighted bot score (0-100). High score = likely bot.
	// Timing params (elapsedMs, difficulty) feed into L6 soft penalty.
	botScore := scoreBotSignals(r.FormValue("signals"), r.FormValue("behavior"), r, pe.logger, elapsedMs, difficulty)

	caddyhttp.SetVar(r.Context(), "policy_engine.challenge_bot_score", strconv.Itoa(botScore))

	// Capture request headers for event detail (same browser session headers).
	captureRequestContext(r, nil)

	// Reject if bot score exceeds threshold (likely headless Chrome).
	if botScore >= 70 {
		pe.logger.Info("challenge rejected: high bot score",
			zap.String("client_ip", clientIP(r)),
			zap.Int("bot_score", botScore))
		caddyhttp.SetVar(r.Context(), "policy_engine.action", "challenge_failed")
		caddyhttp.SetVar(r.Context(), "policy_engine.challenge_fail_reason", "bot_score")
		return caddyhttp.Error(http.StatusForbidden, nil)
	}

	// PoW is valid + bot score acceptable — issue a signed cookie.
	// host and cookieName were computed earlier for the JA4/HMAC lookup.

	// Generate unique token ID (8 random bytes → 16 hex chars).
	jtiBytes := make([]byte, 8)
	rand.Read(jtiBytes)
	jti := hex.EncodeToString(jtiBytes)

	now := time.Now()

	// Build cookie payload.
	cp := challengeCookiePayload{
		Jti:   jti,
		Aud:   host,
		Iat:   now.Unix(),
		Exp:   now.Add(ttl).Unix(),
		Dif:   difficulty,
		Score: botScore,
	}
	if bindIP {
		cp.Sub = clientIP(r)
	}
	if bindJA4 && ja4 != "" {
		cp.Ja4 = ja4
	}

	cpJSON, _ := json.Marshal(cp)
	cpB64 := base64.RawURLEncoding.EncodeToString(cpJSON)

	// Sign.
	cookieMAC := hmac.New(sha256.New, pe.challengeHMACKey)
	cookieMAC.Write([]byte(cpB64))
	sig := base64.RawURLEncoding.EncodeToString(cookieMAC.Sum(nil))

	token := cpB64 + "." + sig

	http.SetCookie(w, &http.Cookie{
		Name:     cookieName,
		Value:    token,
		Path:     "/",
		MaxAge:   int(ttl.Seconds()),
		HttpOnly: true,
		Secure:   r.TLS != nil,
		SameSite: http.SameSiteLaxMode,
	})

	pe.logger.Info("challenge passed",
		zap.String("client_ip", clientIP(r)),
		zap.String("host", host),
		zap.Int("difficulty", difficulty),
		zap.Int("bot_score", botScore),
		zap.String("jti", jti),
		zap.String("cookie", cookieName))

	caddyhttp.SetVar(r.Context(), "policy_engine.action", "challenge_passed")
	caddyhttp.SetVar(r.Context(), "policy_engine.challenge_bot_score", strconv.Itoa(botScore))
	caddyhttp.SetVar(r.Context(), "policy_engine.challenge_jti", jti)

	// Redirect to original URL.
	redirectURL := originalURL
	if redirectURL == "" {
		redirectURL = "/"
	}
	http.Redirect(w, r, redirectURL, http.StatusFound)
	return nil
}
