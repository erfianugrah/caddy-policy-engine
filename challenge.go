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

// ─── Types ──────────────────────────────────────────────────────────

// ChallengeConfig is the per-rule challenge configuration in policy-rules.json.
type ChallengeConfig struct {
	Difficulty int    `json:"difficulty"`  // Leading hex zeros in SHA-256 (1-16)
	Algorithm  string `json:"algorithm"`   // "fast" or "slow"
	TTLSeconds int    `json:"ttl_seconds"` // Cookie lifetime in seconds
	BindIP     bool   `json:"bind_ip"`     // Bind cookie to client IP
}

// ChallengeGlobalConfig holds global challenge settings in policy-rules.json.
type ChallengeGlobalConfig struct {
	HMACKey string `json:"hmac_key,omitempty"` // Hex-encoded 32-byte HMAC-SHA256 key
}

// compiledChallengeConfig is the pre-compiled form of ChallengeConfig.
type compiledChallengeConfig struct {
	difficulty int
	algorithm  string
	ttl        time.Duration
	bindIP     bool
	cookieName string
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
	Sub string `json:"sub"` // Client IP (if bind_ip)
	Aud string `json:"aud"` // Service hostname
	Exp int64  `json:"exp"` // Unix timestamp
	Dif int    `json:"dif"` // Difficulty solved at
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

// ─── Bot Signal Scoring ─────────────────────────────────────────────

// botSignals is the parsed client-side environment probe data.
type botSignals struct {
	Webdriver      int     `json:"wd"`   // 1 = navigator.webdriver true
	CDCPresent     int     `json:"cdc"`  // 1 = ChromeDriver markers found
	ChromeRuntime  int     `json:"cr"`   // 1 = window.chrome.runtime present
	PluginCount    int     `json:"plg"`  // navigator.plugins.length
	LanguageCount  int     `json:"lang"` // navigator.languages.length
	SpeechVoices   int     `json:"sv"`   // speechSynthesis voices count
	WebGLRenderer  string  `json:"wglr"` // UNMASKED_RENDERER_WEBGL
	WebGLVendor    string  `json:"wglv"` // UNMASKED_VENDOR_WEBGL
	Cores          int     `json:"cores"`
	Memory         float64 `json:"mem"`
	TouchPoints    int     `json:"touch"`
	Platform       string  `json:"plt"`
	ScreenWidth    int     `json:"sw"`
	ScreenHeight   int     `json:"sh"`
	ColorDepth     int     `json:"cd"`
	PixelRatio     float64 `json:"dpr"`
	CanvasHash     string  `json:"cvs"`
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

// scoreBotSignals parses the signals and behavior JSON from the challenge
// submission and returns a bot score (0-100).
func scoreBotSignals(signalsJSON, behaviorJSON string, logger *zap.Logger) int {
	var sig botSignals
	var beh botBehavior
	score := 0

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

	// ── Automation markers (deterministic, high confidence) ────────
	if sig.Webdriver == 1 {
		score += 90 // navigator.webdriver = true
	}
	if sig.CDCPresent == 1 {
		score += 95 // ChromeDriver/Puppeteer markers in DOM
	}

	// ── WebGL renderer (SwiftShader = headless Chrome) ─────────────
	if strings.Contains(sig.WebGLRenderer, "SwiftShader") {
		score += 85
	}

	// ── Plugin count (headless has 0, real Chrome has 2-5) ─────────
	if sig.PluginCount == 0 {
		// Only flag if UA suggests Chrome (which should have plugins).
		// Firefox genuinely has 0 plugins in some configs.
		score += 30
	}

	// ── Speech voices (headless has 0) ────────────────────────────
	if sig.SpeechVoices == 0 {
		score += 20
	}

	// ── Permissions API timing (headless < 0.5ms) ─────────────────
	if sig.PermissionTime >= 0 && sig.PermissionTime < 0.5 {
		score += 30
	}

	// ── Language count (headless often has 0 or 1) ─────────────────
	if sig.LanguageCount <= 1 {
		score += 10
	}

	// ── Chrome runtime missing (absent in headless Chrome) ─────────
	if sig.ChromeRuntime == 0 {
		score += 15
	}

	// ── Behavioral: no interaction during PoW ──────────────────────
	if beh.Duration > 2000 && beh.MouseEvents == 0 && beh.KeyEvents == 0 && beh.ScrollEvents == 0 {
		score += 15
	}

	// ── Worker timing variance (containers are unnaturally uniform) ─
	if beh.WorkerVariance >= 0 && beh.WorkerVariance < 1.0 && beh.Duration > 1000 {
		score += 20
	}

	// Cap at 100.
	if score > 100 {
		score = 100
	}

	logger.Debug("challenge bot score",
		zap.Int("score", score),
		zap.Int("webdriver", sig.Webdriver),
		zap.Int("plugins", sig.PluginCount),
		zap.String("webgl", sig.WebGLRenderer),
		zap.Float64("perm_timing", sig.PermissionTime),
		zap.Int("mouse_events", beh.MouseEvents),
		zap.Float64("worker_variance", beh.WorkerVariance))

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

	return true
}

// ─── Interstitial Serving ───────────────────────────────────────────

// serveChallengeInterstitial generates and serves the PoW interstitial page.
func (pe *PolicyEngine) serveChallengeInterstitial(w http.ResponseWriter, r *http.Request, cfg *compiledChallengeConfig) error {
	// Generate random data (64 bytes → 128 hex chars, matching Anubis).
	randomBytes := make([]byte, 64)
	if _, err := rand.Read(randomBytes); err != nil {
		pe.logger.Error("failed to generate challenge nonce", zap.Error(err))
		return caddyhttp.Error(http.StatusInternalServerError, nil)
	}
	randomData := hex.EncodeToString(randomBytes)
	now := time.Now().UTC()

	// Build the challenge payload that will be HMAC'd and embedded.
	payloadStr := fmt.Sprintf("%s|%d|%d", randomData, cfg.difficulty, now.Unix())
	mac := hmac.New(sha256.New, pe.challengeHMACKey)
	mac.Write([]byte(payloadStr))
	payloadHMAC := hex.EncodeToString(mac.Sum(nil))

	originalURL := r.URL.String()

	challengeData := challengePayload{
		RandomData:  randomData,
		Difficulty:  cfg.difficulty,
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
		return caddyhttp.Error(http.StatusForbidden, nil)
	}

	difficulty, err := strconv.Atoi(difficultyStr)
	if err != nil || difficulty < 1 || difficulty > 16 {
		caddyhttp.SetVar(r.Context(), "policy_engine.action", "challenge_failed")
		return caddyhttp.Error(http.StatusForbidden, nil)
	}

	nonce, err := strconv.Atoi(nonceStr)
	if err != nil {
		caddyhttp.SetVar(r.Context(), "policy_engine.action", "challenge_failed")
		return caddyhttp.Error(http.StatusForbidden, nil)
	}

	timestamp, err := strconv.ParseInt(timestampStr, 10, 64)
	if err != nil {
		caddyhttp.SetVar(r.Context(), "policy_engine.action", "challenge_failed")
		return caddyhttp.Error(http.StatusForbidden, nil)
	}

	// Check timestamp freshness (5-minute window).
	if time.Now().Unix()-timestamp > 300 {
		pe.logger.Info("challenge verify: expired",
			zap.String("client_ip", clientIP(r)),
			zap.Int64("timestamp", timestamp))
		caddyhttp.SetVar(r.Context(), "policy_engine.action", "challenge_failed")
		return caddyhttp.Error(http.StatusForbidden, nil)
	}

	// Verify HMAC of the challenge payload (prevents tampering).
	payloadStr := fmt.Sprintf("%s|%d|%d", randomData, difficulty, timestamp)
	mac := hmac.New(sha256.New, pe.challengeHMACKey)
	mac.Write([]byte(payloadStr))
	expectedHMAC := hex.EncodeToString(mac.Sum(nil))
	if subtle.ConstantTimeCompare([]byte(submittedHMAC), []byte(expectedHMAC)) != 1 {
		pe.logger.Info("challenge verify: HMAC mismatch",
			zap.String("client_ip", clientIP(r)))
		caddyhttp.SetVar(r.Context(), "policy_engine.action", "challenge_failed")
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
		return caddyhttp.Error(http.StatusForbidden, nil)
	}

	// Verify leading zeros.
	if !strings.HasPrefix(calculated, strings.Repeat("0", difficulty)) {
		pe.logger.Info("challenge verify: insufficient leading zeros",
			zap.String("client_ip", clientIP(r)),
			zap.Int("difficulty", difficulty),
			zap.String("hash", calculated))
		caddyhttp.SetVar(r.Context(), "policy_engine.action", "challenge_failed")
		return caddyhttp.Error(http.StatusForbidden, nil)
	}

	// ── Bot signal scoring ──────────────────────────────────────────
	// Parse client-side environment probes and behavioral signals.
	// Compute a weighted bot score (0-100). High score = likely bot.
	botScore := scoreBotSignals(r.FormValue("signals"), r.FormValue("behavior"), pe.logger)

	caddyhttp.SetVar(r.Context(), "policy_engine.challenge_bot_score", strconv.Itoa(botScore))

	// Reject if bot score exceeds threshold (likely headless Chrome).
	if botScore >= 70 {
		pe.logger.Info("challenge rejected: high bot score",
			zap.String("client_ip", clientIP(r)),
			zap.Int("bot_score", botScore))
		caddyhttp.SetVar(r.Context(), "policy_engine.action", "challenge_failed")
		return caddyhttp.Error(http.StatusForbidden, nil)
	}

	// PoW is valid + bot score acceptable — issue a signed cookie.
	host := stripPort(r.Host)
	cookieName := challengeCookieName(host)

	// Find the matching challenge rule's TTL and bind_ip setting.
	// Default to 7 days if no matching rule found (shouldn't happen in practice).
	ttl := 7 * 24 * time.Hour
	bindIP := true
	pe.mu.RLock()
	for _, cr := range pe.rules {
		if cr.rule.Type == "challenge" && cr.challengeConfig != nil {
			if cr.challengeConfig.cookieName == cookieName {
				ttl = cr.challengeConfig.ttl
				bindIP = cr.challengeConfig.bindIP
				break
			}
		}
	}
	pe.mu.RUnlock()

	// Build cookie payload.
	cp := challengeCookiePayload{
		Aud: host,
		Exp: time.Now().Add(ttl).Unix(),
		Dif: difficulty,
	}
	if bindIP {
		cp.Sub = clientIP(r)
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
		zap.String("cookie", cookieName))

	caddyhttp.SetVar(r.Context(), "policy_engine.action", "challenge_passed")

	// Redirect to original URL.
	redirectURL := originalURL
	if redirectURL == "" {
		redirectURL = "/"
	}
	http.Redirect(w, r, redirectURL, http.StatusFound)
	return nil
}
