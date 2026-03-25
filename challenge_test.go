package policyengine

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"go.uber.org/zap"
)

// ─── Cookie Name ────────────────────────────────────────────────────

func TestChallengeCookieName(t *testing.T) {
	name := challengeCookieName("httpbun.erfi.io")
	if !strings.HasPrefix(name, "__pc_") {
		t.Errorf("cookie name %q should start with __pc_", name)
	}
	if len(name) != 13 { // __pc_ + 8 hex chars
		t.Errorf("cookie name %q length = %d, want 13", name, len(name))
	}

	// Same input → same output (deterministic).
	name2 := challengeCookieName("httpbun.erfi.io")
	if name != name2 {
		t.Errorf("non-deterministic: %q != %q", name, name2)
	}

	// Different input → different output.
	name3 := challengeCookieName("vault.erfi.io")
	if name == name3 {
		t.Errorf("different services should produce different names: %q == %q", name, name3)
	}
}

// ─── Cookie Signing Round-Trip ──────────────────────────────────────

func TestChallengeCookieRoundTrip(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}

	pe := &PolicyEngine{challengeHMACKey: key}

	// Build a valid cookie manually.
	host := "httpbun.erfi.io"
	cookieName := challengeCookieName(host)
	payload := challengeCookiePayload{
		Sub: "192.168.1.100", // clientIP() strips the port
		Aud: host,
		Exp: time.Now().Add(time.Hour).Unix(),
		Dif: 4,
	}
	cpJSON, _ := json.Marshal(payload)
	cpB64 := base64.RawURLEncoding.EncodeToString(cpJSON)

	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(cpB64))
	sig := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))

	token := cpB64 + "." + sig

	// Build a request with the cookie.
	r := makeRequest("GET", "https://httpbun.erfi.io/test", "192.168.1.100:12345")
	r.Host = host
	r.AddCookie(&http.Cookie{Name: cookieName, Value: token})

	if !pe.validateChallengeCookie(r) {
		t.Error("expected valid cookie to pass validation")
	}
}

func TestChallengeCookieExpired(t *testing.T) {
	key := make([]byte, 32)
	pe := &PolicyEngine{challengeHMACKey: key}

	host := "httpbun.erfi.io"
	cookieName := challengeCookieName(host)
	payload := challengeCookiePayload{
		Aud: host,
		Exp: time.Now().Add(-time.Hour).Unix(), // expired
		Dif: 4,
	}
	cpJSON, _ := json.Marshal(payload)
	cpB64 := base64.RawURLEncoding.EncodeToString(cpJSON)

	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(cpB64))
	sig := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))

	r := makeRequest("GET", "https://httpbun.erfi.io/test", "1.2.3.4:5678")
	r.Host = host
	r.AddCookie(&http.Cookie{Name: cookieName, Value: cpB64 + "." + sig})

	if pe.validateChallengeCookie(r) {
		t.Error("expired cookie should fail validation")
	}
}

func TestChallengeCookieWrongHost(t *testing.T) {
	key := make([]byte, 32)
	pe := &PolicyEngine{challengeHMACKey: key}

	payload := challengeCookiePayload{
		Aud: "vault.erfi.io",
		Exp: time.Now().Add(time.Hour).Unix(),
		Dif: 4,
	}
	cpJSON, _ := json.Marshal(payload)
	cpB64 := base64.RawURLEncoding.EncodeToString(cpJSON)

	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(cpB64))
	sig := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))

	// Request is for httpbun, but cookie was issued for vault.
	host := "httpbun.erfi.io"
	cookieName := challengeCookieName(host) // wrong cookie name — won't even find it
	r := makeRequest("GET", "https://httpbun.erfi.io/test", "1.2.3.4:5678")
	r.Host = host
	r.AddCookie(&http.Cookie{Name: cookieName, Value: cpB64 + "." + sig})

	if pe.validateChallengeCookie(r) {
		t.Error("cookie for different host should fail validation")
	}
}

func TestChallengeCookieIPBinding(t *testing.T) {
	key := make([]byte, 32)
	pe := &PolicyEngine{challengeHMACKey: key}

	host := "httpbun.erfi.io"
	cookieName := challengeCookieName(host)
	payload := challengeCookiePayload{
		Sub: "192.168.1.100:12345", // bound to this IP
		Aud: host,
		Exp: time.Now().Add(time.Hour).Unix(),
		Dif: 4,
	}
	cpJSON, _ := json.Marshal(payload)
	cpB64 := base64.RawURLEncoding.EncodeToString(cpJSON)

	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(cpB64))
	sig := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))

	// Request from a different IP.
	r := makeRequest("GET", "https://httpbun.erfi.io/test", "10.0.0.1:9999")
	r.Host = host
	r.AddCookie(&http.Cookie{Name: cookieName, Value: cpB64 + "." + sig})

	if pe.validateChallengeCookie(r) {
		t.Error("cookie with different IP binding should fail validation")
	}
}

func TestChallengeCookieTampered(t *testing.T) {
	key := make([]byte, 32)
	pe := &PolicyEngine{challengeHMACKey: key}

	host := "httpbun.erfi.io"
	cookieName := challengeCookieName(host)
	payload := challengeCookiePayload{
		Aud: host,
		Exp: time.Now().Add(time.Hour).Unix(),
		Dif: 4,
	}
	cpJSON, _ := json.Marshal(payload)
	cpB64 := base64.RawURLEncoding.EncodeToString(cpJSON)

	// Wrong signature.
	r := makeRequest("GET", "https://httpbun.erfi.io/test", "1.2.3.4:5678")
	r.Host = host
	r.AddCookie(&http.Cookie{Name: cookieName, Value: cpB64 + ".dGFtcGVyZWQ"})

	if pe.validateChallengeCookie(r) {
		t.Error("tampered cookie should fail validation")
	}
}

// ─── PoW Verification ───────────────────────────────────────────────

func TestPoWVerification(t *testing.T) {
	// Find a valid nonce for difficulty 1 (just 1 leading hex zero).
	randomData := "aabbccdd"
	difficulty := 1

	var nonce int
	var hash string
	for i := 0; i < 1000000; i++ {
		calcString := fmt.Sprintf("%s%d", randomData, i)
		h := sha256.Sum256([]byte(calcString))
		hash = hex.EncodeToString(h[:])
		if strings.HasPrefix(hash, strings.Repeat("0", difficulty)) {
			nonce = i
			break
		}
	}

	// Verify the algorithm matches what the server would check.
	calcString := fmt.Sprintf("%s%d", randomData, nonce)
	h := sha256.Sum256([]byte(calcString))
	calculated := hex.EncodeToString(h[:])

	if calculated != hash {
		t.Fatalf("hash mismatch: %s != %s", calculated, hash)
	}
	if !strings.HasPrefix(calculated, "0") {
		t.Fatalf("hash %s doesn't have leading zero", calculated)
	}
}

// ─── Interstitial Serving ───────────────────────────────────────────

func TestServeChallengeInterstitial(t *testing.T) {
	key := make([]byte, 32)
	pe := &PolicyEngine{
		challengeHMACKey: key,
		logger:           zap.NewNop(),
	}

	cfg := &compiledChallengeConfig{
		difficulty: 4,
		algorithm:  "fast",
		ttl:        7 * 24 * time.Hour,
		bindIP:     true,
		cookieName: "__pc_test1234",
	}

	r := makeRequest("GET", "https://httpbun.erfi.io/page", "1.2.3.4:5678")
	w := httptest.NewRecorder()

	err := pe.serveChallengeInterstitial(w, r, cfg)
	if err != nil {
		t.Fatalf("serveChallengeInterstitial returned error: %v", err)
	}

	resp := w.Result()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want 200", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); !strings.Contains(ct, "text/html") {
		t.Errorf("Content-Type = %q, want text/html", ct)
	}
	if cc := resp.Header.Get("Cache-Control"); !strings.Contains(cc, "no-store") {
		t.Errorf("Cache-Control = %q, want no-store", cc)
	}

	body := w.Body.String()
	if !strings.Contains(body, "Verifying your connection") {
		t.Error("body should contain 'Verifying your connection'")
	}
	if !strings.Contains(body, "random_data") {
		t.Error("body should contain challenge data with random_data")
	}
	if !strings.Contains(body, "/.well-known/policy-challenge/worker.js") {
		t.Error("body should contain worker.js URL for Web Workers")
	}
}

// ─── JA4 Token Binding ──────────────────────────────────────────────

func TestChallengeCookieJA4Binding(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	pe := &PolicyEngine{challengeHMACKey: key}

	host := "httpbun.erfi.io"
	cookieName := challengeCookieName(host)

	// Build a cookie with JA4 binding.
	payload := challengeCookiePayload{
		Aud: host,
		Exp: time.Now().Add(time.Hour).Unix(),
		Dif: 4,
		Ja4: "t13d1516h2_8daaf6152771_e5627efa2ab1", // bound to this JA4
	}
	cpJSON, _ := json.Marshal(payload)
	cpB64 := base64.RawURLEncoding.EncodeToString(cpJSON)
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(cpB64))
	sig := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))

	t.Run("matching_ja4", func(t *testing.T) {
		// Set JA4 for this connection.
		ja4Registry.Set("1.2.3.4:5678", "t13d1516h2_8daaf6152771_e5627efa2ab1")
		defer ja4Registry.Delete("1.2.3.4:5678")

		r := makeRequest("GET", "https://httpbun.erfi.io/test", "1.2.3.4:5678")
		r.Host = host
		r.AddCookie(&http.Cookie{Name: cookieName, Value: cpB64 + "." + sig})

		if !pe.validateChallengeCookie(r) {
			t.Error("cookie with matching JA4 should pass validation")
		}
	})

	t.Run("mismatched_ja4", func(t *testing.T) {
		// Set a different JA4 for this connection (different TLS stack).
		ja4Registry.Set("10.0.0.1:9999", "t12d0907h1_abcdef123456_000000000000")
		defer ja4Registry.Delete("10.0.0.1:9999")

		r := makeRequest("GET", "https://httpbun.erfi.io/test", "10.0.0.1:9999")
		r.Host = host
		r.AddCookie(&http.Cookie{Name: cookieName, Value: cpB64 + "." + sig})

		if pe.validateChallengeCookie(r) {
			t.Error("cookie with mismatched JA4 should fail validation")
		}
	})

	t.Run("no_ja4_in_registry", func(t *testing.T) {
		// No JA4 registered for this connection (e.g., non-TLS or internal).
		r := makeRequest("GET", "https://httpbun.erfi.io/test", "10.0.0.2:1234")
		r.Host = host
		r.AddCookie(&http.Cookie{Name: cookieName, Value: cpB64 + "." + sig})

		if pe.validateChallengeCookie(r) {
			t.Error("cookie with JA4 binding but no current JA4 should fail validation")
		}
	})
}

func TestChallengeCookieNoJA4Binding(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	pe := &PolicyEngine{challengeHMACKey: key}

	host := "httpbun.erfi.io"
	cookieName := challengeCookieName(host)

	// Build a cookie without JA4 binding (Ja4 field empty).
	payload := challengeCookiePayload{
		Aud: host,
		Exp: time.Now().Add(time.Hour).Unix(),
		Dif: 4,
		// Ja4 intentionally omitted — bind_ja4 was false at issuance.
	}
	cpJSON, _ := json.Marshal(payload)
	cpB64 := base64.RawURLEncoding.EncodeToString(cpJSON)
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(cpB64))
	sig := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))

	// Should validate regardless of current JA4.
	ja4Registry.Set("1.2.3.4:5678", "t13d1516h2_anything_anything")
	defer ja4Registry.Delete("1.2.3.4:5678")

	r := makeRequest("GET", "https://httpbun.erfi.io/test", "1.2.3.4:5678")
	r.Host = host
	r.AddCookie(&http.Cookie{Name: cookieName, Value: cpB64 + "." + sig})

	if !pe.validateChallengeCookie(r) {
		t.Error("cookie without JA4 binding should pass regardless of current JA4")
	}
}

func TestCompileChallengeRuleBindJA4(t *testing.T) {
	rule := PolicyRule{
		ID:   "c-ja4",
		Name: "Challenge with JA4 binding",
		Type: "challenge",
		Conditions: []PolicyCondition{
			{Field: "path", Operator: "eq", Value: "/"},
		},
		GroupOp: "and",
		Enabled: true,
		Challenge: &ChallengeConfig{
			Difficulty: 4,
			Algorithm:  "fast",
			TTLSeconds: 3600,
			BindIP:     true,
			BindJA4:    true,
		},
		Priority: 150,
	}

	cr, err := compileRule(rule)
	if err != nil {
		t.Fatalf("compileRule failed: %v", err)
	}
	if !cr.challengeConfig.bindJA4 {
		t.Error("bindJA4 = false, want true")
	}

	// Without BindJA4.
	rule.Challenge.BindJA4 = false
	cr, err = compileRule(rule)
	if err != nil {
		t.Fatalf("compileRule failed: %v", err)
	}
	if cr.challengeConfig.bindJA4 {
		t.Error("bindJA4 = true, want false")
	}
}

// ─── Compile Rule ───────────────────────────────────────────────────

func TestCompileChallengeRule(t *testing.T) {
	rule := PolicyRule{
		ID:   "c1",
		Name: "Challenge Browsers",
		Type: "challenge",
		Conditions: []PolicyCondition{
			{Field: "user_agent", Operator: "contains", Value: "Mozilla"},
		},
		GroupOp: "and",
		Enabled: true,
		Challenge: &ChallengeConfig{
			Difficulty: 4,
			Algorithm:  "fast",
			TTLSeconds: 86400,
			BindIP:     true,
		},
		Service:  "httpbun.erfi.io",
		Priority: 150,
	}

	cr, err := compileRule(rule)
	if err != nil {
		t.Fatalf("compileRule failed: %v", err)
	}

	if cr.challengeConfig == nil {
		t.Fatal("challengeConfig is nil")
	}
	if cr.challengeConfig.difficulty != 4 {
		t.Errorf("difficulty = %d, want 4", cr.challengeConfig.difficulty)
	}
	if cr.challengeConfig.algorithm != "fast" {
		t.Errorf("algorithm = %q, want fast", cr.challengeConfig.algorithm)
	}
	if cr.challengeConfig.ttl != 24*time.Hour {
		t.Errorf("ttl = %v, want 24h", cr.challengeConfig.ttl)
	}
	if !cr.challengeConfig.bindIP {
		t.Error("bindIP = false, want true")
	}
	if !strings.HasPrefix(cr.challengeConfig.cookieName, "__pc_") {
		t.Errorf("cookieName = %q, missing __pc_ prefix", cr.challengeConfig.cookieName)
	}
}

func TestCompileChallengeRuleDefaults(t *testing.T) {
	rule := PolicyRule{
		ID:   "c2",
		Name: "Challenge Default",
		Type: "challenge",
		Conditions: []PolicyCondition{
			{Field: "path", Operator: "eq", Value: "/"},
		},
		GroupOp:   "and",
		Enabled:   true,
		Challenge: &ChallengeConfig{
			// All zero values — should get defaults.
		},
		Priority: 150,
	}

	cr, err := compileRule(rule)
	if err != nil {
		t.Fatalf("compileRule failed: %v", err)
	}

	if cr.challengeConfig.difficulty != 4 {
		t.Errorf("default difficulty = %d, want 4", cr.challengeConfig.difficulty)
	}
	if cr.challengeConfig.algorithm != "fast" {
		t.Errorf("default algorithm = %q, want fast", cr.challengeConfig.algorithm)
	}
	if cr.challengeConfig.ttl != time.Hour {
		t.Errorf("default ttl = %v, want 1h", cr.challengeConfig.ttl)
	}
}

func TestCompileChallengeRuleNoConfig(t *testing.T) {
	rule := PolicyRule{
		ID:   "c3",
		Name: "No Config",
		Type: "challenge",
		Conditions: []PolicyCondition{
			{Field: "path", Operator: "eq", Value: "/"},
		},
		GroupOp:  "and",
		Enabled:  true,
		Priority: 150,
		// Challenge is nil.
	}

	_, err := compileRule(rule)
	if err == nil {
		t.Error("expected error for challenge rule without config")
	}
}

func TestCompileChallengeRuleNoConditions(t *testing.T) {
	rule := PolicyRule{
		ID:       "c4",
		Name:     "No Conditions",
		Type:     "challenge",
		GroupOp:  "and",
		Enabled:  true,
		Priority: 150,
		Challenge: &ChallengeConfig{
			Difficulty: 4,
		},
	}

	_, err := compileRule(rule)
	if err == nil {
		t.Error("expected error for challenge rule without conditions")
	}
}

// ─── Worker JS Serving ──────────────────────────────────────────────

func TestServeChallengeWorkerJS(t *testing.T) {
	pe := &PolicyEngine{
		challengeEnabled: true,
		logger:           zap.NewNop(),
	}

	r := makeRequest("GET", "/.well-known/policy-challenge/worker.js", "1.2.3.4:5678")
	w := httptest.NewRecorder()

	err := pe.serveChallengeWorkerJS(w, r)
	if err != nil {
		t.Fatalf("serveChallengeWorkerJS returned error: %v", err)
	}

	resp := w.Result()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want 200", resp.StatusCode)
	}
	ct := resp.Header.Get("Content-Type")
	if !strings.Contains(ct, "application/javascript") {
		t.Errorf("Content-Type = %q, want application/javascript", ct)
	}
	cc := resp.Header.Get("Cache-Control")
	if !strings.Contains(cc, "public") || !strings.Contains(cc, "max-age=86400") {
		t.Errorf("Cache-Control = %q, want public, max-age=86400", cc)
	}

	body := w.Body.String()
	if !strings.Contains(body, "addEventListener") {
		t.Error("worker JS missing addEventListener")
	}
	if !strings.Contains(body, "crypto.subtle.digest") {
		t.Error("worker JS missing WebCrypto digest call")
	}
	if !strings.Contains(body, "sha256Fallback") {
		t.Error("worker JS missing pure-JS fallback")
	}
}

// ─── Bot Signal Scoring ─────────────────────────────────────────────

func TestScoreBotSignals_RealBrowser(t *testing.T) {
	signals := `{"wd":0,"cdc":0,"cr":1,"plg":5,"lang":3,"sv":22,"wglr":"ANGLE (Intel, Intel(R) Iris(R) Xe Graphics)","cores":8,"mem":8,"touch":0,"plt":"Win32","sw":1920,"sh":1080,"pt":12.5,"wglMaxTex":16384,"audioHash":-12345}`
	behavior := `{"me":15,"ke":0,"fc":1,"se":2,"fi":850,"wtv":8.3,"dur":3000}`

	// Real browser request with proper headers.
	r := makeRequestWithHeaders("POST", "/.well-known/policy-challenge/verify", "1.2.3.4:5678", map[string]string{
		"User-Agent":      "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36",
		"Sec-Fetch-Site":  "same-origin",
		"Sec-Fetch-Mode":  "navigate",
		"Accept-Language": "en-US,en;q=0.9",
		"Sec-CH-UA":       `"Chromium";v="120", "Google Chrome";v="120"`,
	})
	score := scoreBotSignals(signals, behavior, r, zap.NewNop(), -1, 0)
	if score > 30 {
		t.Errorf("real browser score = %d, want <= 30", score)
	}
}

func TestScoreBotSignals_HeadlessChrome(t *testing.T) {
	signals := `{"wd":1,"cdc":0,"cr":0,"plg":0,"lang":1,"sv":0,"wglr":"Google SwiftShader","cores":2,"mem":0,"touch":0,"plt":"Linux x86_64","sw":800,"sh":600,"pt":0.1}`
	behavior := `{"me":0,"ke":0,"fc":0,"se":0,"fi":-1,"wtv":0.3,"dur":5000}`

	score := scoreBotSignals(signals, behavior, makeRequest("POST", "/.well-known/policy-challenge/verify", "1.2.3.4:5678"), zap.NewNop(), -1, 0)
	if score < 70 {
		t.Errorf("headless Chrome score = %d, want >= 70", score)
	}
}

func TestScoreBotSignals_Puppeteer(t *testing.T) {
	signals := `{"wd":0,"cdc":1,"cr":0,"plg":0,"lang":1,"sv":0,"wglr":"Google SwiftShader","cores":4,"mem":0,"touch":0,"plt":"Linux x86_64","sw":1280,"sh":720,"pt":0.05}`
	behavior := `{"me":0,"ke":0,"fc":0,"se":0,"fi":-1,"wtv":0.3,"dur":2000}`

	score := scoreBotSignals(signals, behavior, makeRequest("POST", "/.well-known/policy-challenge/verify", "1.2.3.4:5678"), zap.NewNop(), -1, 0)
	if score < 70 {
		t.Errorf("Puppeteer score = %d, want >= 70 (cdc + SwiftShader + 0 plugins)", score)
	}
}

func TestScoreBotSignals_EmptySignals(t *testing.T) {
	score := scoreBotSignals("", "", makeRequest("POST", "/.well-known/policy-challenge/verify", "1.2.3.4:5678"), zap.NewNop(), -1, 0)
	if score != 0 {
		t.Errorf("empty signals score = %d, want 0 (fail open)", score)
	}
}

func TestScoreBotSignals_MalformedJSON(t *testing.T) {
	score := scoreBotSignals("{invalid", "", makeRequest("POST", "/.well-known/policy-challenge/verify", "1.2.3.4:5678"), zap.NewNop(), -1, 0)
	if score != 0 {
		t.Errorf("malformed JSON score = %d, want 0 (fail open)", score)
	}
}

// ─── Verify Endpoint ────────────────────────────────────────────────

func TestHandleChallengeVerifyValid(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}

	pe := &PolicyEngine{
		challengeHMACKey: key,
		challengeEnabled: true,
		logger:           zap.NewNop(),
		mu:               &sync.RWMutex{},
		rules: []compiledRule{
			{
				rule: PolicyRule{Type: "challenge", Enabled: true},
				challengeConfig: &compiledChallengeConfig{
					difficulty: 1,
					algorithm:  "fast",
					ttl:        time.Hour,
					bindIP:     false,
					cookieName: challengeCookieName("httpbun.erfi.io"),
				},
			},
		},
	}

	// Find a valid PoW solution.
	randomData := "aabbccddeeff00112233445566778899"
	difficulty := 1
	now := time.Now().Unix()

	var nonce int
	var hash string
	for i := 0; i < 1000000; i++ {
		calcString := fmt.Sprintf("%s%d", randomData, i)
		h := sha256.Sum256([]byte(calcString))
		hash = hex.EncodeToString(h[:])
		if strings.HasPrefix(hash, "0") {
			nonce = i
			break
		}
	}

	// Compute HMAC of the payload.
	payloadStr := fmt.Sprintf("%s|%d|%d", randomData, difficulty, now)
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(payloadStr))
	payloadHMAC := hex.EncodeToString(mac.Sum(nil))

	// Build the POST form.
	form := url.Values{}
	form.Set("random_data", randomData)
	form.Set("nonce", fmt.Sprintf("%d", nonce))
	form.Set("response", hash)
	form.Set("hmac", payloadHMAC)
	form.Set("difficulty", "1")
	form.Set("timestamp", fmt.Sprintf("%d", now))
	form.Set("original_url", "/page")

	r := httptest.NewRequest("POST", "/.well-known/policy-challenge/verify", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.Host = "httpbun.erfi.io"
	r.RemoteAddr = "1.2.3.4:5678"
	// Set Caddy vars context.
	r = r.WithContext(makeRequest("POST", "/.well-known/policy-challenge/verify", "1.2.3.4:5678").Context())

	w := httptest.NewRecorder()
	err := pe.handleChallengeVerify(w, r)

	if err != nil {
		t.Fatalf("handleChallengeVerify returned error: %v", err)
	}

	resp := w.Result()
	// Verify endpoint now returns 200 JSON (not 302) so the browser
	// processes Set-Cookie before the JS-initiated redirect.
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want 200", resp.StatusCode)
	}

	// Should have set a cookie.
	cookies := resp.Cookies()
	var found bool
	for _, c := range cookies {
		if strings.HasPrefix(c.Name, "__pc_") {
			found = true
			if c.MaxAge <= 0 {
				t.Errorf("cookie MaxAge = %d, want > 0", c.MaxAge)
			}
			if !c.HttpOnly {
				t.Error("cookie should be HttpOnly")
			}
		}
	}
	if !found {
		t.Error("no challenge cookie found in response")
	}

	// Should have JSON body with redirect URL.
	var body struct {
		Redirect string `json:"redirect"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("failed to decode JSON body: %v", err)
	}
	if body.Redirect != "/page" {
		t.Errorf("redirect = %q, want /page", body.Redirect)
	}
}

// ─── Timing Validation ──────────────────────────────────────────────

func TestMinSolveMs(t *testing.T) {
	tests := []struct {
		name       string
		difficulty int
		cores      int
		wantMin    int // minimum expected value (inclusive)
		wantMax    int // maximum expected value (inclusive)
	}{
		{"diff1_1core", 1, 1, 0, 2},                        // 16 / (1*50) * 0.3 ≈ 0.096
		{"diff4_1core", 4, 1, 300, 500},                    // 65536 / 50 * 0.3 ≈ 393
		{"diff4_8cores", 4, 8, 30, 70},                     // 65536 / 400 * 0.3 ≈ 49
		{"diff4_16cores", 4, 16, 15, 35},                   // 65536 / 800 * 0.3 ≈ 24
		{"diff6_8cores", 6, 8, 10000, 15000},               // 16M / 400 * 0.3 ≈ 12288
		{"diff1_256cores", 1, 256, 0, 1},                   // tiny
		{"clamp_0cores", 4, 0, 300, 500},                   // clamped to 1
		{"clamp_negative_cores", 4, -5, 300, 500},          // clamped to 1
		{"clamp_huge_cores", 4, 999, 1, 5},                 // clamped to 256
		{"clamp_low_difficulty", 0, 8, 0, 2},               // clamped to 1
		{"clamp_high_difficulty", 20, 8, 1000000, 1 << 62}, // clamped to 16 — very large value
		{"diff8_4cores", 8, 4, 6000000, 7000000},           // 4B / 200 * 0.3 ≈ 6.4M ms
		{"diff2_4cores", 2, 4, 0, 2},                       // 256 / 200 * 0.3 ≈ 0.38
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := minSolveMs(tc.difficulty, tc.cores)
			if got < tc.wantMin || got > tc.wantMax {
				t.Errorf("minSolveMs(%d, %d) = %d, want [%d, %d]",
					tc.difficulty, tc.cores, got, tc.wantMin, tc.wantMax)
			}
		})
	}
}

func TestMinSolveMs_Monotonic(t *testing.T) {
	// Higher difficulty should always produce >= solve time for same cores.
	cores := 8
	prev := 0
	for diff := 1; diff <= 10; diff++ {
		ms := minSolveMs(diff, cores)
		if ms < prev {
			t.Errorf("minSolveMs(%d, %d) = %d < minSolveMs(%d, %d) = %d — not monotonic",
				diff, cores, ms, diff-1, cores, prev)
		}
		prev = ms
	}
}

func TestScoreBotSignals_TimingPenalty(t *testing.T) {
	// Real browser signals (low base score) but suspiciously fast solve.
	signals := `{"wd":0,"cdc":0,"cr":1,"plg":5,"lang":3,"sv":22,"wglr":"ANGLE (Intel, Intel(R) Iris(R) Xe Graphics)","cores":8,"mem":8,"touch":0,"plt":"Win32","sw":1920,"sh":1080,"pt":12.5,"wglMaxTex":16384,"audioHash":-12345}`
	behavior := `{"me":15,"ke":0,"fc":1,"se":2,"fi":850,"wtv":8.3,"dur":3000}`

	r := makeRequestWithHeaders("POST", "/.well-known/policy-challenge/verify", "1.2.3.4:5678", map[string]string{
		"User-Agent":      "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36",
		"Sec-Fetch-Site":  "same-origin",
		"Sec-Fetch-Mode":  "navigate",
		"Accept-Language": "en-US,en;q=0.9",
		"Sec-CH-UA":       `"Chromium";v="120", "Google Chrome";v="120"`,
	})

	// Normal timing — no penalty.
	scoreNormal := scoreBotSignals(signals, behavior, r, zap.NewNop(), 5000, 4)
	// Suspiciously fast timing — should get +40 penalty.
	scoreFast := scoreBotSignals(signals, behavior, r, zap.NewNop(), 1, 4)

	if scoreFast-scoreNormal != timingScorePenalty {
		t.Errorf("timing penalty: scoreFast=%d - scoreNormal=%d = %d, want %d",
			scoreFast, scoreNormal, scoreFast-scoreNormal, timingScorePenalty)
	}
}

func TestScoreBotSignals_TimingSkipped(t *testing.T) {
	// With elapsedMs = -1, timing scoring is skipped entirely.
	signals := `{"wd":0,"cdc":0,"cr":1,"plg":5,"lang":3,"sv":22,"wglr":"ANGLE","cores":8,"mem":8,"touch":0,"plt":"Win32","sw":1920,"sh":1080,"pt":12.5}`
	r := makeRequestWithHeaders("POST", "/verify", "1.2.3.4:5678", map[string]string{
		"User-Agent":      "Mozilla/5.0 Chrome/120.0.0.0",
		"Sec-Fetch-Site":  "same-origin",
		"Sec-Fetch-Mode":  "navigate",
		"Accept-Language": "en-US",
		"Sec-CH-UA":       `"Chrome";v="120"`,
	})

	scoreSkipped := scoreBotSignals(signals, "", r, zap.NewNop(), -1, 4)
	scoreNormal := scoreBotSignals(signals, "", r, zap.NewNop(), 50000, 4)

	if scoreSkipped != scoreNormal {
		t.Errorf("timing skipped (%d) != timing normal (%d); elapsedMs=-1 should skip timing", scoreSkipped, scoreNormal)
	}
}

func TestHandleChallengeVerifyTimingHardReject(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}

	pe := &PolicyEngine{
		challengeHMACKey: key,
		challengeEnabled: true,
		logger:           zap.NewNop(),
		mu:               &sync.RWMutex{},
		rules: []compiledRule{
			{
				rule: PolicyRule{Type: "challenge", Enabled: true},
				challengeConfig: &compiledChallengeConfig{
					difficulty: 4,
					algorithm:  "fast",
					ttl:        time.Hour,
					bindIP:     false,
					cookieName: challengeCookieName("httpbun.erfi.io"),
				},
			},
		},
	}

	// Find a valid PoW solution for difficulty 1 (quick to compute in test).
	randomData := "aabbccddeeff00112233445566778899"
	difficulty := 1
	now := time.Now().Unix()

	var nonce int
	var hash string
	for i := 0; i < 1000000; i++ {
		calcString := fmt.Sprintf("%s%d", randomData, i)
		h := sha256.Sum256([]byte(calcString))
		hash = hex.EncodeToString(h[:])
		if strings.HasPrefix(hash, "0") {
			nonce = i
			break
		}
	}

	payloadStr := fmt.Sprintf("%s|%d|%d", randomData, difficulty, now)
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(payloadStr))
	payloadHMAC := hex.EncodeToString(mac.Sum(nil))

	// Submit with difficulty=4 (but only 1 leading zero in hash — will fail
	// the leading zeros check). Use difficulty=1 to pass PoW checks, but
	// set the elapsed_ms to 1 (impossibly fast for difficulty 4).
	// Actually, for the hard-reject test we need the PoW to pass first.
	// Difficulty 1 with elapsed_ms=1 — floor for diff 1 is ~0ms, so no hard reject.
	// Instead, let's test with a higher declared difficulty.
	// The HMAC binds the difficulty, so we must use difficulty=1 in the HMAC.
	// With difficulty=1 and 16 cores, minSolveMs is ~0, so hard reject won't fire.
	// For a meaningful test, we need difficulty >= 4.

	// Re-do with difficulty 4.
	difficulty = 4
	// Find valid PoW for difficulty 4 (4 leading hex zeros).
	for i := 0; i < 100000000; i++ {
		calcString := fmt.Sprintf("%s%d", randomData, i)
		h := sha256.Sum256([]byte(calcString))
		hash = hex.EncodeToString(h[:])
		if strings.HasPrefix(hash, "0000") {
			nonce = i
			break
		}
	}

	payloadStr = fmt.Sprintf("%s|%d|%d", randomData, difficulty, now)
	mac = hmac.New(sha256.New, key)
	mac.Write([]byte(payloadStr))
	payloadHMAC = hex.EncodeToString(mac.Sum(nil))

	// Signals with 8 cores. minSolveMs(4, 8) ≈ 49ms. Hard reject floor ≈ 16ms.
	signalsJSON := `{"wd":0,"cdc":0,"cr":1,"plg":5,"lang":3,"sv":22,"wglr":"ANGLE","cores":8,"mem":8,"touch":0,"plt":"Win32","sw":1920,"sh":1080,"pt":12.5}`

	form := url.Values{}
	form.Set("random_data", randomData)
	form.Set("nonce", fmt.Sprintf("%d", nonce))
	form.Set("response", hash)
	form.Set("hmac", payloadHMAC)
	form.Set("difficulty", "4")
	form.Set("timestamp", fmt.Sprintf("%d", now))
	form.Set("original_url", "/page")
	form.Set("elapsed_ms", "1") // impossibly fast
	form.Set("signals", signalsJSON)

	r := httptest.NewRequest("POST", "/.well-known/policy-challenge/verify", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.Host = "httpbun.erfi.io"
	r.RemoteAddr = "1.2.3.4:5678"
	r = r.WithContext(makeRequest("POST", "/.well-known/policy-challenge/verify", "1.2.3.4:5678").Context())

	w := httptest.NewRecorder()
	err := pe.handleChallengeVerify(w, r)

	// Should be rejected (403) due to impossibly fast solve.
	if err == nil {
		t.Fatal("expected error for impossibly fast solve, got nil")
	}
	if !strings.Contains(err.Error(), "403") {
		t.Errorf("expected 403 error, got: %v", err)
	}
}

// ─── Adaptive Difficulty ────────────────────────────────────────────

func TestPreSignalScore_CleanRequest(t *testing.T) {
	// Real browser with proper headers and JA4.
	ja4Registry.Set("1.2.3.4:5678", "t13d1516h2_8daaf6152771_e5627efa2ab1")
	defer ja4Registry.Delete("1.2.3.4:5678")

	r := makeRequestWithHeaders("GET", "/", "1.2.3.4:5678", map[string]string{
		"User-Agent":      "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0",
		"Sec-Fetch-Site":  "none",
		"Sec-Fetch-Mode":  "navigate",
		"Accept-Language": "en-US,en;q=0.9",
		"Sec-CH-UA":       `"Chromium";v="120"`,
	})
	score := preSignalScore(r)
	if score != 0 {
		t.Errorf("clean browser preSignalScore = %d, want 0", score)
	}
}

func TestPreSignalScore_SuspiciousRequest(t *testing.T) {
	// No JA4, no Sec-Fetch, no Accept-Language — but has Chrome UA.
	r := makeRequestWithHeaders("GET", "/", "1.2.3.4:5678", map[string]string{
		"User-Agent": "Mozilla/5.0 Chrome/120.0.0.0",
	})
	score := preSignalScore(r)
	// Missing Sec-Fetch (+20) + missing Accept-Language (+10) + Chrome UA no Client Hints (+15) = 45
	if score < 40 {
		t.Errorf("suspicious preSignalScore = %d, want >= 40", score)
	}
}

func TestPreSignalScore_NonBrowserJA4(t *testing.T) {
	// JA4 with no ALPN (00) + TLS 1.2 — curl/Python-like.
	ja4Registry.Set("1.2.3.4:5678", "t12d050000_abcdef123456_000000000000")
	defer ja4Registry.Delete("1.2.3.4:5678")

	r := makeRequestWithHeaders("GET", "/", "1.2.3.4:5678", map[string]string{
		"User-Agent": "curl/8.0",
	})
	score := preSignalScore(r)
	// No ALPN (+25) + TLS 1.2 (+10) + missing Sec-Fetch (+20) + missing Accept-Language (+10) = 65
	if score < 60 {
		t.Errorf("non-browser JA4 preSignalScore = %d, want >= 60", score)
	}
}

func TestSelectDifficulty(t *testing.T) {
	tests := []struct {
		name    string
		min     int
		max     int
		headers map[string]string
		ja4     string
		wantMin int
		wantMax int
	}{
		{
			name:    "clean_request_gets_min",
			min:     2,
			max:     8,
			headers: map[string]string{"User-Agent": "Chrome/120", "Sec-Fetch-Site": "none", "Sec-Fetch-Mode": "navigate", "Accept-Language": "en", "Sec-CH-UA": `"Chrome"`},
			ja4:     "t13d1516h2_aaa_bbb",
			wantMin: 2,
			wantMax: 2,
		},
		{
			name:    "suspicious_gets_higher",
			min:     2,
			max:     8,
			headers: map[string]string{"User-Agent": "Chrome/120"}, // missing everything
			wantMin: 3,                                             // should be > min
			wantMax: 8,
		},
		{
			name:    "equal_min_max_always_returns_that",
			min:     5,
			max:     5,
			headers: map[string]string{"User-Agent": "curl/8.0"},
			wantMin: 5,
			wantMax: 5,
		},
		{
			name:    "min_greater_than_max_returns_min",
			min:     8,
			max:     3,
			headers: map[string]string{},
			wantMin: 8,
			wantMax: 8,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			addr := "1.2.3.4:5678"
			if tc.ja4 != "" {
				ja4Registry.Set(addr, tc.ja4)
				defer ja4Registry.Delete(addr)
			} else {
				ja4Registry.Delete(addr)
			}

			r := makeRequestWithHeaders("GET", "/", addr, tc.headers)
			got := selectDifficulty(r, tc.min, tc.max)
			if got < tc.wantMin || got > tc.wantMax {
				t.Errorf("selectDifficulty(%d, %d) = %d, want [%d, %d]",
					tc.min, tc.max, got, tc.wantMin, tc.wantMax)
			}
		})
	}
}

func TestSelectDifficulty_ScoreBotSignalsConsistency(t *testing.T) {
	// Verify that preSignalScore returns a subset of what scoreBotSignals
	// returns for L1/L2 signals (when there are no JS probes).
	ja4Registry.Set("10.0.0.1:1234", "t12d050000_abc_def")
	defer ja4Registry.Delete("10.0.0.1:1234")

	r := makeRequestWithHeaders("POST", "/verify", "10.0.0.1:1234", map[string]string{
		"User-Agent": "curl/8.0",
	})

	preScore := preSignalScore(r)
	// scoreBotSignals with no signals returns 0 (fail open).
	// But with minimal signals it should include at least the preScore.
	minimalSignals := `{"wd":0,"cdc":0,"cr":1,"plg":5,"lang":3,"sv":22,"wglr":"ANGLE","cores":8,"mem":8,"touch":0,"plt":"Linux","sw":1920,"sh":1080,"pt":12.5,"wglMaxTex":16384,"audioHash":-1}`
	fullScore := scoreBotSignals(minimalSignals, "", r, zap.NewNop(), -1, 0)

	if fullScore < preScore {
		t.Errorf("scoreBotSignals (%d) < preSignalScore (%d) — full score should include pre-signals", fullScore, preScore)
	}
}

func TestCompileChallengeRuleAdaptiveDifficulty(t *testing.T) {
	tests := []struct {
		name        string
		diff        int
		minDiff     int
		maxDiff     int
		wantDiff    int
		wantMinDiff int
		wantMaxDiff int
	}{
		{"static_only", 4, 0, 0, 4, 4, 4},
		{"min_max_set", 4, 2, 8, 4, 2, 8},
		{"only_min_set", 4, 3, 0, 4, 3, 4},
		{"only_max_set", 4, 0, 8, 4, 4, 8},
		{"min_exceeds_max", 4, 10, 5, 4, 5, 5},
		{"min_max_zero_uses_diff", 6, 0, 0, 6, 6, 6},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rule := PolicyRule{
				ID:   "c-adapt",
				Name: "Adaptive",
				Type: "challenge",
				Conditions: []PolicyCondition{
					{Field: "path", Operator: "eq", Value: "/"},
				},
				GroupOp: "and",
				Enabled: true,
				Challenge: &ChallengeConfig{
					Difficulty:    tc.diff,
					MinDifficulty: tc.minDiff,
					MaxDifficulty: tc.maxDiff,
				},
				Priority: 150,
			}

			cr, err := compileRule(rule)
			if err != nil {
				t.Fatalf("compileRule failed: %v", err)
			}
			if cr.challengeConfig.difficulty != tc.wantDiff {
				t.Errorf("difficulty = %d, want %d", cr.challengeConfig.difficulty, tc.wantDiff)
			}
			if cr.challengeConfig.minDifficulty != tc.wantMinDiff {
				t.Errorf("minDifficulty = %d, want %d", cr.challengeConfig.minDifficulty, tc.wantMinDiff)
			}
			if cr.challengeConfig.maxDifficulty != tc.wantMaxDiff {
				t.Errorf("maxDifficulty = %d, want %d", cr.challengeConfig.maxDifficulty, tc.wantMaxDiff)
			}
		})
	}
}

// ─── Challenge History Condition Field ──────────────────────────────

func TestChallengeHistoryField(t *testing.T) {
	host := "httpbun.erfi.io"
	cookieName := challengeCookieName(host)

	t.Run("no_cookie_returns_none", func(t *testing.T) {
		r := makeRequest("GET", "https://httpbun.erfi.io/test", "1.2.3.4:5678")
		r.Host = host
		cc := compiledCondition{field: "challenge_history"}
		val := extractField(cc, r, nil)
		if val != "none" {
			t.Errorf("got %q, want 'none'", val)
		}
	})

	t.Run("valid_cookie_returns_passed", func(t *testing.T) {
		r := makeRequest("GET", "https://httpbun.erfi.io/test", "1.2.3.4:5678")
		r.Host = host
		r.AddCookie(&http.Cookie{Name: cookieName, Value: "payload.signature"})
		cc := compiledCondition{field: "challenge_history"}
		val := extractField(cc, r, nil)
		if val != "passed" {
			t.Errorf("got %q, want 'passed'", val)
		}
	})

	t.Run("malformed_cookie_returns_expired", func(t *testing.T) {
		r := makeRequest("GET", "https://httpbun.erfi.io/test", "1.2.3.4:5678")
		r.Host = host
		r.AddCookie(&http.Cookie{Name: cookieName, Value: "garbage_no_dot"})
		cc := compiledCondition{field: "challenge_history"}
		val := extractField(cc, r, nil)
		if val != "expired" {
			t.Errorf("got %q, want 'expired'", val)
		}
	})
}

// ─── JTI Denylist Tests ─────────────────────────────────────────────

func TestJTIDenylistInvalidatesCookie(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}

	pe := &PolicyEngine{
		challengeHMACKey: key,
		mu:               &sync.RWMutex{},
		// Denylist with one suspended JTI.
		jtiDenylist: map[string]bool{"suspended-jti-001": true},
	}

	host := "httpbun.erfi.io"
	cookieName := challengeCookieName(host)

	// Build a valid cookie with the suspended JTI.
	payload := challengeCookiePayload{
		Jti: "suspended-jti-001",
		Aud: host,
		Exp: time.Now().Add(time.Hour).Unix(),
		Iat: time.Now().Unix(),
		Dif: 4,
	}
	cpJSON, _ := json.Marshal(payload)
	cpB64 := base64.RawURLEncoding.EncodeToString(cpJSON)
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(cpB64))
	sig := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))

	r := makeRequest("GET", "https://httpbun.erfi.io/test", "1.2.3.4:5678")
	r.Host = host
	r.AddCookie(&http.Cookie{Name: cookieName, Value: cpB64 + "." + sig})

	// Cookie is cryptographically valid, but JTI is denylisted.
	if pe.validateChallengeCookie(r) {
		t.Error("cookie with denylisted JTI should fail validation")
	}
}

func TestJTIDenylistAllowsNonDenied(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}

	pe := &PolicyEngine{
		challengeHMACKey: key,
		mu:               &sync.RWMutex{},
		jtiDenylist:      map[string]bool{"other-jti": true},
	}

	host := "httpbun.erfi.io"
	cookieName := challengeCookieName(host)

	// Build a valid cookie with a non-suspended JTI.
	payload := challengeCookiePayload{
		Jti: "good-jti-002",
		Sub: "1.2.3.4",
		Aud: host,
		Exp: time.Now().Add(time.Hour).Unix(),
		Iat: time.Now().Unix(),
		Dif: 4,
	}
	cpJSON, _ := json.Marshal(payload)
	cpB64 := base64.RawURLEncoding.EncodeToString(cpJSON)
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(cpB64))
	sig := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))

	r := makeRequest("GET", "https://httpbun.erfi.io/test", "1.2.3.4:5678")
	r.Host = host
	r.AddCookie(&http.Cookie{Name: cookieName, Value: cpB64 + "." + sig})

	if !pe.validateChallengeCookie(r) {
		t.Error("cookie with non-denied JTI should pass validation")
	}
}

func TestJTIDenylistNilAllowsAll(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}

	pe := &PolicyEngine{
		challengeHMACKey: key,
		mu:               &sync.RWMutex{},
		jtiDenylist:      nil, // no denylist file loaded
	}

	host := "httpbun.erfi.io"
	cookieName := challengeCookieName(host)

	payload := challengeCookiePayload{
		Jti: "any-jti",
		Sub: "1.2.3.4",
		Aud: host,
		Exp: time.Now().Add(time.Hour).Unix(),
		Iat: time.Now().Unix(),
		Dif: 4,
	}
	cpJSON, _ := json.Marshal(payload)
	cpB64 := base64.RawURLEncoding.EncodeToString(cpJSON)
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(cpB64))
	sig := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))

	r := makeRequest("GET", "https://httpbun.erfi.io/test", "1.2.3.4:5678")
	r.Host = host
	r.AddCookie(&http.Cookie{Name: cookieName, Value: cpB64 + "." + sig})

	if !pe.validateChallengeCookie(r) {
		t.Error("cookie should pass when denylist is nil")
	}
}
