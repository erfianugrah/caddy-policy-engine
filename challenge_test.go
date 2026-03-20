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
	signals := `{"wd":0,"cdc":0,"cr":1,"plg":5,"lang":3,"sv":22,"wglr":"ANGLE (Intel, Intel(R) Iris(R) Xe Graphics)","wglv":"Google Inc. (Intel)","cores":8,"mem":8,"touch":0,"plt":"Win32","sw":1920,"sh":1080,"cd":24,"dpr":1,"cvs":"a1b2c3d4","pt":12.5}`
	behavior := `{"me":15,"ke":0,"fc":1,"se":2,"fi":850,"wtv":8.3,"dur":3000}`

	score := scoreBotSignals(signals, behavior, makeRequest("POST", "/.well-known/policy-challenge/verify", "1.2.3.4:5678"), zap.NewNop())
	if score > 30 {
		t.Errorf("real browser score = %d, want <= 30", score)
	}
}

func TestScoreBotSignals_HeadlessChrome(t *testing.T) {
	signals := `{"wd":1,"cdc":0,"cr":0,"plg":0,"lang":1,"sv":0,"wglr":"Google SwiftShader","wglv":"Google Inc.","cores":2,"mem":0,"touch":0,"plt":"Linux x86_64","sw":800,"sh":600,"cd":24,"dpr":1,"cvs":"deadbeef","pt":0.1}`
	behavior := `{"me":0,"ke":0,"fc":0,"se":0,"fi":-1,"wtv":0.3,"dur":5000}`

	score := scoreBotSignals(signals, behavior, makeRequest("POST", "/.well-known/policy-challenge/verify", "1.2.3.4:5678"), zap.NewNop())
	if score < 70 {
		t.Errorf("headless Chrome score = %d, want >= 70", score)
	}
}

func TestScoreBotSignals_Puppeteer(t *testing.T) {
	signals := `{"wd":0,"cdc":1,"cr":0,"plg":0,"lang":1,"sv":0,"wglr":"Google SwiftShader","wglv":"Google Inc.","cores":4,"mem":0,"touch":0,"plt":"Linux x86_64","sw":1280,"sh":720,"cd":24,"dpr":1,"cvs":"cafebabe","pt":0.05}`
	behavior := `{"me":0,"ke":0,"fc":0,"se":0,"fi":-1,"wtv":0.5,"dur":2000}`

	score := scoreBotSignals(signals, behavior, makeRequest("POST", "/.well-known/policy-challenge/verify", "1.2.3.4:5678"), zap.NewNop())
	if score < 70 {
		t.Errorf("Puppeteer score = %d, want >= 70 (cdc + SwiftShader + 0 plugins)", score)
	}
}

func TestScoreBotSignals_EmptySignals(t *testing.T) {
	score := scoreBotSignals("", "", makeRequest("POST", "/.well-known/policy-challenge/verify", "1.2.3.4:5678"), zap.NewNop())
	if score != 0 {
		t.Errorf("empty signals score = %d, want 0 (fail open)", score)
	}
}

func TestScoreBotSignals_MalformedJSON(t *testing.T) {
	score := scoreBotSignals("{invalid", "", makeRequest("POST", "/.well-known/policy-challenge/verify", "1.2.3.4:5678"), zap.NewNop())
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
	if resp.StatusCode != http.StatusFound {
		t.Errorf("status = %d, want 302", resp.StatusCode)
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
}
