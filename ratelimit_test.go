package policyengine

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"go.uber.org/zap"
)

// ─── Sliding Window Counter Tests ───────────────────────────────────

func TestZone_AllowUnderLimit(t *testing.T) {
	z := newZone(10, time.Minute)
	now := time.Now()
	for i := 0; i < 10; i++ {
		allowed, _, _ := z.allow("key1", now)
		if !allowed {
			t.Fatalf("request %d should be allowed", i)
		}
	}
}

func TestZone_DenyAtLimit(t *testing.T) {
	z := newZone(5, time.Minute)
	now := time.Now()
	for i := 0; i < 5; i++ {
		allowed, _, _ := z.allow("key1", now)
		if !allowed {
			t.Fatalf("request %d should be allowed", i)
		}
	}
	// 6th request should be denied.
	allowed, count, limit := z.allow("key1", now)
	if allowed {
		t.Fatal("6th request should be denied")
	}
	if limit != 5 {
		t.Errorf("limit: want 5, got %d", limit)
	}
	if count < 5 {
		t.Errorf("count should be >= 5, got %d", count)
	}
}

func TestZone_SeparateKeys(t *testing.T) {
	z := newZone(2, time.Minute)
	now := time.Now()

	// key1: 2 requests (at limit)
	z.allow("key1", now)
	z.allow("key1", now)
	allowed, _, _ := z.allow("key1", now)
	if allowed {
		t.Fatal("key1 3rd request should be denied")
	}

	// key2: should still be allowed
	allowed, _, _ = z.allow("key2", now)
	if !allowed {
		t.Fatal("key2 should be allowed (separate counter)")
	}
}

func TestZone_WindowRotation(t *testing.T) {
	z := newZone(5, time.Second)

	t0 := time.Now()
	for i := 0; i < 5; i++ {
		z.allow("key1", t0)
	}
	// Should be denied now.
	allowed, _, _ := z.allow("key1", t0)
	if allowed {
		t.Fatal("should be denied at limit")
	}

	// At exactly 1 window later, the sliding window algorithm rotates:
	// prevCount=5, currCount=0, elapsed=0, weight=1.0, effective=5 → still denied.
	// This is correct: at the start of a new window, the previous window
	// still has full influence.
	t1 := t0.Add(time.Second)
	allowed, _, _ = z.allow("key1", t1)
	if allowed {
		t.Fatal("should still be denied at window boundary (weight=1.0)")
	}

	// After 2 full windows, both are stale → counters reset → allowed.
	t2 := t0.Add(2 * time.Second)
	allowed, _, _ = z.allow("key1", t2)
	if !allowed {
		t.Fatal("should be allowed after 2 windows (both stale)")
	}
}

func TestZone_SlidingWindowInterpolation(t *testing.T) {
	z := newZone(10, time.Second)

	t0 := time.Now()
	// Fill up the window.
	for i := 0; i < 10; i++ {
		z.allow("key1", t0)
	}

	// At 50% through the next window, prevCount=10 weighted by 0.5 = 5.
	// So effective = 5 + 0 = 5, under limit of 10.
	t1 := t0.Add(time.Second + 500*time.Millisecond)
	allowed, _, _ := z.allow("key1", t1)
	if !allowed {
		t.Fatal("should be allowed at 50% interpolation")
	}
}

func TestZone_LongGapResets(t *testing.T) {
	z := newZone(5, time.Minute)

	t0 := time.Now()
	for i := 0; i < 5; i++ {
		z.allow("key1", t0)
	}

	// After 3 full windows (>2× window), both windows should be stale.
	t1 := t0.Add(3 * time.Minute)
	allowed, _, _ := z.allow("key1", t1)
	if !allowed {
		t.Fatal("should be allowed after long gap (counters reset)")
	}
}

func TestZone_Sweep(t *testing.T) {
	z := newZone(100, time.Second)

	t0 := time.Now()
	// Create some counters.
	for i := 0; i < 50; i++ {
		z.allow(fmt.Sprintf("key%d", i), t0)
	}

	// Sweep immediately — nothing expired yet.
	swept := z.sweep(t0)
	if swept != 0 {
		t.Errorf("expected 0 swept, got %d", swept)
	}

	// Sweep after 3× window — all should be expired.
	t1 := t0.Add(3 * time.Second)
	swept = z.sweep(t1)
	if swept != 50 {
		t.Errorf("expected 50 swept, got %d", swept)
	}
}

func TestZone_ConcurrentAccess(t *testing.T) {
	z := newZone(1000, time.Minute)
	now := time.Now()

	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				z.allow(fmt.Sprintf("key%d", id%10), now)
			}
		}(i)
	}
	wg.Wait()
	// If we get here without a race condition, the test passes.
}

// ─── Key Resolution Tests ───────────────────────────────────────────

func TestResolveRateLimitKey_ClientIP(t *testing.T) {
	r := httptest.NewRequest("GET", "/api/test", nil)
	r.RemoteAddr = "10.0.0.1:12345"

	key := resolveRateLimitKey("client_ip", r, nil)
	if key != "10.0.0.1" {
		t.Errorf("want 10.0.0.1, got %s", key)
	}
}

func TestResolveRateLimitKey_Path(t *testing.T) {
	r := httptest.NewRequest("GET", "/api/test", nil)
	key := resolveRateLimitKey("path", r, nil)
	if key != "/api/test" {
		t.Errorf("want /api/test, got %s", key)
	}
}

func TestResolveRateLimitKey_Static(t *testing.T) {
	r := httptest.NewRequest("GET", "/", nil)
	key := resolveRateLimitKey("static", r, nil)
	if key != "static" {
		t.Errorf("want static, got %s", key)
	}
}

func TestResolveRateLimitKey_CompoundIPPath(t *testing.T) {
	r := httptest.NewRequest("GET", "/api/test", nil)
	r.RemoteAddr = "10.0.0.1:12345"
	key := resolveRateLimitKey("client_ip+path", r, nil)
	if key != "10.0.0.1_/api/test" {
		t.Errorf("want 10.0.0.1_/api/test, got %s", key)
	}
}

func TestResolveRateLimitKey_CompoundIPMethod(t *testing.T) {
	r := httptest.NewRequest("POST", "/", nil)
	r.RemoteAddr = "10.0.0.1:12345"
	key := resolveRateLimitKey("client_ip+method", r, nil)
	if key != "10.0.0.1_POST" {
		t.Errorf("want 10.0.0.1_POST, got %s", key)
	}
}

func TestResolveRateLimitKey_Header(t *testing.T) {
	r := httptest.NewRequest("GET", "/", nil)
	r.Header.Set("X-API-Key", "abc123")
	key := resolveRateLimitKey("header:X-API-Key", r, nil)
	if key != "abc123" {
		t.Errorf("want abc123, got %s", key)
	}
}

func TestResolveRateLimitKey_HeaderMissing(t *testing.T) {
	r := httptest.NewRequest("GET", "/", nil)
	key := resolveRateLimitKey("header:X-API-Key", r, nil)
	if key != "" {
		t.Errorf("want empty for missing header, got %s", key)
	}
}

func TestResolveRateLimitKey_Cookie(t *testing.T) {
	r := httptest.NewRequest("GET", "/", nil)
	r.AddCookie(&http.Cookie{Name: "session", Value: "xyz789"})
	key := resolveRateLimitKey("cookie:session", r, nil)
	if key != "xyz789" {
		t.Errorf("want xyz789, got %s", key)
	}
}

func TestResolveRateLimitKey_BodyJSON(t *testing.T) {
	r := httptest.NewRequest("POST", "/", nil)
	body := []byte(`{"user":{"api_key":"secret123"}}`)
	key := resolveRateLimitKey("body_json:.user.api_key", r, body)
	if key != "secret123" {
		t.Errorf("want secret123, got %s", key)
	}
}

func TestResolveRateLimitKey_BodyForm(t *testing.T) {
	r := httptest.NewRequest("POST", "/", nil)
	body := []byte("action=login&user=admin")
	key := resolveRateLimitKey("body_form:action", r, body)
	if key != "login" {
		t.Errorf("want login, got %s", key)
	}
}

func TestResolveRateLimitKey_Default(t *testing.T) {
	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = "10.0.0.1:12345"
	key := resolveRateLimitKey("", r, nil)
	if key != "10.0.0.1" {
		t.Errorf("empty key should default to client_ip, got %s", key)
	}
}

// ─── Config Compilation Tests ───────────────────────────────────────

func TestCompileRLConfig_Valid(t *testing.T) {
	cfg := &RateLimitConfig{
		Key:    "client_ip",
		Events: 100,
		Window: "1m",
		Action: "deny",
	}
	compiled, err := compileRLConfig(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if compiled.Events != 100 {
		t.Errorf("events: want 100, got %d", compiled.Events)
	}
	if compiled.parsedWindow != time.Minute {
		t.Errorf("window: want 1m, got %s", compiled.parsedWindow)
	}
	if compiled.Action != "deny" {
		t.Errorf("action: want deny, got %s", compiled.Action)
	}
}

func TestCompileRLConfig_DefaultAction(t *testing.T) {
	cfg := &RateLimitConfig{Key: "client_ip", Events: 10, Window: "1s"}
	compiled, err := compileRLConfig(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if compiled.Action != "deny" {
		t.Errorf("default action should be deny, got %s", compiled.Action)
	}
}

func TestCompileRLConfig_DefaultKey(t *testing.T) {
	cfg := &RateLimitConfig{Events: 10, Window: "1s"}
	compiled, err := compileRLConfig(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if compiled.Key != "client_ip" {
		t.Errorf("default key should be client_ip, got %s", compiled.Key)
	}
}

func TestCompileRLConfig_LogOnly(t *testing.T) {
	cfg := &RateLimitConfig{Key: "client_ip", Events: 10, Window: "1s", Action: "log_only"}
	compiled, err := compileRLConfig(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if compiled.Action != "log_only" {
		t.Errorf("action: want log_only, got %s", compiled.Action)
	}
}

func TestCompileRLConfig_InvalidAction(t *testing.T) {
	cfg := &RateLimitConfig{Key: "client_ip", Events: 10, Window: "1s", Action: "drop"}
	_, err := compileRLConfig(cfg)
	if err == nil {
		t.Fatal("expected error for invalid action")
	}
}

func TestCompileRLConfig_InvalidWindow(t *testing.T) {
	cfg := &RateLimitConfig{Key: "client_ip", Events: 10, Window: "abc"}
	_, err := compileRLConfig(cfg)
	if err == nil {
		t.Fatal("expected error for invalid window")
	}
}

func TestCompileRLConfig_WindowTooSmall(t *testing.T) {
	cfg := &RateLimitConfig{Key: "client_ip", Events: 10, Window: "500ms"}
	_, err := compileRLConfig(cfg)
	if err == nil {
		t.Fatal("expected error for window < 1s")
	}
}

func TestCompileRLConfig_ZeroEvents(t *testing.T) {
	cfg := &RateLimitConfig{Key: "client_ip", Events: 0, Window: "1s"}
	_, err := compileRLConfig(cfg)
	if err == nil {
		t.Fatal("expected error for zero events")
	}
}

func TestCompileRLConfig_InvalidKey(t *testing.T) {
	cfg := &RateLimitConfig{Key: "invalid_key", Events: 10, Window: "1s"}
	_, err := compileRLConfig(cfg)
	if err == nil {
		t.Fatal("expected error for invalid key")
	}
}

func TestCompileRLConfig_BodyKey(t *testing.T) {
	cfg := &RateLimitConfig{Key: "body_json:.user.api_key", Events: 10, Window: "1s"}
	compiled, err := compileRLConfig(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if !compiled.needsBody {
		t.Error("body_json key should set needsBody")
	}
}

func TestCompileRLConfig_NilConfig(t *testing.T) {
	_, err := compileRLConfig(nil)
	if err == nil {
		t.Fatal("expected error for nil config")
	}
}

// ─── Window Parsing Tests ───────────────────────────────────────────

func TestParseWindow(t *testing.T) {
	tests := []struct {
		input string
		want  time.Duration
		err   bool
	}{
		{"1s", time.Second, false},
		{"30s", 30 * time.Second, false},
		{"1m", time.Minute, false},
		{"5m", 5 * time.Minute, false},
		{"1h", time.Hour, false},
		{"24h", 24 * time.Hour, false},
		{"", 0, true},
		{"abc", 0, true},
		{"1x", 0, true},
		// Go duration format also works.
		{"1m30s", 90 * time.Second, false},
		{"500ms", 500 * time.Millisecond, false},
	}
	for _, tt := range tests {
		d, err := parseWindow(tt.input)
		if tt.err {
			if err == nil {
				t.Errorf("parseWindow(%q): expected error", tt.input)
			}
			continue
		}
		if err != nil {
			t.Errorf("parseWindow(%q): unexpected error: %v", tt.input, err)
			continue
		}
		if d != tt.want {
			t.Errorf("parseWindow(%q): want %s, got %s", tt.input, tt.want, d)
		}
	}
}

// ─── Key Validation Tests ───────────────────────────────────────────

func TestIsValidRLKey(t *testing.T) {
	valid := []string{
		"client_ip", "path", "static", "client_ip+path", "client_ip+method",
		"header:X-API-Key", "cookie:session", "body_json:.user.key",
		"body_form:action",
	}
	for _, k := range valid {
		if !isValidRLKey(k) {
			t.Errorf("key %q should be valid", k)
		}
	}
	invalid := []string{"invalid", "header:", "cookie:", "body_json:", "body_form:", ""}
	for _, k := range invalid {
		if isValidRLKey(k) {
			t.Errorf("key %q should be invalid", k)
		}
	}
}

// ─── State Management Tests ─────────────────────────────────────────

func TestRateLimitState_UpdateZones_Fresh(t *testing.T) {
	rls := newRateLimitState()
	rules := []compiledRule{
		{
			rule:     PolicyRule{ID: "r1", Type: "rate_limit"},
			rlConfig: &compiledRLConfig{Events: 100, parsedWindow: time.Minute},
		},
		{
			rule:     PolicyRule{ID: "r2", Type: "rate_limit"},
			rlConfig: &compiledRLConfig{Events: 50, parsedWindow: 30 * time.Second},
		},
		{
			rule: PolicyRule{ID: "r3", Type: "block"}, // not rate_limit
		},
	}

	rls.updateZones(rules)

	if z := rls.getZone("r1"); z == nil {
		t.Error("r1 zone should exist")
	}
	if z := rls.getZone("r2"); z == nil {
		t.Error("r2 zone should exist")
	}
	if z := rls.getZone("r3"); z != nil {
		t.Error("r3 (block type) should not have a zone")
	}
}

func TestRateLimitState_UpdateZones_PreservesCounters(t *testing.T) {
	rls := newRateLimitState()

	rules1 := []compiledRule{{
		rule:     PolicyRule{ID: "r1", Type: "rate_limit"},
		rlConfig: &compiledRLConfig{Events: 100, parsedWindow: time.Minute},
	}}
	rls.updateZones(rules1)

	// Add some counts.
	z1 := rls.getZone("r1")
	z1.allow("key1", time.Now())
	z1.allow("key1", time.Now())

	// Reload with same config — counters should be preserved.
	rules2 := []compiledRule{{
		rule:     PolicyRule{ID: "r1", Type: "rate_limit"},
		rlConfig: &compiledRLConfig{Events: 100, parsedWindow: time.Minute},
	}}
	rls.updateZones(rules2)

	z2 := rls.getZone("r1")
	if z2 != z1 {
		t.Error("zone pointer should be preserved (same config)")
	}
}

func TestRateLimitState_UpdateZones_ResetsOnConfigChange(t *testing.T) {
	rls := newRateLimitState()

	rules1 := []compiledRule{{
		rule:     PolicyRule{ID: "r1", Type: "rate_limit"},
		rlConfig: &compiledRLConfig{Events: 100, parsedWindow: time.Minute},
	}}
	rls.updateZones(rules1)
	z1 := rls.getZone("r1")
	z1.allow("key1", time.Now())

	// Reload with different events — counters should reset.
	rules2 := []compiledRule{{
		rule:     PolicyRule{ID: "r1", Type: "rate_limit"},
		rlConfig: &compiledRLConfig{Events: 200, parsedWindow: time.Minute},
	}}
	rls.updateZones(rules2)

	z2 := rls.getZone("r1")
	if z2 == z1 {
		t.Error("zone should be new (config changed)")
	}
}

func TestRateLimitState_UpdateZones_RemovesDeleted(t *testing.T) {
	rls := newRateLimitState()

	rules1 := []compiledRule{
		{rule: PolicyRule{ID: "r1", Type: "rate_limit"}, rlConfig: &compiledRLConfig{Events: 10, parsedWindow: time.Second}},
		{rule: PolicyRule{ID: "r2", Type: "rate_limit"}, rlConfig: &compiledRLConfig{Events: 10, parsedWindow: time.Second}},
	}
	rls.updateZones(rules1)

	// Remove r2.
	rules2 := []compiledRule{
		{rule: PolicyRule{ID: "r1", Type: "rate_limit"}, rlConfig: &compiledRLConfig{Events: 10, parsedWindow: time.Second}},
	}
	rls.updateZones(rules2)

	if rls.getZone("r2") != nil {
		t.Error("r2 zone should be removed")
	}
}

// ─── Service Matching Tests ─────────────────────────────────────────

func TestMatchService(t *testing.T) {
	tests := []struct {
		service string
		host    string
		want    bool
	}{
		{"", "anything.com", true},
		{"*", "anything.com", true},
		{"sonarr.erfi.io", "sonarr.erfi.io", true},
		{"sonarr.erfi.io", "SONARR.ERFI.IO", true},
		{"sonarr.erfi.io", "sonarr.erfi.io:443", true},
		{"sonarr.erfi.io", "other.erfi.io", false},
	}
	for _, tt := range tests {
		r := httptest.NewRequest("GET", "/", nil)
		r.Host = tt.host
		got := matchService(tt.service, r)
		if got != tt.want {
			t.Errorf("matchService(%q, host=%q): want %v, got %v", tt.service, tt.host, tt.want, got)
		}
	}
}

// ─── Format/Helper Tests ────────────────────────────────────────────

func TestFormatWindow(t *testing.T) {
	tests := []struct {
		d    time.Duration
		want string
	}{
		{time.Second, "1s"},
		{30 * time.Second, "30s"},
		{time.Minute, "1m"},
		{5 * time.Minute, "5m"},
		{time.Hour, "1h"},
		{90 * time.Second, "90s"}, // not a clean minute
	}
	for _, tt := range tests {
		got := formatWindow(tt.d)
		if got != tt.want {
			t.Errorf("formatWindow(%s): want %s, got %s", tt.d, tt.want, got)
		}
	}
}

func TestRetryAfterSeconds_NoJitter(t *testing.T) {
	s := retryAfterSeconds(time.Minute, 0)
	if s != "60" {
		t.Errorf("want 60, got %s", s)
	}
}

func TestRetryAfterSeconds_WithJitter(t *testing.T) {
	// With jitter, value should be within [30, 90] for 1m window + 0.5 jitter.
	for i := 0; i < 100; i++ {
		s := retryAfterSeconds(time.Minute, 0.5)
		n := 0
		fmt.Sscanf(s, "%d", &n)
		if n < 30 || n > 90 {
			t.Errorf("retry-after %d outside expected range [30, 90]", n)
		}
	}
}

// ─── Global Config Tests ────────────────────────────────────────────

func TestCompileRLGlobalConfig(t *testing.T) {
	cfg := &RateLimitGlobalConfig{
		SweepInterval: "30s",
		Jitter:        0.5,
	}
	parsed := compileRLGlobalConfig(cfg)
	if parsed.parsedSweep != 30*time.Second {
		t.Errorf("sweep: want 30s, got %s", parsed.parsedSweep)
	}
	if parsed.jitter != 0.5 {
		t.Errorf("jitter: want 0.5, got %f", parsed.jitter)
	}
}

func TestCompileRLGlobalConfig_Nil(t *testing.T) {
	parsed := compileRLGlobalConfig(nil)
	if parsed != nil {
		t.Error("nil config should return nil")
	}
}

func TestCompileRLGlobalConfig_ClampJitter(t *testing.T) {
	cfg := &RateLimitGlobalConfig{Jitter: 2.0}
	parsed := compileRLGlobalConfig(cfg)
	if parsed.jitter != 1.0 {
		t.Errorf("jitter > 1 should be clamped to 1.0, got %f", parsed.jitter)
	}

	cfg2 := &RateLimitGlobalConfig{Jitter: -1.0}
	parsed2 := compileRLGlobalConfig(cfg2)
	if parsed2.jitter != 0.0 {
		t.Errorf("jitter < 0 should be clamped to 0.0, got %f", parsed2.jitter)
	}
}

// ─── ServeHTTP Integration Tests ────────────────────────────────────

func newTestPolicyEngine(rules []PolicyRule) *PolicyEngine {
	compiled, err := compileRules(rules)
	if err != nil {
		panic(err)
	}
	pe := &PolicyEngine{
		mu:      &sync.RWMutex{},
		rules:   compiled,
		rlState: newRateLimitState(),
		logger:  zap.NewNop(),
	}
	pe.rlState.updateZones(compiled)
	return pe
}

func TestServeHTTP_RateLimit_Deny(t *testing.T) {
	pe := newTestPolicyEngine([]PolicyRule{{
		ID:      "rl1",
		Name:    "test-limit",
		Type:    "rate_limit",
		Enabled: true,
		RateLimit: &RateLimitConfig{
			Key:    "client_ip",
			Events: 2,
			Window: "1m",
			Action: "deny",
		},
	}})

	for i := 0; i < 2; i++ {
		w := httptest.NewRecorder()
		r := makeRequest("GET", "/", "10.0.0.1:12345")
		next := &nextHandler{}
		err := pe.ServeHTTP(w, r, next)
		if err != nil {
			t.Fatalf("request %d: unexpected error: %v", i, err)
		}
		if !next.called {
			t.Fatalf("request %d: handler should be called (under limit)", i)
		}
		// Check informational headers.
		if w.Header().Get("X-RateLimit-Limit") != "2" {
			t.Errorf("request %d: X-RateLimit-Limit = %s", i, w.Header().Get("X-RateLimit-Limit"))
		}
	}

	// 3rd request — should be rate limited (429).
	w := httptest.NewRecorder()
	r := makeRequest("GET", "/", "10.0.0.1:12345")
	next := &nextHandler{}
	err := pe.ServeHTTP(w, r, next)
	if next.called {
		t.Fatal("handler should NOT be called when rate limited")
	}
	// The error is a caddyhttp.HandlerError with status 429.
	httpErr, ok := err.(caddyhttp.HandlerError)
	if !ok {
		t.Fatalf("expected caddyhttp.HandlerError, got %T", err)
	}
	if httpErr.StatusCode != http.StatusTooManyRequests {
		t.Errorf("want 429, got %d", httpErr.StatusCode)
	}
	// Check Retry-After header.
	if w.Header().Get("Retry-After") == "" {
		t.Error("missing Retry-After header")
	}
	// Check Caddy vars.
	action := caddyhttp.GetVar(r.Context(), "policy_engine.action")
	if action != "rate_limit" {
		t.Errorf("policy_engine.action: want rate_limit, got %v", action)
	}
	ruleName := caddyhttp.GetVar(r.Context(), "policy_engine.rule_name")
	if ruleName != "test-limit" {
		t.Errorf("policy_engine.rule_name: want test-limit, got %v", ruleName)
	}
}

func TestServeHTTP_RateLimit_LogOnly(t *testing.T) {
	pe := newTestPolicyEngine([]PolicyRule{{
		ID:      "rl1",
		Name:    "monitor-rule",
		Type:    "rate_limit",
		Enabled: true,
		RateLimit: &RateLimitConfig{
			Key:    "client_ip",
			Events: 1,
			Window: "1m",
			Action: "log_only",
		},
	}})

	// First request — under limit, should pass.
	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = "10.0.0.1:12345"
	next := &nextHandler{}
	pe.ServeHTTP(w, r, next)
	if !next.called {
		t.Fatal("request should pass through")
	}
	if w.Header().Get("X-RateLimit-Monitor") != "monitor-rule" {
		t.Error("missing X-RateLimit-Monitor header")
	}

	// Second request — over limit, but log_only should still pass.
	w2 := httptest.NewRecorder()
	r2 := httptest.NewRequest("GET", "/", nil)
	r2.RemoteAddr = "10.0.0.1:12345"
	next2 := &nextHandler{}
	err := pe.ServeHTTP(w2, r2, next2)
	if err != nil {
		t.Fatalf("log_only should not return error, got %v", err)
	}
	if !next2.called {
		t.Fatal("log_only should always pass through")
	}
}

func TestServeHTTP_RateLimit_ServiceFilter(t *testing.T) {
	pe := newTestPolicyEngine([]PolicyRule{{
		ID:      "rl1",
		Name:    "sonarr-limit",
		Type:    "rate_limit",
		Service: "sonarr.erfi.io",
		Enabled: true,
		RateLimit: &RateLimitConfig{
			Key:    "client_ip",
			Events: 1,
			Window: "1m",
			Action: "deny",
		},
	}})

	// Request to different host — should pass (service doesn't match).
	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/", nil)
	r.Host = "other.erfi.io"
	r.RemoteAddr = "10.0.0.1:12345"
	next := &nextHandler{}
	for i := 0; i < 5; i++ {
		next.called = false
		pe.ServeHTTP(w, r, next)
		if !next.called {
			t.Fatalf("request %d to non-matching host should pass", i)
		}
	}

	// Request to matching host — should be rate limited.
	r2 := httptest.NewRequest("GET", "/", nil)
	r2.Host = "sonarr.erfi.io"
	r2.RemoteAddr = "10.0.0.1:12345"
	next2 := &nextHandler{}
	pe.ServeHTTP(httptest.NewRecorder(), r2, next2)
	if !next2.called {
		t.Fatal("first request to matching host should pass")
	}
	// Second request.
	w3 := httptest.NewRecorder()
	r3 := httptest.NewRequest("GET", "/", nil)
	r3.Host = "sonarr.erfi.io"
	r3.RemoteAddr = "10.0.0.1:12345"
	next3 := &nextHandler{}
	err := pe.ServeHTTP(w3, r3, next3)
	if next3.called {
		t.Fatal("second request should be rate limited")
	}
	httpErr, _ := err.(caddyhttp.HandlerError)
	if httpErr.StatusCode != 429 {
		t.Errorf("want 429, got %d", httpErr.StatusCode)
	}
}

func TestServeHTTP_RateLimit_WithConditions(t *testing.T) {
	pe := newTestPolicyEngine([]PolicyRule{{
		ID:      "rl1",
		Name:    "api-limit",
		Type:    "rate_limit",
		Enabled: true,
		Conditions: []PolicyCondition{
			{Field: "path", Operator: "begins_with", Value: "/api"},
		},
		RateLimit: &RateLimitConfig{
			Key:    "client_ip",
			Events: 1,
			Window: "1m",
			Action: "deny",
		},
	}})

	// Request to /other — conditions don't match, no rate limiting.
	for i := 0; i < 5; i++ {
		w := httptest.NewRecorder()
		r := httptest.NewRequest("GET", "/other", nil)
		r.RemoteAddr = "10.0.0.1:12345"
		next := &nextHandler{}
		pe.ServeHTTP(w, r, next)
		if !next.called {
			t.Fatalf("/other request %d should pass (no match)", i)
		}
	}

	// Request to /api/test — conditions match, should rate limit.
	w1 := httptest.NewRecorder()
	r1 := httptest.NewRequest("GET", "/api/test", nil)
	r1.RemoteAddr = "10.0.0.1:12345"
	next1 := &nextHandler{}
	pe.ServeHTTP(w1, r1, next1)
	if !next1.called {
		t.Fatal("first /api request should pass")
	}
	// Second request.
	r2 := httptest.NewRequest("GET", "/api/other", nil)
	r2.RemoteAddr = "10.0.0.1:12345"
	next2 := &nextHandler{}
	err := pe.ServeHTTP(httptest.NewRecorder(), r2, next2)
	if next2.called {
		t.Fatal("second /api request should be rate limited")
	}
	httpErr, _ := err.(caddyhttp.HandlerError)
	if httpErr.StatusCode != 429 {
		t.Errorf("want 429, got %d", httpErr.StatusCode)
	}
}

func TestServeHTTP_RateLimit_EmptyKey_Skipped(t *testing.T) {
	pe := newTestPolicyEngine([]PolicyRule{{
		ID:      "rl1",
		Name:    "header-limit",
		Type:    "rate_limit",
		Enabled: true,
		RateLimit: &RateLimitConfig{
			Key:    "header:X-API-Key",
			Events: 1,
			Window: "1m",
			Action: "deny",
		},
	}})

	// Request without the header — key resolves to "", rule skipped.
	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/", nil)
	next := &nextHandler{}
	pe.ServeHTTP(w, r, next)
	if !next.called {
		t.Fatal("request with empty key should pass (rule skipped)")
	}
}

func TestServeHTTP_RateLimit_Tags(t *testing.T) {
	pe := newTestPolicyEngine([]PolicyRule{{
		ID:      "rl1",
		Name:    "tagged-limit",
		Type:    "rate_limit",
		Tags:    []string{"api", "protection"},
		Enabled: true,
		RateLimit: &RateLimitConfig{
			Key:    "client_ip",
			Events: 1,
			Window: "1m",
			Action: "deny",
		},
	}})

	// Exhaust the limit.
	r1 := makeRequest("GET", "/", "10.0.0.1:12345")
	pe.ServeHTTP(httptest.NewRecorder(), r1, &nextHandler{})

	// Trigger rate limit.
	r2 := makeRequest("GET", "/", "10.0.0.1:12345")
	pe.ServeHTTP(httptest.NewRecorder(), r2, &nextHandler{})

	tags := caddyhttp.GetVar(r2.Context(), "policy_engine.tags")
	if tags != "api,protection" {
		t.Errorf("policy_engine.tags: want api,protection, got %v", tags)
	}
}

// ─── Hot Reload Tests ───────────────────────────────────────────────

func TestHotReload_RateLimitRules(t *testing.T) {
	// Write initial rules file with a rate limit rule.
	tmpFile, err := os.CreateTemp("", "policy-rules-*.json")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpFile.Name())

	rules := PolicyRulesFile{
		Version: 1,
		Rules: []PolicyRule{{
			ID:      "rl1",
			Name:    "test-rl",
			Type:    "rate_limit",
			Enabled: true,
			RateLimit: &RateLimitConfig{
				Key:    "client_ip",
				Events: 5,
				Window: "1m",
				Action: "deny",
			},
		}},
		RateLimitConfig: &RateLimitGlobalConfig{
			SweepInterval: "30s",
			Jitter:        0.1,
		},
	}
	data, _ := json.Marshal(rules)
	tmpFile.Write(data)
	tmpFile.Close()

	pe := &PolicyEngine{
		RulesFile: tmpFile.Name(),
		mu:        &sync.RWMutex{},
		rlState:   newRateLimitState(),
		logger:    zap.NewNop(),
	}

	if err := pe.loadFromFile(); err != nil {
		t.Fatal(err)
	}

	pe.mu.RLock()
	ruleCount := len(pe.rules)
	pe.mu.RUnlock()

	if ruleCount != 1 {
		t.Fatalf("expected 1 rule, got %d", ruleCount)
	}
	if pe.rlState.getZone("rl1") == nil {
		t.Fatal("zone rl1 should exist after load")
	}
	if pe.rlGlobalConfig == nil {
		t.Fatal("global config should be loaded")
	}
	if pe.rlGlobalConfig.jitter != 0.1 {
		t.Errorf("jitter: want 0.1, got %f", pe.rlGlobalConfig.jitter)
	}
}

func TestHotReload_MixedRuleTypes(t *testing.T) {
	tmpFile, err := os.CreateTemp("", "policy-rules-*.json")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpFile.Name())

	rules := PolicyRulesFile{
		Version: 1,
		Rules: []PolicyRule{
			{
				ID:      "b1",
				Name:    "block-bad",
				Type:    "block",
				Enabled: true,
				Conditions: []PolicyCondition{
					{Field: "path", Operator: "eq", Value: "/blocked"},
				},
			},
			{
				ID:      "rl1",
				Name:    "rate-limit",
				Type:    "rate_limit",
				Enabled: true,
				RateLimit: &RateLimitConfig{
					Key:    "client_ip",
					Events: 10,
					Window: "1m",
				},
			},
		},
	}
	data, _ := json.Marshal(rules)
	tmpFile.Write(data)
	tmpFile.Close()

	pe := &PolicyEngine{
		RulesFile: tmpFile.Name(),
		mu:        &sync.RWMutex{},
		rlState:   newRateLimitState(),
		logger:    zap.NewNop(),
	}
	if err := pe.loadFromFile(); err != nil {
		t.Fatal(err)
	}

	pe.mu.RLock()
	if len(pe.rules) != 2 {
		t.Fatalf("expected 2 rules, got %d", len(pe.rules))
	}
	pe.mu.RUnlock()

	// Block rule should not have a zone.
	if pe.rlState.getZone("b1") != nil {
		t.Error("block rule should not have a rate limit zone")
	}
	// Rate limit rule should have a zone.
	if pe.rlState.getZone("rl1") == nil {
		t.Error("rate limit rule should have a zone")
	}
}

// ─── NeedsBodyForKey Tests ──────────────────────────────────────────

func TestNeedsBodyForKey(t *testing.T) {
	tests := []struct {
		key  string
		want bool
	}{
		{"client_ip", false},
		{"path", false},
		{"header:X-Key", false},
		{"cookie:session", false},
		{"body_json:.user.key", true},
		{"body_form:action", true},
	}
	for _, tt := range tests {
		got := needsBodyForKey(tt.key)
		if got != tt.want {
			t.Errorf("needsBodyForKey(%q): want %v, got %v", tt.key, tt.want, got)
		}
	}
}

// ─── Rate Limit Headers Tests ───────────────────────────────────────

func TestSetRateLimitHeaders(t *testing.T) {
	w := httptest.NewRecorder()
	setRateLimitHeaders(w, 100, 42, time.Minute, "my-rule")

	if w.Header().Get("X-RateLimit-Limit") != "100" {
		t.Errorf("X-RateLimit-Limit: want 100, got %s", w.Header().Get("X-RateLimit-Limit"))
	}
	if w.Header().Get("X-RateLimit-Remaining") != "42" {
		t.Errorf("X-RateLimit-Remaining: want 42, got %s", w.Header().Get("X-RateLimit-Remaining"))
	}
	if w.Header().Get("X-RateLimit-Reset") == "" {
		t.Error("X-RateLimit-Reset should be set")
	}
	policy := w.Header().Get("X-RateLimit-Policy")
	if !strings.Contains(policy, "100") || !strings.Contains(policy, "my-rule") {
		t.Errorf("X-RateLimit-Policy: unexpected value %q", policy)
	}
}

func TestSetRateLimitHeaders_NegativeRemaining(t *testing.T) {
	w := httptest.NewRecorder()
	setRateLimitHeaders(w, 10, -5, time.Minute, "")
	if w.Header().Get("X-RateLimit-Remaining") != "0" {
		t.Errorf("negative remaining should be clamped to 0, got %s",
			w.Header().Get("X-RateLimit-Remaining"))
	}
}

// ─── Block + RateLimit Coexistence Test ─────────────────────────────

func TestServeHTTP_BlockBeforeRateLimit(t *testing.T) {
	// Block rule has lower priority, should fire first.
	pe := newTestPolicyEngine([]PolicyRule{
		{
			ID:       "b1",
			Name:     "block-bad",
			Type:     "block",
			Priority: 10,
			Enabled:  true,
			Conditions: []PolicyCondition{
				{Field: "path", Operator: "eq", Value: "/blocked"},
			},
		},
		{
			ID:       "rl1",
			Name:     "rate-limit",
			Type:     "rate_limit",
			Priority: 100,
			Enabled:  true,
			RateLimit: &RateLimitConfig{
				Key:    "client_ip",
				Events: 1000,
				Window: "1m",
			},
		},
	})

	// Request to /blocked — block rule fires, returns 403 (not 429).
	r := httptest.NewRequest("GET", "/blocked", nil)
	r.RemoteAddr = "10.0.0.1:12345"
	err := pe.ServeHTTP(httptest.NewRecorder(), r, &nextHandler{})
	httpErr, ok := err.(caddyhttp.HandlerError)
	if !ok || httpErr.StatusCode != 403 {
		t.Errorf("want 403 from block rule, got %v", err)
	}
}
