package policyengine

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// mustCompileResponseHeaders is a test helper that compiles response headers
// and fails the test on error.
func mustCompileResponseHeaders(t *testing.T, cfg *ResponseHeaderConfig) *compiledResponseHeaders {
	t.Helper()
	result, err := compileResponseHeaders(cfg)
	if err != nil {
		t.Fatalf("compileResponseHeaders: %v", err)
	}
	return result
}

// ─── buildCSPHeaderString ───────────────────────────────────────────

func TestBuildCSPHeaderString_Empty(t *testing.T) {
	got := buildCSPHeaderString(CSPPolicy{})
	if got != "" {
		t.Errorf("expected empty string, got %q", got)
	}
}

func TestBuildCSPHeaderString_SingleDirective(t *testing.T) {
	got := buildCSPHeaderString(CSPPolicy{
		DefaultSrc: []string{"'self'"},
	})
	want := "default-src 'self'"
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestBuildCSPHeaderString_MultipleDirectives(t *testing.T) {
	got := buildCSPHeaderString(CSPPolicy{
		DefaultSrc: []string{"'self'"},
		ScriptSrc:  []string{"'self'", "'unsafe-inline'"},
		ImgSrc:     []string{"'self'", "data:", "https:"},
	})
	want := "default-src 'self'; script-src 'self' 'unsafe-inline'; img-src 'self' data: https:"
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestBuildCSPHeaderString_UpgradeInsecureRequests(t *testing.T) {
	got := buildCSPHeaderString(CSPPolicy{
		DefaultSrc:              []string{"'self'"},
		UpgradeInsecureRequests: true,
	})
	want := "default-src 'self'; upgrade-insecure-requests"
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestBuildCSPHeaderString_RawDirectives(t *testing.T) {
	got := buildCSPHeaderString(CSPPolicy{
		DefaultSrc:    []string{"'self'"},
		RawDirectives: "report-uri /csp-report",
	})
	want := "default-src 'self'; report-uri /csp-report"
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestBuildCSPHeaderString_AllDirectives(t *testing.T) {
	p := CSPPolicy{
		DefaultSrc:  []string{"'self'"},
		ScriptSrc:   []string{"'self'"},
		StyleSrc:    []string{"'self'"},
		ImgSrc:      []string{"'self'"},
		FontSrc:     []string{"'self'"},
		ConnectSrc:  []string{"'self'"},
		MediaSrc:    []string{"'self'"},
		FrameSrc:    []string{"'self'"},
		WorkerSrc:   []string{"'self'"},
		ObjectSrc:   []string{"'none'"},
		ChildSrc:    []string{"'self'"},
		ManifestSrc: []string{"'self'"},
		BaseURI:     []string{"'self'"},
		FormAction:  []string{"'self'"},
		FrameAnc:    []string{"'self'"},
	}
	got := buildCSPHeaderString(p)
	// Should contain all 15 directives separated by "; "
	for _, d := range []string{
		"default-src", "script-src", "style-src", "img-src", "font-src",
		"connect-src", "media-src", "frame-src", "worker-src", "object-src",
		"child-src", "manifest-src", "base-uri", "form-action", "frame-ancestors",
	} {
		if !contains(got, d) {
			t.Errorf("expected %q in CSP header, got %q", d, got)
		}
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && containsSubstr(s, substr))
}

func containsSubstr(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

// ─── mergeCSPPolicy ─────────────────────────────────────────────────

func TestMergeCSPPolicy_EmptyOverride(t *testing.T) {
	base := CSPPolicy{
		DefaultSrc: []string{"'self'"},
		ScriptSrc:  []string{"'self'", "'unsafe-inline'"},
	}
	merged := mergeCSPPolicy(base, CSPPolicy{})
	if len(merged.DefaultSrc) != 1 || merged.DefaultSrc[0] != "'self'" {
		t.Errorf("expected base default_src preserved, got %v", merged.DefaultSrc)
	}
	if len(merged.ScriptSrc) != 2 {
		t.Errorf("expected base script_src preserved, got %v", merged.ScriptSrc)
	}
}

func TestMergeCSPPolicy_OverrideReplaces(t *testing.T) {
	base := CSPPolicy{
		DefaultSrc: []string{"'self'"},
		ScriptSrc:  []string{"'self'", "'unsafe-inline'"},
	}
	override := CSPPolicy{
		ScriptSrc: []string{"'self'", "'unsafe-eval'"},
	}
	merged := mergeCSPPolicy(base, override)
	if len(merged.DefaultSrc) != 1 {
		t.Errorf("expected base default_src preserved, got %v", merged.DefaultSrc)
	}
	if len(merged.ScriptSrc) != 2 || merged.ScriptSrc[1] != "'unsafe-eval'" {
		t.Errorf("expected override script_src, got %v", merged.ScriptSrc)
	}
}

func TestMergeCSPPolicy_UpgradeInsecureRequestsSticky(t *testing.T) {
	base := CSPPolicy{UpgradeInsecureRequests: true}
	override := CSPPolicy{}
	merged := mergeCSPPolicy(base, override)
	if !merged.UpgradeInsecureRequests {
		t.Error("expected UpgradeInsecureRequests sticky from base")
	}

	base2 := CSPPolicy{}
	override2 := CSPPolicy{UpgradeInsecureRequests: true}
	merged2 := mergeCSPPolicy(base2, override2)
	if !merged2.UpgradeInsecureRequests {
		t.Error("expected UpgradeInsecureRequests sticky from override")
	}
}

func TestMergeCSPPolicy_RawDirectivesOverride(t *testing.T) {
	base := CSPPolicy{RawDirectives: "report-uri /old"}
	override := CSPPolicy{RawDirectives: "report-uri /new"}
	merged := mergeCSPPolicy(base, override)
	if merged.RawDirectives != "report-uri /new" {
		t.Errorf("expected override raw_directives, got %q", merged.RawDirectives)
	}
}

func TestMergeCSPPolicy_RawDirectivesPreservedWhenEmpty(t *testing.T) {
	base := CSPPolicy{RawDirectives: "report-uri /old"}
	override := CSPPolicy{}
	merged := mergeCSPPolicy(base, override)
	if merged.RawDirectives != "report-uri /old" {
		t.Errorf("expected base raw_directives preserved, got %q", merged.RawDirectives)
	}
}

// ─── compileResponseHeaders ─────────────────────────────────────────

func TestCompileResponseHeaders_Nil(t *testing.T) {
	result, err := compileResponseHeaders(nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result != nil {
		t.Error("expected nil for nil config")
	}
}

func TestCompileResponseHeaders_CSPEnabled(t *testing.T) {
	boolTrue := true
	cfg := &ResponseHeaderConfig{
		CSP: &CSPConfig{
			Enabled: &boolTrue,
			GlobalDefaults: CSPPolicy{
				DefaultSrc: []string{"'self'"},
			},
			Services: map[string]CSPServiceConfig{
				"example.com": {
					Mode:    "set",
					Inherit: true,
					Policy: CSPPolicy{
						ScriptSrc: []string{"'self'", "'unsafe-inline'"},
					},
				},
			},
		},
	}
	result := mustCompileResponseHeaders(t, cfg)
	if result == nil || result.csp == nil {
		t.Fatal("expected compiled CSP")
	}
	if !result.csp.enabled {
		t.Error("expected CSP enabled")
	}
	// Check global fallback.
	if result.csp.fallback.rendered != "default-src 'self'" {
		t.Errorf("unexpected fallback: %q", result.csp.fallback.rendered)
	}
	// Check per-service.
	svc, ok := result.csp.services["example.com"]
	if !ok {
		t.Fatal("expected example.com in services")
	}
	if svc.mode != "set" {
		t.Errorf("expected mode 'set', got %q", svc.mode)
	}
	// Inherited: should have default_src from base + script_src from override.
	if !containsSubstr(svc.rendered, "default-src 'self'") {
		t.Errorf("expected inherited default-src in rendered, got %q", svc.rendered)
	}
	if !containsSubstr(svc.rendered, "script-src 'self' 'unsafe-inline'") {
		t.Errorf("expected override script-src in rendered, got %q", svc.rendered)
	}
}

func TestCompileResponseHeaders_CSPEnabledNil(t *testing.T) {
	// nil Enabled should default to true.
	cfg := &ResponseHeaderConfig{
		CSP: &CSPConfig{
			GlobalDefaults: CSPPolicy{DefaultSrc: []string{"'self'"}},
		},
	}
	result := mustCompileResponseHeaders(t, cfg)
	if result == nil || result.csp == nil || !result.csp.enabled {
		t.Error("expected CSP enabled when Enabled is nil")
	}
}

func TestCompileResponseHeaders_CSPDisabled(t *testing.T) {
	boolFalse := false
	cfg := &ResponseHeaderConfig{
		CSP: &CSPConfig{
			Enabled:        &boolFalse,
			GlobalDefaults: CSPPolicy{DefaultSrc: []string{"'self'"}},
		},
	}
	result := mustCompileResponseHeaders(t, cfg)
	if result == nil || result.csp == nil {
		t.Fatal("expected compiled CSP struct")
	}
	if result.csp.enabled {
		t.Error("expected CSP disabled")
	}
}

func TestCompileResponseHeaders_CSPNoInherit(t *testing.T) {
	cfg := &ResponseHeaderConfig{
		CSP: &CSPConfig{
			GlobalDefaults: CSPPolicy{
				DefaultSrc: []string{"'self'"},
				ScriptSrc:  []string{"'self'"},
			},
			Services: map[string]CSPServiceConfig{
				"api.example.com": {
					Mode:    "set",
					Inherit: false,
					Policy: CSPPolicy{
						DefaultSrc: []string{"'none'"},
					},
				},
			},
		},
	}
	result := mustCompileResponseHeaders(t, cfg)
	svc := result.csp.services["api.example.com"]
	// No inherit: should NOT include script_src from global.
	if containsSubstr(svc.rendered, "script-src") {
		t.Errorf("expected no inherited script-src, got %q", svc.rendered)
	}
	if svc.rendered != "default-src 'none'" {
		t.Errorf("expected only override policy, got %q", svc.rendered)
	}
}

func TestCompileResponseHeaders_SecurityHeaders(t *testing.T) {
	cfg := &ResponseHeaderConfig{
		Security: &SecurityHeaderConfig{
			Headers: map[string]string{
				"X-Content-Type-Options": "nosniff",
				"Referrer-Policy":        "strict-origin-when-cross-origin",
			},
			Remove: []string{"Server", "X-Powered-By"},
			PerService: map[string]SecurityServiceOverride{
				"api.example.com": {
					Headers: map[string]string{
						"Referrer-Policy": "no-referrer",
					},
					Remove: []string{"X-Custom"},
				},
			},
		},
	}
	result := mustCompileResponseHeaders(t, cfg)
	if result == nil || result.security == nil {
		t.Fatal("expected compiled security")
	}
	if !result.security.enabled {
		t.Error("expected security enabled")
	}
	// Check global headers.
	if result.security.headers["X-Content-Type-Options"] != "nosniff" {
		t.Error("expected global X-Content-Type-Options")
	}
	// Check per-service merged headers.
	svc, ok := result.security.services["api.example.com"]
	if !ok {
		t.Fatal("expected api.example.com in services")
	}
	if svc.headers["Referrer-Policy"] != "no-referrer" {
		t.Errorf("expected override Referrer-Policy, got %q", svc.headers["Referrer-Policy"])
	}
	// Global header preserved.
	if svc.headers["X-Content-Type-Options"] != "nosniff" {
		t.Error("expected inherited X-Content-Type-Options")
	}
	// Remove list merged.
	removeSet := make(map[string]bool)
	for _, h := range svc.remove {
		removeSet[h] = true
	}
	if !removeSet["Server"] || !removeSet["X-Powered-By"] || !removeSet["X-Custom"] {
		t.Errorf("expected merged remove list, got %v", svc.remove)
	}
}

// ─── resolveCSP ─────────────────────────────────────────────────────

func TestResolveCSP_NilConfig(t *testing.T) {
	var crh *compiledResponseHeaders
	svc := crh.resolveCSP("example.com")
	if svc.mode != "none" {
		t.Errorf("expected none for nil config, got %q", svc.mode)
	}
}

func TestResolveCSP_Disabled(t *testing.T) {
	boolFalse := false
	cfg := &ResponseHeaderConfig{
		CSP: &CSPConfig{
			Enabled:        &boolFalse,
			GlobalDefaults: CSPPolicy{DefaultSrc: []string{"'self'"}},
		},
	}
	crh := mustCompileResponseHeaders(t, cfg)
	svc := crh.resolveCSP("example.com")
	if svc.mode != "none" {
		t.Errorf("expected none for disabled CSP, got %q", svc.mode)
	}
}

func TestResolveCSP_PerService(t *testing.T) {
	cfg := &ResponseHeaderConfig{
		CSP: &CSPConfig{
			GlobalDefaults: CSPPolicy{DefaultSrc: []string{"'self'"}},
			Services: map[string]CSPServiceConfig{
				"app.example.com": {
					Mode:    "default",
					Inherit: true,
					Policy: CSPPolicy{
						ScriptSrc: []string{"'self'", "cdn.example.com"},
					},
				},
			},
		},
	}
	crh := mustCompileResponseHeaders(t, cfg)

	// Exact match.
	svc := crh.resolveCSP("app.example.com")
	if svc.mode != "default" {
		t.Errorf("expected default, got %q", svc.mode)
	}

	// Case insensitive.
	svc2 := crh.resolveCSP("APP.EXAMPLE.COM")
	if svc2.mode != "default" {
		t.Errorf("expected case-insensitive match, got %q", svc2.mode)
	}

	// With port.
	svc3 := crh.resolveCSP("app.example.com:443")
	if svc3.mode != "default" {
		t.Errorf("expected match with port stripped, got %q", svc3.mode)
	}

	// Fallback to global.
	svc4 := crh.resolveCSP("other.example.com")
	if svc4.mode != "set" {
		t.Errorf("expected fallback mode 'set', got %q", svc4.mode)
	}
}

// ─── resolveSecurity ────────────────────────────────────────────────

func TestResolveSecurity_NilConfig(t *testing.T) {
	var crh *compiledResponseHeaders
	headers, remove := crh.resolveSecurity("example.com")
	if headers != nil || remove != nil {
		t.Error("expected nil for nil config")
	}
}

func TestResolveSecurity_GlobalHeaders(t *testing.T) {
	cfg := &ResponseHeaderConfig{
		Security: &SecurityHeaderConfig{
			Headers: map[string]string{
				"Strict-Transport-Security": "max-age=63072000",
			},
			Remove: []string{"Server"},
		},
	}
	crh := mustCompileResponseHeaders(t, cfg)
	headers, remove := crh.resolveSecurity("any.example.com")
	if headers["Strict-Transport-Security"] != "max-age=63072000" {
		t.Error("expected global HSTS header")
	}
	if len(remove) != 1 || remove[0] != "Server" {
		t.Errorf("expected Server in remove, got %v", remove)
	}
}

func TestResolveSecurity_PerServiceOverride(t *testing.T) {
	cfg := &ResponseHeaderConfig{
		Security: &SecurityHeaderConfig{
			Headers: map[string]string{
				"Cross-Origin-Opener-Policy": "same-origin",
			},
			PerService: map[string]SecurityServiceOverride{
				"immich.example.com": {
					Headers: map[string]string{
						"Cross-Origin-Opener-Policy": "same-origin-allow-popups",
					},
				},
			},
		},
	}
	crh := mustCompileResponseHeaders(t, cfg)

	// Per-service override.
	headers, _ := crh.resolveSecurity("immich.example.com")
	if headers["Cross-Origin-Opener-Policy"] != "same-origin-allow-popups" {
		t.Errorf("expected per-service override, got %q", headers["Cross-Origin-Opener-Policy"])
	}

	// Global for other services.
	headers2, _ := crh.resolveSecurity("other.example.com")
	if headers2["Cross-Origin-Opener-Policy"] != "same-origin" {
		t.Errorf("expected global value, got %q", headers2["Cross-Origin-Opener-Policy"])
	}
}

func TestResolveSecurity_CaseInsensitiveHost(t *testing.T) {
	cfg := &ResponseHeaderConfig{
		Security: &SecurityHeaderConfig{
			Headers: map[string]string{"X-Test": "global"},
			PerService: map[string]SecurityServiceOverride{
				"App.Example.COM": {
					Headers: map[string]string{"X-Test": "override"},
				},
			},
		},
	}
	crh := mustCompileResponseHeaders(t, cfg)
	// The key in PerService is lowercased at compile time.
	headers, _ := crh.resolveSecurity("app.example.com")
	if headers["X-Test"] != "override" {
		t.Errorf("expected case-insensitive override, got %q", headers["X-Test"])
	}
}

// ─── responseHeaderWriter ───────────────────────────────────────────

func TestResponseHeaderWriter_RemoveHeaders(t *testing.T) {
	rec := httptest.NewRecorder()
	rec.Header().Set("Server", "caddy")
	rec.Header().Set("X-Powered-By", "Go")

	rw := &responseHeaderWriter{
		ResponseWriter: rec,
		removeHeaders:  []string{"Server", "X-Powered-By"},
	}
	rw.WriteHeader(http.StatusOK)

	if rec.Header().Get("Server") != "" {
		t.Error("expected Server removed")
	}
	if rec.Header().Get("X-Powered-By") != "" {
		t.Error("expected X-Powered-By removed")
	}
}

func TestResponseHeaderWriter_DefaultModeCSP_Injects(t *testing.T) {
	rec := httptest.NewRecorder()
	// Upstream did NOT set CSP.

	rw := &responseHeaderWriter{
		ResponseWriter: rec,
		cspHeader:      "default-src 'self'",
		cspHeaderName:  "Content-Security-Policy",
	}
	rw.WriteHeader(http.StatusOK)

	got := rec.Header().Get("Content-Security-Policy")
	if got != "default-src 'self'" {
		t.Errorf("expected CSP injected, got %q", got)
	}
}

func TestResponseHeaderWriter_DefaultModeCSP_UpstreamPreserved(t *testing.T) {
	rec := httptest.NewRecorder()
	// Upstream DID set CSP.
	rec.Header().Set("Content-Security-Policy", "default-src 'none'")

	rw := &responseHeaderWriter{
		ResponseWriter: rec,
		cspHeader:      "default-src 'self'",
		cspHeaderName:  "Content-Security-Policy",
	}
	rw.WriteHeader(http.StatusOK)

	got := rec.Header().Get("Content-Security-Policy")
	if got != "default-src 'none'" {
		t.Errorf("expected upstream CSP preserved, got %q", got)
	}
}

func TestResponseHeaderWriter_ReportOnly(t *testing.T) {
	rec := httptest.NewRecorder()

	rw := &responseHeaderWriter{
		ResponseWriter: rec,
		cspHeader:      "default-src 'self'",
		cspHeaderName:  "Content-Security-Policy-Report-Only",
	}
	rw.WriteHeader(http.StatusOK)

	got := rec.Header().Get("Content-Security-Policy-Report-Only")
	if got != "default-src 'self'" {
		t.Errorf("expected report-only CSP, got %q", got)
	}
	if rec.Header().Get("Content-Security-Policy") != "" {
		t.Error("expected no non-report-only CSP")
	}
}

func TestResponseHeaderWriter_DoubleWriteHeader(t *testing.T) {
	rec := httptest.NewRecorder()
	rw := &responseHeaderWriter{
		ResponseWriter: rec,
		cspHeader:      "default-src 'self'",
		cspHeaderName:  "Content-Security-Policy",
	}
	rw.WriteHeader(http.StatusOK)
	rw.WriteHeader(http.StatusInternalServerError) // should be ignored

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rec.Code)
	}
}

func TestResponseHeaderWriter_ImplicitWriteHeader(t *testing.T) {
	rec := httptest.NewRecorder()
	rw := &responseHeaderWriter{
		ResponseWriter: rec,
		cspHeader:      "default-src 'self'",
		cspHeaderName:  "Content-Security-Policy",
	}
	// Write without calling WriteHeader — should trigger implicit 200.
	_, _ = rw.Write([]byte("hello"))

	got := rec.Header().Get("Content-Security-Policy")
	if got != "default-src 'self'" {
		t.Errorf("expected CSP set on implicit WriteHeader, got %q", got)
	}
}

func TestResponseHeaderWriter_Unwrap(t *testing.T) {
	rec := httptest.NewRecorder()
	rw := &responseHeaderWriter{ResponseWriter: rec}
	if rw.Unwrap() != rec {
		t.Error("Unwrap should return underlying ResponseWriter")
	}
}

// ─── applyResponseHeaders ───────────────────────────────────────────

func TestApplyResponseHeaders_NilConfig(t *testing.T) {
	rec := httptest.NewRecorder()
	w := applyResponseHeaders(rec, "example.com", httptest.NewRequest("GET", "/", nil), nil)
	if w != rec {
		t.Error("expected original writer for nil config")
	}
}

func TestApplyResponseHeaders_CSPSetMode(t *testing.T) {
	cfg := &ResponseHeaderConfig{
		CSP: &CSPConfig{
			GlobalDefaults: CSPPolicy{DefaultSrc: []string{"'self'"}},
		},
	}
	crh := mustCompileResponseHeaders(t, cfg)

	rec := httptest.NewRecorder()
	w := applyResponseHeaders(rec, "example.com", httptest.NewRequest("GET", "/", nil), crh)

	// "set" mode (default fallback) should set header directly — no wrapper needed.
	got := rec.Header().Get("Content-Security-Policy")
	if got != "default-src 'self'" {
		t.Errorf("expected CSP set directly, got %q", got)
	}
	// No wrapper since no "default" mode or remove headers.
	if w != rec {
		t.Error("expected no wrapper for set mode")
	}
}

func TestApplyResponseHeaders_CSPDefaultMode(t *testing.T) {
	cfg := &ResponseHeaderConfig{
		CSP: &CSPConfig{
			GlobalDefaults: CSPPolicy{DefaultSrc: []string{"'self'"}},
			Services: map[string]CSPServiceConfig{
				"app.example.com": {
					Mode:    "default",
					Inherit: true,
					Policy:  CSPPolicy{ScriptSrc: []string{"'self'"}},
				},
			},
		},
	}
	crh := mustCompileResponseHeaders(t, cfg)

	rec := httptest.NewRecorder()
	w := applyResponseHeaders(rec, "app.example.com", httptest.NewRequest("GET", "/", nil), crh)

	// "default" mode requires wrapper.
	if w == rec {
		t.Error("expected wrapper for default mode")
	}
	// Header shouldn't be set yet — it's injected on WriteHeader.
	if rec.Header().Get("Content-Security-Policy") != "" {
		t.Error("expected CSP not yet set before WriteHeader")
	}
	// Trigger WriteHeader.
	w.WriteHeader(http.StatusOK)
	got := rec.Header().Get("Content-Security-Policy")
	if got == "" {
		t.Error("expected CSP injected on WriteHeader")
	}
}

func TestApplyResponseHeaders_CSPNoneMode(t *testing.T) {
	cfg := &ResponseHeaderConfig{
		CSP: &CSPConfig{
			GlobalDefaults: CSPPolicy{DefaultSrc: []string{"'self'"}},
			Services: map[string]CSPServiceConfig{
				"api.example.com": {
					Mode: "none",
				},
			},
		},
	}
	crh := mustCompileResponseHeaders(t, cfg)

	rec := httptest.NewRecorder()
	w := applyResponseHeaders(rec, "api.example.com", httptest.NewRequest("GET", "/", nil), crh)

	if rec.Header().Get("Content-Security-Policy") != "" {
		t.Error("expected no CSP for none mode")
	}
	if w != rec {
		t.Error("expected no wrapper for none mode")
	}
}

func TestApplyResponseHeaders_SecurityHeaders(t *testing.T) {
	cfg := &ResponseHeaderConfig{
		Security: &SecurityHeaderConfig{
			Headers: map[string]string{
				"Strict-Transport-Security": "max-age=63072000; includeSubDomains; preload",
				"X-Content-Type-Options":    "nosniff",
			},
		},
	}
	crh := mustCompileResponseHeaders(t, cfg)

	rec := httptest.NewRecorder()
	w := applyResponseHeaders(rec, "example.com", httptest.NewRequest("GET", "/", nil), crh)

	if rec.Header().Get("Strict-Transport-Security") != "max-age=63072000; includeSubDomains; preload" {
		t.Error("expected HSTS header")
	}
	if rec.Header().Get("X-Content-Type-Options") != "nosniff" {
		t.Error("expected X-Content-Type-Options header")
	}
	// No remove headers, no default CSP — no wrapper.
	if w != rec {
		t.Error("expected no wrapper when no removal or default mode")
	}
}

func TestApplyResponseHeaders_SecurityHeaderRemoval(t *testing.T) {
	cfg := &ResponseHeaderConfig{
		Security: &SecurityHeaderConfig{
			Headers: map[string]string{"X-Content-Type-Options": "nosniff"},
			Remove:  []string{"Server", "X-Powered-By"},
		},
	}
	crh := mustCompileResponseHeaders(t, cfg)

	rec := httptest.NewRecorder()
	// Simulate upstream setting these headers.
	rec.Header().Set("Server", "caddy")
	rec.Header().Set("X-Powered-By", "Go")

	w := applyResponseHeaders(rec, "example.com", httptest.NewRequest("GET", "/", nil), crh)
	if w == rec {
		t.Error("expected wrapper for header removal")
	}

	// Write to trigger removal.
	w.WriteHeader(http.StatusOK)
	if rec.Header().Get("Server") != "" {
		t.Error("expected Server removed")
	}
	if rec.Header().Get("X-Powered-By") != "" {
		t.Error("expected X-Powered-By removed")
	}
	// Set headers should still be present.
	if rec.Header().Get("X-Content-Type-Options") != "nosniff" {
		t.Error("expected X-Content-Type-Options present")
	}
}

func TestApplyResponseHeaders_CSPReportOnly(t *testing.T) {
	cfg := &ResponseHeaderConfig{
		CSP: &CSPConfig{
			GlobalDefaults: CSPPolicy{DefaultSrc: []string{"'self'"}},
			Services: map[string]CSPServiceConfig{
				"app.example.com": {
					Mode:       "set",
					ReportOnly: true,
					Inherit:    true,
					Policy:     CSPPolicy{},
				},
			},
		},
	}
	crh := mustCompileResponseHeaders(t, cfg)

	rec := httptest.NewRecorder()
	_ = applyResponseHeaders(rec, "app.example.com", httptest.NewRequest("GET", "/", nil), crh)

	// Should use Report-Only header name.
	if rec.Header().Get("Content-Security-Policy-Report-Only") == "" {
		t.Error("expected Content-Security-Policy-Report-Only header")
	}
	if rec.Header().Get("Content-Security-Policy") != "" {
		t.Error("expected no non-report-only header")
	}
}

func TestApplyResponseHeaders_Combined(t *testing.T) {
	// Test both CSP and security headers together.
	cfg := &ResponseHeaderConfig{
		CSP: &CSPConfig{
			GlobalDefaults: CSPPolicy{DefaultSrc: []string{"'self'"}},
		},
		Security: &SecurityHeaderConfig{
			Headers: map[string]string{
				"X-Content-Type-Options": "nosniff",
			},
			Remove: []string{"Server"},
		},
	}
	crh := mustCompileResponseHeaders(t, cfg)

	rec := httptest.NewRecorder()
	rec.Header().Set("Server", "caddy")
	w := applyResponseHeaders(rec, "example.com", httptest.NewRequest("GET", "/", nil), crh)

	// Security header set immediately.
	if rec.Header().Get("X-Content-Type-Options") != "nosniff" {
		t.Error("expected security header")
	}
	// CSP set immediately (global fallback is "set" mode).
	if rec.Header().Get("Content-Security-Policy") != "default-src 'self'" {
		t.Error("expected CSP header")
	}
	// Wrapper needed for Server removal.
	if w == rec {
		t.Error("expected wrapper for Server removal")
	}
	w.WriteHeader(http.StatusOK)
	if rec.Header().Get("Server") != "" {
		t.Error("expected Server removed")
	}
}

// ─── Integration: ServeHTTP with response headers via rules file ────

func TestServeHTTP_ResponseHeaders(t *testing.T) {
	// Write a rules file with response_headers config.
	dir := t.TempDir()
	path := filepath.Join(dir, "policy-rules.json")
	file := PolicyRulesFile{
		Rules: []PolicyRule{
			{
				ID:      "allow-all",
				Name:    "allow all",
				Type:    "allow",
				Enabled: true,
				Conditions: []PolicyCondition{
					{Field: "path", Operator: "begins_with", Value: "/"},
				},
				GroupOp:  "and",
				Priority: 200,
			},
		},
		ResponseHeaders: &ResponseHeaderConfig{
			CSP: &CSPConfig{
				GlobalDefaults: CSPPolicy{
					DefaultSrc: []string{"'self'"},
					ScriptSrc:  []string{"'self'", "'unsafe-inline'"},
				},
			},
			Security: &SecurityHeaderConfig{
				Headers: map[string]string{
					"X-Content-Type-Options": "nosniff",
					"Referrer-Policy":        "strict-origin-when-cross-origin",
				},
				Remove: []string{"X-Powered-By"},
			},
		},
		Generated: time.Now().UTC().Format(time.RFC3339),
		Version:   1,
	}
	data, err := json.MarshalIndent(file, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0644); err != nil {
		t.Fatal(err)
	}

	pe := &PolicyEngine{RulesFile: path}
	mustProvision(t, pe)
	defer pe.Cleanup()

	r := makeRequest("GET", "/test", "10.0.0.1:1234")
	r.Host = "example.com"
	rec := httptest.NewRecorder()

	next := &nextHandler{}
	err = pe.ServeHTTP(rec, r, next)
	if err != nil {
		t.Fatalf("ServeHTTP error: %v", err)
	}
	if !next.called {
		t.Error("expected next handler called")
	}

	// Check CSP header.
	csp := rec.Header().Get("Content-Security-Policy")
	if csp == "" {
		t.Error("expected Content-Security-Policy header")
	}
	if !containsSubstr(csp, "default-src 'self'") {
		t.Errorf("expected default-src in CSP, got %q", csp)
	}

	// Check security headers.
	if rec.Header().Get("X-Content-Type-Options") != "nosniff" {
		t.Error("expected X-Content-Type-Options")
	}
	if rec.Header().Get("Referrer-Policy") != "strict-origin-when-cross-origin" {
		t.Error("expected Referrer-Policy")
	}

	// Check removed header (set by nextHandler implicitly via ResponseWriter).
	// Note: X-Powered-By removal happens on WriteHeader, which nextHandler calls.
	if rec.Header().Get("X-Powered-By") != "" {
		t.Error("expected X-Powered-By removed")
	}
}

func TestServeHTTP_ResponseHeaders_PerService(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "policy-rules.json")
	file := PolicyRulesFile{
		Rules: []PolicyRule{},
		ResponseHeaders: &ResponseHeaderConfig{
			CSP: &CSPConfig{
				GlobalDefaults: CSPPolicy{
					DefaultSrc: []string{"'self'"},
				},
				Services: map[string]CSPServiceConfig{
					"app.example.com": {
						Mode:    "set",
						Inherit: true,
						Policy: CSPPolicy{
							ScriptSrc: []string{"'self'", "cdn.example.com"},
						},
					},
				},
			},
		},
		Generated: time.Now().UTC().Format(time.RFC3339),
		Version:   1,
	}
	data, err := json.MarshalIndent(file, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0644); err != nil {
		t.Fatal(err)
	}

	pe := &PolicyEngine{RulesFile: path}
	mustProvision(t, pe)
	defer pe.Cleanup()

	// Request to app.example.com — should get per-service CSP.
	r1 := makeRequest("GET", "/", "10.0.0.1:1234")
	r1.Host = "app.example.com"
	rec1 := httptest.NewRecorder()
	next1 := &nextHandler{}
	if err := pe.ServeHTTP(rec1, r1, next1); err != nil {
		t.Fatal(err)
	}
	csp1 := rec1.Header().Get("Content-Security-Policy")
	if !containsSubstr(csp1, "cdn.example.com") {
		t.Errorf("expected per-service CSP with cdn.example.com, got %q", csp1)
	}

	// Request to other.example.com — should get global fallback.
	r2 := makeRequest("GET", "/", "10.0.0.1:1234")
	r2.Host = "other.example.com"
	rec2 := httptest.NewRecorder()
	next2 := &nextHandler{}
	if err := pe.ServeHTTP(rec2, r2, next2); err != nil {
		t.Fatal(err)
	}
	csp2 := rec2.Header().Get("Content-Security-Policy")
	if !containsSubstr(csp2, "default-src 'self'") {
		t.Errorf("expected global fallback CSP, got %q", csp2)
	}
	if containsSubstr(csp2, "cdn.example.com") {
		t.Errorf("expected no per-service CDN in global fallback, got %q", csp2)
	}
}

func TestServeHTTP_ResponseHeaders_BlockRuleSkipsHeaders(t *testing.T) {
	// Block rules return early (403) — response headers should NOT be applied
	// since the response is an error page handled by Caddy's handle_errors.
	dir := t.TempDir()
	path := filepath.Join(dir, "policy-rules.json")
	file := PolicyRulesFile{
		Rules: []PolicyRule{
			{
				ID:      "block-admin",
				Name:    "block admin",
				Type:    "block",
				Enabled: true,
				Conditions: []PolicyCondition{
					{Field: "path", Operator: "eq", Value: "/admin"},
				},
				GroupOp:  "and",
				Priority: 100,
			},
		},
		ResponseHeaders: &ResponseHeaderConfig{
			CSP: &CSPConfig{
				GlobalDefaults: CSPPolicy{DefaultSrc: []string{"'self'"}},
			},
		},
		Generated: time.Now().UTC().Format(time.RFC3339),
		Version:   1,
	}
	data, _ := json.MarshalIndent(file, "", "  ")
	os.WriteFile(path, data, 0644)

	pe := &PolicyEngine{RulesFile: path}
	mustProvision(t, pe)
	defer pe.Cleanup()

	r := makeRequest("GET", "/admin", "10.0.0.1:1234")
	r.Host = "example.com"
	rec := httptest.NewRecorder()
	next := &nextHandler{}
	err := pe.ServeHTTP(rec, r, next)

	// Should return error (block).
	if err == nil {
		t.Error("expected error from block rule")
	}
	if next.called {
		t.Error("expected next handler NOT called on block")
	}
	// CSP should NOT be set (block returns before applyResponseHeaders).
	if rec.Header().Get("Content-Security-Policy") != "" {
		t.Error("expected no CSP on blocked request")
	}
}

func TestServeHTTP_ResponseHeaders_HotReload(t *testing.T) {
	// Test that response headers are updated on hot reload.
	dir := t.TempDir()
	path := filepath.Join(dir, "policy-rules.json")

	// Initial: CSP with 'self'.
	file1 := PolicyRulesFile{
		Rules: []PolicyRule{},
		ResponseHeaders: &ResponseHeaderConfig{
			CSP: &CSPConfig{
				GlobalDefaults: CSPPolicy{DefaultSrc: []string{"'self'"}},
			},
		},
		Generated: time.Now().UTC().Format(time.RFC3339),
		Version:   1,
	}
	data1, _ := json.MarshalIndent(file1, "", "  ")
	os.WriteFile(path, data1, 0644)

	pe := &PolicyEngine{RulesFile: path}
	mustProvision(t, pe)
	defer pe.Cleanup()

	// Verify initial CSP.
	r1 := makeRequest("GET", "/", "10.0.0.1:1234")
	r1.Host = "example.com"
	rec1 := httptest.NewRecorder()
	pe.ServeHTTP(rec1, r1, &nextHandler{})
	csp1 := rec1.Header().Get("Content-Security-Policy")
	if csp1 != "default-src 'self'" {
		t.Errorf("initial CSP: got %q, want %q", csp1, "default-src 'self'")
	}

	// Update: CSP with 'self' and https:.
	file2 := PolicyRulesFile{
		Rules: []PolicyRule{},
		ResponseHeaders: &ResponseHeaderConfig{
			CSP: &CSPConfig{
				GlobalDefaults: CSPPolicy{DefaultSrc: []string{"'self'", "https:"}},
			},
		},
		Generated: time.Now().UTC().Format(time.RFC3339),
		Version:   1,
	}
	data2, _ := json.MarshalIndent(file2, "", "  ")
	// Sleep to ensure mtime changes (some filesystems have 1-second granularity).
	time.Sleep(50 * time.Millisecond)
	os.WriteFile(path, data2, 0644)

	// Trigger reload.
	if err := pe.loadFromFile(); err != nil {
		t.Fatalf("loadFromFile: %v", err)
	}

	// Verify updated CSP.
	r2 := makeRequest("GET", "/", "10.0.0.1:1234")
	r2.Host = "example.com"
	rec2 := httptest.NewRecorder()
	pe.ServeHTTP(rec2, r2, &nextHandler{})
	csp2 := rec2.Header().Get("Content-Security-Policy")
	want2 := "default-src 'self' https:"
	if csp2 != want2 {
		t.Errorf("updated CSP: got %q, want %q", csp2, want2)
	}
}

func TestServeHTTP_NoResponseHeaders(t *testing.T) {
	// Rules file with no response_headers — should work fine (nil respHeaders).
	dir := t.TempDir()
	path := filepath.Join(dir, "policy-rules.json")
	file := PolicyRulesFile{
		Rules:     []PolicyRule{},
		Generated: time.Now().UTC().Format(time.RFC3339),
		Version:   1,
	}
	data, _ := json.MarshalIndent(file, "", "  ")
	os.WriteFile(path, data, 0644)

	pe := &PolicyEngine{RulesFile: path}
	mustProvision(t, pe)
	defer pe.Cleanup()

	r := makeRequest("GET", "/", "10.0.0.1:1234")
	r.Host = "example.com"
	rec := httptest.NewRecorder()
	next := &nextHandler{}
	if err := pe.ServeHTTP(rec, r, next); err != nil {
		t.Fatal(err)
	}
	if !next.called {
		t.Error("expected next called")
	}
	if rec.Header().Get("Content-Security-Policy") != "" {
		t.Error("expected no CSP when response_headers absent")
	}
}

// ─── Security Preset Tests ──────────────────────────────────────────

func TestCompileResponseHeaders_SecurityPresetStrict(t *testing.T) {
	cfg := &ResponseHeaderConfig{
		Security: &SecurityHeaderConfig{
			Preset: "strict",
		},
	}
	result := mustCompileResponseHeaders(t, cfg)
	if result == nil || result.security == nil {
		t.Fatal("expected compiled security")
	}
	// Check all strict preset headers are present.
	for k, v := range strictPreset {
		if result.security.headers[k] != v {
			t.Errorf("expected preset %q=%q, got %q", k, v, result.security.headers[k])
		}
	}
}

func TestCompileResponseHeaders_SecurityPresetModerate(t *testing.T) {
	cfg := &ResponseHeaderConfig{
		Security: &SecurityHeaderConfig{
			Preset: "moderate",
		},
	}
	result := mustCompileResponseHeaders(t, cfg)
	if result == nil || result.security == nil {
		t.Fatal("expected compiled security")
	}
	for k, v := range moderatePreset {
		if result.security.headers[k] != v {
			t.Errorf("expected preset %q=%q, got %q", k, v, result.security.headers[k])
		}
	}
	// Strict-only headers should NOT be present.
	if _, ok := result.security.headers["Strict-Transport-Security"]; ok {
		t.Error("expected no HSTS in moderate preset")
	}
}

func TestCompileResponseHeaders_SecurityPresetOverriddenByExplicit(t *testing.T) {
	cfg := &ResponseHeaderConfig{
		Security: &SecurityHeaderConfig{
			Preset: "strict",
			Headers: map[string]string{
				"X-Frame-Options": "SAMEORIGIN", // override strict's DENY
			},
		},
	}
	result := mustCompileResponseHeaders(t, cfg)
	if result == nil || result.security == nil {
		t.Fatal("expected compiled security")
	}
	// Explicit header should override preset.
	if result.security.headers["X-Frame-Options"] != "SAMEORIGIN" {
		t.Errorf("expected explicit override, got %q", result.security.headers["X-Frame-Options"])
	}
	// Other preset headers should still be present.
	if result.security.headers["X-Content-Type-Options"] != "nosniff" {
		t.Error("expected preset X-Content-Type-Options preserved")
	}
}

func TestCompileResponseHeaders_SecurityPresetUnknown(t *testing.T) {
	cfg := &ResponseHeaderConfig{
		Security: &SecurityHeaderConfig{
			Preset: "maximum",
		},
	}
	_, err := compileResponseHeaders(cfg)
	if err == nil {
		t.Fatal("expected error for unknown preset")
	}
	if !containsSubstr(err.Error(), "unknown preset") {
		t.Errorf("expected 'unknown preset' in error, got %q", err.Error())
	}
}

func TestCompileResponseHeaders_SecurityPresetEmpty(t *testing.T) {
	// Empty preset should produce no preset headers.
	cfg := &ResponseHeaderConfig{
		Security: &SecurityHeaderConfig{
			Headers: map[string]string{"X-Custom": "value"},
		},
	}
	result := mustCompileResponseHeaders(t, cfg)
	if result.security.headers["X-Custom"] != "value" {
		t.Error("expected explicit header")
	}
	if _, ok := result.security.headers["Strict-Transport-Security"]; ok {
		t.Error("expected no HSTS without preset")
	}
}

func TestCompileResponseHeaders_SecurityPresetPerServiceMerge(t *testing.T) {
	// Per-service overrides should merge with preset base.
	cfg := &ResponseHeaderConfig{
		Security: &SecurityHeaderConfig{
			Preset: "strict",
			PerService: map[string]SecurityServiceOverride{
				"api.example.com": {
					Headers: map[string]string{
						"X-Frame-Options": "SAMEORIGIN",
					},
				},
			},
		},
	}
	result := mustCompileResponseHeaders(t, cfg)
	svc, ok := result.security.services["api.example.com"]
	if !ok {
		t.Fatal("expected per-service override")
	}
	// Override should replace preset value.
	if svc.headers["X-Frame-Options"] != "SAMEORIGIN" {
		t.Errorf("expected per-service override, got %q", svc.headers["X-Frame-Options"])
	}
	// Other preset headers should be inherited.
	if svc.headers["X-Content-Type-Options"] != "nosniff" {
		t.Error("expected inherited preset header")
	}
}

// ─── CSP Fallback Mode Tests ────────────────────────────────────────

func TestCompileResponseHeaders_CSPFallbackModeDefault(t *testing.T) {
	// When no Mode is set on CSPConfig, fallback should use "set".
	cfg := &ResponseHeaderConfig{
		CSP: &CSPConfig{
			GlobalDefaults: CSPPolicy{DefaultSrc: []string{"'self'"}},
		},
	}
	result := mustCompileResponseHeaders(t, cfg)
	if result.csp.fallback.mode != "set" {
		t.Errorf("expected fallback mode 'set', got %q", result.csp.fallback.mode)
	}
	if result.csp.fallback.reportOnly {
		t.Error("expected reportOnly false by default")
	}
}

func TestCompileResponseHeaders_CSPFallbackModeConfigured(t *testing.T) {
	// Configure fallback mode to "default" and report_only to true.
	cfg := &ResponseHeaderConfig{
		CSP: &CSPConfig{
			Mode:           "default",
			ReportOnly:     true,
			GlobalDefaults: CSPPolicy{DefaultSrc: []string{"'self'"}},
		},
	}
	result := mustCompileResponseHeaders(t, cfg)
	if result.csp.fallback.mode != "default" {
		t.Errorf("expected fallback mode 'default', got %q", result.csp.fallback.mode)
	}
	if !result.csp.fallback.reportOnly {
		t.Error("expected reportOnly true")
	}
}

func TestCompileResponseHeaders_CSPFallbackModeNone(t *testing.T) {
	cfg := &ResponseHeaderConfig{
		CSP: &CSPConfig{
			Mode:           "none",
			GlobalDefaults: CSPPolicy{DefaultSrc: []string{"'self'"}},
		},
	}
	result := mustCompileResponseHeaders(t, cfg)
	if result.csp.fallback.mode != "none" {
		t.Errorf("expected fallback mode 'none', got %q", result.csp.fallback.mode)
	}
}

func TestCompileResponseHeaders_CSPFallbackModeInvalid(t *testing.T) {
	cfg := &ResponseHeaderConfig{
		CSP: &CSPConfig{
			Mode:           "enforce",
			GlobalDefaults: CSPPolicy{DefaultSrc: []string{"'self'"}},
		},
	}
	_, err := compileResponseHeaders(cfg)
	if err == nil {
		t.Fatal("expected error for invalid CSP mode")
	}
	if !containsSubstr(err.Error(), "unknown") {
		t.Errorf("expected 'unknown' in error, got %q", err.Error())
	}
}

func TestApplyResponseHeaders_CSPFallbackDefaultMode(t *testing.T) {
	// Global fallback with mode "default" should use wrapper.
	cfg := &ResponseHeaderConfig{
		CSP: &CSPConfig{
			Mode:           "default",
			GlobalDefaults: CSPPolicy{DefaultSrc: []string{"'self'"}},
		},
	}
	crh := mustCompileResponseHeaders(t, cfg)

	rec := httptest.NewRecorder()
	w := applyResponseHeaders(rec, "unknown.example.com", httptest.NewRequest("GET", "/", nil), crh)

	// "default" mode requires wrapper (CSP injected on WriteHeader if absent).
	if w == rec {
		t.Error("expected wrapper for default fallback mode")
	}
	// CSP should not be set yet.
	if rec.Header().Get("Content-Security-Policy") != "" {
		t.Error("expected no CSP before WriteHeader")
	}
	w.WriteHeader(http.StatusOK)
	if rec.Header().Get("Content-Security-Policy") != "default-src 'self'" {
		t.Errorf("expected CSP injected on WriteHeader, got %q", rec.Header().Get("Content-Security-Policy"))
	}
}

func TestApplyResponseHeaders_CSPFallbackReportOnly(t *testing.T) {
	cfg := &ResponseHeaderConfig{
		CSP: &CSPConfig{
			ReportOnly:     true,
			GlobalDefaults: CSPPolicy{DefaultSrc: []string{"'self'"}},
		},
	}
	crh := mustCompileResponseHeaders(t, cfg)

	rec := httptest.NewRecorder()
	_ = applyResponseHeaders(rec, "any.example.com", httptest.NewRequest("GET", "/", nil), crh)

	// Report-only header should be used.
	if rec.Header().Get("Content-Security-Policy-Report-Only") != "default-src 'self'" {
		t.Errorf("expected report-only CSP, got %q", rec.Header().Get("Content-Security-Policy-Report-Only"))
	}
	if rec.Header().Get("Content-Security-Policy") != "" {
		t.Error("expected no enforcing CSP header")
	}
}

// ─── Hijacker / Flusher Interface Tests ─────────────────────────────

type fakeHijacker struct {
	http.ResponseWriter
	hijacked bool
}

func (fh *fakeHijacker) Hijack() (interface{ Close() error }, interface{}, error) {
	fh.hijacked = true
	return nil, nil, nil
}

func TestResponseHeaderWriter_Hijack_Supported(t *testing.T) {
	// When the underlying ResponseWriter implements http.Hijacker,
	// the wrapper should delegate.
	rec := httptest.NewRecorder()
	rw := &responseHeaderWriter{
		ResponseWriter: rec,
	}
	// httptest.ResponseRecorder implements Hijacker in newer Go versions.
	// If not, the Hijack method should return http.ErrNotSupported.
	_, _, err := rw.Hijack()
	// We just check it doesn't panic — the actual behavior depends on
	// whether httptest.ResponseRecorder implements Hijacker.
	_ = err
}

func TestResponseHeaderWriter_Flush(t *testing.T) {
	rec := httptest.NewRecorder()
	rw := &responseHeaderWriter{
		ResponseWriter: rec,
	}
	// Should not panic; httptest.ResponseRecorder implements http.Flusher.
	rw.Flush()
	if !rw.wroteHeader {
		t.Error("Flush should trigger WriteHeader")
	}
}

// ─── compileCORSSettings ────────────────────────────────────────────

func mustCompileCORSSettings(t *testing.T, s CORSSettings) *compiledCORSSettings {
	t.Helper()
	cs, err := compileCORSSettings(s)
	if err != nil {
		t.Fatalf("compileCORSSettings: %v", err)
	}
	return cs
}

func TestCompileCORSSettings_ExactOriginMatch(t *testing.T) {
	cs := mustCompileCORSSettings(t, CORSSettings{
		AllowedOrigins: []string{"https://example.com", "https://app.example.com"},
	})
	if len(cs.allowedOrigins) != 2 {
		t.Fatalf("expected 2 exact origins, got %d", len(cs.allowedOrigins))
	}
	// Origins should be normalized (lowercased).
	if cs.allowedOrigins[0] != "https://example.com" {
		t.Errorf("expected https://example.com, got %q", cs.allowedOrigins[0])
	}
}

func TestCompileCORSSettings_RegexAutoAnchoring(t *testing.T) {
	cs := mustCompileCORSSettings(t, CORSSettings{
		AllowedOrigins: []string{`^https://.*\.example\.com$`},
	})
	if len(cs.originPatterns) != 1 {
		t.Fatalf("expected 1 regex pattern, got %d", len(cs.originPatterns))
	}
	// Already anchored — should not double-anchor.
	pattern := cs.originPatterns[0].String()
	if pattern != `^https://.*\.example\.com$` {
		t.Errorf("unexpected pattern: %q", pattern)
	}
}

func TestCompileCORSSettings_RegexAutoAnchoringAddsAnchors(t *testing.T) {
	// Pattern without anchors that looks like regex (contains ".*").
	cs := mustCompileCORSSettings(t, CORSSettings{
		AllowedOrigins: []string{`https://.*\.example\.com`},
	})
	if len(cs.originPatterns) != 1 {
		t.Fatalf("expected 1 regex pattern, got %d", len(cs.originPatterns))
	}
	pattern := cs.originPatterns[0].String()
	if pattern != `^https://.*\.example\.com$` {
		t.Errorf("expected auto-anchored pattern, got %q", pattern)
	}
}

func TestCompileCORSSettings_NullRejection(t *testing.T) {
	_, err := compileCORSSettings(CORSSettings{
		AllowedOrigins: []string{"null"},
	})
	if err == nil {
		t.Fatal("expected error for 'null' origin")
	}
	if !containsSubstr(err.Error(), "null") {
		t.Errorf("expected error about null origin, got: %v", err)
	}
}

func TestCompileCORSSettings_NullRejectionCaseInsensitive(t *testing.T) {
	_, err := compileCORSSettings(CORSSettings{
		AllowedOrigins: []string{"NULL"},
	})
	if err == nil {
		t.Fatal("expected error for 'NULL' origin (case-insensitive)")
	}
}

func TestCompileCORSSettings_CredentialsWithWildcardRegex(t *testing.T) {
	_, err := compileCORSSettings(CORSSettings{
		AllowedOrigins:   []string{`^https://.*`},
		AllowCredentials: true,
	})
	if err == nil {
		t.Fatal("expected error for AllowCredentials with broad regex")
	}
	if !containsSubstr(err.Error(), "AllowCredentials") {
		t.Errorf("expected credential theft warning, got: %v", err)
	}
}

func TestCompileCORSSettings_CredentialsWithNarrowRegex(t *testing.T) {
	// Narrow regex that doesn't match evil.example.com should be allowed.
	cs := mustCompileCORSSettings(t, CORSSettings{
		AllowedOrigins:   []string{`^https://app\.example\.com$`},
		AllowCredentials: true,
	})
	if !cs.allowCredentials {
		t.Error("expected allowCredentials true")
	}
}

func TestCompileCORSSettings_InvalidRegex(t *testing.T) {
	_, err := compileCORSSettings(CORSSettings{
		AllowedOrigins: []string{`^https://[invalid`},
	})
	if err == nil {
		t.Fatal("expected error for invalid regex")
	}
	if !containsSubstr(err.Error(), "invalid origin regex") {
		t.Errorf("expected regex error, got: %v", err)
	}
}

func TestCompileCORSSettings_DefaultMethods(t *testing.T) {
	cs := mustCompileCORSSettings(t, CORSSettings{})
	if cs.allowedMethods != "GET, POST, PUT, PATCH, DELETE, OPTIONS" {
		t.Errorf("expected default methods, got %q", cs.allowedMethods)
	}
}

func TestCompileCORSSettings_DefaultHeaders(t *testing.T) {
	cs := mustCompileCORSSettings(t, CORSSettings{})
	if cs.allowedHeaders != "Content-Type, Authorization" {
		t.Errorf("expected default headers, got %q", cs.allowedHeaders)
	}
}

func TestCompileCORSSettings_DefaultMaxAge(t *testing.T) {
	cs := mustCompileCORSSettings(t, CORSSettings{})
	if cs.maxAge != "3600" {
		t.Errorf("expected default max-age 3600, got %q", cs.maxAge)
	}
}

func TestCompileCORSSettings_CustomMaxAge(t *testing.T) {
	cs := mustCompileCORSSettings(t, CORSSettings{MaxAge: 7200})
	if cs.maxAge != "7200" {
		t.Errorf("expected max-age 7200, got %q", cs.maxAge)
	}
}

// ─── matchOrigin ────────────────────────────────────────────────────

func TestMatchOrigin_AllowedOrigin(t *testing.T) {
	cs := mustCompileCORSSettings(t, CORSSettings{
		AllowedOrigins: []string{"https://example.com"},
	})
	if !cs.matchOrigin("https://example.com") {
		t.Error("expected match for exact allowed origin")
	}
}

func TestMatchOrigin_AllowedOriginCaseInsensitive(t *testing.T) {
	cs := mustCompileCORSSettings(t, CORSSettings{
		AllowedOrigins: []string{"https://example.com"},
	})
	if !cs.matchOrigin("https://EXAMPLE.COM") {
		t.Error("expected case-insensitive match")
	}
}

func TestMatchOrigin_AllowedOriginDefaultPortStripped(t *testing.T) {
	cs := mustCompileCORSSettings(t, CORSSettings{
		AllowedOrigins: []string{"https://example.com"},
	})
	if !cs.matchOrigin("https://example.com:443") {
		t.Error("expected match with default port stripped")
	}
}

func TestMatchOrigin_RejectedOrigin(t *testing.T) {
	cs := mustCompileCORSSettings(t, CORSSettings{
		AllowedOrigins: []string{"https://example.com"},
	})
	if cs.matchOrigin("https://evil.com") {
		t.Error("expected no match for non-allowed origin")
	}
}

func TestMatchOrigin_RegexMatch(t *testing.T) {
	cs := mustCompileCORSSettings(t, CORSSettings{
		AllowedOrigins: []string{`^https://.*\.example\.com$`},
	})
	if !cs.matchOrigin("https://app.example.com") {
		t.Error("expected regex match")
	}
	if cs.matchOrigin("https://evil.com") {
		t.Error("expected no match for non-matching origin")
	}
}

func TestMatchOrigin_EmptyOrigin(t *testing.T) {
	cs := mustCompileCORSSettings(t, CORSSettings{
		AllowedOrigins: []string{"https://example.com"},
	})
	if cs.matchOrigin("") {
		t.Error("expected no match for empty origin")
	}
}

func TestMatchOrigin_NilSettings(t *testing.T) {
	var cs *compiledCORSSettings
	if cs.matchOrigin("https://example.com") {
		t.Error("expected no match for nil settings")
	}
}

// ─── HandlePreflight ────────────────────────────────────────────────

func TestHandlePreflight_CorrectHeaders(t *testing.T) {
	cfg := &ResponseHeaderConfig{
		CORS: &CORSConfig{
			Global: CORSSettings{
				AllowedOrigins: []string{"https://example.com"},
				AllowedMethods: []string{"GET", "POST"},
				AllowedHeaders: []string{"Content-Type", "X-Custom"},
				MaxAge:         600,
			},
		},
	}
	crh := mustCompileResponseHeaders(t, cfg)

	rec := httptest.NewRecorder()
	r := httptest.NewRequest("OPTIONS", "/api/test", nil)
	r.Header.Set("Origin", "https://example.com")
	r.Header.Set("Access-Control-Request-Method", "POST")
	r.Host = "api.example.com"

	handled := crh.HandlePreflight(rec, r)
	if !handled {
		t.Fatal("expected preflight to be handled")
	}
	if rec.Code != http.StatusNoContent {
		t.Errorf("expected 204, got %d", rec.Code)
	}
	if rec.Header().Get("Access-Control-Allow-Origin") != "https://example.com" {
		t.Errorf("unexpected Allow-Origin: %q", rec.Header().Get("Access-Control-Allow-Origin"))
	}
	if rec.Header().Get("Access-Control-Allow-Methods") != "GET, POST" {
		t.Errorf("unexpected Allow-Methods: %q", rec.Header().Get("Access-Control-Allow-Methods"))
	}
	if rec.Header().Get("Access-Control-Allow-Headers") != "Content-Type, X-Custom" {
		t.Errorf("unexpected Allow-Headers: %q", rec.Header().Get("Access-Control-Allow-Headers"))
	}
	if rec.Header().Get("Access-Control-Max-Age") != "600" {
		t.Errorf("unexpected Max-Age: %q", rec.Header().Get("Access-Control-Max-Age"))
	}
}

func TestHandlePreflight_VaryHeader(t *testing.T) {
	cfg := &ResponseHeaderConfig{
		CORS: &CORSConfig{
			Global: CORSSettings{
				AllowedOrigins: []string{"https://example.com"},
			},
		},
	}
	crh := mustCompileResponseHeaders(t, cfg)

	rec := httptest.NewRecorder()
	r := httptest.NewRequest("OPTIONS", "/api/test", nil)
	r.Header.Set("Origin", "https://example.com")
	r.Header.Set("Access-Control-Request-Method", "GET")
	r.Host = "api.example.com"

	crh.HandlePreflight(rec, r)

	vary := rec.Header().Get("Vary")
	if !containsSubstr(vary, "Origin") {
		t.Errorf("Vary missing 'Origin': %q", vary)
	}
	if !containsSubstr(vary, "Access-Control-Request-Method") {
		t.Errorf("Vary missing 'Access-Control-Request-Method': %q", vary)
	}
	if !containsSubstr(vary, "Access-Control-Request-Headers") {
		t.Errorf("Vary missing 'Access-Control-Request-Headers': %q", vary)
	}
}

func TestHandlePreflight_WithCredentials(t *testing.T) {
	cfg := &ResponseHeaderConfig{
		CORS: &CORSConfig{
			Global: CORSSettings{
				AllowedOrigins:   []string{"https://example.com"},
				AllowCredentials: true,
			},
		},
	}
	crh := mustCompileResponseHeaders(t, cfg)

	rec := httptest.NewRecorder()
	r := httptest.NewRequest("OPTIONS", "/api/test", nil)
	r.Header.Set("Origin", "https://example.com")
	r.Header.Set("Access-Control-Request-Method", "GET")
	r.Host = "api.example.com"

	crh.HandlePreflight(rec, r)
	if rec.Header().Get("Access-Control-Allow-Credentials") != "true" {
		t.Error("expected Access-Control-Allow-Credentials: true")
	}
}

func TestHandlePreflight_NonPreflightOptionsNotHandled(t *testing.T) {
	cfg := &ResponseHeaderConfig{
		CORS: &CORSConfig{
			Global: CORSSettings{
				AllowedOrigins: []string{"https://example.com"},
			},
		},
	}
	crh := mustCompileResponseHeaders(t, cfg)

	// OPTIONS request without CORS preflight markers.
	rec := httptest.NewRecorder()
	r := httptest.NewRequest("OPTIONS", "/api/test", nil)
	r.Host = "api.example.com"
	// No Origin or Access-Control-Request-Method.

	handled := crh.HandlePreflight(rec, r)
	if handled {
		t.Error("expected non-preflight OPTIONS to not be handled")
	}
}

func TestHandlePreflight_MissingRequestMethod(t *testing.T) {
	cfg := &ResponseHeaderConfig{
		CORS: &CORSConfig{
			Global: CORSSettings{
				AllowedOrigins: []string{"https://example.com"},
			},
		},
	}
	crh := mustCompileResponseHeaders(t, cfg)

	// OPTIONS with Origin but no Access-Control-Request-Method.
	rec := httptest.NewRecorder()
	r := httptest.NewRequest("OPTIONS", "/api/test", nil)
	r.Header.Set("Origin", "https://example.com")
	r.Host = "api.example.com"

	handled := crh.HandlePreflight(rec, r)
	if handled {
		t.Error("expected preflight without ACRM to not be handled")
	}
}

func TestHandlePreflight_NonMatchingOriginNotHandled(t *testing.T) {
	cfg := &ResponseHeaderConfig{
		CORS: &CORSConfig{
			Global: CORSSettings{
				AllowedOrigins: []string{"https://example.com"},
			},
		},
	}
	crh := mustCompileResponseHeaders(t, cfg)

	rec := httptest.NewRecorder()
	r := httptest.NewRequest("OPTIONS", "/api/test", nil)
	r.Header.Set("Origin", "https://evil.com")
	r.Header.Set("Access-Control-Request-Method", "GET")
	r.Host = "api.example.com"

	handled := crh.HandlePreflight(rec, r)
	if handled {
		t.Error("expected non-matching origin to not be handled")
	}
	if rec.Header().Get("Access-Control-Allow-Origin") != "" {
		t.Error("expected no CORS headers for non-matching origin")
	}
}

func TestHandlePreflight_NonOptionsMethodNotHandled(t *testing.T) {
	cfg := &ResponseHeaderConfig{
		CORS: &CORSConfig{
			Global: CORSSettings{
				AllowedOrigins: []string{"https://example.com"},
			},
		},
	}
	crh := mustCompileResponseHeaders(t, cfg)

	rec := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/api/test", nil)
	r.Header.Set("Origin", "https://example.com")
	r.Header.Set("Access-Control-Request-Method", "GET")
	r.Host = "api.example.com"

	handled := crh.HandlePreflight(rec, r)
	if handled {
		t.Error("expected GET request to not be handled as preflight")
	}
}

func TestHandlePreflight_NilConfig(t *testing.T) {
	var crh *compiledResponseHeaders
	rec := httptest.NewRecorder()
	r := httptest.NewRequest("OPTIONS", "/", nil)
	r.Header.Set("Origin", "https://example.com")
	r.Header.Set("Access-Control-Request-Method", "GET")

	handled := crh.HandlePreflight(rec, r)
	if handled {
		t.Error("expected nil config to not handle preflight")
	}
}

// ─── ApplyCORSHeaders ───────────────────────────────────────────────

func TestApplyCORSHeaders_VaryOriginAlwaysSet(t *testing.T) {
	cfg := &ResponseHeaderConfig{
		CORS: &CORSConfig{
			Global: CORSSettings{
				AllowedOrigins: []string{"https://example.com"},
			},
		},
	}
	crh := mustCompileResponseHeaders(t, cfg)

	// Non-matching origin — Vary: Origin should still be set.
	rec := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/api/test", nil)
	r.Header.Set("Origin", "https://evil.com")
	r.Host = "api.example.com"

	crh.ApplyCORSHeaders(rec, r)
	if rec.Header().Get("Vary") != "Origin" {
		t.Errorf("expected Vary: Origin even for non-matching origin, got %q", rec.Header().Get("Vary"))
	}
	// Should NOT set Allow-Origin for non-matching origin.
	if rec.Header().Get("Access-Control-Allow-Origin") != "" {
		t.Error("expected no Allow-Origin for non-matching origin")
	}
}

func TestApplyCORSHeaders_VaryOriginWithoutOriginHeader(t *testing.T) {
	cfg := &ResponseHeaderConfig{
		CORS: &CORSConfig{
			Global: CORSSettings{
				AllowedOrigins: []string{"https://example.com"},
			},
		},
	}
	crh := mustCompileResponseHeaders(t, cfg)

	// Request without Origin header — Vary: Origin should still be set.
	rec := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/api/test", nil)
	r.Host = "api.example.com"

	crh.ApplyCORSHeaders(rec, r)
	if rec.Header().Get("Vary") != "Origin" {
		t.Errorf("expected Vary: Origin even without Origin header, got %q", rec.Header().Get("Vary"))
	}
}

func TestApplyCORSHeaders_CredentialsHeader(t *testing.T) {
	cfg := &ResponseHeaderConfig{
		CORS: &CORSConfig{
			Global: CORSSettings{
				AllowedOrigins:   []string{"https://example.com"},
				AllowCredentials: true,
			},
		},
	}
	crh := mustCompileResponseHeaders(t, cfg)

	rec := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/api/test", nil)
	r.Header.Set("Origin", "https://example.com")
	r.Host = "api.example.com"

	crh.ApplyCORSHeaders(rec, r)
	if rec.Header().Get("Access-Control-Allow-Credentials") != "true" {
		t.Error("expected Access-Control-Allow-Credentials: true")
	}
}

func TestApplyCORSHeaders_OriginReflection(t *testing.T) {
	cfg := &ResponseHeaderConfig{
		CORS: &CORSConfig{
			Global: CORSSettings{
				AllowedOrigins: []string{"https://example.com", "https://app.example.com"},
			},
		},
	}
	crh := mustCompileResponseHeaders(t, cfg)

	// First origin.
	rec1 := httptest.NewRecorder()
	r1 := httptest.NewRequest("GET", "/api/test", nil)
	r1.Header.Set("Origin", "https://example.com")
	r1.Host = "api.example.com"
	crh.ApplyCORSHeaders(rec1, r1)
	if rec1.Header().Get("Access-Control-Allow-Origin") != "https://example.com" {
		t.Errorf("expected origin reflection, got %q", rec1.Header().Get("Access-Control-Allow-Origin"))
	}

	// Second origin — should reflect that origin, not the first.
	rec2 := httptest.NewRecorder()
	r2 := httptest.NewRequest("GET", "/api/test", nil)
	r2.Header.Set("Origin", "https://app.example.com")
	r2.Host = "api.example.com"
	crh.ApplyCORSHeaders(rec2, r2)
	if rec2.Header().Get("Access-Control-Allow-Origin") != "https://app.example.com" {
		t.Errorf("expected origin reflection for second origin, got %q", rec2.Header().Get("Access-Control-Allow-Origin"))
	}
}

func TestApplyCORSHeaders_ExposedHeaders(t *testing.T) {
	cfg := &ResponseHeaderConfig{
		CORS: &CORSConfig{
			Global: CORSSettings{
				AllowedOrigins: []string{"https://example.com"},
				ExposedHeaders: []string{"X-Request-Id", "X-Custom"},
			},
		},
	}
	crh := mustCompileResponseHeaders(t, cfg)

	rec := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/api/test", nil)
	r.Header.Set("Origin", "https://example.com")
	r.Host = "api.example.com"

	crh.ApplyCORSHeaders(rec, r)
	if rec.Header().Get("Access-Control-Expose-Headers") != "X-Request-Id, X-Custom" {
		t.Errorf("expected exposed headers, got %q", rec.Header().Get("Access-Control-Expose-Headers"))
	}
}

func TestApplyCORSHeaders_NilConfig(t *testing.T) {
	var crh *compiledResponseHeaders
	rec := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/", nil)
	r.Header.Set("Origin", "https://example.com")

	// Should not panic.
	crh.ApplyCORSHeaders(rec, r)
	if rec.Header().Get("Access-Control-Allow-Origin") != "" {
		t.Error("expected no CORS headers for nil config")
	}
}

// ─── resolveCORS ────────────────────────────────────────────────────

func TestResolveCORS_NilConfig(t *testing.T) {
	var crh *compiledResponseHeaders
	if crh.resolveCORS("example.com") != nil {
		t.Error("expected nil for nil config")
	}
}

func TestResolveCORS_DisabledCORS(t *testing.T) {
	boolFalse := false
	cfg := &ResponseHeaderConfig{
		CORS: &CORSConfig{
			Enabled: &boolFalse,
			Global: CORSSettings{
				AllowedOrigins: []string{"https://example.com"},
			},
		},
	}
	crh := mustCompileResponseHeaders(t, cfg)
	if crh.resolveCORS("example.com") != nil {
		t.Error("expected nil for disabled CORS")
	}
}

func TestResolveCORS_PerServiceOverride(t *testing.T) {
	cfg := &ResponseHeaderConfig{
		CORS: &CORSConfig{
			Global: CORSSettings{
				AllowedOrigins: []string{"https://example.com"},
				MaxAge:         3600,
			},
			PerService: map[string]CORSSettings{
				"api.example.com": {
					AllowedOrigins: []string{"https://app.example.com"},
					MaxAge:         600,
				},
			},
		},
	}
	crh := mustCompileResponseHeaders(t, cfg)

	// Per-service override.
	svc := crh.resolveCORS("api.example.com")
	if svc == nil {
		t.Fatal("expected per-service CORS config")
	}
	if svc.maxAge != "600" {
		t.Errorf("expected per-service max-age 600, got %q", svc.maxAge)
	}
	if len(svc.allowedOrigins) != 1 || svc.allowedOrigins[0] != "https://app.example.com" {
		t.Errorf("expected per-service origin, got %v", svc.allowedOrigins)
	}

	// Fallback to global.
	global := crh.resolveCORS("other.example.com")
	if global == nil {
		t.Fatal("expected global CORS fallback")
	}
	if global.maxAge != "3600" {
		t.Errorf("expected global max-age 3600, got %q", global.maxAge)
	}
}

func TestResolveCORS_CaseInsensitiveHost(t *testing.T) {
	cfg := &ResponseHeaderConfig{
		CORS: &CORSConfig{
			Global: CORSSettings{
				AllowedOrigins: []string{"https://example.com"},
			},
			PerService: map[string]CORSSettings{
				"API.Example.COM": {
					AllowedOrigins: []string{"https://special.com"},
					MaxAge:         900,
				},
			},
		},
	}
	crh := mustCompileResponseHeaders(t, cfg)

	svc := crh.resolveCORS("api.example.com")
	if svc == nil || svc.maxAge != "900" {
		t.Error("expected case-insensitive host match for per-service CORS")
	}
}

func TestResolveCORS_HostWithPort(t *testing.T) {
	cfg := &ResponseHeaderConfig{
		CORS: &CORSConfig{
			Global: CORSSettings{
				AllowedOrigins: []string{"https://example.com"},
			},
			PerService: map[string]CORSSettings{
				"api.example.com": {
					AllowedOrigins: []string{"https://special.com"},
					MaxAge:         900,
				},
			},
		},
	}
	crh := mustCompileResponseHeaders(t, cfg)

	svc := crh.resolveCORS("api.example.com:443")
	if svc == nil || svc.maxAge != "900" {
		t.Error("expected host with port to match per-service CORS")
	}
}
