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
	result := compileResponseHeaders(nil)
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
	result := compileResponseHeaders(cfg)
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
	result := compileResponseHeaders(cfg)
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
	result := compileResponseHeaders(cfg)
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
	result := compileResponseHeaders(cfg)
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
	result := compileResponseHeaders(cfg)
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
	crh := compileResponseHeaders(cfg)
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
	crh := compileResponseHeaders(cfg)

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
	crh := compileResponseHeaders(cfg)
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
	crh := compileResponseHeaders(cfg)

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
	crh := compileResponseHeaders(cfg)
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
	w := applyResponseHeaders(rec, "example.com", nil)
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
	crh := compileResponseHeaders(cfg)

	rec := httptest.NewRecorder()
	w := applyResponseHeaders(rec, "example.com", crh)

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
	crh := compileResponseHeaders(cfg)

	rec := httptest.NewRecorder()
	w := applyResponseHeaders(rec, "app.example.com", crh)

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
	crh := compileResponseHeaders(cfg)

	rec := httptest.NewRecorder()
	w := applyResponseHeaders(rec, "api.example.com", crh)

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
	crh := compileResponseHeaders(cfg)

	rec := httptest.NewRecorder()
	w := applyResponseHeaders(rec, "example.com", crh)

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
	crh := compileResponseHeaders(cfg)

	rec := httptest.NewRecorder()
	// Simulate upstream setting these headers.
	rec.Header().Set("Server", "caddy")
	rec.Header().Set("X-Powered-By", "Go")

	w := applyResponseHeaders(rec, "example.com", crh)
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
	crh := compileResponseHeaders(cfg)

	rec := httptest.NewRecorder()
	_ = applyResponseHeaders(rec, "app.example.com", crh)

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
	crh := compileResponseHeaders(cfg)

	rec := httptest.NewRecorder()
	rec.Header().Set("Server", "caddy")
	w := applyResponseHeaders(rec, "example.com", crh)

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
