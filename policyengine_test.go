package policyengine

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

// ─── Helpers ────────────────────────────────────────────────────────

func testContext() (caddy.Context, context.CancelFunc) {
	ctx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
	return ctx, cancel
}

func mustProvision(t *testing.T, pe *PolicyEngine) {
	t.Helper()
	ctx, cancel := testContext()
	defer cancel()
	if err := pe.Provision(ctx); err != nil {
		t.Fatalf("Provision failed: %v", err)
	}
}

// nextHandler is a caddyhttp.Handler that records whether it was called.
type nextHandler struct {
	called bool
}

func (h *nextHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) error {
	h.called = true
	w.WriteHeader(http.StatusOK)
	return nil
}

func makeRequest(method, path, remoteAddr string) *http.Request {
	r := httptest.NewRequest(method, path, nil)
	if remoteAddr != "" {
		r.RemoteAddr = remoteAddr
	}
	// Ensure request has a Caddy vars map (required for SetVar/GetVar).
	ctx := context.WithValue(r.Context(), caddyhttp.VarsCtxKey, make(map[string]interface{}))
	return r.WithContext(ctx)
}

func makeRequestWithHeaders(method, path, remoteAddr string, headers map[string]string) *http.Request {
	r := makeRequest(method, path, remoteAddr)
	for k, v := range headers {
		r.Header.Set(k, v)
	}
	return r
}

func writeTempRulesFile(t *testing.T, rules []PolicyRule) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "policy-rules.json")
	file := PolicyRulesFile{
		Rules:     rules,
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
	return path
}

// ─── Condition Matching: eq / neq ───────────────────────────────────

func TestCondition_Eq_Match(t *testing.T) {
	cc, err := compileCondition(PolicyCondition{Field: "path", Operator: "eq", Value: "/admin"})
	if err != nil {
		t.Fatal(err)
	}
	r := makeRequest("GET", "/admin", "10.0.0.1:1234")
	if !matchCondition(cc, r) {
		t.Error("expected /admin to match eq /admin")
	}
}

func TestCondition_Eq_NoMatch(t *testing.T) {
	cc, err := compileCondition(PolicyCondition{Field: "path", Operator: "eq", Value: "/admin"})
	if err != nil {
		t.Fatal(err)
	}
	r := makeRequest("GET", "/administrator", "10.0.0.1:1234")
	if matchCondition(cc, r) {
		t.Error("expected /administrator to NOT match eq /admin")
	}
}

func TestCondition_Neq_Match(t *testing.T) {
	cc, err := compileCondition(PolicyCondition{Field: "method", Operator: "neq", Value: "GET"})
	if err != nil {
		t.Fatal(err)
	}
	r := makeRequest("POST", "/", "10.0.0.1:1234")
	if !matchCondition(cc, r) {
		t.Error("expected POST to match neq GET")
	}
}

func TestCondition_Neq_NoMatch(t *testing.T) {
	cc, err := compileCondition(PolicyCondition{Field: "method", Operator: "neq", Value: "GET"})
	if err != nil {
		t.Fatal(err)
	}
	r := makeRequest("GET", "/", "10.0.0.1:1234")
	if matchCondition(cc, r) {
		t.Error("expected GET to NOT match neq GET")
	}
}

// ─── Condition Matching: contains ───────────────────────────────────

func TestCondition_Contains_Match(t *testing.T) {
	cc, err := compileCondition(PolicyCondition{Field: "user_agent", Operator: "contains", Value: "BadBot"})
	if err != nil {
		t.Fatal(err)
	}
	r := makeRequestWithHeaders("GET", "/", "10.0.0.1:1234", map[string]string{
		"User-Agent": "Mozilla/5.0 BadBot/1.0",
	})
	if !matchCondition(cc, r) {
		t.Error("expected match for UA containing BadBot")
	}
}

func TestCondition_Contains_NoMatch(t *testing.T) {
	cc, err := compileCondition(PolicyCondition{Field: "user_agent", Operator: "contains", Value: "BadBot"})
	if err != nil {
		t.Fatal(err)
	}
	r := makeRequestWithHeaders("GET", "/", "10.0.0.1:1234", map[string]string{
		"User-Agent": "Mozilla/5.0",
	})
	if matchCondition(cc, r) {
		t.Error("expected no match for UA without BadBot")
	}
}

// ─── Condition Matching: begins_with / ends_with ────────────────────

func TestCondition_BeginsWith(t *testing.T) {
	cc, err := compileCondition(PolicyCondition{Field: "uri_path", Operator: "begins_with", Value: "/api/"})
	if err != nil {
		t.Fatal(err)
	}
	r := makeRequest("GET", "/api/v3/queue", "10.0.0.1:1234")
	if !matchCondition(cc, r) {
		t.Error("expected /api/v3/queue to match begins_with /api/")
	}
	r2 := makeRequest("GET", "/login", "10.0.0.1:1234")
	if matchCondition(cc, r2) {
		t.Error("expected /login to NOT match begins_with /api/")
	}
}

func TestCondition_EndsWith(t *testing.T) {
	cc, err := compileCondition(PolicyCondition{Field: "uri_path", Operator: "ends_with", Value: ".php"})
	if err != nil {
		t.Fatal(err)
	}
	r := makeRequest("GET", "/wp-login.php", "10.0.0.1:1234")
	if !matchCondition(cc, r) {
		t.Error("expected wp-login.php to match ends_with .php")
	}
	r2 := makeRequest("GET", "/index.html", "10.0.0.1:1234")
	if matchCondition(cc, r2) {
		t.Error("expected index.html to NOT match ends_with .php")
	}
}

// ─── Condition Matching: regex ──────────────────────────────────────

func TestCondition_Regex_Match(t *testing.T) {
	cc, err := compileCondition(PolicyCondition{Field: "uri_path", Operator: "regex", Value: `^/wp-(admin|login|content)`})
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"/wp-admin", "/wp-login.php", "/wp-content/uploads"} {
		r := makeRequest("GET", path, "10.0.0.1:1234")
		if !matchCondition(cc, r) {
			t.Errorf("expected %s to match regex", path)
		}
	}
	r := makeRequest("GET", "/about", "10.0.0.1:1234")
	if matchCondition(cc, r) {
		t.Error("expected /about to NOT match regex")
	}
}

func TestCondition_Regex_Invalid(t *testing.T) {
	_, err := compileCondition(PolicyCondition{Field: "path", Operator: "regex", Value: `[invalid`})
	if err == nil {
		t.Error("expected error for invalid regex")
	}
}

// ─── Condition Matching: ip_match / not_ip_match ────────────────────

func TestCondition_IPMatch_Single(t *testing.T) {
	cc, err := compileCondition(PolicyCondition{Field: "ip", Operator: "ip_match", Value: "10.0.0.1"})
	if err != nil {
		t.Fatal(err)
	}
	r := makeRequest("GET", "/", "10.0.0.1:1234")
	if !matchCondition(cc, r) {
		t.Error("expected 10.0.0.1 to match ip_match 10.0.0.1")
	}
	r2 := makeRequest("GET", "/", "10.0.0.2:1234")
	if matchCondition(cc, r2) {
		t.Error("expected 10.0.0.2 to NOT match ip_match 10.0.0.1")
	}
}

func TestCondition_IPMatch_CIDR(t *testing.T) {
	cc, err := compileCondition(PolicyCondition{Field: "ip", Operator: "ip_match", Value: "192.168.1.0/24"})
	if err != nil {
		t.Fatal(err)
	}
	r := makeRequest("GET", "/", "192.168.1.50:1234")
	if !matchCondition(cc, r) {
		t.Error("expected 192.168.1.50 to match ip_match 192.168.1.0/24")
	}
	r2 := makeRequest("GET", "/", "192.168.2.1:1234")
	if matchCondition(cc, r2) {
		t.Error("expected 192.168.2.1 to NOT match ip_match 192.168.1.0/24")
	}
}

func TestCondition_IPMatch_MultipleCIDRs(t *testing.T) {
	cc, err := compileCondition(PolicyCondition{Field: "ip", Operator: "ip_match", Value: "10.0.0.0/8, 192.168.0.0/16"})
	if err != nil {
		t.Fatal(err)
	}
	for _, ip := range []string{"10.1.2.3", "192.168.100.50"} {
		r := makeRequest("GET", "/", ip+":1234")
		if !matchCondition(cc, r) {
			t.Errorf("expected %s to match", ip)
		}
	}
	r := makeRequest("GET", "/", "172.16.0.1:1234")
	if matchCondition(cc, r) {
		t.Error("expected 172.16.0.1 to NOT match")
	}
}

func TestCondition_NotIPMatch(t *testing.T) {
	cc, err := compileCondition(PolicyCondition{Field: "ip", Operator: "not_ip_match", Value: "10.0.0.0/8"})
	if err != nil {
		t.Fatal(err)
	}
	r := makeRequest("GET", "/", "192.168.1.1:1234")
	if !matchCondition(cc, r) {
		t.Error("expected 192.168.1.1 to match not_ip_match 10.0.0.0/8")
	}
	r2 := makeRequest("GET", "/", "10.0.0.1:1234")
	if matchCondition(cc, r2) {
		t.Error("expected 10.0.0.1 to NOT match not_ip_match 10.0.0.0/8")
	}
}

// ─── Condition Matching: in (CRITICAL — exact match, not substring) ─

func TestCondition_In_ExactMatch(t *testing.T) {
	cc, err := compileCondition(PolicyCondition{Field: "uri_path", Operator: "in", Value: "/admin /wp-login.php /xmlrpc.php"})
	if err != nil {
		t.Fatal(err)
	}
	// Should match exact paths.
	for _, path := range []string{"/admin", "/wp-login.php", "/xmlrpc.php"} {
		r := makeRequest("GET", path, "10.0.0.1:1234")
		if !matchCondition(cc, r) {
			t.Errorf("expected %s to match in operator", path)
		}
	}
}

func TestCondition_In_NotSubstring(t *testing.T) {
	// This is THE critical test — the core security fix.
	// @pm /admin would match /administrator (substring). Our in operator must NOT.
	cc, err := compileCondition(PolicyCondition{Field: "uri_path", Operator: "in", Value: "/admin /login"})
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"/administrator", "/login-page", "/wp-admin", "/admin/"} {
		r := makeRequest("GET", path, "10.0.0.1:1234")
		if matchCondition(cc, r) {
			t.Errorf("SECURITY: %s should NOT match 'in /admin /login' (exact match, not substring)", path)
		}
	}
}

func TestCondition_In_Country(t *testing.T) {
	cc, err := compileCondition(PolicyCondition{Field: "country", Operator: "in", Value: "US GB DE"})
	if err != nil {
		t.Fatal(err)
	}
	r := makeRequestWithHeaders("GET", "/", "10.0.0.1:1234", map[string]string{
		"Cf-Ipcountry": "US",
	})
	if !matchCondition(cc, r) {
		t.Error("expected US to match in US GB DE")
	}
	r2 := makeRequestWithHeaders("GET", "/", "10.0.0.1:1234", map[string]string{
		"Cf-Ipcountry": "USA",
	})
	if matchCondition(cc, r2) {
		t.Error("SECURITY: USA should NOT match in US GB DE (exact match)")
	}
}

// ─── Condition Matching: field extraction ────────────────────────────

func TestField_Host(t *testing.T) {
	cc, err := compileCondition(PolicyCondition{Field: "host", Operator: "eq", Value: "example.com"})
	if err != nil {
		t.Fatal(err)
	}
	r := makeRequest("GET", "http://example.com/", "10.0.0.1:1234")
	r.Host = "example.com"
	if !matchCondition(cc, r) {
		t.Error("expected host match")
	}
}

func TestField_Method(t *testing.T) {
	cc, err := compileCondition(PolicyCondition{Field: "method", Operator: "in", Value: "GET POST"})
	if err != nil {
		t.Fatal(err)
	}
	r := makeRequest("GET", "/", "10.0.0.1:1234")
	if !matchCondition(cc, r) {
		t.Error("expected GET to match in GET POST")
	}
	r2 := makeRequest("DELETE", "/", "10.0.0.1:1234")
	if matchCondition(cc, r2) {
		t.Error("expected DELETE to NOT match in GET POST")
	}
}

func TestField_NamedHeader(t *testing.T) {
	cc, err := compileCondition(PolicyCondition{Field: "header", Operator: "eq", Value: "X-Api-Key:secret123"})
	if err != nil {
		t.Fatal(err)
	}
	r := makeRequestWithHeaders("GET", "/", "10.0.0.1:1234", map[string]string{
		"X-Api-Key": "secret123",
	})
	if !matchCondition(cc, r) {
		t.Error("expected header match")
	}
	r2 := makeRequestWithHeaders("GET", "/", "10.0.0.1:1234", map[string]string{
		"X-Api-Key": "wrong",
	})
	if matchCondition(cc, r2) {
		t.Error("expected no header match for wrong value")
	}
}

func TestField_Cookie(t *testing.T) {
	cc, err := compileCondition(PolicyCondition{Field: "cookie", Operator: "eq", Value: "session:abc123"})
	if err != nil {
		t.Fatal(err)
	}
	r := makeRequest("GET", "/", "10.0.0.1:1234")
	r.AddCookie(&http.Cookie{Name: "session", Value: "abc123"})
	if !matchCondition(cc, r) {
		t.Error("expected cookie match")
	}
}

func TestField_Args(t *testing.T) {
	cc, err := compileCondition(PolicyCondition{Field: "args", Operator: "eq", Value: "action:delete"})
	if err != nil {
		t.Fatal(err)
	}
	r := makeRequest("GET", "/?action=delete", "10.0.0.1:1234")
	if !matchCondition(cc, r) {
		t.Error("expected args match")
	}
	r2 := makeRequest("GET", "/?action=edit", "10.0.0.1:1234")
	if matchCondition(cc, r2) {
		t.Error("expected no args match for action=edit")
	}
}

func TestField_Query(t *testing.T) {
	cc, err := compileCondition(PolicyCondition{Field: "query", Operator: "contains", Value: "debug=true"})
	if err != nil {
		t.Fatal(err)
	}
	r := makeRequest("GET", "/?foo=bar&debug=true", "10.0.0.1:1234")
	if !matchCondition(cc, r) {
		t.Error("expected query match")
	}
}

func TestField_Referer(t *testing.T) {
	cc, err := compileCondition(PolicyCondition{Field: "referer", Operator: "contains", Value: "evil.com"})
	if err != nil {
		t.Fatal(err)
	}
	r := makeRequestWithHeaders("GET", "/", "10.0.0.1:1234", map[string]string{
		"Referer": "https://evil.com/attack",
	})
	if !matchCondition(cc, r) {
		t.Error("expected referer match")
	}
}

func TestField_HTTPVersion(t *testing.T) {
	cc, err := compileCondition(PolicyCondition{Field: "http_version", Operator: "eq", Value: "HTTP/1.1"})
	if err != nil {
		t.Fatal(err)
	}
	r := makeRequest("GET", "/", "10.0.0.1:1234")
	r.Proto = "HTTP/1.1"
	if !matchCondition(cc, r) {
		t.Error("expected http_version match")
	}
}

// ─── Path vs URI_Path ───────────────────────────────────────────────

func TestField_Path_IncludesQuery(t *testing.T) {
	cc, err := compileCondition(PolicyCondition{Field: "path", Operator: "contains", Value: "debug=true"})
	if err != nil {
		t.Fatal(err)
	}
	r := makeRequest("GET", "/page?debug=true", "10.0.0.1:1234")
	if !matchCondition(cc, r) {
		t.Error("path field should include query string")
	}
}

func TestField_URIPath_ExcludesQuery(t *testing.T) {
	cc, err := compileCondition(PolicyCondition{Field: "uri_path", Operator: "eq", Value: "/page"})
	if err != nil {
		t.Fatal(err)
	}
	r := makeRequest("GET", "/page?debug=true", "10.0.0.1:1234")
	if !matchCondition(cc, r) {
		t.Error("uri_path should match just the path without query")
	}
}

// ─── Rule Evaluation: AND / OR ──────────────────────────────────────

func TestRule_AND_AllMatch(t *testing.T) {
	rule := PolicyRule{
		ID: "test", Type: "block", Enabled: true, GroupOp: "and",
		Conditions: []PolicyCondition{
			{Field: "ip", Operator: "ip_match", Value: "10.0.0.0/8"},
			{Field: "uri_path", Operator: "eq", Value: "/admin"},
		},
	}
	cr, err := compileRule(rule)
	if err != nil {
		t.Fatal(err)
	}
	r := makeRequest("GET", "/admin", "10.0.0.1:1234")
	if !matchRule(cr, r) {
		t.Error("AND: both conditions match, rule should match")
	}
}

func TestRule_AND_PartialMatch(t *testing.T) {
	rule := PolicyRule{
		ID: "test", Type: "block", Enabled: true, GroupOp: "and",
		Conditions: []PolicyCondition{
			{Field: "ip", Operator: "ip_match", Value: "10.0.0.0/8"},
			{Field: "uri_path", Operator: "eq", Value: "/admin"},
		},
	}
	cr, err := compileRule(rule)
	if err != nil {
		t.Fatal(err)
	}
	r := makeRequest("GET", "/login", "10.0.0.1:1234")
	if matchRule(cr, r) {
		t.Error("AND: only IP matches, rule should NOT match")
	}
}

func TestRule_OR_AnyMatch(t *testing.T) {
	rule := PolicyRule{
		ID: "test", Type: "block", Enabled: true, GroupOp: "or",
		Conditions: []PolicyCondition{
			{Field: "uri_path", Operator: "eq", Value: "/admin"},
			{Field: "uri_path", Operator: "eq", Value: "/wp-login.php"},
		},
	}
	cr, err := compileRule(rule)
	if err != nil {
		t.Fatal(err)
	}
	r := makeRequest("GET", "/wp-login.php", "10.0.0.1:1234")
	if !matchRule(cr, r) {
		t.Error("OR: second condition matches, rule should match")
	}
}

func TestRule_OR_NoneMatch(t *testing.T) {
	rule := PolicyRule{
		ID: "test", Type: "block", Enabled: true, GroupOp: "or",
		Conditions: []PolicyCondition{
			{Field: "uri_path", Operator: "eq", Value: "/admin"},
			{Field: "uri_path", Operator: "eq", Value: "/wp-login.php"},
		},
	}
	cr, err := compileRule(rule)
	if err != nil {
		t.Fatal(err)
	}
	r := makeRequest("GET", "/about", "10.0.0.1:1234")
	if matchRule(cr, r) {
		t.Error("OR: no condition matches, rule should NOT match")
	}
}

func TestRule_NoConditions_MatchesAll(t *testing.T) {
	rule := PolicyRule{
		ID: "test", Type: "block", Enabled: true, GroupOp: "and",
	}
	cr, err := compileRule(rule)
	if err != nil {
		t.Fatal(err)
	}
	r := makeRequest("GET", "/anything", "10.0.0.1:1234")
	if !matchRule(cr, r) {
		t.Error("rule with no conditions should match all requests")
	}
}

// ─── Action: block ──────────────────────────────────────────────────

func TestAction_Block(t *testing.T) {
	pe := &PolicyEngine{
		Rules: []PolicyRule{
			{
				ID: "b1", Name: "Block Admin", Type: "block", Enabled: true,
				Priority: 200,
				Conditions: []PolicyCondition{
					{Field: "uri_path", Operator: "eq", Value: "/admin"},
				},
			},
		},
	}
	mustProvision(t, pe)

	r := makeRequest("GET", "/admin", "10.0.0.1:1234")
	w := httptest.NewRecorder()
	next := &nextHandler{}

	err := pe.ServeHTTP(w, r, next)
	if err == nil {
		t.Fatal("expected error (caddyhttp.Error) for block action")
	}
	if next.called {
		t.Error("next handler should NOT be called for block")
	}
	if w.Header().Get("X-Blocked-By") != "policy-engine" {
		t.Errorf("X-Blocked-By = %q, want policy-engine", w.Header().Get("X-Blocked-By"))
	}
	if w.Header().Get("X-Blocked-Rule") != "Block Admin" {
		t.Errorf("X-Blocked-Rule = %q, want Block Admin", w.Header().Get("X-Blocked-Rule"))
	}
}

// ─── Action: honeypot (same as block) ───────────────────────────────

func TestAction_Honeypot(t *testing.T) {
	pe := &PolicyEngine{
		Rules: []PolicyRule{
			{
				ID: "h1", Name: "Honeypot WP", Type: "honeypot", Enabled: true,
				Priority: 100,
				Conditions: []PolicyCondition{
					{Field: "uri_path", Operator: "in", Value: "/wp-admin /xmlrpc.php"},
				},
			},
		},
	}
	mustProvision(t, pe)

	r := makeRequest("GET", "/wp-admin", "10.0.0.1:1234")
	w := httptest.NewRecorder()
	next := &nextHandler{}

	err := pe.ServeHTTP(w, r, next)
	if err == nil {
		t.Fatal("expected error for honeypot action")
	}
	if next.called {
		t.Error("next handler should NOT be called for honeypot")
	}
}

// ─── Action: allow ──────────────────────────────────────────────────

func TestAction_Allow(t *testing.T) {
	pe := &PolicyEngine{
		Rules: []PolicyRule{
			{
				ID: "a1", Name: "Allow Office", Type: "allow", Enabled: true,
				Priority: 300,
				Conditions: []PolicyCondition{
					{Field: "ip", Operator: "ip_match", Value: "10.0.0.0/8"},
				},
			},
		},
	}
	mustProvision(t, pe)

	r := makeRequest("GET", "/api/data", "10.0.0.1:1234")
	w := httptest.NewRecorder()
	next := &nextHandler{}

	err := pe.ServeHTTP(w, r, next)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !next.called {
		t.Error("next handler SHOULD be called for allow")
	}
	// Check Caddy vars were set.
	action, _ := caddyhttp.GetVar(r.Context(), "policy_engine.action").(string)
	if action != "allow" {
		t.Errorf("policy_engine.action = %q, want allow", action)
	}
	ruleID, _ := caddyhttp.GetVar(r.Context(), "policy_engine.rule_id").(string)
	if ruleID != "a1" {
		t.Errorf("policy_engine.rule_id = %q, want a1", ruleID)
	}
	ruleName, _ := caddyhttp.GetVar(r.Context(), "policy_engine.rule_name").(string)
	if ruleName != "Allow Office" {
		t.Errorf("policy_engine.rule_name = %q, want Allow Office", ruleName)
	}
}

// ─── No Match: pass through ─────────────────────────────────────────

func TestNoMatch_PassThrough(t *testing.T) {
	pe := &PolicyEngine{
		Rules: []PolicyRule{
			{
				ID: "b1", Type: "block", Enabled: true, Priority: 200,
				Conditions: []PolicyCondition{
					{Field: "uri_path", Operator: "eq", Value: "/admin"},
				},
			},
		},
	}
	mustProvision(t, pe)

	r := makeRequest("GET", "/about", "10.0.0.1:1234")
	w := httptest.NewRecorder()
	next := &nextHandler{}

	err := pe.ServeHTTP(w, r, next)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !next.called {
		t.Error("next handler should be called when no rule matches")
	}
}

// ─── Disabled Rules Skipped ─────────────────────────────────────────

func TestDisabledRule_Skipped(t *testing.T) {
	pe := &PolicyEngine{
		Rules: []PolicyRule{
			{
				ID: "b1", Type: "block", Enabled: false, Priority: 200,
				Conditions: []PolicyCondition{
					{Field: "uri_path", Operator: "eq", Value: "/admin"},
				},
			},
		},
	}
	mustProvision(t, pe)

	r := makeRequest("GET", "/admin", "10.0.0.1:1234")
	w := httptest.NewRecorder()
	next := &nextHandler{}

	err := pe.ServeHTTP(w, r, next)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !next.called {
		t.Error("disabled rule should be skipped, next handler should be called")
	}
}

// ─── Priority Ordering: first match wins ────────────────────────────

func TestPriority_FirstMatchWins(t *testing.T) {
	pe := &PolicyEngine{
		Rules: []PolicyRule{
			// Allow has lower priority number (100) — evaluated first.
			{
				ID: "a1", Type: "allow", Enabled: true, Priority: 100,
				Conditions: []PolicyCondition{
					{Field: "ip", Operator: "ip_match", Value: "10.0.0.0/8"},
				},
			},
			// Block has higher priority number (200) — evaluated second.
			{
				ID: "b1", Type: "block", Enabled: true, Priority: 200,
				Conditions: []PolicyCondition{
					{Field: "uri_path", Operator: "eq", Value: "/admin"},
				},
			},
		},
	}
	mustProvision(t, pe)

	// Request matches both rules — allow should win (lower priority number).
	r := makeRequest("GET", "/admin", "10.0.0.1:1234")
	w := httptest.NewRecorder()
	next := &nextHandler{}

	err := pe.ServeHTTP(w, r, next)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !next.called {
		t.Error("allow rule should fire first (lower priority), passing to next handler")
	}
	action, _ := caddyhttp.GetVar(r.Context(), "policy_engine.action").(string)
	if action != "allow" {
		t.Errorf("expected allow action, got %q", action)
	}
}

// ─── Hot Reload ─────────────────────────────────────────────────────

func TestHotReload_FileChange(t *testing.T) {
	// Write initial rules file.
	path := writeTempRulesFile(t, []PolicyRule{
		{ID: "b1", Name: "Block Admin", Type: "block", Enabled: true, Priority: 200,
			Conditions: []PolicyCondition{{Field: "uri_path", Operator: "eq", Value: "/admin"}}},
	})

	pe := &PolicyEngine{RulesFile: path}
	mustProvision(t, pe)
	defer pe.Cleanup()

	// Verify initial rule works.
	r := makeRequest("GET", "/admin", "10.0.0.1:1234")
	w := httptest.NewRecorder()
	err := pe.ServeHTTP(w, r, &nextHandler{})
	if err == nil {
		t.Fatal("expected block error initially")
	}

	// Update the rules file — now block /secret instead.
	time.Sleep(10 * time.Millisecond) // ensure mtime changes
	file := PolicyRulesFile{
		Rules: []PolicyRule{
			{ID: "b2", Name: "Block Secret", Type: "block", Enabled: true, Priority: 200,
				Conditions: []PolicyCondition{{Field: "uri_path", Operator: "eq", Value: "/secret"}}},
		},
		Generated: time.Now().UTC().Format(time.RFC3339),
		Version:   1,
	}
	data, _ := json.MarshalIndent(file, "", "  ")
	os.WriteFile(path, data, 0644)

	// Trigger reload manually (don't wait for poll).
	pe.checkReload()

	// /admin should now pass through.
	r2 := makeRequest("GET", "/admin", "10.0.0.1:1234")
	w2 := httptest.NewRecorder()
	next2 := &nextHandler{}
	err = pe.ServeHTTP(w2, r2, next2)
	if err != nil {
		t.Fatalf("expected pass-through after reload, got error: %v", err)
	}
	if !next2.called {
		t.Error("/admin should pass through after reload")
	}

	// /secret should now be blocked.
	r3 := makeRequest("GET", "/secret", "10.0.0.1:1234")
	w3 := httptest.NewRecorder()
	err = pe.ServeHTTP(w3, r3, &nextHandler{})
	if err == nil {
		t.Fatal("expected block error for /secret after reload")
	}
}

func TestHotReload_InvalidJSON_KeepsOldRules(t *testing.T) {
	path := writeTempRulesFile(t, []PolicyRule{
		{ID: "b1", Name: "Block Admin", Type: "block", Enabled: true, Priority: 200,
			Conditions: []PolicyCondition{{Field: "uri_path", Operator: "eq", Value: "/admin"}}},
	})

	pe := &PolicyEngine{RulesFile: path}
	mustProvision(t, pe)
	defer pe.Cleanup()

	// Write invalid JSON.
	time.Sleep(10 * time.Millisecond)
	os.WriteFile(path, []byte("{invalid json"), 0644)

	pe.checkReload()

	// Old rule should still work.
	r := makeRequest("GET", "/admin", "10.0.0.1:1234")
	w := httptest.NewRecorder()
	err := pe.ServeHTTP(w, r, &nextHandler{})
	if err == nil {
		t.Fatal("expected block error — old rules should be preserved after invalid JSON")
	}
}

func TestHotReload_FileDeleted_ClearsRules(t *testing.T) {
	path := writeTempRulesFile(t, []PolicyRule{
		{ID: "b1", Type: "block", Enabled: true, Priority: 200,
			Conditions: []PolicyCondition{{Field: "uri_path", Operator: "eq", Value: "/admin"}}},
	})

	pe := &PolicyEngine{RulesFile: path}
	mustProvision(t, pe)
	defer pe.Cleanup()

	// Delete the file.
	os.Remove(path)

	pe.checkReload()

	// Should pass through (no rules).
	r := makeRequest("GET", "/admin", "10.0.0.1:1234")
	w := httptest.NewRecorder()
	next := &nextHandler{}
	err := pe.ServeHTTP(w, r, next)
	if err != nil {
		t.Fatalf("expected pass-through after file deleted, got error: %v", err)
	}
	if !next.called {
		t.Error("next handler should be called when rules are cleared")
	}
}

// ─── Concurrent Safety ──────────────────────────────────────────────

func TestConcurrentReads(t *testing.T) {
	pe := &PolicyEngine{
		Rules: []PolicyRule{
			{ID: "b1", Type: "block", Enabled: true, Priority: 200,
				Conditions: []PolicyCondition{{Field: "uri_path", Operator: "eq", Value: "/admin"}}},
		},
	}
	mustProvision(t, pe)

	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r := makeRequest("GET", "/about", "10.0.0.1:1234")
			w := httptest.NewRecorder()
			pe.ServeHTTP(w, r, &nextHandler{})
		}()
	}
	wg.Wait()
}

// ─── Empty Rules: pass through ──────────────────────────────────────

func TestEmptyRules_PassThrough(t *testing.T) {
	path := writeTempRulesFile(t, nil) // empty rules

	pe := &PolicyEngine{RulesFile: path}
	mustProvision(t, pe)
	defer pe.Cleanup()

	r := makeRequest("GET", "/admin", "10.0.0.1:1234")
	w := httptest.NewRecorder()
	next := &nextHandler{}
	err := pe.ServeHTTP(w, r, next)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !next.called {
		t.Error("empty rules should pass through")
	}
}

// ─── File Load from Disk ────────────────────────────────────────────

func TestLoadFromFile(t *testing.T) {
	path := writeTempRulesFile(t, []PolicyRule{
		{ID: "b1", Name: "Block Admin", Type: "block", Enabled: true, Priority: 200,
			GroupOp: "and",
			Conditions: []PolicyCondition{
				{Field: "uri_path", Operator: "eq", Value: "/admin"},
			}},
		{ID: "a1", Name: "Allow Office", Type: "allow", Enabled: true, Priority: 300,
			GroupOp: "and",
			Conditions: []PolicyCondition{
				{Field: "ip", Operator: "ip_match", Value: "10.0.0.0/8"},
			}},
	})

	pe := &PolicyEngine{RulesFile: path}
	mustProvision(t, pe)
	defer pe.Cleanup()

	pe.mu.RLock()
	count := len(pe.rules)
	pe.mu.RUnlock()

	if count != 2 {
		t.Errorf("expected 2 rules loaded, got %d", count)
	}
}

// ─── Missing File at Startup ────────────────────────────────────────

func TestMissingFile_StartsEmpty(t *testing.T) {
	pe := &PolicyEngine{RulesFile: "/nonexistent/policy-rules.json"}
	mustProvision(t, pe)
	defer pe.Cleanup()

	pe.mu.RLock()
	count := len(pe.rules)
	pe.mu.RUnlock()

	if count != 0 {
		t.Errorf("expected 0 rules for missing file, got %d", count)
	}
}

// ─── Compile Errors ─────────────────────────────────────────────────

func TestCompile_UnsupportedOperator(t *testing.T) {
	_, err := compileCondition(PolicyCondition{Field: "path", Operator: "invalid_op", Value: "test"})
	if err == nil {
		t.Error("expected error for unsupported operator")
	}
}

func TestCompile_InvalidIPCIDR(t *testing.T) {
	_, err := compileCondition(PolicyCondition{Field: "ip", Operator: "ip_match", Value: "not-an-ip"})
	if err == nil {
		t.Error("expected error for invalid IP")
	}
}

// ─── Validate ───────────────────────────────────────────────────────

func TestValidate_NoConfig(t *testing.T) {
	pe := &PolicyEngine{}
	if err := pe.Validate(); err == nil {
		t.Error("expected validation error when neither rules_file nor rules are set")
	}
}

func TestValidate_WithRulesFile(t *testing.T) {
	pe := &PolicyEngine{RulesFile: "/data/policy-rules.json"}
	if err := pe.Validate(); err != nil {
		t.Errorf("unexpected validation error: %v", err)
	}
}

func TestValidate_WithInlineRules(t *testing.T) {
	pe := &PolicyEngine{
		Rules: []PolicyRule{{ID: "test", Type: "block"}},
	}
	if err := pe.Validate(); err != nil {
		t.Errorf("unexpected validation error: %v", err)
	}
}
