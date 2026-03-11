package policyengine

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
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

// pbFrom creates a parsedBody from raw bytes for testing.
func pbFrom(data []byte) *parsedBody {
	if data == nil {
		return nil
	}
	return &parsedBody{raw: data}
}

// ─── Condition Matching: eq / neq ───────────────────────────────────

func TestCondition_Eq_Match(t *testing.T) {
	cc, err := compileCondition(PolicyCondition{Field: "path", Operator: "eq", Value: "/admin"})
	if err != nil {
		t.Fatal(err)
	}
	r := makeRequest("GET", "/admin", "10.0.0.1:1234")
	if !matchCondition(cc, r, nil) {
		t.Error("expected /admin to match eq /admin")
	}
}

func TestCondition_Eq_NoMatch(t *testing.T) {
	cc, err := compileCondition(PolicyCondition{Field: "path", Operator: "eq", Value: "/admin"})
	if err != nil {
		t.Fatal(err)
	}
	r := makeRequest("GET", "/administrator", "10.0.0.1:1234")
	if matchCondition(cc, r, nil) {
		t.Error("expected /administrator to NOT match eq /admin")
	}
}

func TestCondition_Neq_Match(t *testing.T) {
	cc, err := compileCondition(PolicyCondition{Field: "method", Operator: "neq", Value: "GET"})
	if err != nil {
		t.Fatal(err)
	}
	r := makeRequest("POST", "/", "10.0.0.1:1234")
	if !matchCondition(cc, r, nil) {
		t.Error("expected POST to match neq GET")
	}
}

func TestCondition_Neq_NoMatch(t *testing.T) {
	cc, err := compileCondition(PolicyCondition{Field: "method", Operator: "neq", Value: "GET"})
	if err != nil {
		t.Fatal(err)
	}
	r := makeRequest("GET", "/", "10.0.0.1:1234")
	if matchCondition(cc, r, nil) {
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
	if !matchCondition(cc, r, nil) {
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
	if matchCondition(cc, r, nil) {
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
	if !matchCondition(cc, r, nil) {
		t.Error("expected /api/v3/queue to match begins_with /api/")
	}
	r2 := makeRequest("GET", "/login", "10.0.0.1:1234")
	if matchCondition(cc, r2, nil) {
		t.Error("expected /login to NOT match begins_with /api/")
	}
}

func TestCondition_EndsWith(t *testing.T) {
	cc, err := compileCondition(PolicyCondition{Field: "uri_path", Operator: "ends_with", Value: ".php"})
	if err != nil {
		t.Fatal(err)
	}
	r := makeRequest("GET", "/wp-login.php", "10.0.0.1:1234")
	if !matchCondition(cc, r, nil) {
		t.Error("expected wp-login.php to match ends_with .php")
	}
	r2 := makeRequest("GET", "/index.html", "10.0.0.1:1234")
	if matchCondition(cc, r2, nil) {
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
		if !matchCondition(cc, r, nil) {
			t.Errorf("expected %s to match regex", path)
		}
	}
	r := makeRequest("GET", "/about", "10.0.0.1:1234")
	if matchCondition(cc, r, nil) {
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
	if !matchCondition(cc, r, nil) {
		t.Error("expected 10.0.0.1 to match ip_match 10.0.0.1")
	}
	r2 := makeRequest("GET", "/", "10.0.0.2:1234")
	if matchCondition(cc, r2, nil) {
		t.Error("expected 10.0.0.2 to NOT match ip_match 10.0.0.1")
	}
}

func TestCondition_IPMatch_CIDR(t *testing.T) {
	cc, err := compileCondition(PolicyCondition{Field: "ip", Operator: "ip_match", Value: "192.168.1.0/24"})
	if err != nil {
		t.Fatal(err)
	}
	r := makeRequest("GET", "/", "192.168.1.50:1234")
	if !matchCondition(cc, r, nil) {
		t.Error("expected 192.168.1.50 to match ip_match 192.168.1.0/24")
	}
	r2 := makeRequest("GET", "/", "192.168.2.1:1234")
	if matchCondition(cc, r2, nil) {
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
		if !matchCondition(cc, r, nil) {
			t.Errorf("expected %s to match", ip)
		}
	}
	r := makeRequest("GET", "/", "172.16.0.1:1234")
	if matchCondition(cc, r, nil) {
		t.Error("expected 172.16.0.1 to NOT match")
	}
}

func TestCondition_NotIPMatch(t *testing.T) {
	cc, err := compileCondition(PolicyCondition{Field: "ip", Operator: "not_ip_match", Value: "10.0.0.0/8"})
	if err != nil {
		t.Fatal(err)
	}
	r := makeRequest("GET", "/", "192.168.1.1:1234")
	if !matchCondition(cc, r, nil) {
		t.Error("expected 192.168.1.1 to match not_ip_match 10.0.0.0/8")
	}
	r2 := makeRequest("GET", "/", "10.0.0.1:1234")
	if matchCondition(cc, r2, nil) {
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
		if !matchCondition(cc, r, nil) {
			t.Errorf("expected %s to match in operator", path)
		}
	}
}

func TestCondition_In_PipeDelimited(t *testing.T) {
	// The wafctl frontend stores "in" values with pipe delimiters (PipeTagInput).
	// The plugin must accept both pipes and spaces.
	cc, err := compileCondition(PolicyCondition{Field: "path", Operator: "in", Value: "/trap|/honeypot|/wp-login.php"})
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"/trap", "/honeypot", "/wp-login.php"} {
		r := makeRequest("GET", path, "10.0.0.1:1234")
		if !matchCondition(cc, r, nil) {
			t.Errorf("expected pipe-delimited %s to match in operator", path)
		}
	}
	// Must not match substrings.
	r := makeRequest("GET", "/trap-extended", "10.0.0.1:1234")
	if matchCondition(cc, r, nil) {
		t.Error("SECURITY: /trap-extended should NOT match pipe-delimited 'in /trap|/honeypot|/wp-login.php'")
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
		if matchCondition(cc, r, nil) {
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
	if !matchCondition(cc, r, nil) {
		t.Error("expected US to match in US GB DE")
	}
	r2 := makeRequestWithHeaders("GET", "/", "10.0.0.1:1234", map[string]string{
		"Cf-Ipcountry": "USA",
	})
	if matchCondition(cc, r2, nil) {
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
	if !matchCondition(cc, r, nil) {
		t.Error("expected host match")
	}
}

func TestField_Method(t *testing.T) {
	cc, err := compileCondition(PolicyCondition{Field: "method", Operator: "in", Value: "GET POST"})
	if err != nil {
		t.Fatal(err)
	}
	r := makeRequest("GET", "/", "10.0.0.1:1234")
	if !matchCondition(cc, r, nil) {
		t.Error("expected GET to match in GET POST")
	}
	r2 := makeRequest("DELETE", "/", "10.0.0.1:1234")
	if matchCondition(cc, r2, nil) {
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
	if !matchCondition(cc, r, nil) {
		t.Error("expected header match")
	}
	r2 := makeRequestWithHeaders("GET", "/", "10.0.0.1:1234", map[string]string{
		"X-Api-Key": "wrong",
	})
	if matchCondition(cc, r2, nil) {
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
	if !matchCondition(cc, r, nil) {
		t.Error("expected cookie match")
	}
}

func TestField_Args(t *testing.T) {
	cc, err := compileCondition(PolicyCondition{Field: "args", Operator: "eq", Value: "action:delete"})
	if err != nil {
		t.Fatal(err)
	}
	r := makeRequest("GET", "/?action=delete", "10.0.0.1:1234")
	if !matchCondition(cc, r, nil) {
		t.Error("expected args match")
	}
	r2 := makeRequest("GET", "/?action=edit", "10.0.0.1:1234")
	if matchCondition(cc, r2, nil) {
		t.Error("expected no args match for action=edit")
	}
}

func TestField_Query(t *testing.T) {
	cc, err := compileCondition(PolicyCondition{Field: "query", Operator: "contains", Value: "debug=true"})
	if err != nil {
		t.Fatal(err)
	}
	r := makeRequest("GET", "/?foo=bar&debug=true", "10.0.0.1:1234")
	if !matchCondition(cc, r, nil) {
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
	if !matchCondition(cc, r, nil) {
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
	if !matchCondition(cc, r, nil) {
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
	if !matchCondition(cc, r, nil) {
		t.Error("path field should include query string")
	}
}

func TestField_URIPath_ExcludesQuery(t *testing.T) {
	cc, err := compileCondition(PolicyCondition{Field: "uri_path", Operator: "eq", Value: "/page"})
	if err != nil {
		t.Fatal(err)
	}
	r := makeRequest("GET", "/page?debug=true", "10.0.0.1:1234")
	if !matchCondition(cc, r, nil) {
		t.Error("uri_path should match just the path without query")
	}
}

// ─── Body Field Matching ────────────────────────────────────────────

func TestField_Body_Contains(t *testing.T) {
	cc, err := compileCondition(PolicyCondition{Field: "body", Operator: "contains", Value: "malicious"})
	if err != nil {
		t.Fatal(err)
	}
	r := makeRequest("POST", "/api", "10.0.0.1:1234")
	body := []byte(`some malicious payload here`)
	if !matchCondition(cc, r, pbFrom(body)) {
		t.Error("body contains should match")
	}
	if matchCondition(cc, r, pbFrom([]byte(`clean payload`))) {
		t.Error("body contains should not match clean payload")
	}
	if matchCondition(cc, r, nil) {
		t.Error("body contains should not match nil body")
	}
}

func TestField_Body_Regex(t *testing.T) {
	cc, err := compileCondition(PolicyCondition{Field: "body", Operator: "regex", Value: `\b(DROP|DELETE)\s+TABLE\b`})
	if err != nil {
		t.Fatal(err)
	}
	r := makeRequest("POST", "/api", "10.0.0.1:1234")
	if !matchCondition(cc, r, pbFrom([]byte(`query: DROP TABLE users`))) {
		t.Error("body regex should match SQL drop")
	}
	if matchCondition(cc, r, pbFrom([]byte(`normal query`))) {
		t.Error("body regex should not match normal content")
	}
}

func TestField_BodyJSON_DotPath(t *testing.T) {
	cc, err := compileCondition(PolicyCondition{Field: "body_json", Operator: "eq", Value: ".user.role:admin"})
	if err != nil {
		t.Fatal(err)
	}
	r := makeRequest("POST", "/api", "10.0.0.1:1234")
	body := []byte(`{"user":{"role":"admin","name":"test"}}`)
	if !matchCondition(cc, r, pbFrom(body)) {
		t.Error("body_json should match .user.role=admin")
	}
	body2 := []byte(`{"user":{"role":"viewer","name":"test"}}`)
	if matchCondition(cc, r, pbFrom(body2)) {
		t.Error("body_json should not match .user.role=viewer")
	}
}

func TestField_BodyJSON_NestedArray(t *testing.T) {
	cc, err := compileCondition(PolicyCondition{Field: "body_json", Operator: "eq", Value: ".items.0.type:secret"})
	if err != nil {
		t.Fatal(err)
	}
	r := makeRequest("POST", "/api", "10.0.0.1:1234")
	body := []byte(`{"items":[{"type":"secret"},{"type":"public"}]}`)
	if !matchCondition(cc, r, pbFrom(body)) {
		t.Error("body_json should match array index .items.0.type")
	}
}

func TestField_BodyJSON_NumericValue(t *testing.T) {
	cc, err := compileCondition(PolicyCondition{Field: "body_json", Operator: "eq", Value: ".count:42"})
	if err != nil {
		t.Fatal(err)
	}
	r := makeRequest("POST", "/api", "10.0.0.1:1234")
	if !matchCondition(cc, r, pbFrom([]byte(`{"count":42}`))) {
		t.Error("body_json should match numeric value 42")
	}
	if matchCondition(cc, r, pbFrom([]byte(`{"count":99}`))) {
		t.Error("body_json should not match numeric value 99")
	}
}

func TestField_BodyJSON_BoolValue(t *testing.T) {
	cc, err := compileCondition(PolicyCondition{Field: "body_json", Operator: "eq", Value: ".active:true"})
	if err != nil {
		t.Fatal(err)
	}
	r := makeRequest("POST", "/api", "10.0.0.1:1234")
	if !matchCondition(cc, r, pbFrom([]byte(`{"active":true}`))) {
		t.Error("body_json should match boolean true")
	}
	if matchCondition(cc, r, pbFrom([]byte(`{"active":false}`))) {
		t.Error("body_json should not match boolean false")
	}
}

func TestField_BodyJSON_Contains(t *testing.T) {
	cc, err := compileCondition(PolicyCondition{Field: "body_json", Operator: "contains", Value: ".message:error"})
	if err != nil {
		t.Fatal(err)
	}
	r := makeRequest("POST", "/api", "10.0.0.1:1234")
	if !matchCondition(cc, r, pbFrom([]byte(`{"message":"fatal error occurred"}`))) {
		t.Error("body_json contains should match substring")
	}
}

func TestField_BodyJSON_Regex(t *testing.T) {
	cc, err := compileCondition(PolicyCondition{Field: "body_json", Operator: "regex", Value: `.token:^Bearer\s`})
	if err != nil {
		t.Fatal(err)
	}
	r := makeRequest("POST", "/api", "10.0.0.1:1234")
	if !matchCondition(cc, r, pbFrom([]byte(`{"token":"Bearer abc123"}`))) {
		t.Error("body_json regex should match")
	}
	if matchCondition(cc, r, pbFrom([]byte(`{"token":"Basic abc123"}`))) {
		t.Error("body_json regex should not match Basic")
	}
}

func TestField_BodyJSON_Exists(t *testing.T) {
	cc, err := compileCondition(PolicyCondition{Field: "body_json", Operator: "exists", Value: ".token:"})
	if err != nil {
		t.Fatal(err)
	}
	r := makeRequest("POST", "/api", "10.0.0.1:1234")
	if !matchCondition(cc, r, pbFrom([]byte(`{"token":"abc"}`))) {
		t.Error("body_json exists should match when field present")
	}
	if matchCondition(cc, r, pbFrom([]byte(`{"other":"abc"}`))) {
		t.Error("body_json exists should not match when field absent")
	}
	if matchCondition(cc, r, nil) {
		t.Error("body_json exists should not match nil body")
	}
}

func TestField_BodyJSON_Exists_Nested(t *testing.T) {
	cc, err := compileCondition(PolicyCondition{Field: "body_json", Operator: "exists", Value: ".data.secret:"})
	if err != nil {
		t.Fatal(err)
	}
	r := makeRequest("POST", "/api", "10.0.0.1:1234")
	if !matchCondition(cc, r, pbFrom([]byte(`{"data":{"secret":"hidden"}}`))) {
		t.Error("body_json exists should match nested field")
	}
	if matchCondition(cc, r, pbFrom([]byte(`{"data":{"public":"visible"}}`))) {
		t.Error("body_json exists should not match absent nested field")
	}
}

func TestField_BodyJSON_MissingPath(t *testing.T) {
	cc, err := compileCondition(PolicyCondition{Field: "body_json", Operator: "eq", Value: ".nonexistent:value"})
	if err != nil {
		t.Fatal(err)
	}
	r := makeRequest("POST", "/api", "10.0.0.1:1234")
	if matchCondition(cc, r, pbFrom([]byte(`{"other":"value"}`))) {
		t.Error("body_json should not match when path doesn't exist")
	}
}

func TestField_BodyJSON_InvalidJSON(t *testing.T) {
	cc, err := compileCondition(PolicyCondition{Field: "body_json", Operator: "eq", Value: ".key:value"})
	if err != nil {
		t.Fatal(err)
	}
	r := makeRequest("POST", "/api", "10.0.0.1:1234")
	if matchCondition(cc, r, pbFrom([]byte(`not json at all`))) {
		t.Error("body_json should not match invalid JSON")
	}
}

func TestField_BodyForm_Eq(t *testing.T) {
	cc, err := compileCondition(PolicyCondition{Field: "body_form", Operator: "eq", Value: "action:login"})
	if err != nil {
		t.Fatal(err)
	}
	r := makeRequest("POST", "/api", "10.0.0.1:1234")
	body := []byte("action=login&user=test")
	if !matchCondition(cc, r, pbFrom(body)) {
		t.Error("body_form should match action=login")
	}
	body2 := []byte("action=logout&user=test")
	if matchCondition(cc, r, pbFrom(body2)) {
		t.Error("body_form should not match action=logout")
	}
}

func TestField_BodyForm_Contains(t *testing.T) {
	cc, err := compileCondition(PolicyCondition{Field: "body_form", Operator: "contains", Value: "query:SELECT"})
	if err != nil {
		t.Fatal(err)
	}
	r := makeRequest("POST", "/api", "10.0.0.1:1234")
	if !matchCondition(cc, r, pbFrom([]byte("query=SELECT+*+FROM+users"))) {
		t.Error("body_form contains should match")
	}
}

func TestField_BodyForm_URLEncoding(t *testing.T) {
	cc, err := compileCondition(PolicyCondition{Field: "body_form", Operator: "eq", Value: "email:user@test.com"})
	if err != nil {
		t.Fatal(err)
	}
	r := makeRequest("POST", "/api", "10.0.0.1:1234")
	// url.ParseQuery decodes %40 → @
	if !matchCondition(cc, r, pbFrom([]byte("email=user%40test.com"))) {
		t.Error("body_form should handle URL-encoded values")
	}
}

func TestField_BodyForm_MissingField(t *testing.T) {
	cc, err := compileCondition(PolicyCondition{Field: "body_form", Operator: "eq", Value: "action:login"})
	if err != nil {
		t.Fatal(err)
	}
	r := makeRequest("POST", "/api", "10.0.0.1:1234")
	if matchCondition(cc, r, pbFrom([]byte("user=test"))) {
		t.Error("body_form should not match when field is missing")
	}
}

func TestField_Body_NilBody(t *testing.T) {
	cc, err := compileCondition(PolicyCondition{Field: "body", Operator: "eq", Value: ""})
	if err != nil {
		t.Fatal(err)
	}
	r := makeRequest("GET", "/", "10.0.0.1:1234")
	// nil body → empty string, eq "" should match.
	if !matchCondition(cc, r, nil) {
		t.Error("body eq empty string should match nil body")
	}
}

// ─── needsBody Compile-Time Flag ────────────────────────────────────

func TestNeedsBody_SetForBodyConditions(t *testing.T) {
	for _, field := range []string{"body", "body_json", "body_form"} {
		rule := PolicyRule{
			ID: "test", Type: "block", Enabled: true,
			Conditions: []PolicyCondition{
				{Field: field, Operator: "contains", Value: "test"},
			},
		}
		cr, err := compileRule(rule)
		if err != nil {
			t.Fatalf("field %s: %v", field, err)
		}
		if !cr.needsBody {
			t.Errorf("needsBody should be true for field %s", field)
		}
	}
}

func TestNeedsBody_FalseForNonBodyConditions(t *testing.T) {
	rule := PolicyRule{
		ID: "test", Type: "block", Enabled: true,
		Conditions: []PolicyCondition{
			{Field: "path", Operator: "eq", Value: "/admin"},
			{Field: "method", Operator: "eq", Value: "POST"},
		},
	}
	cr, err := compileRule(rule)
	if err != nil {
		t.Fatal(err)
	}
	if cr.needsBody {
		t.Error("needsBody should be false when no body conditions")
	}
}

// ─── readBody ───────────────────────────────────────────────────────

func TestReadBody_SmallBody(t *testing.T) {
	body := "hello world"
	r := httptest.NewRequest("POST", "/", strings.NewReader(body))
	buf, err := readBody(r, 1024)
	if err != nil {
		t.Fatal(err)
	}
	if string(buf) != body {
		t.Errorf("expected %q, got %q", body, string(buf))
	}
	// Verify body is re-wrapped — can still read.
	remaining, _ := io.ReadAll(r.Body)
	if string(remaining) != body {
		t.Errorf("downstream should see full body, got %q", string(remaining))
	}
}

func TestReadBody_ExceedsLimit(t *testing.T) {
	body := strings.Repeat("x", 100)
	r := httptest.NewRequest("POST", "/", strings.NewReader(body))
	buf, err := readBody(r, 50)
	if err != nil {
		t.Fatal(err)
	}
	if len(buf) != 50 {
		t.Errorf("expected truncated to 50 bytes, got %d", len(buf))
	}
	// Downstream should see the full body.
	remaining, _ := io.ReadAll(r.Body)
	if len(remaining) != 100 {
		t.Errorf("downstream should see full body (100 bytes), got %d", len(remaining))
	}
}

func TestReadBody_EmptyBody(t *testing.T) {
	r := httptest.NewRequest("GET", "/", strings.NewReader(""))
	buf, err := readBody(r, 1024)
	if err != nil {
		t.Fatal(err)
	}
	if len(buf) != 0 {
		t.Errorf("expected empty buf for empty body, got %d bytes", len(buf))
	}
}

// ─── JSON Helpers ───────────────────────────────────────────────────

func TestResolveJSONPath_Simple(t *testing.T) {
	body := []byte(`{"user":"alice","count":42}`)
	val, ok := resolveJSONPath(body, ".user")
	if !ok || jsonValueToString(val) != "alice" {
		t.Errorf("expected alice, got %v", val)
	}
	val2, ok := resolveJSONPath(body, ".count")
	if !ok || jsonValueToString(val2) != "42" {
		t.Errorf("expected 42, got %v", val2)
	}
}

func TestResolveJSONPath_Nested(t *testing.T) {
	body := []byte(`{"data":{"nested":{"key":"value"}}}`)
	val, ok := resolveJSONPath(body, ".data.nested.key")
	if !ok || jsonValueToString(val) != "value" {
		t.Errorf("expected value, got %v (found=%v)", val, ok)
	}
}

func TestResolveJSONPath_Array(t *testing.T) {
	body := []byte(`{"items":[{"name":"first"},{"name":"second"}]}`)
	val, ok := resolveJSONPath(body, ".items.1.name")
	if !ok || jsonValueToString(val) != "second" {
		t.Errorf("expected second, got %v", val)
	}
}

func TestResolveJSONPath_Missing(t *testing.T) {
	body := []byte(`{"user":"alice"}`)
	_, ok := resolveJSONPath(body, ".nonexistent")
	if ok {
		t.Error("expected not found for missing path")
	}
}

func TestResolveJSONPath_InvalidJSON(t *testing.T) {
	_, ok := resolveJSONPath([]byte(`not json`), ".key")
	if ok {
		t.Error("expected not found for invalid JSON")
	}
}

func TestJsonValueToString_Types(t *testing.T) {
	tests := []struct {
		input interface{}
		want  string
	}{
		{"hello", "hello"},
		{float64(42), "42"},
		{float64(3.14), "3.14"},
		{true, "true"},
		{false, "false"},
		{nil, "null"},
	}
	for _, tt := range tests {
		got := jsonValueToString(tt.input)
		if got != tt.want {
			t.Errorf("jsonValueToString(%v) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

// ─── parseSize ──────────────────────────────────────────────────────

func TestParseSize(t *testing.T) {
	tests := []struct {
		input string
		want  int64
	}{
		{"1024", 1024},
		{"10kb", 10 * 1024},
		{"13mb", 13 * 1024 * 1024},
		{"1gb", 1024 * 1024 * 1024},
		{"13MB", 13 * 1024 * 1024},
	}
	for _, tt := range tests {
		got, err := parseSize(tt.input)
		if err != nil {
			t.Errorf("parseSize(%q) error: %v", tt.input, err)
			continue
		}
		if got != tt.want {
			t.Errorf("parseSize(%q) = %d, want %d", tt.input, got, tt.want)
		}
	}
}

func TestParseSize_Invalid(t *testing.T) {
	_, err := parseSize("abc")
	if err == nil {
		t.Error("expected error for invalid size")
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
	if !matchRule(cr, r, nil) {
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
	if matchRule(cr, r, nil) {
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
	if !matchRule(cr, r, nil) {
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
	if matchRule(cr, r, nil) {
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
	if !matchRule(cr, r, nil) {
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
	// Caddy vars should also be set for block actions (reliable detection
	// via log_append, unlike response headers which may be lowercased by HTTP/2).
	action, _ := caddyhttp.GetVar(r.Context(), "policy_engine.action").(string)
	if action != "block" {
		t.Errorf("policy_engine.action = %q, want block", action)
	}
	ruleID, _ := caddyhttp.GetVar(r.Context(), "policy_engine.rule_id").(string)
	if ruleID != "b1" {
		t.Errorf("policy_engine.rule_id = %q, want b1", ruleID)
	}
	ruleName, _ := caddyhttp.GetVar(r.Context(), "policy_engine.rule_name").(string)
	if ruleName != "Block Admin" {
		t.Errorf("policy_engine.rule_name = %q, want Block Admin", ruleName)
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
	// Caddy vars should be set for honeypot actions too.
	action, _ := caddyhttp.GetVar(r.Context(), "policy_engine.action").(string)
	if action != "honeypot" {
		t.Errorf("policy_engine.action = %q, want honeypot", action)
	}
	ruleName, _ := caddyhttp.GetVar(r.Context(), "policy_engine.rule_name").(string)
	if ruleName != "Honeypot WP" {
		t.Errorf("policy_engine.rule_name = %q, want Honeypot WP", ruleName)
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

// ─── Tags ───────────────────────────────────────────────────────────

func TestAction_Block_WithTags(t *testing.T) {
	pe := &PolicyEngine{
		Rules: []PolicyRule{
			{
				ID: "t1", Name: "Scanner Block", Type: "block", Enabled: true,
				Priority: 200,
				Tags:     []string{"scanner", "bot-detection"},
				Conditions: []PolicyCondition{
					{Field: "user_agent", Operator: "contains", Value: "sqlmap"},
				},
			},
		},
	}
	mustProvision(t, pe)

	r := makeRequest("GET", "/", "1.2.3.4:1234")
	r.Header.Set("User-Agent", "sqlmap/1.0")
	w := httptest.NewRecorder()

	err := pe.ServeHTTP(w, r, &nextHandler{})
	if err == nil {
		t.Fatal("expected error for blocked request")
	}
	// X-Policy-Tags header should contain comma-joined tags.
	tags := w.Header().Get("X-Policy-Tags")
	if tags != "scanner,bot-detection" {
		t.Errorf("X-Policy-Tags = %q, want %q", tags, "scanner,bot-detection")
	}
	// Tags var should also be set.
	tagsVar, _ := caddyhttp.GetVar(r.Context(), "policy_engine.tags").(string)
	if tagsVar != "scanner,bot-detection" {
		t.Errorf("policy_engine.tags = %q, want %q", tagsVar, "scanner,bot-detection")
	}
}

func TestAction_Block_NoTags(t *testing.T) {
	pe := &PolicyEngine{
		Rules: []PolicyRule{
			{
				ID: "t2", Name: "Simple Block", Type: "block", Enabled: true,
				Priority: 200,
				Conditions: []PolicyCondition{
					{Field: "path", Operator: "eq", Value: "/bad"},
				},
			},
		},
	}
	mustProvision(t, pe)

	r := makeRequest("GET", "/bad", "1.2.3.4:1234")
	w := httptest.NewRecorder()

	err := pe.ServeHTTP(w, r, &nextHandler{})
	if err == nil {
		t.Fatal("expected error for blocked request")
	}
	// No X-Policy-Tags header when rule has no tags.
	tags := w.Header().Get("X-Policy-Tags")
	if tags != "" {
		t.Errorf("X-Policy-Tags = %q, want empty", tags)
	}
}

func TestAction_Allow_WithTags(t *testing.T) {
	pe := &PolicyEngine{
		Rules: []PolicyRule{
			{
				ID: "t3", Name: "Trusted API", Type: "allow", Enabled: true,
				Priority: 300,
				Tags:     []string{"trusted", "internal"},
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
		t.Error("next handler should be called for allow")
	}
	tagsVar, _ := caddyhttp.GetVar(r.Context(), "policy_engine.tags").(string)
	if tagsVar != "trusted,internal" {
		t.Errorf("policy_engine.tags = %q, want %q", tagsVar, "trusted,internal")
	}
}

func TestAction_Honeypot_WithTags(t *testing.T) {
	pe := &PolicyEngine{
		Rules: []PolicyRule{
			{
				ID: "t4", Name: "Trap Paths", Type: "honeypot", Enabled: true,
				Priority: 100,
				Tags:     []string{"honeypot", "trap"},
				Conditions: []PolicyCondition{
					{Field: "path", Operator: "in", Value: "/wp-login.php|/xmlrpc.php"},
				},
			},
		},
	}
	mustProvision(t, pe)

	r := makeRequest("GET", "/wp-login.php", "1.2.3.4:1234")
	w := httptest.NewRecorder()

	err := pe.ServeHTTP(w, r, &nextHandler{})
	if err == nil {
		t.Fatal("expected error for honeypot block")
	}
	tags := w.Header().Get("X-Policy-Tags")
	if tags != "honeypot,trap" {
		t.Errorf("X-Policy-Tags = %q, want %q", tags, "honeypot,trap")
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

func TestPriority_BlockAlwaysWins(t *testing.T) {
	// In the 3-pass evaluation model, block/honeypot rules always terminate
	// even if an allow rule matched earlier. Blocks are the "deny list" —
	// they cannot be overridden by allows.
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

	// Request matches both rules — block should win (blocks always terminate).
	r := makeRequest("GET", "/admin", "10.0.0.1:1234")
	w := httptest.NewRecorder()
	next := &nextHandler{}

	err := pe.ServeHTTP(w, r, next)
	if err == nil {
		t.Fatal("expected error from block rule")
	}
	httpErr, ok := err.(caddyhttp.HandlerError)
	if !ok || httpErr.StatusCode != 403 {
		t.Errorf("want 403 from block rule, got %v", err)
	}
	if next.called {
		t.Error("next handler should NOT be called when block fires")
	}
	action, _ := caddyhttp.GetVar(r.Context(), "policy_engine.action").(string)
	if action != "block" {
		t.Errorf("expected block action, got %q", action)
	}
}

func TestPriority_AllowDoesNotShortCircuitRateLimit(t *testing.T) {
	// Allow rules set the WAF-bypass flag but do not prevent rate limit
	// evaluation. If a rate limit is exceeded, 429 takes precedence.
	pe := newTestPolicyEngine(t, []PolicyRule{
		{
			ID: "a1", Name: "Allow Office", Type: "allow", Enabled: true,
			Priority: 200,
			Conditions: []PolicyCondition{
				{Field: "ip", Operator: "ip_match", Value: "10.0.0.0/8"},
			},
		},
		{
			ID: "rl1", Name: "Global RL", Type: "rate_limit", Enabled: true,
			Priority: 300,
			RateLimit: &RateLimitConfig{
				Key:    "client_ip",
				Events: 1,
				Window: "1m",
				Action: "deny",
			},
		},
	})

	// First request — allow matches, RL counter ticks (1/1), passes through.
	r1 := makeRequest("GET", "/api/data", "10.0.0.1:1234")
	next1 := &nextHandler{}
	err := pe.ServeHTTP(httptest.NewRecorder(), r1, next1)
	if err != nil {
		t.Fatalf("first request: unexpected error: %v", err)
	}
	if !next1.called {
		t.Error("first request: next handler should be called (allow + under RL limit)")
	}
	action1, _ := caddyhttp.GetVar(r1.Context(), "policy_engine.action").(string)
	if action1 != "allow" {
		t.Errorf("first request: action = %q, want allow", action1)
	}

	// Second request — same IP, rate limit exceeded. 429 overrides allow.
	r2 := makeRequest("GET", "/api/data", "10.0.0.1:1234")
	next2 := &nextHandler{}
	err = pe.ServeHTTP(httptest.NewRecorder(), r2, next2)
	if err == nil {
		t.Fatal("second request: expected 429 error")
	}
	httpErr, ok := err.(caddyhttp.HandlerError)
	if !ok || httpErr.StatusCode != 429 {
		t.Errorf("second request: want 429, got %v", err)
	}
	if next2.called {
		t.Error("second request: next handler should NOT be called when rate limited")
	}
	// The final action should be rate_limit (overrides earlier allow).
	action2, _ := caddyhttp.GetVar(r2.Context(), "policy_engine.action").(string)
	if action2 != "rate_limit" {
		t.Errorf("second request: action = %q, want rate_limit", action2)
	}
}

func TestPriority_AllowPassesThroughWhenUnderRateLimit(t *testing.T) {
	// When an allow matches and rate limit is under the threshold,
	// the request passes through with action=allow (WAF bypass).
	pe := newTestPolicyEngine(t, []PolicyRule{
		{
			ID: "a1", Name: "Allow Health", Type: "allow", Enabled: true,
			Priority: 200,
			Conditions: []PolicyCondition{
				{Field: "path", Operator: "eq", Value: "/health"},
			},
		},
		{
			ID: "rl1", Name: "Global RL", Type: "rate_limit", Enabled: true,
			Priority: 300,
			RateLimit: &RateLimitConfig{
				Key:    "client_ip",
				Events: 100,
				Window: "1m",
				Action: "deny",
			},
		},
	})

	r := makeRequest("GET", "/health", "10.0.0.1:1234")
	next := &nextHandler{}

	err := pe.ServeHTTP(httptest.NewRecorder(), r, next)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !next.called {
		t.Error("next handler should be called (allow + under RL limit)")
	}
	action, _ := caddyhttp.GetVar(r.Context(), "policy_engine.action").(string)
	if action != "allow" {
		t.Errorf("action = %q, want allow (RL under limit shouldn't override)", action)
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

// ─── in_list / not_in_list Operators ────────────────────────────────

func TestCondition_InList_StringKind(t *testing.T) {
	cc, err := compileCondition(PolicyCondition{
		Field: "country", Operator: "in_list", Value: "",
		ListItems: []string{"CN", "RU", "KP", "IR"},
		ListKind:  "string",
	})
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	if !evalOperator(cc, "CN") {
		t.Error("expected CN to match")
	}
	if !evalOperator(cc, "RU") {
		t.Error("expected RU to match")
	}
	if evalOperator(cc, "US") {
		t.Error("expected US NOT to match")
	}
	if evalOperator(cc, "C") {
		t.Error("expected partial match 'C' NOT to match (exact only)")
	}
}

func TestCondition_InList_IPKind_SingleIPs(t *testing.T) {
	cc, err := compileCondition(PolicyCondition{
		Field: "ip", Operator: "in_list", Value: "",
		ListItems: []string{"10.0.0.1", "192.168.1.5", "172.16.0.1"},
		ListKind:  "ip",
	})
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	if !evalOperator(cc, "10.0.0.1") {
		t.Error("expected 10.0.0.1 to match")
	}
	if !evalOperator(cc, "192.168.1.5") {
		t.Error("expected 192.168.1.5 to match")
	}
	if evalOperator(cc, "10.0.0.2") {
		t.Error("expected 10.0.0.2 NOT to match")
	}
}

func TestCondition_InList_IPKind_CIDRs(t *testing.T) {
	cc, err := compileCondition(PolicyCondition{
		Field: "ip", Operator: "in_list", Value: "",
		ListItems: []string{"10.0.0.0/8", "192.168.1.0/24"},
		ListKind:  "ip",
	})
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	if !evalOperator(cc, "10.255.0.1") {
		t.Error("expected 10.255.0.1 to match /8")
	}
	if !evalOperator(cc, "192.168.1.100") {
		t.Error("expected 192.168.1.100 to match /24")
	}
	if evalOperator(cc, "192.168.2.1") {
		t.Error("expected 192.168.2.1 NOT to match")
	}
}

func TestCondition_InList_IPKind_Mixed(t *testing.T) {
	// Mix of single IPs and CIDRs — single IPs go in hash set, CIDRs in linear scan.
	cc, err := compileCondition(PolicyCondition{
		Field: "ip", Operator: "in_list", Value: "",
		ListItems: []string{"10.0.0.1", "192.168.0.0/16", "172.16.5.5"},
		ListKind:  "ip",
	})
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	// Hash set hits.
	if !evalOperator(cc, "10.0.0.1") {
		t.Error("expected 10.0.0.1 (hash set)")
	}
	if !evalOperator(cc, "172.16.5.5") {
		t.Error("expected 172.16.5.5 (hash set)")
	}
	// CIDR hit.
	if !evalOperator(cc, "192.168.100.200") {
		t.Error("expected 192.168.100.200 (CIDR)")
	}
	// Miss.
	if evalOperator(cc, "8.8.8.8") {
		t.Error("expected 8.8.8.8 NOT to match")
	}
}

func TestCondition_NotInList_String(t *testing.T) {
	cc, err := compileCondition(PolicyCondition{
		Field: "country", Operator: "not_in_list", Value: "",
		ListItems: []string{"CN", "RU"},
		ListKind:  "string",
	})
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	if !cc.negate {
		t.Error("expected negate=true for not_in_list")
	}
	// evalOperator returns the raw match; negate is applied by matchCondition.
	if !evalOperator(cc, "CN") {
		t.Error("expected raw match for CN (negate applied externally)")
	}
	if evalOperator(cc, "US") {
		t.Error("expected no raw match for US")
	}
}

func TestCondition_NotInList_IP(t *testing.T) {
	cc, err := compileCondition(PolicyCondition{
		Field: "ip", Operator: "not_in_list", Value: "",
		ListItems: []string{"10.0.0.1", "192.168.1.0/24"},
		ListKind:  "ip",
	})
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	if !cc.negate {
		t.Error("expected negate=true for not_in_list")
	}
}

func TestCondition_InList_HostnameKind(t *testing.T) {
	cc, err := compileCondition(PolicyCondition{
		Field: "host", Operator: "in_list", Value: "",
		ListItems: []string{"evil.example.com", "bad.example.org"},
		ListKind:  "hostname",
	})
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	if !evalOperator(cc, "evil.example.com") {
		t.Error("expected evil.example.com to match")
	}
	if evalOperator(cc, "evil.example.com.attacker.io") {
		t.Error("expected subdomain NOT to match (exact only)")
	}
}

func TestCondition_InList_EmptyList(t *testing.T) {
	cc, err := compileCondition(PolicyCondition{
		Field: "country", Operator: "in_list", Value: "",
		ListItems: []string{},
		ListKind:  "string",
	})
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	if evalOperator(cc, "US") {
		t.Error("expected nothing to match empty list")
	}
}

func TestCondition_InList_InvalidIP(t *testing.T) {
	_, err := compileCondition(PolicyCondition{
		Field: "ip", Operator: "in_list", Value: "",
		ListItems: []string{"not-an-ip"},
		ListKind:  "ip",
	})
	if err == nil {
		t.Error("expected compile error for invalid IP in list")
	}
}

// ─── in_list Large Scale Tests ──────────────────────────────────────

func generateTestIPs(n int) []string {
	ips := make([]string, n)
	for i := 0; i < n; i++ {
		// Generate unique IPs in the 10.x.x.x range using all 3 octets.
		// Each octet uses a different portion of the index to ensure uniqueness
		// for up to 256*256*254 (~16.7M) IPs. Octet c is 1-254 (skip 0 and 255).
		a := (i / (254 * 256)) % 256
		b := (i / 254) % 256
		c := (i % 254) + 1
		ips[i] = fmt.Sprintf("10.%d.%d.%d", a, b, c)
	}
	return ips
}

func TestCondition_InList_200K_IPs_Compile(t *testing.T) {
	const n = 200_000
	ips := generateTestIPs(n)
	start := time.Now()
	cc, err := compileCondition(PolicyCondition{
		Field: "ip", Operator: "in_list", Value: "",
		ListItems: ips,
		ListKind:  "ip",
	})
	compileDur := time.Since(start)
	if err != nil {
		t.Fatalf("compile 200K IPs: %v", err)
	}
	t.Logf("compile 200K IPs: %v, ipSet=%d, ipNets=%d", compileDur, len(cc.ipSet), len(cc.ipNets))

	// All should be in hash set (single IPs), none in CIDR nets.
	if len(cc.ipSet) == 0 {
		t.Error("expected ipSet to be populated")
	}
	if len(cc.ipNets) != 0 {
		t.Errorf("expected 0 ipNets for single IPs, got %d", len(cc.ipNets))
	}

	// Spot-check: first IP should match.
	if !evalOperator(cc, "10.0.0.1") {
		t.Error("expected first IP to match")
	}
	// An IP NOT in the list should not match.
	if evalOperator(cc, "8.8.8.8") {
		t.Error("expected 8.8.8.8 NOT to match")
	}
}

func TestCondition_InList_200K_IPs_Match(t *testing.T) {
	const n = 200_000
	ips := generateTestIPs(n)
	cc, err := compileCondition(PolicyCondition{
		Field: "ip", Operator: "in_list", Value: "",
		ListItems: ips,
		ListKind:  "ip",
	})
	if err != nil {
		t.Fatalf("compile: %v", err)
	}

	// Match 1000 random IPs from the list — should all hit.
	start := time.Now()
	for i := 0; i < 1000; i++ {
		idx := (i * 137) % n // pseudo-random scatter
		if !evalOperator(cc, ips[idx]) {
			t.Fatalf("expected %s to match", ips[idx])
		}
	}
	matchDur := time.Since(start)
	t.Logf("1000 lookups in 200K IP set: %v (%v per lookup)", matchDur, matchDur/1000)

	// Match 1000 IPs NOT in the list — should all miss.
	for i := 0; i < 1000; i++ {
		missIP := fmt.Sprintf("8.8.%d.%d", i/256, i%256)
		if evalOperator(cc, missIP) {
			t.Fatalf("expected %s NOT to match", missIP)
		}
	}
}

func TestCondition_InList_200K_Strings_Match(t *testing.T) {
	const n = 200_000
	items := make([]string, n)
	for i := range items {
		items[i] = fmt.Sprintf("item-%06d", i)
	}
	cc, err := compileCondition(PolicyCondition{
		Field: "path", Operator: "in_list", Value: "",
		ListItems: items,
		ListKind:  "string",
	})
	if err != nil {
		t.Fatalf("compile: %v", err)
	}

	// Match hits.
	start := time.Now()
	for i := 0; i < 1000; i++ {
		idx := (i * 137) % n
		if !evalOperator(cc, items[idx]) {
			t.Fatalf("expected %s to match", items[idx])
		}
	}
	matchDur := time.Since(start)
	t.Logf("1000 lookups in 200K string set: %v (%v per lookup)", matchDur, matchDur/1000)

	// Match misses.
	if evalOperator(cc, "not-in-list") {
		t.Error("expected miss for 'not-in-list'")
	}
}

// ─── Benchmarks ─────────────────────────────────────────────────────

func BenchmarkIPMatch_Linear_100(b *testing.B) {
	// Baseline: ip_match with 100 CIDRs (linear scan).
	cidrs := make([]string, 100)
	for i := range cidrs {
		cidrs[i] = fmt.Sprintf("10.%d.%d.0/24", i/256, i%256)
	}
	cc, _ := compileCondition(PolicyCondition{
		Field: "ip", Operator: "ip_match", Value: strings.Join(cidrs, " "),
	})
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		evalOperator(cc, "8.8.8.8") // worst case: miss, scans all
	}
}

func BenchmarkInList_IP_200K_Hit(b *testing.B) {
	ips := generateTestIPs(200_000)
	cc, _ := compileCondition(PolicyCondition{
		Field: "ip", Operator: "in_list", Value: "",
		ListItems: ips, ListKind: "ip",
	})
	target := ips[100_000] // middle of list
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		evalOperator(cc, target)
	}
}

func BenchmarkInList_IP_200K_Miss(b *testing.B) {
	ips := generateTestIPs(200_000)
	cc, _ := compileCondition(PolicyCondition{
		Field: "ip", Operator: "in_list", Value: "",
		ListItems: ips, ListKind: "ip",
	})
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		evalOperator(cc, "8.8.8.8")
	}
}

func BenchmarkInList_String_200K_Hit(b *testing.B) {
	items := make([]string, 200_000)
	for i := range items {
		items[i] = fmt.Sprintf("/path-%06d", i)
	}
	cc, _ := compileCondition(PolicyCondition{
		Field: "path", Operator: "in_list", Value: "",
		ListItems: items, ListKind: "string",
	})
	target := items[100_000]
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		evalOperator(cc, target)
	}
}

func BenchmarkInList_String_200K_Miss(b *testing.B) {
	items := make([]string, 200_000)
	for i := range items {
		items[i] = fmt.Sprintf("/path-%06d", i)
	}
	cc, _ := compileCondition(PolicyCondition{
		Field: "path", Operator: "in_list", Value: "",
		ListItems: items, ListKind: "string",
	})
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		evalOperator(cc, "/not-in-list")
	}
}

func BenchmarkInList_IP_Compile_200K(b *testing.B) {
	ips := generateTestIPs(200_000)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		compileCondition(PolicyCondition{
			Field: "ip", Operator: "in_list", Value: "",
			ListItems: ips, ListKind: "ip",
		})
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

// ─── Regex Length Limit (#5) ────────────────────────────────────────

func TestCompile_RegexTooLong(t *testing.T) {
	longPattern := strings.Repeat("a", maxRegexLen+1)
	_, err := compileCondition(PolicyCondition{Field: "path", Operator: "regex", Value: longPattern})
	if err == nil {
		t.Error("expected error for regex exceeding max length")
	}
	if !strings.Contains(err.Error(), "regex pattern too long") {
		t.Errorf("expected 'regex pattern too long' error, got: %v", err)
	}
}

func TestCompile_RegexAtLimit(t *testing.T) {
	// Exactly at the limit should still compile.
	pattern := strings.Repeat("a", maxRegexLen)
	_, err := compileCondition(PolicyCondition{Field: "path", Operator: "regex", Value: pattern})
	if err != nil {
		t.Errorf("regex at exactly max length should compile, got: %v", err)
	}
}

// ─── HideHeaders (#7) ──────────────────────────────────────────────

func TestHideHeaders_Block(t *testing.T) {
	pe := &PolicyEngine{
		Rules: []PolicyRule{
			{
				ID: "b1", Name: "Block Admin", Type: "block", Enabled: true,
				Priority: 200,
				Tags:     []string{"test-tag"},
				Conditions: []PolicyCondition{
					{Field: "uri_path", Operator: "eq", Value: "/admin"},
				},
			},
		},
		HideHeaders: true,
	}
	mustProvision(t, pe)

	r := makeRequest("GET", "/admin", "10.0.0.1:1234")
	w := httptest.NewRecorder()
	err := pe.ServeHTTP(w, r, &nextHandler{})
	if err == nil {
		t.Fatal("expected error for block action")
	}
	// Headers should NOT be set when HideHeaders is true.
	if w.Header().Get("X-Blocked-By") != "" {
		t.Error("X-Blocked-By should be suppressed when HideHeaders=true")
	}
	if w.Header().Get("X-Blocked-Rule") != "" {
		t.Error("X-Blocked-Rule should be suppressed when HideHeaders=true")
	}
	if w.Header().Get("X-Policy-Tags") != "" {
		t.Error("X-Policy-Tags should be suppressed when HideHeaders=true")
	}
	// Caddy vars should still be set.
	action, _ := caddyhttp.GetVar(r.Context(), "policy_engine.action").(string)
	if action != "block" {
		t.Errorf("policy_engine.action should still be set, got %q", action)
	}
	tags, _ := caddyhttp.GetVar(r.Context(), "policy_engine.tags").(string)
	if tags != "test-tag" {
		t.Errorf("policy_engine.tags should still be set, got %q", tags)
	}
}

func TestHideHeaders_Disabled(t *testing.T) {
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
		HideHeaders: false,
	}
	mustProvision(t, pe)

	r := makeRequest("GET", "/admin", "10.0.0.1:1234")
	w := httptest.NewRecorder()
	err := pe.ServeHTTP(w, r, &nextHandler{})
	if err == nil {
		t.Fatal("expected error for block action")
	}
	// Headers should be set when HideHeaders is false.
	if w.Header().Get("X-Blocked-By") != "policy-engine" {
		t.Error("X-Blocked-By should be present when HideHeaders=false")
	}
}

// ─── Rule Type Validation (#11) ─────────────────────────────────────

func TestCompile_InvalidRuleType(t *testing.T) {
	_, err := compileRule(PolicyRule{
		ID: "test", Type: "unknown_type", Enabled: true,
		Conditions: []PolicyCondition{{Field: "path", Operator: "eq", Value: "/test"}},
	})
	if err == nil {
		t.Error("expected error for unsupported rule type")
	}
	if !strings.Contains(err.Error(), "unsupported rule type") {
		t.Errorf("expected 'unsupported rule type' error, got: %v", err)
	}
}

func TestCompile_ValidRuleTypes(t *testing.T) {
	for _, ruleType := range []string{"allow", "block", "honeypot"} {
		_, err := compileRule(PolicyRule{
			ID: "test", Type: ruleType, Enabled: true,
			Conditions: []PolicyCondition{{Field: "path", Operator: "eq", Value: "/test"}},
		})
		if err != nil {
			t.Errorf("rule type %q should compile, got: %v", ruleType, err)
		}
	}
}

// ─── parsedBody Caching (#2/#8) ─────────────────────────────────────

func TestParsedBody_JSONCaching(t *testing.T) {
	raw := []byte(`{"user":{"role":"admin"}}`)
	pb := &parsedBody{raw: raw}

	// First call parses.
	root1, ok1 := pb.getJSON()
	if !ok1 || root1 == nil {
		t.Fatal("first getJSON should succeed")
	}

	// Second call returns cached result without re-parsing.
	root2, ok2 := pb.getJSON()
	if !ok2 || root2 == nil {
		t.Fatal("second getJSON should succeed")
	}
	if !pb.jsonDone {
		t.Error("jsonDone should be true after getJSON")
	}
}

func TestParsedBody_FormCaching(t *testing.T) {
	raw := []byte("action=login&user=admin")
	pb := &parsedBody{raw: raw}

	vals1 := pb.getForm()
	if vals1 == nil || vals1.Get("action") != "login" {
		t.Fatal("first getForm should parse correctly")
	}

	vals2 := pb.getForm()
	if vals2 == nil || vals2.Get("user") != "admin" {
		t.Fatal("second getForm should return cached result")
	}
	if !pb.formDone {
		t.Error("formDone should be true after getForm")
	}
}

func TestParsedBody_InvalidJSON(t *testing.T) {
	pb := &parsedBody{raw: []byte(`not json`)}
	_, ok := pb.getJSON()
	if ok {
		t.Error("getJSON should fail for invalid JSON")
	}
	if !pb.jsonDone {
		t.Error("jsonDone should be true even on failure (don't retry)")
	}
}

func TestParsedBody_NilAndEmpty(t *testing.T) {
	// nil parsedBody.
	var pb *parsedBody
	_, ok := pb.getJSON()
	if ok {
		t.Error("nil parsedBody getJSON should return false")
	}
	vals := pb.getForm()
	if vals != nil {
		t.Error("nil parsedBody getForm should return nil")
	}

	// Empty raw.
	pb2 := &parsedBody{raw: []byte{}}
	_, ok2 := pb2.getJSON()
	if ok2 {
		t.Error("empty raw getJSON should return false")
	}
}

// ─── clientIP Tests ─────────────────────────────────────────────────

func TestClientIP_CaddyVar(t *testing.T) {
	// When Caddy's ClientIPVarKey is set, clientIP should return that IP,
	// NOT r.RemoteAddr (which is the TCP peer — e.g., a CF proxy IP).
	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = "172.71.98.44:12345" // CF proxy IP
	ctx := context.WithValue(r.Context(), caddyhttp.VarsCtxKey, map[string]any{
		caddyhttp.ClientIPVarKey: "93.123.109.246:54321",
	})
	r = r.WithContext(ctx)

	got := clientIP(r)
	if got != "93.123.109.246" {
		t.Errorf("clientIP = %q, want %q (should use Caddy var, not RemoteAddr)", got, "93.123.109.246")
	}
}

func TestClientIP_CaddyVarNoPort(t *testing.T) {
	// ClientIPVarKey may not include a port.
	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = "172.71.98.44:12345"
	ctx := context.WithValue(r.Context(), caddyhttp.VarsCtxKey, map[string]any{
		caddyhttp.ClientIPVarKey: "93.123.109.246",
	})
	r = r.WithContext(ctx)

	got := clientIP(r)
	if got != "93.123.109.246" {
		t.Errorf("clientIP = %q, want %q", got, "93.123.109.246")
	}
}

func TestClientIP_FallbackToRemoteAddr(t *testing.T) {
	// Without Caddy vars context (e.g., unit tests), falls back to r.RemoteAddr.
	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = "10.0.0.1:12345"

	got := clientIP(r)
	if got != "10.0.0.1" {
		t.Errorf("clientIP = %q, want %q", got, "10.0.0.1")
	}
}

func TestClientIP_EmptyCaddyVar(t *testing.T) {
	// If Caddy var is set but empty, fall back to RemoteAddr.
	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = "10.0.0.1:12345"
	ctx := context.WithValue(r.Context(), caddyhttp.VarsCtxKey, map[string]any{
		caddyhttp.ClientIPVarKey: "",
	})
	r = r.WithContext(ctx)

	got := clientIP(r)
	if got != "10.0.0.1" {
		t.Errorf("clientIP = %q, want %q (should fall back to RemoteAddr)", got, "10.0.0.1")
	}
}

func TestClientIP_IPv6CaddyVar(t *testing.T) {
	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = "172.71.98.44:12345"
	ctx := context.WithValue(r.Context(), caddyhttp.VarsCtxKey, map[string]any{
		caddyhttp.ClientIPVarKey: "[2001:db8::1]:54321",
	})
	r = r.WithContext(ctx)

	got := clientIP(r)
	if got != "2001:db8::1" {
		t.Errorf("clientIP = %q, want %q", got, "2001:db8::1")
	}
}

func TestClientIP_IPBlockWithCaddyVar(t *testing.T) {
	// Integration test: verify that a block rule with ip condition
	// matches the Caddy-resolved IP, not the TCP peer.
	rule := PolicyRule{
		ID:      "test-block-ip",
		Name:    "Block bad IP",
		Type:    "block",
		Enabled: true,
		Conditions: []PolicyCondition{
			{Field: "ip", Operator: "eq", Value: "93.123.109.246"},
		},
	}
	cr, err := compileRule(rule)
	if err != nil {
		t.Fatal(err)
	}

	r := httptest.NewRequest("GET", "/test", nil)
	r.RemoteAddr = "172.71.98.44:12345" // CF proxy
	ctx := context.WithValue(r.Context(), caddyhttp.VarsCtxKey, map[string]any{
		caddyhttp.ClientIPVarKey: "93.123.109.246:54321",
	})
	r = r.WithContext(ctx)

	if !matchRule(cr, r, nil) {
		t.Error("block rule should match when Caddy var has the target IP")
	}

	// Same request but with a different real IP — should NOT match.
	ctx2 := context.WithValue(r.Context(), caddyhttp.VarsCtxKey, map[string]any{
		caddyhttp.ClientIPVarKey: "1.2.3.4:54321",
	})
	r2 := r.WithContext(ctx2)
	if matchRule(cr, r2, nil) {
		t.Error("block rule should NOT match when Caddy var has a different IP")
	}
}

// ─── Detect Rule & Anomaly Scoring Tests ────────────────────────────

// writeTempRulesFileWithConfig writes a rules file that includes waf_config.
func writeTempRulesFileWithConfig(t *testing.T, rules []PolicyRule, wafCfg *WafConfig) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "policy-rules.json")
	file := PolicyRulesFile{
		Rules:     rules,
		WafConfig: wafCfg,
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

func TestDetect_SingleRule_ScoresCorrectly(t *testing.T) {
	pe := &PolicyEngine{
		Rules: []PolicyRule{
			{
				ID: "d1", Name: "Missing Accept", Type: "detect", Enabled: true,
				Priority: 150, Severity: "NOTICE", ParanoiaLevel: 1,
				Conditions: []PolicyCondition{
					{Field: "header", Operator: "eq", Value: "Accept:"},
				},
			},
		},
	}
	mustProvision(t, pe)

	// Request without Accept header → condition matches (header equals empty).
	r := makeRequest("GET", "/test", "10.0.0.1:1234")
	w := httptest.NewRecorder()
	next := &nextHandler{}
	err := pe.ServeHTTP(w, r, next)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !next.called {
		t.Fatal("next handler should be called (score below threshold)")
	}
	// Check anomaly_score is set.
	score, _ := caddyhttp.GetVar(r.Context(), "policy_engine.anomaly_score").(string)
	if score != "2" {
		t.Errorf("expected anomaly_score=2 (NOTICE), got %q", score)
	}
}

func TestDetect_MultipleRules_Cumulative(t *testing.T) {
	pe := &PolicyEngine{
		Rules: []PolicyRule{
			{
				ID: "d1", Name: "NOTICE rule", Type: "detect", Enabled: true,
				Priority: 150, Severity: "NOTICE", ParanoiaLevel: 1,
				Conditions: []PolicyCondition{
					{Field: "path", Operator: "contains", Value: "/test"},
				},
			},
			{
				ID: "d2", Name: "WARNING rule", Type: "detect", Enabled: true,
				Priority: 150, Severity: "WARNING", ParanoiaLevel: 1,
				Conditions: []PolicyCondition{
					{Field: "method", Operator: "eq", Value: "GET"},
				},
			},
			{
				ID: "d3", Name: "CRITICAL rule", Type: "detect", Enabled: true,
				Priority: 150, Severity: "CRITICAL", ParanoiaLevel: 1,
				Conditions: []PolicyCondition{
					{Field: "path", Operator: "contains", Value: "/test"},
				},
			},
		},
	}
	mustProvision(t, pe)

	r := makeRequest("GET", "/test", "10.0.0.1:1234")
	w := httptest.NewRecorder()
	next := &nextHandler{}
	_ = pe.ServeHTTP(w, r, next)

	// NOTICE(2) + WARNING(3) + CRITICAL(5) = 10
	score, _ := caddyhttp.GetVar(r.Context(), "policy_engine.anomaly_score").(string)
	if score != "10" {
		t.Errorf("expected cumulative score=10, got %q", score)
	}
	matched, _ := caddyhttp.GetVar(r.Context(), "policy_engine.matched_rules").(string)
	if matched != "3" {
		t.Errorf("expected 3 matched rules, got %q", matched)
	}
}

func TestDetect_ThresholdExceeded_Blocks(t *testing.T) {
	path := writeTempRulesFileWithConfig(t, []PolicyRule{
		{
			ID: "d1", Name: "CRITICAL detect", Type: "detect", Enabled: true,
			Priority: 150, Severity: "CRITICAL", ParanoiaLevel: 1,
			Conditions: []PolicyCondition{
				{Field: "path", Operator: "contains", Value: "/bad"},
			},
		},
		{
			ID: "d2", Name: "ERROR detect", Type: "detect", Enabled: true,
			Priority: 150, Severity: "ERROR", ParanoiaLevel: 1,
			Conditions: []PolicyCondition{
				{Field: "path", Operator: "contains", Value: "/bad"},
			},
		},
		{
			ID: "d3", Name: "WARNING detect", Type: "detect", Enabled: true,
			Priority: 150, Severity: "WARNING", ParanoiaLevel: 1,
			Conditions: []PolicyCondition{
				{Field: "path", Operator: "contains", Value: "/bad"},
			},
		},
	}, &WafConfig{
		ParanoiaLevel:    2,
		InboundThreshold: 10,
	})

	pe := &PolicyEngine{RulesFile: path}
	mustProvision(t, pe)

	// Score: CRITICAL(5) + ERROR(4) + WARNING(3) = 12 > threshold 10.
	r := makeRequest("GET", "/bad-path", "10.0.0.1:1234")
	w := httptest.NewRecorder()
	next := &nextHandler{}
	err := pe.ServeHTTP(w, r, next)
	if err == nil {
		t.Fatal("expected error for detect_block (score exceeded threshold)")
	}
	if next.called {
		t.Error("next handler should NOT be called when score exceeds threshold")
	}
	action, _ := caddyhttp.GetVar(r.Context(), "policy_engine.action").(string)
	if action != "detect_block" {
		t.Errorf("expected action=detect_block, got %q", action)
	}
	score, _ := caddyhttp.GetVar(r.Context(), "policy_engine.anomaly_score").(string)
	if score != "12" {
		t.Errorf("expected anomaly_score=12, got %q", score)
	}
}

func TestDetect_BelowThreshold_Passes(t *testing.T) {
	path := writeTempRulesFileWithConfig(t, []PolicyRule{
		{
			ID: "d1", Name: "NOTICE detect", Type: "detect", Enabled: true,
			Priority: 150, Severity: "NOTICE", ParanoiaLevel: 1,
			Conditions: []PolicyCondition{
				{Field: "path", Operator: "contains", Value: "/test"},
			},
		},
	}, &WafConfig{
		ParanoiaLevel:    2,
		InboundThreshold: 10,
	})

	pe := &PolicyEngine{RulesFile: path}
	mustProvision(t, pe)

	// Score: NOTICE(2) < threshold 10.
	r := makeRequest("GET", "/test", "10.0.0.1:1234")
	w := httptest.NewRecorder()
	next := &nextHandler{}
	err := pe.ServeHTTP(w, r, next)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !next.called {
		t.Error("next handler should be called (score below threshold)")
	}
	action, _ := caddyhttp.GetVar(r.Context(), "policy_engine.action").(string)
	if action == "detect_block" {
		t.Error("should not block when below threshold")
	}
}

func TestDetect_ParanoiaLevel_Filtering(t *testing.T) {
	path := writeTempRulesFileWithConfig(t, []PolicyRule{
		{
			ID: "d1", Name: "PL1 rule", Type: "detect", Enabled: true,
			Priority: 150, Severity: "CRITICAL", ParanoiaLevel: 1,
			Conditions: []PolicyCondition{
				{Field: "path", Operator: "contains", Value: "/test"},
			},
		},
		{
			ID: "d2", Name: "PL3 rule", Type: "detect", Enabled: true,
			Priority: 150, Severity: "CRITICAL", ParanoiaLevel: 3,
			Conditions: []PolicyCondition{
				{Field: "path", Operator: "contains", Value: "/test"},
			},
		},
	}, &WafConfig{
		ParanoiaLevel:    2, // Only PL1 and PL2 rules should fire.
		InboundThreshold: 20,
	})

	pe := &PolicyEngine{RulesFile: path}
	mustProvision(t, pe)

	r := makeRequest("GET", "/test", "10.0.0.1:1234")
	w := httptest.NewRecorder()
	next := &nextHandler{}
	_ = pe.ServeHTTP(w, r, next)

	// Only PL1 rule (CRITICAL=5) should fire. PL3 rule is filtered out.
	score, _ := caddyhttp.GetVar(r.Context(), "policy_engine.anomaly_score").(string)
	if score != "5" {
		t.Errorf("expected score=5 (only PL1 rule), got %q", score)
	}
	matched, _ := caddyhttp.GetVar(r.Context(), "policy_engine.matched_rules").(string)
	if matched != "1" {
		t.Errorf("expected 1 matched rule, got %q", matched)
	}
}

func TestDetect_PerServiceThreshold(t *testing.T) {
	path := writeTempRulesFileWithConfig(t, []PolicyRule{
		{
			ID: "d1", Name: "CRITICAL detect", Type: "detect", Enabled: true,
			Priority: 150, Severity: "CRITICAL", ParanoiaLevel: 1,
			Conditions: []PolicyCondition{
				{Field: "path", Operator: "contains", Value: "/test"},
			},
		},
	}, &WafConfig{
		ParanoiaLevel:    2,
		InboundThreshold: 3, // Default: score 5 > threshold 3 → block.
		PerService: map[string]WafServiceConfig{
			"relaxed.example.com": {InboundThreshold: 20}, // Override: 5 < 20 → pass.
		},
	})

	pe := &PolicyEngine{RulesFile: path}
	mustProvision(t, pe)

	// Request to default host → should block (5 >= 3).
	r1 := makeRequest("GET", "/test", "10.0.0.1:1234")
	r1.Host = "strict.example.com"
	w1 := httptest.NewRecorder()
	next1 := &nextHandler{}
	err := pe.ServeHTTP(w1, r1, next1)
	if err == nil {
		t.Fatal("expected block on strict host")
	}

	// Request to relaxed host → should pass (5 < 20).
	r2 := makeRequest("GET", "/test", "10.0.0.1:1234")
	r2.Host = "relaxed.example.com"
	w2 := httptest.NewRecorder()
	next2 := &nextHandler{}
	err = pe.ServeHTTP(w2, r2, next2)
	if err != nil {
		t.Fatalf("unexpected error on relaxed host: %v", err)
	}
	if !next2.called {
		t.Error("next handler should be called for relaxed host")
	}
}

func TestDetect_AllowBypassesScoring(t *testing.T) {
	pe := &PolicyEngine{
		Rules: []PolicyRule{
			{
				ID: "a1", Name: "Allow all", Type: "allow", Enabled: true,
				Priority: 200,
				Conditions: []PolicyCondition{
					{Field: "path", Operator: "contains", Value: "/test"},
				},
			},
			{
				ID: "d1", Name: "CRITICAL detect", Type: "detect", Enabled: true,
				Priority: 150, Severity: "CRITICAL", ParanoiaLevel: 1,
				Conditions: []PolicyCondition{
					{Field: "path", Operator: "contains", Value: "/test"},
				},
			},
		},
	}
	mustProvision(t, pe)

	r := makeRequest("GET", "/test", "10.0.0.1:1234")
	w := httptest.NewRecorder()
	next := &nextHandler{}
	err := pe.ServeHTTP(w, r, next)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Allow rule matched → detect rules should be skipped.
	action, _ := caddyhttp.GetVar(r.Context(), "policy_engine.action").(string)
	if action != "allow" {
		t.Errorf("expected action=allow, got %q", action)
	}
	// No score should be set since detect was skipped.
	score, _ := caddyhttp.GetVar(r.Context(), "policy_engine.anomaly_score").(string)
	if score != "" {
		t.Errorf("expected no anomaly_score (detect skipped by allow), got %q", score)
	}
}

func TestDetect_BlockTakesPrecedenceOverDetect(t *testing.T) {
	pe := &PolicyEngine{
		Rules: []PolicyRule{
			{
				ID: "b1", Name: "Block path", Type: "block", Enabled: true,
				Priority: 100,
				Conditions: []PolicyCondition{
					{Field: "path", Operator: "eq", Value: "/blocked"},
				},
			},
			{
				ID: "d1", Name: "CRITICAL detect", Type: "detect", Enabled: true,
				Priority: 150, Severity: "CRITICAL", ParanoiaLevel: 1,
				Conditions: []PolicyCondition{
					{Field: "path", Operator: "eq", Value: "/blocked"},
				},
			},
		},
	}
	mustProvision(t, pe)

	r := makeRequest("GET", "/blocked", "10.0.0.1:1234")
	w := httptest.NewRecorder()
	err := pe.ServeHTTP(w, r, &nextHandler{})
	if err == nil {
		t.Fatal("expected error for block action")
	}
	action, _ := caddyhttp.GetVar(r.Context(), "policy_engine.action").(string)
	if action != "block" {
		t.Errorf("expected action=block (not detect_block), got %q", action)
	}
}

func TestDetect_NoWafConfig_NoBlocking(t *testing.T) {
	// Without waf_config, threshold is 0 meaning no threshold-based blocking.
	pe := &PolicyEngine{
		Rules: []PolicyRule{
			{
				ID: "d1", Name: "CRITICAL detect", Type: "detect", Enabled: true,
				Priority: 150, Severity: "CRITICAL", ParanoiaLevel: 1,
				Conditions: []PolicyCondition{
					{Field: "path", Operator: "contains", Value: "/test"},
				},
			},
		},
	}
	mustProvision(t, pe)

	r := makeRequest("GET", "/test", "10.0.0.1:1234")
	w := httptest.NewRecorder()
	next := &nextHandler{}
	err := pe.ServeHTTP(w, r, next)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !next.called {
		t.Error("next handler should be called (no waf_config = no threshold blocking)")
	}
	// Score should still be set for observability.
	score, _ := caddyhttp.GetVar(r.Context(), "policy_engine.anomaly_score").(string)
	if score != "5" {
		t.Errorf("expected anomaly_score=5 even without config, got %q", score)
	}
}

func TestDetect_SeverityMapping(t *testing.T) {
	tests := []struct {
		severity string
		score    int
	}{
		{"CRITICAL", 5},
		{"ERROR", 4},
		{"WARNING", 3},
		{"NOTICE", 2},
	}
	for _, tt := range tests {
		t.Run(tt.severity, func(t *testing.T) {
			rule := PolicyRule{
				ID: "d1", Name: "test", Type: "detect", Enabled: true,
				Priority: 150, Severity: tt.severity, ParanoiaLevel: 1,
				Conditions: []PolicyCondition{
					{Field: "path", Operator: "eq", Value: "/"},
				},
			}
			cr, err := compileRule(rule)
			if err != nil {
				t.Fatalf("compile error: %v", err)
			}
			if cr.score != tt.score {
				t.Errorf("expected score=%d for %s, got %d", tt.score, tt.severity, cr.score)
			}
		})
	}
}

func TestDetect_InvalidSeverity_Rejected(t *testing.T) {
	rule := PolicyRule{
		ID: "d1", Name: "test", Type: "detect", Enabled: true,
		Priority: 150, Severity: "UNKNOWN", ParanoiaLevel: 1,
		Conditions: []PolicyCondition{
			{Field: "path", Operator: "eq", Value: "/"},
		},
	}
	_, err := compileRule(rule)
	if err == nil {
		t.Fatal("expected error for invalid severity")
	}
	if !strings.Contains(err.Error(), "unknown severity") {
		t.Errorf("expected 'unknown severity' error, got: %v", err)
	}
}

func TestDetect_MissingSeverity_Rejected(t *testing.T) {
	rule := PolicyRule{
		ID: "d1", Name: "test", Type: "detect", Enabled: true,
		Priority: 150, ParanoiaLevel: 1,
		Conditions: []PolicyCondition{
			{Field: "path", Operator: "eq", Value: "/"},
		},
	}
	_, err := compileRule(rule)
	if err == nil {
		t.Fatal("expected error for missing severity")
	}
	if !strings.Contains(err.Error(), "must have a severity") {
		t.Errorf("expected 'must have a severity' error, got: %v", err)
	}
}

func TestDetect_InvalidParanoiaLevel_Rejected(t *testing.T) {
	rule := PolicyRule{
		ID: "d1", Name: "test", Type: "detect", Enabled: true,
		Priority: 150, Severity: "CRITICAL", ParanoiaLevel: 5,
		Conditions: []PolicyCondition{
			{Field: "path", Operator: "eq", Value: "/"},
		},
	}
	_, err := compileRule(rule)
	if err == nil {
		t.Fatal("expected error for paranoia_level > 4")
	}
}

func TestCompileWafConfig_Nil(t *testing.T) {
	c := compileWafConfig(nil)
	if c != nil {
		t.Error("expected nil for nil config")
	}
}

func TestCompileWafConfig_Defaults(t *testing.T) {
	c := compileWafConfig(&WafConfig{})
	if c == nil {
		t.Fatal("expected non-nil compiled config")
	}
	if c.defaultPL != 1 {
		t.Errorf("expected defaultPL=1, got %d", c.defaultPL)
	}
	if c.defaultInThreshold != 10 {
		t.Errorf("expected defaultInThreshold=10, got %d", c.defaultInThreshold)
	}
}

func TestCompileWafConfig_PerService(t *testing.T) {
	c := compileWafConfig(&WafConfig{
		ParanoiaLevel:    2,
		InboundThreshold: 10,
		PerService: map[string]WafServiceConfig{
			"strict.example.com":  {ParanoiaLevel: 1, InboundThreshold: 5},
			"relaxed.example.com": {InboundThreshold: 20}, // PL inherits from default.
		},
	})
	if c == nil {
		t.Fatal("expected non-nil")
	}
	// Default lookup.
	pl, th := resolveWafConfig(c, "unknown.example.com")
	if pl != 2 || th != 10 {
		t.Errorf("default: expected PL=2 threshold=10, got PL=%d threshold=%d", pl, th)
	}
	// Strict override.
	pl, th = resolveWafConfig(c, "strict.example.com")
	if pl != 1 || th != 5 {
		t.Errorf("strict: expected PL=1 threshold=5, got PL=%d threshold=%d", pl, th)
	}
	// Relaxed override (PL inherits, threshold overridden).
	pl, th = resolveWafConfig(c, "relaxed.example.com")
	if pl != 2 || th != 20 {
		t.Errorf("relaxed: expected PL=2 threshold=20, got PL=%d threshold=%d", pl, th)
	}
}

func TestResolveWafConfig_Nil(t *testing.T) {
	pl, th := resolveWafConfig(nil, "example.com")
	if pl != 1 || th != 0 {
		t.Errorf("nil config: expected PL=1 threshold=0, got PL=%d threshold=%d", pl, th)
	}
}

func TestDetect_ServiceMatching(t *testing.T) {
	path := writeTempRulesFileWithConfig(t, []PolicyRule{
		{
			ID: "d1", Name: "Service-specific detect", Type: "detect", Enabled: true,
			Priority: 150, Severity: "CRITICAL", ParanoiaLevel: 1,
			Service: "target.example.com",
			Conditions: []PolicyCondition{
				{Field: "path", Operator: "contains", Value: "/test"},
			},
		},
	}, &WafConfig{
		ParanoiaLevel:    2,
		InboundThreshold: 3,
	})

	pe := &PolicyEngine{RulesFile: path}
	mustProvision(t, pe)

	// Request to matching service → should score and block.
	r1 := makeRequest("GET", "/test", "10.0.0.1:1234")
	r1.Host = "target.example.com"
	w1 := httptest.NewRecorder()
	err := pe.ServeHTTP(w1, r1, &nextHandler{})
	if err == nil {
		t.Fatal("expected block on matching service")
	}

	// Request to different service → detect rule skipped, no scoring.
	r2 := makeRequest("GET", "/test", "10.0.0.1:1234")
	r2.Host = "other.example.com"
	w2 := httptest.NewRecorder()
	next2 := &nextHandler{}
	err = pe.ServeHTTP(w2, r2, next2)
	if err != nil {
		t.Fatalf("unexpected error on non-matching service: %v", err)
	}
	if !next2.called {
		t.Error("next handler should be called for non-matching service")
	}
}

func TestDetect_AnomalyScoreHeader(t *testing.T) {
	path := writeTempRulesFileWithConfig(t, []PolicyRule{
		{
			ID: "d1", Name: "CRITICAL detect", Type: "detect", Enabled: true,
			Priority: 150, Severity: "CRITICAL", ParanoiaLevel: 1,
			Conditions: []PolicyCondition{
				{Field: "path", Operator: "contains", Value: "/bad"},
			},
		},
		{
			ID: "d2", Name: "CRITICAL detect 2", Type: "detect", Enabled: true,
			Priority: 150, Severity: "CRITICAL", ParanoiaLevel: 1,
			Conditions: []PolicyCondition{
				{Field: "path", Operator: "contains", Value: "/bad"},
			},
		},
	}, &WafConfig{
		ParanoiaLevel:    2,
		InboundThreshold: 5,
	})

	pe := &PolicyEngine{RulesFile: path}
	mustProvision(t, pe)

	r := makeRequest("GET", "/bad", "10.0.0.1:1234")
	w := httptest.NewRecorder()
	_ = pe.ServeHTTP(w, r, &nextHandler{})

	// Should have X-Anomaly-Score header (score=10 exceeds threshold=5).
	if w.Header().Get("X-Anomaly-Score") != "10" {
		t.Errorf("expected X-Anomaly-Score=10, got %q", w.Header().Get("X-Anomaly-Score"))
	}
	if w.Header().Get("X-Blocked-By") != "policy-engine" {
		t.Errorf("expected X-Blocked-By=policy-engine, got %q", w.Header().Get("X-Blocked-By"))
	}
}

func TestDetect_DisabledRulesSkipped(t *testing.T) {
	pe := &PolicyEngine{
		Rules: []PolicyRule{
			{
				ID: "d1", Name: "Disabled detect", Type: "detect", Enabled: false,
				Priority: 150, Severity: "CRITICAL", ParanoiaLevel: 1,
				Conditions: []PolicyCondition{
					{Field: "path", Operator: "contains", Value: "/test"},
				},
			},
		},
	}
	mustProvision(t, pe)

	r := makeRequest("GET", "/test", "10.0.0.1:1234")
	w := httptest.NewRecorder()
	next := &nextHandler{}
	err := pe.ServeHTTP(w, r, next)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !next.called {
		t.Error("next handler should be called (disabled rule)")
	}
	score, _ := caddyhttp.GetVar(r.Context(), "policy_engine.anomaly_score").(string)
	if score != "" {
		t.Errorf("expected no score for disabled rule, got %q", score)
	}
}

func TestStripPort(t *testing.T) {
	tests := []struct {
		input, expected string
	}{
		{"example.com:8080", "example.com"},
		{"example.com", "example.com"},
		{"[::1]:8080", "::1"},
		{"::1", "::1"},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := stripPort(tt.input)
			if got != tt.expected {
				t.Errorf("stripPort(%q) = %q, want %q", tt.input, got, tt.expected)
			}
		})
	}
}

func TestDetect_HotReload_WafConfig(t *testing.T) {
	// Start with threshold=20 (no block for score=5).
	path := writeTempRulesFileWithConfig(t, []PolicyRule{
		{
			ID: "d1", Name: "CRITICAL detect", Type: "detect", Enabled: true,
			Priority: 150, Severity: "CRITICAL", ParanoiaLevel: 1,
			Conditions: []PolicyCondition{
				{Field: "path", Operator: "contains", Value: "/test"},
			},
		},
	}, &WafConfig{
		ParanoiaLevel:    2,
		InboundThreshold: 20,
	})

	pe := &PolicyEngine{RulesFile: path}
	mustProvision(t, pe)

	// Should pass (5 < 20).
	r := makeRequest("GET", "/test", "10.0.0.1:1234")
	w := httptest.NewRecorder()
	next := &nextHandler{}
	err := pe.ServeHTTP(w, r, next)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !next.called {
		t.Error("should pass with threshold=20")
	}

	// Update file to lower threshold to 3.
	time.Sleep(50 * time.Millisecond)
	file := PolicyRulesFile{
		Rules: []PolicyRule{
			{
				ID: "d1", Name: "CRITICAL detect", Type: "detect", Enabled: true,
				Priority: 150, Severity: "CRITICAL", ParanoiaLevel: 1,
				Conditions: []PolicyCondition{
					{Field: "path", Operator: "contains", Value: "/test"},
				},
			},
		},
		WafConfig: &WafConfig{
			ParanoiaLevel:    2,
			InboundThreshold: 3,
		},
		Generated: time.Now().UTC().Format(time.RFC3339),
		Version:   1,
	}
	data, _ := json.MarshalIndent(file, "", "  ")
	os.WriteFile(path, data, 0644)

	// Force reload.
	if err := pe.loadFromFile(); err != nil {
		t.Fatalf("reload failed: %v", err)
	}

	// Now should block (5 >= 3).
	r2 := makeRequest("GET", "/test", "10.0.0.1:1234")
	w2 := httptest.NewRecorder()
	next2 := &nextHandler{}
	err = pe.ServeHTTP(w2, r2, next2)
	if err == nil {
		t.Fatal("expected block after threshold lowered")
	}
	action, _ := caddyhttp.GetVar(r2.Context(), "policy_engine.action").(string)
	if action != "detect_block" {
		t.Errorf("expected action=detect_block, got %q", action)
	}
}

// ─── v0.9.0: Multi-Variable Inspection ────────────────────────────────

func TestExtractMultiField_AllArgs(t *testing.T) {
	r := makeRequest("GET", "/search?q=hello&sort=asc&q=world", "")
	cc := compiledCondition{field: "all_args"}
	vals := extractMultiField(cc, r, nil)

	// Should contain param names AND values.
	have := make(map[string]bool)
	for _, v := range vals {
		have[v] = true
	}
	for _, want := range []string{"q", "sort", "hello", "asc", "world"} {
		if !have[want] {
			t.Errorf("all_args missing %q, got %v", want, vals)
		}
	}
}

func TestExtractMultiField_AllArgsValues(t *testing.T) {
	r := makeRequest("GET", "/search?q=hello&sort=asc", "")
	cc := compiledCondition{field: "all_args_values"}
	vals := extractMultiField(cc, r, nil)

	have := make(map[string]bool)
	for _, v := range vals {
		have[v] = true
	}
	// Should contain values only, not names.
	if have["q"] || have["sort"] {
		t.Errorf("all_args_values should not contain param names, got %v", vals)
	}
	for _, want := range []string{"hello", "asc"} {
		if !have[want] {
			t.Errorf("all_args_values missing %q", want)
		}
	}
}

func TestExtractMultiField_AllArgsNames(t *testing.T) {
	r := makeRequest("GET", "/search?q=hello&sort=asc", "")
	cc := compiledCondition{field: "all_args_names"}
	vals := extractMultiField(cc, r, nil)

	have := make(map[string]bool)
	for _, v := range vals {
		have[v] = true
	}
	for _, want := range []string{"q", "sort"} {
		if !have[want] {
			t.Errorf("all_args_names missing %q", want)
		}
	}
	// Should not contain values.
	if have["hello"] || have["asc"] {
		t.Errorf("all_args_names should not contain values, got %v", vals)
	}
}

func TestExtractMultiField_AllHeaders(t *testing.T) {
	r := makeRequestWithHeaders("GET", "/", "", map[string]string{
		"X-Custom":     "foo",
		"X-Another":    "bar",
		"Content-Type": "text/html",
	})
	cc := compiledCondition{field: "all_headers"}
	vals := extractMultiField(cc, r, nil)

	have := make(map[string]bool)
	for _, v := range vals {
		have[v] = true
	}
	if !have["foo"] || !have["bar"] || !have["text/html"] {
		t.Errorf("all_headers missing expected values, got %v", vals)
	}
}

func TestExtractMultiField_AllHeadersNames(t *testing.T) {
	r := makeRequestWithHeaders("GET", "/", "", map[string]string{
		"X-Custom":  "foo",
		"X-Another": "bar",
	})
	cc := compiledCondition{field: "all_headers_names"}
	vals := extractMultiField(cc, r, nil)

	have := make(map[string]bool)
	for _, v := range vals {
		have[v] = true
	}
	// Go canonicalizes header names.
	if !have["X-Custom"] || !have["X-Another"] {
		t.Errorf("all_headers_names missing expected names, got %v", vals)
	}
}

func TestExtractMultiField_AllCookies(t *testing.T) {
	r := makeRequest("GET", "/", "")
	r.Header.Set("Cookie", "session=abc123; pref=dark")
	cc := compiledCondition{field: "all_cookies"}
	vals := extractMultiField(cc, r, nil)

	have := make(map[string]bool)
	for _, v := range vals {
		have[v] = true
	}
	if !have["abc123"] || !have["dark"] {
		t.Errorf("all_cookies missing expected values, got %v", vals)
	}
}

func TestExtractMultiField_AllCookiesNames(t *testing.T) {
	r := makeRequest("GET", "/", "")
	r.Header.Set("Cookie", "session=abc123; pref=dark")
	cc := compiledCondition{field: "all_cookies_names"}
	vals := extractMultiField(cc, r, nil)

	have := make(map[string]bool)
	for _, v := range vals {
		have[v] = true
	}
	if !have["session"] || !have["pref"] {
		t.Errorf("all_cookies_names missing expected names, got %v", vals)
	}
}

func TestExtractMultiField_WithFormBody(t *testing.T) {
	r := httptest.NewRequest("POST", "/login?redirect=/home", strings.NewReader("username=admin&password=secret"))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	ctx := context.WithValue(r.Context(), caddyhttp.VarsCtxKey, make(map[string]interface{}))
	r = r.WithContext(ctx)

	buf, _ := readBody(r, 1024*1024)
	pb := &parsedBody{raw: buf}

	cc := compiledCondition{field: "all_args"}
	vals := extractMultiField(cc, r, pb)

	have := make(map[string]bool)
	for _, v := range vals {
		have[v] = true
	}
	// Should include both query params AND form params (names + values).
	for _, want := range []string{"redirect", "/home", "username", "admin", "password", "secret"} {
		if !have[want] {
			t.Errorf("all_args (with body) missing %q, got %v", want, vals)
		}
	}
}

// ─── v0.9.0: Multi-Value Matching (matchCondition with isMulti) ────

func TestMatchCondition_MultiField_Contains(t *testing.T) {
	cc, err := compileCondition(PolicyCondition{
		Field:    "all_args",
		Operator: "contains",
		Value:    "select",
	})
	if err != nil {
		t.Fatal(err)
	}
	if !cc.isMulti {
		t.Fatal("all_args should set isMulti")
	}

	// Request with SQL in a query param value.
	r := makeRequest("GET", "/search?q=1+union+select+1", "")
	if !matchCondition(cc, r, nil) {
		t.Error("should match: 'select' is in query param value")
	}

	// Clean request.
	r2 := makeRequest("GET", "/search?q=hello+world", "")
	if matchCondition(cc, r2, nil) {
		t.Error("should not match: no 'select' in any arg")
	}
}

func TestMatchCondition_MultiField_Negate(t *testing.T) {
	// neq on multi-field: negate + any match = false (NOT-ANY = ALL-NOT).
	cc, err := compileCondition(PolicyCondition{
		Field:    "all_headers",
		Operator: "neq",
		Value:    "bad-value",
	})
	if err != nil {
		t.Fatal(err)
	}

	// One header has "bad-value" — neq should return false.
	r := makeRequestWithHeaders("GET", "/", "", map[string]string{
		"X-Test": "bad-value",
	})
	if matchCondition(cc, r, nil) {
		t.Error("neq on multi-field should return false when any value equals the target")
	}

	// No header has "bad-value" — neq should return true.
	r2 := makeRequestWithHeaders("GET", "/", "", map[string]string{
		"X-Test": "good-value",
	})
	if !matchCondition(cc, r2, nil) {
		t.Error("neq on multi-field should return true when no value equals the target")
	}
}

func TestMatchCondition_MultiField_WithTransforms(t *testing.T) {
	cc, err := compileCondition(PolicyCondition{
		Field:      "all_args_values",
		Operator:   "contains",
		Value:      "select",
		Transforms: []string{"lowercase", "urlDecode"},
	})
	if err != nil {
		t.Fatal(err)
	}

	// URL-encoded uppercase.
	r := makeRequest("GET", "/search?q=%53ELECT", "")
	if !matchCondition(cc, r, nil) {
		t.Error("transforms should decode %53 → S, then lowercase → select")
	}
}

// ─── v0.9.0: phrase_match Operator ─────────────────────────────────

func TestCompileCondition_PhraseMatch(t *testing.T) {
	cc, err := compileCondition(PolicyCondition{
		Field:     "all_args",
		Operator:  "phrase_match",
		ListItems: []string{"select", "union", "insert", "drop"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if cc.acMatcher == nil {
		t.Fatal("phrase_match should compile an AC matcher")
	}
	if !cc.isMulti {
		t.Fatal("all_args should set isMulti")
	}
}

func TestCompileCondition_PhraseMatch_NoItems(t *testing.T) {
	_, err := compileCondition(PolicyCondition{
		Field:    "path",
		Operator: "phrase_match",
	})
	if err == nil {
		t.Fatal("phrase_match without list_items should fail")
	}
}

func TestMatchCondition_PhraseMatch_SingleField(t *testing.T) {
	cc, err := compileCondition(PolicyCondition{
		Field:     "query",
		Operator:  "phrase_match",
		ListItems: []string{"select", "union", "drop", "insert"},
	})
	if err != nil {
		t.Fatal(err)
	}

	r := makeRequest("GET", "/search?q=1+union+select+1,2,3", "")
	if !matchCondition(cc, r, nil) {
		t.Error("phrase_match should find 'union' or 'select' in query string")
	}

	r2 := makeRequest("GET", "/search?q=hello+world", "")
	if matchCondition(cc, r2, nil) {
		t.Error("phrase_match should not match clean query string")
	}
}

func TestMatchCondition_PhraseMatch_MultiField(t *testing.T) {
	cc, err := compileCondition(PolicyCondition{
		Field:     "all_args",
		Operator:  "phrase_match",
		ListItems: []string{"<script", "javascript:", "onerror="},
	})
	if err != nil {
		t.Fatal(err)
	}

	r := makeRequest("GET", "/page?name=normal&bio=<script>alert(1)</script>", "")
	if !matchCondition(cc, r, nil) {
		t.Error("phrase_match should find '<script' in bio arg value")
	}

	r2 := makeRequest("GET", "/page?name=normal&bio=hello", "")
	if matchCondition(cc, r2, nil) {
		t.Error("phrase_match should not match clean args")
	}
}

func TestMatchCondition_PhraseMatch_WithTransforms(t *testing.T) {
	cc, err := compileCondition(PolicyCondition{
		Field:      "all_args_values",
		Operator:   "phrase_match",
		ListItems:  []string{"select", "union", "insert"},
		Transforms: []string{"lowercase", "urlDecode"},
	})
	if err != nil {
		t.Fatal(err)
	}

	// URL-encoded uppercase: %53ELECT → SELECT → select
	r := makeRequest("GET", "/search?q=%53ELECT", "")
	if !matchCondition(cc, r, nil) {
		t.Error("phrase_match with transforms should decode and lowercase")
	}
}

// ─── v0.9.0: Numeric Comparison Operators ──────────────────────────

func TestCompileCondition_NumericOperators(t *testing.T) {
	tests := []struct {
		op    string
		value string
		err   bool
	}{
		{"gt", "100", false},
		{"ge", "0", false},
		{"lt", "255.5", false},
		{"le", "-1", false},
		{"gt", "abc", true}, // non-numeric
		{"le", "", true},    // empty
	}

	for _, tt := range tests {
		_, err := compileCondition(PolicyCondition{
			Field:    "header",
			Operator: tt.op,
			Value:    "Content-Length:" + tt.value,
		})
		if tt.err && err == nil {
			t.Errorf("op=%s value=%q should fail", tt.op, tt.value)
		}
		if !tt.err && err != nil {
			t.Errorf("op=%s value=%q unexpected error: %v", tt.op, tt.value, err)
		}
	}
}

func TestEvalOperator_NumericComparison(t *testing.T) {
	tests := []struct {
		op     string
		numVal float64
		target string
		want   bool
	}{
		{"gt", 100, "150", true},
		{"gt", 100, "100", false},
		{"gt", 100, "50", false},
		{"ge", 100, "100", true},
		{"ge", 100, "101", true},
		{"ge", 100, "99", false},
		{"lt", 100, "50", true},
		{"lt", 100, "100", false},
		{"lt", 100, "150", false},
		{"le", 100, "100", true},
		{"le", 100, "99", true},
		{"le", 100, "101", false},
		// Non-numeric target → false.
		{"gt", 100, "abc", false},
		{"lt", 100, "", false},
		// Decimal comparison.
		{"gt", 99.5, "100", true},
		{"lt", 99.5, "99", true},
	}

	for _, tt := range tests {
		cc := compiledCondition{operator: tt.op, numericVal: tt.numVal}
		got := evalOperator(cc, tt.target)
		if got != tt.want {
			t.Errorf("evalOperator(%s, numVal=%.1f, target=%q) = %v, want %v",
				tt.op, tt.numVal, tt.target, got, tt.want)
		}
	}
}

// ─── v0.9.0: count: Pseudo-Field ──────────────────────────────────

func TestCompileCondition_Count(t *testing.T) {
	cc, err := compileCondition(PolicyCondition{
		Field:    "count:all_args",
		Operator: "gt",
		Value:    "10",
	})
	if err != nil {
		t.Fatal(err)
	}
	if !cc.isCount {
		t.Error("count: field should set isCount")
	}
	if cc.countField != "all_args" {
		t.Errorf("countField = %q, want all_args", cc.countField)
	}
	if cc.isMulti {
		t.Error("count: should NOT set isMulti (produces a single value)")
	}
}

func TestCompileCondition_Count_InvalidField(t *testing.T) {
	_, err := compileCondition(PolicyCondition{
		Field:    "count:path",
		Operator: "gt",
		Value:    "10",
	})
	if err == nil {
		t.Fatal("count:path should fail (path is not an aggregate field)")
	}
}

func TestMatchCondition_Count(t *testing.T) {
	cc, err := compileCondition(PolicyCondition{
		Field:    "count:all_args",
		Operator: "gt",
		Value:    "3",
	})
	if err != nil {
		t.Fatal(err)
	}

	// 4 values (2 names + 2 values = 4 in all_args) > 3
	r := makeRequest("GET", "/search?q=hello&sort=asc", "")
	if !matchCondition(cc, r, nil) {
		t.Error("count:all_args should be > 3 (q, hello, sort, asc = 4)")
	}

	// 2 values (1 name + 1 value = 2) not > 3
	r2 := makeRequest("GET", "/search?q=hello", "")
	if matchCondition(cc, r2, nil) {
		t.Error("count:all_args should NOT be > 3 (q, hello = 2)")
	}
}

func TestMatchCondition_Count_ArgsNames(t *testing.T) {
	cc, err := compileCondition(PolicyCondition{
		Field:    "count:all_args_names",
		Operator: "gt",
		Value:    "255",
	})
	if err != nil {
		t.Fatal(err)
	}

	// Build a request with 256 unique query params.
	q := make([]string, 256)
	for i := range q {
		q[i] = fmt.Sprintf("p%d=v", i)
	}
	path := "/?" + strings.Join(q, "&")
	r := makeRequest("GET", path, "")
	if !matchCondition(cc, r, nil) {
		t.Error("count:all_args_names should be > 255 with 256 params")
	}
}

// ─── v0.9.0: ServeHTTP Integration ────────────────────────────────

func TestServeHTTP_PhraseMatch_Block(t *testing.T) {
	rules := []PolicyRule{
		{
			ID:   "pm-block",
			Name: "sql-keyword-block",
			Type: "block",
			Conditions: []PolicyCondition{
				{
					Field:      "all_args_values",
					Operator:   "phrase_match",
					ListItems:  []string{"select", "union", "insert", "drop", "delete"},
					Transforms: []string{"lowercase"},
				},
			},
			Enabled:  true,
			Priority: 100,
		},
	}

	path := writeTempRulesFile(t, rules)
	pe := &PolicyEngine{RulesFile: path, ReloadInterval: caddy.Duration(0)}
	mustProvision(t, pe)

	// Attack request: "UNION SELECT" in query param.
	r := makeRequest("GET", "/search?q=1+UNION+SELECT+1,2,3", "")
	w := httptest.NewRecorder()
	next := &nextHandler{}
	err := pe.ServeHTTP(w, r, next)

	if err == nil {
		t.Fatal("expected block error for SQL keywords in args")
	}
	if next.called {
		t.Error("next handler should not be called on block")
	}

	// Clean request: should pass.
	r2 := makeRequest("GET", "/search?q=hello+world", "")
	w2 := httptest.NewRecorder()
	next2 := &nextHandler{}
	err2 := pe.ServeHTTP(w2, r2, next2)

	if err2 != nil {
		t.Errorf("clean request should pass, got error: %v", err2)
	}
	if !next2.called {
		t.Error("next handler should be called for clean request")
	}
}

func TestServeHTTP_NumericBlock(t *testing.T) {
	rules := []PolicyRule{
		{
			ID:   "count-block",
			Name: "too-many-args",
			Type: "block",
			Conditions: []PolicyCondition{
				{
					Field:    "count:all_args_names",
					Operator: "gt",
					Value:    "5",
				},
			},
			Enabled:  true,
			Priority: 100,
		},
	}

	path := writeTempRulesFile(t, rules)
	pe := &PolicyEngine{RulesFile: path, ReloadInterval: caddy.Duration(0)}
	mustProvision(t, pe)

	// 6 params > 5 → block.
	r := makeRequest("GET", "/?a=1&b=2&c=3&d=4&e=5&f=6", "")
	w := httptest.NewRecorder()
	next := &nextHandler{}
	err := pe.ServeHTTP(w, r, next)
	if err == nil {
		t.Fatal("expected block for 6 args > 5")
	}

	// 3 params ≤ 5 → pass.
	r2 := makeRequest("GET", "/?a=1&b=2&c=3", "")
	w2 := httptest.NewRecorder()
	next2 := &nextHandler{}
	err2 := pe.ServeHTTP(w2, r2, next2)
	if err2 != nil {
		t.Errorf("3 args should pass, got error: %v", err2)
	}
}

func TestServeHTTP_Detect_PhraseMatch(t *testing.T) {
	rules := []PolicyRule{
		{
			ID:   "detect-sqli",
			Name: "sql-keywords-detect",
			Type: "detect",
			Conditions: []PolicyCondition{
				{
					Field:      "all_args_values",
					Operator:   "phrase_match",
					ListItems:  []string{"select", "union", "insert", "drop"},
					Transforms: []string{"lowercase"},
				},
			},
			Severity:      "CRITICAL",
			ParanoiaLevel: 1,
			Enabled:       true,
			Priority:      100,
		},
	}

	wafCfg := &WafConfig{
		ParanoiaLevel:    1,
		InboundThreshold: 4, // CRITICAL=5 > threshold=4, should block
	}

	path := writeTempRulesFileWithConfig(t, rules, wafCfg)
	pe := &PolicyEngine{RulesFile: path, ReloadInterval: caddy.Duration(0)}
	mustProvision(t, pe)

	r := makeRequest("GET", "/search?q=1+union+select+1", "")
	w := httptest.NewRecorder()
	next := &nextHandler{}
	err := pe.ServeHTTP(w, r, next)

	if err == nil {
		t.Fatal("expected detect_block — CRITICAL(5) > threshold(4)")
	}
	action, _ := caddyhttp.GetVar(r.Context(), "policy_engine.action").(string)
	if action != "detect_block" {
		t.Errorf("expected action=detect_block, got %q", action)
	}
}

func TestNeedsBodyField(t *testing.T) {
	tests := []struct {
		field string
		want  bool
	}{
		{"all_args", true},
		{"all_args_values", true},
		{"all_args_names", true},
		{"all_headers", false},
		{"all_cookies", false},
		{"path", false},
		{"count:all_args", true},
		{"count:all_headers", false},
	}

	for _, tt := range tests {
		got := needsBodyField(tt.field)
		if got != tt.want {
			t.Errorf("needsBodyField(%q) = %v, want %v", tt.field, got, tt.want)
		}
	}
}
