package policyengine

import (
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"go.uber.org/zap"
)

// ─── Phase 1 Transform Unit Tests ──────────────────────────────────

func TestTransformLowercase(t *testing.T) {
	tests := []struct{ in, want string }{
		{"Hello World", "hello world"},
		{"<SCRIPT>", "<script>"},
		{"already lower", "already lower"},
		{"", ""},
		{"MiXeD cAsE 123", "mixed case 123"},
	}
	for _, tc := range tests {
		got := transformLowercase(tc.in)
		if got != tc.want {
			t.Errorf("lowercase(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestTransformURLDecode(t *testing.T) {
	tests := []struct{ in, want string }{
		{"%3Cscript%3E", "<script>"},
		{"hello+world", "hello world"},
		{"%2F..%2F..%2Fetc%2Fpasswd", "/../../etc/passwd"},
		{"no%encoding", "no%encoding"}, // invalid hex
		{"%", "%"},                     // truncated
		{"%2", "%2"},                   // truncated
		{"", ""},
		{"plain", "plain"},
		{"%00null%00", "\x00null\x00"},
	}
	for _, tc := range tests {
		got := transformURLDecode(tc.in)
		if got != tc.want {
			t.Errorf("urlDecode(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestTransformURLDecodeUni(t *testing.T) {
	tests := []struct{ in, want string }{
		// Standard %XX still works.
		{"%3Cscript%3E", "<script>"},
		// %uXXXX Unicode.
		{"%u003Cscript%u003E", "<script>"},
		// Mixed.
		{"%u0041%42%u0043", "ABC"},
		// Case insensitive.
		{"%U0041", "A"},
		// Plus decoding.
		{"hello+world", "hello world"},
		{"", ""},
		// Invalid sequences pass through.
		{"%uZZZZ", "%uZZZZ"},
	}
	for _, tc := range tests {
		got := transformURLDecodeUni(tc.in)
		if got != tc.want {
			t.Errorf("urlDecodeUni(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestTransformHTMLEntityDecode(t *testing.T) {
	tests := []struct{ in, want string }{
		{"&lt;script&gt;", "<script>"},
		{"&amp;", "&"},
		{"&quot;hello&quot;", "\"hello\""},
		{"&#60;", "<"},  // decimal
		{"&#x3C;", "<"}, // hex
		{"&#X3c;", "<"}, // hex uppercase X
		{"&apos;", "'"},
		{"no entities", "no entities"},
		{"&unknown;", "&unknown;"}, // unknown named entity
		{"&", "&"},                 // bare ampersand
		{"", ""},
	}
	for _, tc := range tests {
		got := transformHTMLEntityDecode(tc.in)
		if got != tc.want {
			t.Errorf("htmlEntityDecode(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestTransformNormalizePath(t *testing.T) {
	tests := []struct{ in, want string }{
		{"/a/b/../c", "/a/c"},
		{"/a/./b", "/a/b"},
		{"/a//b///c", "/a/b/c"},
		{"/a/b/../../c", "/c"},
		{"/a/b/..", "/a/"},
		{"/../etc/passwd", "/etc/passwd"},
		{"/a/b/c", "/a/b/c"}, // no change
		{"", ""},
	}
	for _, tc := range tests {
		got := transformNormalizePath(tc.in)
		if got != tc.want {
			t.Errorf("normalizePath(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestTransformNormalizePathWin(t *testing.T) {
	tests := []struct{ in, want string }{
		{`\a\b\..\c`, "/a/c"},
		{`\a\\b\.\c`, "/a/b/c"},
		{`/a\b`, "/a/b"},
		{`C:\Windows\System32`, "C:/Windows/System32"},
	}
	for _, tc := range tests {
		got := transformNormalizePathWin(tc.in)
		if got != tc.want {
			t.Errorf("normalizePathWin(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestTransformRemoveNulls(t *testing.T) {
	tests := []struct{ in, want string }{
		{"he\x00llo", "hello"},
		{"\x00\x00\x00", ""},
		{"no nulls", "no nulls"},
		{"", ""},
	}
	for _, tc := range tests {
		got := transformRemoveNulls(tc.in)
		if got != tc.want {
			t.Errorf("removeNulls(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestTransformCompressWhitespace(t *testing.T) {
	tests := []struct{ in, want string }{
		{"hello   world", "hello world"},
		{"a\t\t\tb", "a b"},
		{"a\n\n\nb", "a b"},
		{"  leading", " leading"},
		{"trailing  ", "trailing "},
		{"a  b  c  d", "a b c d"},
		{"no extra", "no extra"},
		{"", ""},
	}
	for _, tc := range tests {
		got := transformCompressWhitespace(tc.in)
		if got != tc.want {
			t.Errorf("compressWhitespace(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestTransformRemoveWhitespace(t *testing.T) {
	tests := []struct{ in, want string }{
		{"hello world", "helloworld"},
		{"a \t b \n c", "abc"},
		{"  hello  ", "hello"},
		{"nospaces", "nospaces"},
		{"", ""},
	}
	for _, tc := range tests {
		got := transformRemoveWhitespace(tc.in)
		if got != tc.want {
			t.Errorf("removeWhitespace(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// ─── Phase 2 Transform Unit Tests ──────────────────────────────────

func TestTransformBase64Decode(t *testing.T) {
	tests := []struct{ in, want string }{
		{"PHNjcmlwdD4=", "<script>"},       // standard
		{"aGVsbG8=", "hello"},              // standard
		{"aGVsbG8", "hello"},               // raw (no padding) — fallback
		{"!!!invalid!!!", "!!!invalid!!!"}, // invalid → return unchanged
		{"", ""},
	}
	for _, tc := range tests {
		got := transformBase64Decode(tc.in)
		if got != tc.want {
			t.Errorf("base64Decode(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestTransformHexDecode(t *testing.T) {
	tests := []struct{ in, want string }{
		{"3c7363726970743e", "<script>"},
		{"48656c6c6f", "Hello"},
		{"zzzz", "zzzz"}, // invalid hex
		{"123", "123"},   // odd length
		{"", ""},
	}
	for _, tc := range tests {
		got := transformHexDecode(tc.in)
		if got != tc.want {
			t.Errorf("hexDecode(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestTransformJSDecode(t *testing.T) {
	tests := []struct{ in, want string }{
		{`\x3cscript\x3e`, "<script>"},
		{`\u003cscript\u003e`, "<script>"},
		{`hello\nworld`, "hello\nworld"},
		{`escaped\\backslash`, "escaped\\backslash"},
		{`tab\there`, "tab\there"},
		{`null\0byte`, "null\x00byte"},
		{`\x`, `\x`}, // invalid \x
		{`no escapes`, "no escapes"},
		{"", ""},
	}
	for _, tc := range tests {
		got := transformJSDecode(tc.in)
		if got != tc.want {
			t.Errorf("jsDecode(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestTransformCSSDecode(t *testing.T) {
	tests := []struct{ in, want string }{
		{`\3c script`, "<script"},     // hex 3c + optional space consumed
		{`\3C`, "<"},                  // uppercase hex
		{`\000041`, "A"},              // 6-digit hex
		{`\41 B`, "AB"},               // hex + space consumed
		{`no\Qescapes`, "noQescapes"}, // non-hex escape → literal char (Q is not hex)
		{"", ""},
	}
	for _, tc := range tests {
		got := transformCSSDecode(tc.in)
		if got != tc.want {
			t.Errorf("cssDecode(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestTransformUTF8ToUnicode(t *testing.T) {
	tests := []struct{ in, want string }{
		{"hello", "hello"},     // ASCII unchanged
		{"café", "caf\\u00e9"}, // non-ASCII converted
		{"日本語", "\\u65e5\\u672c\\u8a9e"},
		{"", ""},
	}
	for _, tc := range tests {
		got := transformUTF8ToUnicode(tc.in)
		if got != tc.want {
			t.Errorf("utf8toUnicode(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestTransformRemoveComments(t *testing.T) {
	tests := []struct{ in, want string }{
		{"hello /* comment */ world", "hello  world"},
		{"hello <!-- html --> world", "hello  world"},
		{"no comments here", "no comments here"},
		{"nested /* a /* b */ c */ end", "nested  c */ end"}, // not truly nested
		{"unclosed /* comment", "unclosed "},                 // strips to end
		{"unclosed <!-- comment", "unclosed "},
		{"", ""},
	}
	for _, tc := range tests {
		got := transformRemoveComments(tc.in)
		if got != tc.want {
			t.Errorf("removeComments(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestTransformTrim(t *testing.T) {
	tests := []struct{ in, want string }{
		{"  hello  ", "hello"},
		{"\thello\n", "hello"},
		{"hello", "hello"},
		{"", ""},
	}
	for _, tc := range tests {
		got := transformTrim(tc.in)
		if got != tc.want {
			t.Errorf("trim(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestTransformLength(t *testing.T) {
	tests := []struct{ in, want string }{
		{"hello", "5"},
		{"", "0"},
		{"abc def", "7"},
	}
	for _, tc := range tests {
		got := transformLength(tc.in)
		if got != tc.want {
			t.Errorf("length(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// ─── Transform Chain Tests ─────────────────────────────────────────

func TestApplyTransforms_Chain(t *testing.T) {
	// Simulate CRS-style transform chain: urlDecode → htmlEntityDecode → lowercase
	chain := []transformFunc{
		transformURLDecode,
		transformHTMLEntityDecode,
		transformLowercase,
	}

	tests := []struct {
		name string
		in   string
		want string
	}{
		{"url+html+lower", "%3CSCRIPT%3E", "<script>"},
		{"html entity after url decode", "%26lt%3BSCRIPT%26gt%3B", "<script>"},
		{"already clean", "hello", "hello"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := applyTransforms(tc.in, chain)
			if got != tc.want {
				t.Errorf("chain(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

func TestApplyTransforms_Empty(t *testing.T) {
	// No transforms = no-op.
	got := applyTransforms("Hello World", nil)
	if got != "Hello World" {
		t.Errorf("applyTransforms(nil) = %q, want %q", got, "Hello World")
	}
}

// ─── Transform Registry Tests ──────────────────────────────────────

func TestValidTransformNames(t *testing.T) {
	names := validTransformNames()
	if len(names) != 17 {
		t.Errorf("expected 17 transforms, got %d: %v", len(names), names)
	}
	// Verify sorted.
	for i := 1; i < len(names); i++ {
		if names[i] < names[i-1] {
			t.Errorf("not sorted: %q before %q", names[i-1], names[i])
		}
	}
}

// ─── Compile-Time Transform Resolution Tests ───────────────────────

func TestCompileCondition_WithTransforms(t *testing.T) {
	cond := PolicyCondition{
		Field:      "path",
		Operator:   "contains",
		Value:      "<script>",
		Transforms: []string{"urlDecode", "lowercase"},
	}
	cc, err := compileCondition(cond)
	if err != nil {
		t.Fatalf("compileCondition: %v", err)
	}
	if len(cc.transforms) != 2 {
		t.Errorf("expected 2 compiled transforms, got %d", len(cc.transforms))
	}
}

func TestCompileCondition_UnknownTransform(t *testing.T) {
	cond := PolicyCondition{
		Field:      "path",
		Operator:   "contains",
		Value:      "test",
		Transforms: []string{"lowercase", "invalidTransform"},
	}
	_, err := compileCondition(cond)
	if err == nil {
		t.Fatal("expected error for unknown transform, got nil")
	}
	if !strings.Contains(err.Error(), "unknown transform") {
		t.Errorf("expected 'unknown transform' error, got: %v", err)
	}
}

func TestCompileCondition_EmptyTransforms(t *testing.T) {
	cond := PolicyCondition{
		Field:    "path",
		Operator: "contains",
		Value:    "test",
	}
	cc, err := compileCondition(cond)
	if err != nil {
		t.Fatalf("compileCondition: %v", err)
	}
	if len(cc.transforms) != 0 {
		t.Errorf("expected 0 transforms, got %d", len(cc.transforms))
	}
}

// ─── Integration: matchCondition with Transforms ───────────────────

func TestMatchCondition_URLDecodeTransform(t *testing.T) {
	// Condition: path contains "<script>" after urlDecode.
	// Request path: /page?q=%3Cscript%3Ealert(1)
	cond := PolicyCondition{
		Field:      "path",
		Operator:   "contains",
		Value:      "<script>",
		Transforms: []string{"urlDecode"},
	}
	cc, err := compileCondition(cond)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}

	req := httptest.NewRequest("GET", "/page?q=%3Cscript%3Ealert(1)", nil)
	if !matchCondition(cc, req, nil) {
		t.Error("expected match: URL-encoded <script> should be detected after urlDecode")
	}

	// Without encoding — should still match.
	req2 := httptest.NewRequest("GET", "/page?q=<script>alert(1)", nil)
	if !matchCondition(cc, req2, nil) {
		t.Error("expected match: literal <script> should match")
	}

	// Clean request — should not match.
	req3 := httptest.NewRequest("GET", "/page?q=hello", nil)
	if matchCondition(cc, req3, nil) {
		t.Error("expected no match on clean request")
	}
}

func TestMatchCondition_LowercaseTransform(t *testing.T) {
	cond := PolicyCondition{
		Field:      "user_agent",
		Operator:   "contains",
		Value:      "sqlmap",
		Transforms: []string{"lowercase"},
	}
	cc, err := compileCondition(cond)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}

	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("User-Agent", "SQLMAP/1.0")
	if !matchCondition(cc, req, nil) {
		t.Error("expected match: SQLMAP should match 'sqlmap' after lowercase")
	}

	req2 := httptest.NewRequest("GET", "/", nil)
	req2.Header.Set("User-Agent", "Mozilla/5.0")
	if matchCondition(cc, req2, nil) {
		t.Error("expected no match on normal UA")
	}
}

func TestMatchCondition_TransformChain(t *testing.T) {
	// urlDecode + htmlEntityDecode + lowercase → catches double-encoded XSS.
	cond := PolicyCondition{
		Field:      "path",
		Operator:   "contains",
		Value:      "<script",
		Transforms: []string{"urlDecode", "htmlEntityDecode", "lowercase"},
	}
	cc, err := compileCondition(cond)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}

	// URL-encoded HTML entities: %26lt%3B = &lt; → < after urlDecode + htmlEntityDecode
	req := httptest.NewRequest("GET", "/page?q=%26lt%3BSCRIPT", nil)
	if !matchCondition(cc, req, nil) {
		t.Error("expected match: double-encoded <SCRIPT should be detected")
	}
}

func TestMatchCondition_NormalizePathTransform(t *testing.T) {
	cond := PolicyCondition{
		Field:      "path",
		Operator:   "contains",
		Value:      "/etc/passwd",
		Transforms: []string{"urlDecode", "normalizePath"},
	}
	cc, err := compileCondition(cond)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}

	req := httptest.NewRequest("GET", "/files/..%2F..%2Fetc%2Fpasswd", nil)
	if !matchCondition(cc, req, nil) {
		t.Error("expected match: path traversal should be normalized")
	}
}

func TestMatchCondition_TransformWithRegex(t *testing.T) {
	// Transforms also work with regex operator.
	cond := PolicyCondition{
		Field:      "user_agent",
		Operator:   "regex",
		Value:      "^(sqlmap|nikto|nuclei)",
		Transforms: []string{"lowercase"},
	}
	cc, err := compileCondition(cond)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}

	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("User-Agent", "NIKTO/2.5.0")
	if !matchCondition(cc, req, nil) {
		t.Error("expected match: NIKTO should match after lowercase")
	}
}

func TestMatchCondition_TransformWithEq(t *testing.T) {
	// Transform + exact match.
	cond := PolicyCondition{
		Field:      "method",
		Operator:   "eq",
		Value:      "get",
		Transforms: []string{"lowercase"},
	}
	cc, err := compileCondition(cond)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}

	req := httptest.NewRequest("GET", "/", nil)
	if !matchCondition(cc, req, nil) {
		t.Error("expected match: GET → get after lowercase")
	}
}

func TestMatchCondition_TransformNoMatch(t *testing.T) {
	cond := PolicyCondition{
		Field:      "path",
		Operator:   "contains",
		Value:      "attack",
		Transforms: []string{"urlDecode", "lowercase"},
	}
	cc, err := compileCondition(cond)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}

	req := httptest.NewRequest("GET", "/innocent/page?q=hello", nil)
	if matchCondition(cc, req, nil) {
		t.Error("expected no match on clean request")
	}
}

// ─── Full Rule Compile + Evaluate with Transforms ──────────────────

func TestCompileRule_DetectWithTransforms(t *testing.T) {
	rule := PolicyRule{
		ID:       "test-xss-1",
		Name:     "XSS via encoded script",
		Type:     "detect",
		Enabled:  true,
		Priority: 150,
		Severity: "CRITICAL",
		Conditions: []PolicyCondition{
			{
				Field:      "path",
				Operator:   "contains",
				Value:      "<script",
				Transforms: []string{"urlDecode", "htmlEntityDecode", "lowercase"},
			},
		},
		GroupOp: "and",
	}
	cr, err := compileRule(rule)
	if err != nil {
		t.Fatalf("compileRule: %v", err)
	}
	if len(cr.conditions[0].transforms) != 3 {
		t.Errorf("expected 3 transforms, got %d", len(cr.conditions[0].transforms))
	}
	if cr.score != 5 {
		t.Errorf("expected CRITICAL score=5, got %d", cr.score)
	}
}

func TestCompileRule_InvalidTransform(t *testing.T) {
	rule := PolicyRule{
		ID:      "test-bad",
		Name:    "bad transform",
		Type:    "block",
		Enabled: true,
		Conditions: []PolicyCondition{
			{
				Field:      "path",
				Operator:   "contains",
				Value:      "test",
				Transforms: []string{"doesNotExist"},
			},
		},
		GroupOp: "and",
	}
	_, err := compileRule(rule)
	if err == nil {
		t.Fatal("expected error for invalid transform in rule")
	}
}

// ─── Edge Cases ────────────────────────────────────────────────────

func TestTransform_URLDecodeUni_HighUnicode(t *testing.T) {
	// %uD800 is an invalid surrogate — should still decode to the raw rune.
	got := transformURLDecodeUni("%uD800")
	if len(got) == 0 {
		t.Error("expected non-empty output for surrogate code point")
	}
}

func TestTransform_HTMLEntity_LargeCodePoint(t *testing.T) {
	// Valid large code point.
	got := transformHTMLEntityDecode("&#x1F600;") // 😀
	if got != "😀" {
		t.Errorf("expected emoji, got %q", got)
	}
}

func TestTransform_NormalizePath_DeepTraversal(t *testing.T) {
	got := transformNormalizePath("/a/b/c/../../../../etc/passwd")
	if !strings.Contains(got, "etc/passwd") {
		t.Errorf("expected etc/passwd in result, got %q", got)
	}
}

func TestTransform_CompressWhitespace_MixedTypes(t *testing.T) {
	got := transformCompressWhitespace("a \t \n \r b")
	if got != "a b" {
		t.Errorf("expected 'a b', got %q", got)
	}
}

func TestTransform_JSDecode_Mixed(t *testing.T) {
	got := transformJSDecode(`\x3c\u0073cript\x3e`)
	if got != "<script>" {
		t.Errorf("expected '<script>', got %q", got)
	}
}

func TestTransform_CSSDecode_MultipleEscapes(t *testing.T) {
	// \3c = <, space consumed, \73 followed by space consumed = s, then "cript"
	got := transformCSSDecode(`\3c \73 cript`)
	if got != "<script" {
		t.Errorf("expected '<script', got %q", got)
	}
}

// ─── ServeHTTP Integration (block rule with transforms) ────────────

func TestServeHTTP_BlockWithTransform(t *testing.T) {
	pe := &PolicyEngine{
		logger: zap.NewNop(),
	}
	pe.mu = &sync.RWMutex{}

	rules := []PolicyRule{
		{
			ID:       "block-xss",
			Name:     "Block XSS",
			Type:     "block",
			Enabled:  true,
			Priority: 100,
			Conditions: []PolicyCondition{
				{
					Field:      "path",
					Operator:   "contains",
					Value:      "<script",
					Transforms: []string{"urlDecode", "lowercase"},
				},
			},
			GroupOp: "and",
		},
	}

	compiled, err := compileRules(rules)
	if err != nil {
		t.Fatalf("compileRules: %v", err)
	}

	pe.mu.Lock()
	pe.rules = compiled
	pe.mu.Unlock()

	// Request with URL-encoded script tag — should be blocked.
	req := httptest.NewRequest("GET", "/page?q=%3CSCRIPT%3Ealert(1)", nil)
	rr := httptest.NewRecorder()

	err = pe.ServeHTTP(rr, req, &nextHandler{})
	if err == nil {
		t.Fatal("expected error (block) but got nil")
	}
	httpErr, ok := err.(caddyhttp.HandlerError)
	if !ok {
		t.Fatalf("expected caddyhttp.HandlerError, got %T", err)
	}
	if httpErr.StatusCode != 403 {
		t.Errorf("expected 403, got %d", httpErr.StatusCode)
	}

	// Clean request — should pass.
	req2 := httptest.NewRequest("GET", "/page?q=hello", nil)
	rr2 := httptest.NewRecorder()
	err2 := pe.ServeHTTP(rr2, req2, &nextHandler{})
	if err2 != nil {
		t.Errorf("expected nil error for clean request, got: %v", err2)
	}
}

func TestServeHTTP_DetectWithTransform(t *testing.T) {
	pe := &PolicyEngine{
		logger: zap.NewNop(),
	}
	pe.mu = &sync.RWMutex{}

	rules := []PolicyRule{
		{
			ID:            "detect-xss",
			Name:          "Detect XSS",
			Type:          "detect",
			Enabled:       true,
			Priority:      150,
			Severity:      "CRITICAL",
			ParanoiaLevel: 1,
			Conditions: []PolicyCondition{
				{
					Field:      "path",
					Operator:   "contains",
					Value:      "<script",
					Transforms: []string{"urlDecode", "lowercase"},
				},
			},
			GroupOp: "and",
		},
	}

	compiled, err := compileRules(rules)
	if err != nil {
		t.Fatalf("compileRules: %v", err)
	}

	wafCfg := &compiledWafConfig{
		defaultPL:          2,
		defaultInThreshold: 3, // CRITICAL=5 > 3 → block
	}

	pe.mu.Lock()
	pe.rules = compiled
	pe.wafConfig = wafCfg
	pe.mu.Unlock()

	// Encoded XSS — should trigger detect, score=5 > threshold=3 → block.
	req := httptest.NewRequest("GET", "/page?q=%3CSCRIPT%3Ealert(1)", nil)
	rr := httptest.NewRecorder()

	err = pe.ServeHTTP(rr, req, &nextHandler{})
	if err == nil {
		t.Fatal("expected error (detect_block) but got nil")
	}
	httpErr, ok := err.(caddyhttp.HandlerError)
	if !ok {
		t.Fatalf("expected caddyhttp.HandlerError, got %T", err)
	}
	if httpErr.StatusCode != 403 {
		t.Errorf("expected 403, got %d", httpErr.StatusCode)
	}
}
