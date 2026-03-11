package policyengine

import (
	"fmt"
	"strings"
	"testing"
)

// --- Aho-Corasick Unit Tests ---

func TestAC_BasicSubstringMatch(t *testing.T) {
	ac := CompileAC([]string{"select", "union", "insert", "drop"})

	tests := []struct {
		input string
		want  bool
	}{
		{"SELECT * FROM users", false},     // case-sensitive, no match
		{"select * from users", true},      // exact substring
		{"1 union select 1,2,3", true},     // union matches
		{"drop table students", true},      // drop matches
		{"normal request data", false},     // no match
		{"the insert command", true},       // insert in middle
		{"selectivity is important", true}, // select is a substring of selectivity
		{"", false},                        // empty input
		{"a]b[c", false},                   // no match, special chars
		{"reselect", true},                 // select as suffix of reselect
		{"preinsertpost", true},            // insert embedded
	}

	for _, tt := range tests {
		got := ac.ContainsAny(tt.input)
		if got != tt.want {
			t.Errorf("ContainsAny(%q) = %v, want %v", tt.input, got, tt.want)
		}
	}
}

func TestAC_FindFirst(t *testing.T) {
	ac := CompileAC([]string{"cat", "car", "card"})

	tests := []struct {
		input   string
		wantPat string
		wantOK  bool
	}{
		{"the cat sat", "cat", true},
		{"a card game", "car", true}, // "car" is found before "card" completes
		{"no match here", "", false},
		{"racecar", "car", true},
	}

	for _, tt := range tests {
		pat, ok := ac.FindFirst(tt.input)
		if ok != tt.wantOK {
			t.Errorf("FindFirst(%q) ok = %v, want %v", tt.input, ok, tt.wantOK)
		}
		if pat != tt.wantPat {
			t.Errorf("FindFirst(%q) pattern = %q, want %q", tt.input, pat, tt.wantPat)
		}
	}
}

func TestAC_EmptyPatterns(t *testing.T) {
	ac := CompileAC(nil)
	if ac.ContainsAny("anything") {
		t.Error("empty matcher should never match")
	}

	ac2 := CompileAC([]string{})
	if ac2.ContainsAny("anything") {
		t.Error("empty slice matcher should never match")
	}

	ac3 := CompileAC([]string{"", "", ""})
	if ac3.ContainsAny("anything") {
		t.Error("all-empty patterns matcher should never match")
	}
}

func TestAC_SingleCharPatterns(t *testing.T) {
	ac := CompileAC([]string{"a", "b", "c"})

	tests := []struct {
		input string
		want  bool
	}{
		{"a", true},
		{"xyz", false},
		{"xbz", true},
		{"", false},
		{"ABC", false}, // case-sensitive
	}

	for _, tt := range tests {
		if got := ac.ContainsAny(tt.input); got != tt.want {
			t.Errorf("ContainsAny(%q) = %v, want %v", tt.input, got, tt.want)
		}
	}
}

func TestAC_OverlappingPatterns(t *testing.T) {
	// "he", "her", "hers", "his", "she" — classic AC example
	ac := CompileAC([]string{"he", "her", "hers", "his", "she"})

	tests := []struct {
		input string
		want  bool
	}{
		{"she", true},    // "she" matches, and "he" is a suffix
		{"hers", true},   // all of "he", "her", "hers" match
		{"this", true},   // "his" is a substring
		{"hero", true},   // "he" matches
		{"xyz", false},   // no match
		{"ushers", true}, // "she", "he", "her", "hers" all in there
	}

	for _, tt := range tests {
		if got := ac.ContainsAny(tt.input); got != tt.want {
			t.Errorf("ContainsAny(%q) = %v, want %v", tt.input, got, tt.want)
		}
	}
}

func TestAC_FailureLinkChain(t *testing.T) {
	// Patterns that share prefixes and exercise failure links.
	ac := CompileAC([]string{"abc", "bc", "c"})

	tests := []struct {
		input string
		want  bool
	}{
		{"abc", true},   // direct match
		{"xbc", true},   // "bc" via failure from root
		{"xxc", true},   // "c" via failure
		{"xxx", false},  // no match
		{"xabcx", true}, // "abc" in middle
	}

	for _, tt := range tests {
		if got := ac.ContainsAny(tt.input); got != tt.want {
			t.Errorf("ContainsAny(%q) = %v, want %v", tt.input, got, tt.want)
		}
	}
}

func TestAC_DictionarySuffixLink(t *testing.T) {
	// Test dictionary suffix links — when we reach a node that isn't an output
	// but its fail chain leads to a node that is.
	ac := CompileAC([]string{"sting", "tin"})

	if !ac.ContainsAny("testing") {
		t.Error("should match 'tin' in 'testing' via dictionary suffix link")
	}
	if !ac.ContainsAny("sting") {
		t.Error("should match 'sting' directly")
	}
}

func TestAC_CRSLikeSQLKeywords(t *testing.T) {
	// Realistic CRS-style SQL keyword list.
	keywords := []string{
		"select", "union", "insert", "update", "delete", "drop",
		"exec", "execute", "xp_", "sp_", "0x", "/*", "*/", "--",
		"alter", "create", "grant", "revoke", "truncate",
		"information_schema", "sysobjects", "syscolumns",
		"waitfor", "delay", "benchmark", "sleep",
		"char(", "concat(", "group_concat(", "load_file(",
	}
	ac := CompileAC(keywords)

	attacks := []struct {
		input string
		want  bool
	}{
		{"1 UNION SELECT 1,2,3", false},          // case-sensitive, uppercase won't match
		{"1 union select 1,2,3", true},           // lowercase matches
		{"admin'--", true},                       // "--" matches
		{"1; drop table users", true},            // "drop" matches
		{"'; exec xp_cmdshell('cmd')", true},     // "exec" and "xp_" match
		{"normal user input", false},             // clean
		{"my email is user@example.com", false},  // clean
		{"searching for products", false},        // clean
		{"concat(username,0x3a,password)", true}, // "concat(" and "0x" match
		{"select/**/username/**/from", true},     // "select" and "/*" match
		{"benchmark(10000000,sha1('a'))", true},  // "benchmark" matches
		{"waitfor delay '0:0:5'", true},          // "waitfor" matches
		{" information_schema.tables", true},     // "information_schema" matches
	}

	for _, tt := range attacks {
		if got := ac.ContainsAny(tt.input); got != tt.want {
			t.Errorf("ContainsAny(%q) = %v, want %v", tt.input, got, tt.want)
		}
	}
}

func TestAC_CRSLikeXSSVectors(t *testing.T) {
	vectors := []string{
		"<script", "javascript:", "onerror=", "onload=", "onfocus=",
		"onmouseover=", "eval(", "alert(", "document.cookie",
		"document.domain", "document.write(", "innerhtml",
		".fromcharcode(", "expression(", "vbscript:",
	}
	ac := CompileAC(vectors)

	tests := []struct {
		input string
		want  bool
	}{
		{`<script>alert(1)</script>`, true},
		{`<img onerror=alert(1)>`, true},
		{`javascript:void(0)`, true},
		{`normal paragraph text`, false},
		{`<div class="container">Hello</div>`, false},
		{`document.cookie`, true},
		{`String.fromcharcode(72,101)`, true},
	}

	for _, tt := range tests {
		if got := ac.ContainsAny(tt.input); got != tt.want {
			t.Errorf("ContainsAny(%q) = %v, want %v", tt.input, got, tt.want)
		}
	}
}

func TestAC_BinaryData(t *testing.T) {
	// Ensure it handles arbitrary bytes including null bytes.
	ac := CompileAC([]string{"\x00\x01", "AB\xffCD"})

	if !ac.ContainsAny("prefix\x00\x01suffix") {
		t.Error("should match null byte pattern")
	}
	if !ac.ContainsAny("xxAB\xffCDxx") {
		t.Error("should match high-byte pattern")
	}
	if ac.ContainsAny("normal text") {
		t.Error("should not match normal text")
	}
}

func TestAC_DuplicatePatterns(t *testing.T) {
	ac := CompileAC([]string{"foo", "foo", "bar", "bar", "foo"})

	if !ac.ContainsAny("foo") {
		t.Error("should match foo")
	}
	if !ac.ContainsAny("bar") {
		t.Error("should match bar")
	}
	if ac.ContainsAny("baz") {
		t.Error("should not match baz")
	}
}

func TestAC_LongInput(t *testing.T) {
	ac := CompileAC([]string{"needle"})

	// 100KB of padding + needle at the end.
	input := strings.Repeat("x", 100_000) + "needle"
	if !ac.ContainsAny(input) {
		t.Error("should find needle at end of long input")
	}

	// needle at the start.
	input2 := "needle" + strings.Repeat("x", 100_000)
	if !ac.ContainsAny(input2) {
		t.Error("should find needle at start of long input")
	}

	// No needle.
	input3 := strings.Repeat("x", 100_000)
	if ac.ContainsAny(input3) {
		t.Error("should not match without needle")
	}
}

func TestAC_ManyPatterns(t *testing.T) {
	// Build 1000 patterns, verify matching works.
	patterns := make([]string, 1000)
	for i := range patterns {
		patterns[i] = fmt.Sprintf("pattern_%04d", i)
	}
	ac := CompileAC(patterns)

	// First and last should match.
	if !ac.ContainsAny("xxxpattern_0000xxx") {
		t.Error("should match first pattern")
	}
	if !ac.ContainsAny("xxxpattern_0999xxx") {
		t.Error("should match last pattern")
	}
	// Non-existent pattern should not match.
	if ac.ContainsAny("xxxpattern_1000xxx") {
		t.Error("should not match out-of-range pattern")
	}
	if ac.ContainsAny("no patterns here at all") {
		t.Error("should not match clean input")
	}
}

func TestAC_SubstringNotExactMatch(t *testing.T) {
	// Verify this is substring matching, not exact.
	ac := CompileAC([]string{"admin"})

	if !ac.ContainsAny("administrator") {
		t.Error("admin should match as substring of administrator")
	}
	if !ac.ContainsAny("superadmin") {
		t.Error("admin should match as substring of superadmin")
	}
	if !ac.ContainsAny("xadminx") {
		t.Error("admin should match embedded")
	}
}

func TestAC_ExactInputEqualsPattern(t *testing.T) {
	ac := CompileAC([]string{"hello"})

	if !ac.ContainsAny("hello") {
		t.Error("exact match should work")
	}
}

// --- Benchmarks ---

func BenchmarkAC_Compile1000Patterns(b *testing.B) {
	patterns := make([]string, 1000)
	for i := range patterns {
		patterns[i] = fmt.Sprintf("keyword_%04d", i)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		CompileAC(patterns)
	}
}

func BenchmarkAC_Search_NoMatch(b *testing.B) {
	patterns := []string{
		"select", "union", "insert", "update", "delete", "drop",
		"exec", "execute", "xp_", "waitfor", "benchmark", "sleep",
	}
	ac := CompileAC(patterns)
	input := "normal user input with no sql keywords just regular text"
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ac.ContainsAny(input)
	}
}

func BenchmarkAC_Search_EarlyMatch(b *testing.B) {
	patterns := []string{
		"select", "union", "insert", "update", "delete", "drop",
	}
	ac := CompileAC(patterns)
	input := "1 union select 1,2,3 from users where id=1"
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ac.ContainsAny(input)
	}
}

func BenchmarkAC_Search_1000Patterns(b *testing.B) {
	patterns := make([]string, 1000)
	for i := range patterns {
		patterns[i] = fmt.Sprintf("pattern_%04d", i)
	}
	ac := CompileAC(patterns)
	input := strings.Repeat("normal text without any matches ", 10)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ac.ContainsAny(input)
	}
}
