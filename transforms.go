// Transform functions for the policy engine.
//
// Transforms are applied to extracted field values before operator evaluation,
// matching the CRS t:xxx transform semantics. They are resolved at compile time
// (rule load) and applied left-to-right per condition evaluation.
//
// Phase 1 (covers ~90% of CRS usage):
//
//	lowercase, urlDecode, urlDecodeUni, htmlEntityDecode, normalizePath,
//	normalizePathWin, removeNulls, compressWhitespace, removeWhitespace
//
// Phase 2 (extended):
//
//	base64Decode, hexDecode, jsDecode, cssDecode, utf8toUnicode,
//	removeComments, trim, length
package policyengine

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
	"unicode/utf8"
)

// transformFunc transforms a string value in-place before operator evaluation.
type transformFunc func(string) string

// transformRegistry maps transform names to their implementations.
// All names match CRS t:xxx conventions (camelCase).
var transformRegistry = map[string]transformFunc{
	// Phase 1
	"lowercase":          transformLowercase,
	"urlDecode":          transformURLDecode,
	"urlDecodeUni":       transformURLDecodeUni,
	"htmlEntityDecode":   transformHTMLEntityDecode,
	"normalizePath":      transformNormalizePath,
	"normalizePathWin":   transformNormalizePathWin,
	"removeNulls":        transformRemoveNulls,
	"compressWhitespace": transformCompressWhitespace,
	"removeWhitespace":   transformRemoveWhitespace,
	// Phase 2
	"base64Decode":   transformBase64Decode,
	"hexDecode":      transformHexDecode,
	"jsDecode":       transformJSDecode,
	"cssDecode":      transformCSSDecode,
	"utf8toUnicode":  transformUTF8ToUnicode,
	"removeComments": transformRemoveComments,
	"trim":           transformTrim,
	"length":         transformLength,
	// Phase 3 — CRS detection-critical
	"cmdLine":            transformCmdLine,
	"escapeSeqDecode":    transformEscapeSeqDecode,
	"removeCommentsChar": transformRemoveCommentsChar,
}

// validTransformNames returns a sorted list of all valid transform names.
// Used for error messages.
func validTransformNames() []string {
	names := make([]string, 0, len(transformRegistry))
	for name := range transformRegistry {
		names = append(names, name)
	}
	// Sort for deterministic output.
	for i := 0; i < len(names); i++ {
		for j := i + 1; j < len(names); j++ {
			if names[i] > names[j] {
				names[i], names[j] = names[j], names[i]
			}
		}
	}
	return names
}

// applyTransforms applies a chain of transforms left-to-right.
func applyTransforms(value string, transforms []transformFunc) string {
	for _, fn := range transforms {
		value = fn(value)
	}
	return value
}

// ─── Phase 1 Transforms ────────────────────────────────────────────

// transformLowercase converts to lowercase. CRS: t:lowercase
func transformLowercase(s string) string {
	return strings.ToLower(s)
}

// transformURLDecode decodes percent-encoded sequences (%XX).
// CRS: t:urlDecode
func transformURLDecode(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	i := 0
	for i < len(s) {
		if s[i] == '%' && i+2 < len(s) {
			hi := unhex(s[i+1])
			lo := unhex(s[i+2])
			if hi >= 0 && lo >= 0 {
				b.WriteByte(byte(hi<<4 | lo))
				i += 3
				continue
			}
		}
		// Also decode '+' as space (form encoding).
		if s[i] == '+' {
			b.WriteByte(' ')
			i++
			continue
		}
		b.WriteByte(s[i])
		i++
	}
	return b.String()
}

// transformURLDecodeUni decodes %uXXXX Unicode sequences AND standard %XX.
// CRS: t:urlDecodeUni
func transformURLDecodeUni(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	i := 0
	for i < len(s) {
		// %uXXXX Unicode escape.
		if s[i] == '%' && i+5 < len(s) && (s[i+1] == 'u' || s[i+1] == 'U') {
			h3 := unhex(s[i+2])
			h2 := unhex(s[i+3])
			h1 := unhex(s[i+4])
			h0 := unhex(s[i+5])
			if h3 >= 0 && h2 >= 0 && h1 >= 0 && h0 >= 0 {
				cp := rune(h3<<12 | h2<<8 | h1<<4 | h0)
				b.WriteRune(cp)
				i += 6
				continue
			}
		}
		// Standard %XX.
		if s[i] == '%' && i+2 < len(s) {
			hi := unhex(s[i+1])
			lo := unhex(s[i+2])
			if hi >= 0 && lo >= 0 {
				b.WriteByte(byte(hi<<4 | lo))
				i += 3
				continue
			}
		}
		if s[i] == '+' {
			b.WriteByte(' ')
			i++
			continue
		}
		b.WriteByte(s[i])
		i++
	}
	return b.String()
}

// unhex returns the numeric value of a hex digit, or -1 if not a hex digit.
func unhex(c byte) int {
	switch {
	case '0' <= c && c <= '9':
		return int(c - '0')
	case 'a' <= c && c <= 'f':
		return int(c - 'a' + 10)
	case 'A' <= c && c <= 'F':
		return int(c - 'A' + 10)
	}
	return -1
}

// transformHTMLEntityDecode decodes HTML entities: &amp; &#NN; &#xHH;
// and common named entities. CRS: t:htmlEntityDecode
func transformHTMLEntityDecode(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	i := 0
	for i < len(s) {
		if s[i] != '&' {
			b.WriteByte(s[i])
			i++
			continue
		}
		// Find semicolon.
		end := strings.IndexByte(s[i:], ';')
		if end < 0 || end > 12 {
			// No semicolon nearby — try semicolon-less numeric entities.
			if i+2 < len(s) && s[i+1] == '#' {
				j := i + 2
				isHex := false
				if j < len(s) && (s[j] == 'x' || s[j] == 'X') {
					isHex = true
					j++
				}
				start := j
				for j < len(s) {
					if isHex {
						if (s[j] >= '0' && s[j] <= '9') || (s[j] >= 'a' && s[j] <= 'f') || (s[j] >= 'A' && s[j] <= 'F') {
							j++
							continue
						}
					} else {
						if s[j] >= '0' && s[j] <= '9' {
							j++
							continue
						}
					}
					break
				}
				if j > start {
					var cp int64
					var err error
					if isHex {
						cp, err = strconv.ParseInt(s[start:j], 16, 32)
					} else {
						cp, err = strconv.ParseInt(s[start:j], 10, 32)
					}
					if err == nil && cp >= 0 && cp <= 0x10FFFF {
						b.WriteRune(rune(cp))
						i = j
						continue
					}
				}
			}
			// Not a valid entity — pass through.
			b.WriteByte('&')
			i++
			continue
		}
		entity := s[i+1 : i+end]
		if len(entity) > 0 && entity[0] == '#' {
			// Numeric entity.
			var cp int64
			var err error
			if len(entity) > 1 && (entity[1] == 'x' || entity[1] == 'X') {
				// Hex: &#xHH;
				cp, err = strconv.ParseInt(entity[2:], 16, 32)
			} else {
				// Decimal: &#NN;
				cp, err = strconv.ParseInt(entity[1:], 10, 32)
			}
			if err == nil && cp >= 0 && cp <= 0x10FFFF {
				b.WriteRune(rune(cp))
				i += end + 1
				continue
			}
		} else {
			// Named entity.
			if decoded, ok := htmlEntities[entity]; ok {
				b.WriteString(decoded)
				i += end + 1
				continue
			}
		}
		// Unknown entity — pass through.
		b.WriteByte('&')
		i++
	}
	return b.String()
}

// htmlEntities covers the most common named HTML entities.
// Matching CRS/ModSecurity behavior which handles these core entities.
var htmlEntities = map[string]string{
	"amp":    "&",
	"lt":     "<",
	"gt":     ">",
	"quot":   "\"",
	"apos":   "'",
	"nbsp":   "\u00a0",
	"copy":   "\u00a9",
	"reg":    "\u00ae",
	"trade":  "\u2122",
	"laquo":  "\u00ab",
	"raquo":  "\u00bb",
	"mdash":  "\u2014",
	"ndash":  "\u2013",
	"hellip": "\u2026",
	// Security-critical entities — used in URL/injection evasion.
	"colon":   ":",
	"sol":     "/",
	"bsol":    "\\",
	"lpar":    "(",
	"rpar":    ")",
	"lsqb":    "[",
	"rsqb":    "]",
	"lcub":    "{",
	"rcub":    "}",
	"Tab":     "\t",
	"NewLine": "\n",
	"excl":    "!",
	"num":     "#",
	"period":  ".",
	"comma":   ",",
	"semi":    ";",
	"equals":  "=",
}

// transformNormalizePath collapses /../, /./, and // sequences.
// CRS: t:normalizePath
func transformNormalizePath(s string) string {
	// Collapse multiple slashes.
	for strings.Contains(s, "//") {
		s = strings.ReplaceAll(s, "//", "/")
	}
	// Remove /./
	for strings.Contains(s, "/./") {
		s = strings.ReplaceAll(s, "/./", "/")
	}
	// Collapse /../ — walk segments.
	s = collapseParentRefs(s)
	return s
}

// transformNormalizePathWin normalizes backslashes then applies normalizePath.
// CRS: t:normalizePathWin
func transformNormalizePathWin(s string) string {
	s = strings.ReplaceAll(s, "\\", "/")
	return transformNormalizePath(s)
}

// collapseParentRefs resolves /../ references in a path string.
func collapseParentRefs(s string) string {
	for {
		idx := strings.Index(s, "/../")
		if idx < 0 {
			break
		}
		// Find the start of the parent segment.
		parent := strings.LastIndex(s[:idx], "/")
		if parent < 0 {
			// No parent to collapse — strip the /../ itself.
			s = s[idx+3:]
		} else {
			s = s[:parent] + s[idx+3:]
		}
	}
	// Handle trailing /.. (no trailing slash).
	if strings.HasSuffix(s, "/..") {
		idx := len(s) - 3
		parent := strings.LastIndex(s[:idx], "/")
		if parent >= 0 {
			s = s[:parent+1]
		} else {
			s = "/"
		}
	}
	return s
}

// transformRemoveNulls strips null bytes. CRS: t:removeNulls
func transformRemoveNulls(s string) string {
	return strings.ReplaceAll(s, "\x00", "")
}

// transformCompressWhitespace collapses whitespace runs to single space.
// CRS: t:compressWhitespace
func transformCompressWhitespace(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	inSpace := false
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\f' || c == '\v' {
			if !inSpace {
				b.WriteByte(' ')
				inSpace = true
			}
		} else {
			b.WriteByte(c)
			inSpace = false
		}
	}
	return b.String()
}

// transformRemoveWhitespace strips all whitespace.
// CRS: t:removeWhitespace
func transformRemoveWhitespace(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c != ' ' && c != '\t' && c != '\n' && c != '\r' && c != '\f' && c != '\v' {
			b.WriteByte(c)
		}
	}
	return b.String()
}

// ─── Phase 2 Transforms ────────────────────────────────────────────

// transformBase64Decode decodes standard base64 (with padding).
// Invalid input is returned unchanged. CRS: t:base64Decode
func transformBase64Decode(s string) string {
	decoded, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		// Try URL-safe variant only — RawStdEncoding is intentionally excluded
		// because it accepts arbitrary strings (no padding required), which
		// causes false-positive decoding of non-base64 input.
		decoded, err = base64.URLEncoding.DecodeString(s)
		if err != nil {
			return s // invalid base64 — return unchanged
		}
	}
	return string(decoded)
}

// transformHexDecode decodes hex-encoded bytes (e.g., "3c736372697074" → "<script>").
// Invalid input is returned unchanged. CRS: t:hexDecode
func transformHexDecode(s string) string {
	decoded, err := hex.DecodeString(s)
	if err != nil {
		return s // invalid hex — return unchanged
	}
	return string(decoded)
}

// transformJSDecode decodes JavaScript escape sequences.
// Handles: \xHH, \uHHHH, \n, \r, \t, \\, \', \", \0
// CRS: t:jsDecode
func transformJSDecode(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	i := 0
	for i < len(s) {
		if s[i] != '\\' || i+1 >= len(s) {
			b.WriteByte(s[i])
			i++
			continue
		}
		next := s[i+1]
		switch next {
		case 'n':
			b.WriteByte('\n')
			i += 2
		case 'r':
			b.WriteByte('\r')
			i += 2
		case 't':
			b.WriteByte('\t')
			i += 2
		case '\\':
			b.WriteByte('\\')
			i += 2
		case '\'':
			b.WriteByte('\'')
			i += 2
		case '"':
			b.WriteByte('"')
			i += 2
		case '0', '1', '2', '3', '4', '5', '6', '7':
			// Octal escape: \0 through \377 (up to 3 octal digits).
			j := i + 2
			val := int(next - '0')
			for k := 0; k < 2 && j < len(s); k++ {
				d := s[j]
				if d < '0' || d > '7' {
					break
				}
				val = val*8 + int(d-'0')
				j++
			}
			if val > 255 {
				val = 255
			}
			b.WriteByte(byte(val))
			i = j
		case 'x':
			// \xHH
			if i+3 < len(s) {
				hi := unhex(s[i+2])
				lo := unhex(s[i+3])
				if hi >= 0 && lo >= 0 {
					b.WriteByte(byte(hi<<4 | lo))
					i += 4
					continue
				}
			}
			b.WriteByte('\\')
			i++
		case 'u':
			// \uHHHH
			if i+5 < len(s) {
				h3 := unhex(s[i+2])
				h2 := unhex(s[i+3])
				h1 := unhex(s[i+4])
				h0 := unhex(s[i+5])
				if h3 >= 0 && h2 >= 0 && h1 >= 0 && h0 >= 0 {
					cp := rune(h3<<12 | h2<<8 | h1<<4 | h0)
					b.WriteRune(cp)
					i += 6
					continue
				}
			}
			b.WriteByte('\\')
			i++
		default:
			// Unknown escape — pass through backslash.
			b.WriteByte('\\')
			i++
		}
	}
	return b.String()
}

// transformCSSDecode decodes CSS escape sequences (\HH to \HHHHHH).
// CRS: t:cssDecode
func transformCSSDecode(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	i := 0
	for i < len(s) {
		if s[i] != '\\' || i+1 >= len(s) {
			b.WriteByte(s[i])
			i++
			continue
		}
		// CSS hex escape: \H to \HHHHHH (1-6 hex digits), optionally followed by whitespace.
		j := i + 1
		hexStart := j
		for j < len(s) && j-hexStart < 6 && unhex(s[j]) >= 0 {
			j++
		}
		if j > hexStart {
			// Parse hex code point.
			cp, err := strconv.ParseInt(s[hexStart:j], 16, 32)
			if err == nil && cp >= 0 && cp <= 0x10FFFF {
				b.WriteRune(rune(cp))
				// CSS spec: skip one optional whitespace after hex escape.
				if j < len(s) && (s[j] == ' ' || s[j] == '\t' || s[j] == '\n' || s[j] == '\r' || s[j] == '\f') {
					j++
				}
				i = j
				continue
			}
		}
		// Not a hex escape — treat as escaped character.
		if i+1 < len(s) {
			b.WriteByte(s[i+1])
			i += 2
		} else {
			b.WriteByte('\\')
			i++
		}
	}
	return b.String()
}

// transformUTF8ToUnicode converts UTF-8 characters to \uHHHH notation.
// Only non-ASCII characters are converted. CRS: t:utf8toUnicode
func transformUTF8ToUnicode(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); {
		r, size := utf8.DecodeRuneInString(s[i:])
		if r < 128 {
			b.WriteByte(s[i])
			i++
		} else {
			fmt.Fprintf(&b, "\\u%04x", r)
			i += size
		}
	}
	return b.String()
}

// transformRemoveComments strips C-style /* ... */ and HTML <!-- ... --> comments.
// CRS: t:removeComments
func transformRemoveComments(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	i := 0
	for i < len(s) {
		// C-style comment.
		if i+1 < len(s) && s[i] == '/' && s[i+1] == '*' {
			end := strings.Index(s[i+2:], "*/")
			if end >= 0 {
				i = i + 2 + end + 2
				continue
			}
			// Unclosed — strip to end.
			break
		}
		// HTML comment.
		if i+3 < len(s) && s[i] == '<' && s[i+1] == '!' && s[i+2] == '-' && s[i+3] == '-' {
			end := strings.Index(s[i+4:], "-->")
			if end >= 0 {
				i = i + 4 + end + 3
				continue
			}
			// Unclosed — strip to end.
			break
		}
		b.WriteByte(s[i])
		i++
	}
	return b.String()
}

// transformTrim strips leading and trailing whitespace.
// CRS: t:trim
func transformTrim(s string) string {
	return strings.TrimSpace(s)
}

// transformLength replaces the value with its string length (as a decimal string).
// Used with numeric operators: { "transforms": ["length"], "operator": "gt", "value": "100" }
// CRS: t:length
func transformLength(s string) string {
	return strconv.Itoa(len(s))
}

// ─── Phase 3 Transforms (CRS detection-critical) ──────────────────

// transformCmdLine normalizes command line evasion techniques.
// Strips characters inserted between command characters to evade detection:
//   - Deletes: \, ^, "  (Windows cmd evasion: c^o^m^m^a^n^d, c"o"m"m"a"n"d)
//   - Replaces / with space (Unix path separator used as word boundary)
//   - Replaces ( with space (shell subshell syntax normalization)
//   - Collapses whitespace runs to single space
//   - Lowercases
//
// CRS: t:cmdLine — used by 13 RCE detection rules (932xxx).
func transformCmdLine(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	inSpace := false
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch c {
		case '\\', '^', '"', '\'', '`':
			// Delete evasion characters (including backtick for shell evasion).
			continue
		case '/', '(':
			// Replace with space (path separator / subshell).
			if !inSpace {
				b.WriteByte(' ')
				inSpace = true
			}
		case ' ', '\t', '\n', '\r':
			// Collapse whitespace.
			if !inSpace {
				b.WriteByte(' ')
				inSpace = true
			}
		case ',':
			// Replace comma with space (argument separator).
			if !inSpace {
				b.WriteByte(' ')
				inSpace = true
			}
		default:
			// Lowercase alphanumeric.
			if c >= 'A' && c <= 'Z' {
				c += 0x20
			}
			b.WriteByte(c)
			inSpace = false
		}
	}
	return b.String()
}

// transformEscapeSeqDecode decodes ANSI C-style escape sequences.
// Handles: \a, \b, \f, \n, \r, \t, \v, \\, \xHH, \0NNN (octal).
// CRS: t:escapeSeqDecode — used by 7 RCE/PHP detection rules.
func transformEscapeSeqDecode(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	i := 0
	for i < len(s) {
		if s[i] != '\\' || i+1 >= len(s) {
			b.WriteByte(s[i])
			i++
			continue
		}
		next := s[i+1]
		switch next {
		case 'a':
			b.WriteByte('\a')
			i += 2
		case 'b':
			b.WriteByte('\b')
			i += 2
		case 'f':
			b.WriteByte('\f')
			i += 2
		case 'n':
			b.WriteByte('\n')
			i += 2
		case 'r':
			b.WriteByte('\r')
			i += 2
		case 't':
			b.WriteByte('\t')
			i += 2
		case 'v':
			b.WriteByte('\v')
			i += 2
		case '\\':
			b.WriteByte('\\')
			i += 2
		case 'x':
			// \xHH hex escape.
			if i+3 < len(s) {
				hi := unhex(s[i+2])
				lo := unhex(s[i+3])
				if hi >= 0 && lo >= 0 {
					b.WriteByte(byte(hi<<4 | lo))
					i += 4
					continue
				}
			}
			b.WriteByte('\\')
			b.WriteByte('x')
			i += 2
		case '0':
			// \0NNN octal escape (1-3 octal digits after the 0).
			j := i + 2
			val := 0
			digits := 0
			for j < len(s) && digits < 3 && s[j] >= '0' && s[j] <= '7' {
				val = val*8 + int(s[j]-'0')
				j++
				digits++
			}
			if digits > 0 && val <= 255 {
				b.WriteByte(byte(val))
				i = j
			} else {
				b.WriteByte('\x00')
				i += 2
			}
		default:
			// Unknown escape — pass through.
			b.WriteByte('\\')
			i++
		}
	}
	return b.String()
}

// transformRemoveCommentsChar strips SQL/shell comment markers: /*, */, --, #
// Unlike removeComments which strips entire comment blocks, this removes only
// the marker characters themselves, exposing the content inside.
// CRS: t:removeCommentsChar — used by SQL injection detection rules.
func transformRemoveCommentsChar(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	i := 0
	for i < len(s) {
		// Strip /*
		if i+1 < len(s) && s[i] == '/' && s[i+1] == '*' {
			i += 2
			continue
		}
		// Strip */
		if i+1 < len(s) && s[i] == '*' && s[i+1] == '/' {
			i += 2
			continue
		}
		// Strip -- (SQL comment)
		if i+1 < len(s) && s[i] == '-' && s[i+1] == '-' {
			i += 2
			continue
		}
		// Strip # (shell/MySQL comment)
		if s[i] == '#' {
			i++
			continue
		}
		b.WriteByte(s[i])
		i++
	}
	return b.String()
}
