package policyengine

import (
	"strings"
	"testing"
)

// ─── GREASE Filtering ───────────────────────────────────────────────

func TestIsGREASE(t *testing.T) {
	greaseExamples := []uint16{0x0a0a, 0x1a1a, 0x4a4a, 0xfafa}
	for _, v := range greaseExamples {
		if !isGREASE(v) {
			t.Errorf("expected 0x%04x to be GREASE", v)
		}
	}

	nonGrease := []uint16{0x0001, 0x0035, 0x1301, 0xc02b, 0x00ff}
	for _, v := range nonGrease {
		if isGREASE(v) {
			t.Errorf("expected 0x%04x to NOT be GREASE", v)
		}
	}
}

// ─── Version Resolution ─────────────────────────────────────────────

func TestResolveVersion(t *testing.T) {
	tests := []struct {
		name     string
		ch       *parsedClientHello
		expected string
	}{
		{
			name:     "TLS 1.3 via supported_versions",
			ch:       &parsedClientHello{ProtocolVersion: 0x0303, SupportedVersions: []uint16{0x0304, 0x0303}},
			expected: "13",
		},
		{
			name:     "TLS 1.2 fallback (no supported_versions)",
			ch:       &parsedClientHello{ProtocolVersion: 0x0303},
			expected: "12",
		},
		{
			name:     "TLS 1.3 with GREASE in supported_versions",
			ch:       &parsedClientHello{ProtocolVersion: 0x0303, SupportedVersions: []uint16{0x4a4a, 0x0304, 0x0303}},
			expected: "13",
		},
		{
			name:     "TLS 1.0",
			ch:       &parsedClientHello{ProtocolVersion: 0x0301},
			expected: "10",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := resolveVersion(tt.ch)
			if got != tt.expected {
				t.Errorf("resolveVersion() = %q, want %q", got, tt.expected)
			}
		})
	}
}

// ─── ALPN Chars ─────────────────────────────────────────────────────

func TestAlpnChars(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"h2", "h2"},
		{"http/1.1", "h1"},
		{"", "00"},
		{"h3", "h3"},
		{"spdy/3", "s3"},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := alpnChars(tt.input)
			if got != tt.expected {
				t.Errorf("alpnChars(%q) = %q, want %q", tt.input, got, tt.expected)
			}
		})
	}
}

// ─── SHA-256 Truncation ─────────────────────────────────────────────

func TestSha256Trunc12(t *testing.T) {
	// Known: SHA-256("") = e3b0c44298fc...
	result := sha256Trunc12("")
	if len(result) != 12 {
		t.Errorf("sha256Trunc12 length = %d, want 12", len(result))
	}
	if result != "e3b0c44298fc" {
		t.Errorf("sha256Trunc12('') = %q, want 'e3b0c44298fc'", result)
	}
}

// ─── JA4 Computation ────────────────────────────────────────────────

func TestComputeJA4_Basic(t *testing.T) {
	ch := &parsedClientHello{
		ProtocolVersion:   0x0303,
		SupportedVersions: []uint16{0x0304, 0x0303},
		ServerName:        "example.com",
		CipherSuites:      []uint16{0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f},
		Extensions:        []uint16{0x0000, 0x0010, 0x002b, 0x000d, 0x0033},
		ALPNProtocols:     []string{"h2", "http/1.1"},
		SignatureAlgos:    []uint16{0x0403, 0x0804, 0x0401},
	}

	ja4 := computeJA4(ch)

	// Should have 3 sections separated by underscores.
	parts := strings.Split(ja4, "_")
	if len(parts) != 3 {
		t.Fatalf("JA4 has %d sections, want 3: %s", len(parts), ja4)
	}

	// Section a: t13d0505h2
	// t=TCP, 13=TLS1.3, d=domain, 05=5 ciphers, 05=5 extensions, h2=ALPN
	a := parts[0]
	if len(a) != 10 {
		t.Errorf("section a length = %d, want 10: %q", len(a), a)
	}
	if a[0] != 't' {
		t.Errorf("protocol = %c, want t", a[0])
	}
	if a[1:3] != "13" {
		t.Errorf("version = %s, want 13", a[1:3])
	}
	if a[3] != 'd' {
		t.Errorf("sni = %c, want d", a[3])
	}

	// Section b: 12 hex chars.
	b := parts[1]
	if len(b) != 12 {
		t.Errorf("section b length = %d, want 12: %q", len(b), b)
	}

	// Section c: 12 hex chars.
	c := parts[2]
	if len(c) != 12 {
		t.Errorf("section c length = %d, want 12: %q", len(c), c)
	}

	t.Logf("JA4: %s", ja4)
}

func TestComputeJA4_NoALPN(t *testing.T) {
	ch := &parsedClientHello{
		ProtocolVersion: 0x0303,
		CipherSuites:    []uint16{0x002f, 0x0035},
		Extensions:      []uint16{0x000d},
		SignatureAlgos:  []uint16{0x0401},
	}

	ja4 := computeJA4(ch)
	parts := strings.Split(ja4, "_")

	// No SNI, no ALPN → "i" and "00"
	a := parts[0]
	if a[3] != 'i' {
		t.Errorf("sni = %c, want i (no SNI)", a[3])
	}
	if a[8:10] != "00" {
		t.Errorf("alpn = %s, want 00", a[8:10])
	}
}

func TestComputeJA4_GREASEFiltering(t *testing.T) {
	ch := &parsedClientHello{
		ProtocolVersion:   0x0303,
		SupportedVersions: []uint16{0x4a4a, 0x0304},                 // GREASE + TLS 1.3
		CipherSuites:      []uint16{0x0a0a, 0x1301, 0x2a2a, 0x1302}, // 2 GREASE + 2 real
		Extensions:        []uint16{0xbaba, 0x0000, 0x000d},         // 1 GREASE + 2 real
		ServerName:        "test.com",
		SignatureAlgos:    []uint16{0x0403},
	}

	ja4 := computeJA4(ch)
	parts := strings.Split(ja4, "_")
	a := parts[0]

	// Cipher count should be 2 (GREASE filtered).
	if a[4:6] != "02" {
		t.Errorf("cipher count = %s, want 02 (GREASE filtered)", a[4:6])
	}
	// Extension count should be 2 (GREASE filtered).
	if a[6:8] != "02" {
		t.Errorf("extension count = %s, want 02 (GREASE filtered)", a[6:8])
	}
}

// ─── ClientHello Parser ─────────────────────────────────────────────

func TestParseClientHello_Minimal(t *testing.T) {
	// Build a minimal valid ClientHello.
	// TLS record header (5) + Handshake header (4) + client_version (2) +
	// random (32) + session_id (1+0) + cipher_suites (2+4) + compression (1+1) +
	// extensions (2+0)
	var b []byte

	// TLS record header
	b = append(b, 0x16)       // handshake
	b = append(b, 0x03, 0x01) // TLS 1.0 compat
	recordLen := 4 + 2 + 32 + 1 + 2 + 4 + 1 + 1 + 2
	b = append(b, byte(recordLen>>8), byte(recordLen))

	// Handshake header
	b = append(b, 0x01) // ClientHello
	bodyLen := recordLen - 4
	b = append(b, 0, byte(bodyLen>>8), byte(bodyLen))

	// client_version
	b = append(b, 0x03, 0x03) // TLS 1.2

	// random (32 zeros)
	b = append(b, make([]byte, 32)...)

	// session_id (empty)
	b = append(b, 0)

	// cipher_suites (2 suites)
	b = append(b, 0, 4)       // 4 bytes = 2 suites
	b = append(b, 0x13, 0x01) // TLS_AES_128_GCM_SHA256
	b = append(b, 0x00, 0x2f) // TLS_RSA_WITH_AES_128_CBC_SHA

	// compression
	b = append(b, 1, 0) // 1 method: null

	// extensions (empty)
	b = append(b, 0, 0)

	ch, err := parseClientHello(b)
	if err != nil {
		t.Fatalf("parseClientHello failed: %v", err)
	}
	if ch.ProtocolVersion != 0x0303 {
		t.Errorf("version = 0x%04x, want 0x0303", ch.ProtocolVersion)
	}
	if len(ch.CipherSuites) != 2 {
		t.Errorf("cipher count = %d, want 2", len(ch.CipherSuites))
	}
	if ch.CipherSuites[0] != 0x1301 {
		t.Errorf("cipher[0] = 0x%04x, want 0x1301", ch.CipherSuites[0])
	}
}

// ─── JA4 Registry ───────────────────────────────────────────────────

func TestJA4Registry(t *testing.T) {
	addr := "192.168.1.1:12345"
	ja4 := "t13d1516h2_8daaf6152771_e5627efa2ab1"

	ja4Registry.Set(addr, ja4)
	got := ja4Registry.Get(addr)
	if got != ja4 {
		t.Errorf("Get() = %q, want %q", got, ja4)
	}

	ja4Registry.Delete(addr)
	got = ja4Registry.Get(addr)
	if got != "" {
		t.Errorf("Get() after Delete = %q, want empty", got)
	}

	// Non-existent key.
	got = ja4Registry.Get("unknown")
	if got != "" {
		t.Errorf("Get(unknown) = %q, want empty", got)
	}
}

// ─── Known ClientHello Fixture ──────────────────────────────────────

func TestParseClientHello_WithExtensions(t *testing.T) {
	// Build a structurally valid ClientHello with extensions programmatically
	// to avoid hand-counting hex lengths.
	var body []byte

	// client_version
	body = append(body, 0x03, 0x03) // TLS 1.2

	// random (32 zeros)
	body = append(body, make([]byte, 32)...)

	// session_id (empty)
	body = append(body, 0)

	// cipher_suites (3 suites)
	body = append(body, 0, 6)
	body = append(body, 0x13, 0x01, 0x13, 0x02, 0x13, 0x03)

	// compression (null only)
	body = append(body, 1, 0)

	// Build extensions
	var exts []byte
	// SNI: example.com
	sniHost := []byte("example.com")
	sniEntry := []byte{0} // host_name type
	sniEntry = append(sniEntry, byte(len(sniHost)>>8), byte(len(sniHost)))
	sniEntry = append(sniEntry, sniHost...)
	sniList := make([]byte, 2+len(sniEntry))
	sniList[0] = byte(len(sniEntry) >> 8)
	sniList[1] = byte(len(sniEntry))
	copy(sniList[2:], sniEntry)
	exts = appendExt(exts, 0x0000, sniList)

	// supported_versions: TLS 1.3
	exts = appendExt(exts, 0x002b, []byte{2, 0x03, 0x04})

	// signature_algorithms: 3 algos
	exts = appendExt(exts, 0x000d, []byte{0, 6, 0x04, 0x03, 0x08, 0x04, 0x04, 0x01})

	// ALPN: h2
	exts = appendExt(exts, 0x0010, []byte{0, 3, 2, 'h', '2'})

	// key_share (0x0033) — empty
	exts = appendExt(exts, 0x0033, []byte{0, 0})

	// supported_groups (0x000a)
	exts = appendExt(exts, 0x000a, []byte{0, 2, 0, 0x1d})

	// Add extensions length
	body = append(body, byte(len(exts)>>8), byte(len(exts)))
	body = append(body, exts...)

	// Wrap in handshake header
	var hs []byte
	hs = append(hs, 0x01) // ClientHello
	hs = append(hs, byte(len(body)>>16), byte(len(body)>>8), byte(len(body)))
	hs = append(hs, body...)

	// Wrap in TLS record header
	var raw []byte
	raw = append(raw, 0x16, 0x03, 0x01) // handshake, TLS 1.0 compat
	raw = append(raw, byte(len(hs)>>8), byte(len(hs)))
	raw = append(raw, hs...)

	ch, err := parseClientHello(raw)
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}

	if ch.ServerName != "example.com" {
		t.Errorf("SNI = %q, want example.com", ch.ServerName)
	}
	if len(ch.CipherSuites) != 3 {
		t.Errorf("cipher count = %d, want 3", len(ch.CipherSuites))
	}
	if len(ch.ALPNProtocols) == 0 || ch.ALPNProtocols[0] != "h2" {
		t.Errorf("ALPN = %v, want [h2]", ch.ALPNProtocols)
	}
	if len(ch.SupportedVersions) == 0 || ch.SupportedVersions[0] != 0x0304 {
		t.Errorf("supported_versions = %v, want [0x0304]", ch.SupportedVersions)
	}
	if len(ch.SignatureAlgos) != 3 {
		t.Errorf("sig algs count = %d, want 3", len(ch.SignatureAlgos))
	}
	if len(ch.Extensions) != 6 {
		t.Errorf("extension count = %d, want 6", len(ch.Extensions))
	}

	ja4 := computeJA4(ch)
	t.Logf("JA4: %s", ja4)

	parts := strings.Split(ja4, "_")
	if len(parts) != 3 {
		t.Fatalf("JA4 sections = %d, want 3", len(parts))
	}
	if parts[0][0:3] != "t13" {
		t.Errorf("expected t13, got %s", parts[0][0:3])
	}
	if parts[0][3] != 'd' {
		t.Errorf("expected SNI=d, got %c", parts[0][3])
	}
	// 3 ciphers, 6 extensions → "0306"
	if parts[0][4:8] != "0306" {
		t.Errorf("counts = %s, want 0306", parts[0][4:8])
	}
	if parts[0][8:10] != "h2" {
		t.Errorf("alpn = %s, want h2", parts[0][8:10])
	}
}

// appendExt appends a TLS extension (type + length + data) to the buffer.
func appendExt(buf []byte, extType uint16, data []byte) []byte {
	buf = append(buf, byte(extType>>8), byte(extType))
	buf = append(buf, byte(len(data)>>8), byte(len(data)))
	buf = append(buf, data...)
	return buf
}
