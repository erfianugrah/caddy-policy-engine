package policyengine

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"sort"
	"strings"
)

// ─── JA4 TLS Fingerprinting ────────────────────────────────────────
//
// JA4 fingerprint format (FoxIO spec):
//   {a}_{b}_{c}
//
// Section a (10 chars): protocol + version + sni + cipher_count + ext_count + alpn
// Section b (12 chars): SHA-256 truncated hash of sorted cipher suites
// Section c (12 chars): SHA-256 truncated hash of sorted extensions + signature algorithms
//
// Reference: https://github.com/FoxIO-LLC/ja4/blob/main/technical_details/JA4.md

// ─── GREASE Values ──────────────────────────────────────────────────

// greaseValues is the set of TLS GREASE sentinel values (RFC 8701).
// These must be filtered from all JA4 computations.
var greaseValues = map[uint16]bool{
	0x0a0a: true, 0x1a1a: true, 0x2a2a: true, 0x3a3a: true,
	0x4a4a: true, 0x5a5a: true, 0x6a6a: true, 0x7a7a: true,
	0x8a8a: true, 0x9a9a: true, 0xaaaa: true, 0xbaba: true,
	0xcaca: true, 0xdada: true, 0xeaea: true, 0xfafa: true,
}

func isGREASE(v uint16) bool { return greaseValues[v] }

// ─── Parsed ClientHello ─────────────────────────────────────────────

// parsedClientHello holds the extracted fields from a TLS ClientHello
// needed for JA4 computation.
type parsedClientHello struct {
	ProtocolVersion   uint16   // client_version field (e.g. 0x0303 for TLS 1.2)
	CipherSuites      []uint16 // raw cipher suite list
	Extensions        []uint16 // extension type IDs in original order
	ServerName        string   // SNI value (empty if not present)
	ALPNProtocols     []string // ALPN protocol list
	SignatureAlgos    []uint16 // signature_algorithms in original order
	SupportedVersions []uint16 // from supported_versions extension (0x002b)
}

// ─── ClientHello Binary Parser ──────────────────────────────────────

// readClientHello reads a single TLS record from the connection.
// Returns the full record bytes (header + payload).
// The caller must rewind these bytes before passing the conn to the TLS handler.
func readClientHello(conn net.Conn) ([]byte, error) {
	// TLS record header: 1 byte content_type + 2 byte version + 2 byte length
	hdr := make([]byte, 5)
	if _, err := io.ReadFull(conn, hdr); err != nil {
		return hdr, err
	}

	// content_type must be 0x16 (Handshake)
	if hdr[0] != 0x16 {
		return hdr, errors.New("not a TLS handshake record")
	}

	length := int(binary.BigEndian.Uint16(hdr[3:5]))
	if length < 4 || length > 16384 {
		return hdr, fmt.Errorf("invalid TLS record length: %d", length)
	}

	payload := make([]byte, length)
	if _, err := io.ReadFull(conn, payload); err != nil {
		return append(hdr, payload...), err
	}

	return append(hdr, payload...), nil
}

// parseClientHello extracts the fields needed for JA4 from raw ClientHello bytes.
// Input is the full TLS record (5-byte header + payload).
func parseClientHello(raw []byte) (*parsedClientHello, error) {
	if len(raw) < 5 {
		return nil, errors.New("record too short")
	}

	// Skip TLS record header (5 bytes)
	data := raw[5:]

	// Handshake header: msg_type (1) + length (3)
	if len(data) < 4 {
		return nil, errors.New("handshake header too short")
	}
	if data[0] != 0x01 { // ClientHello
		return nil, fmt.Errorf("not a ClientHello: msg_type=0x%02x", data[0])
	}
	data = data[4:] // skip handshake header

	ch := &parsedClientHello{}

	// client_version (2 bytes)
	if len(data) < 2 {
		return nil, errors.New("missing client_version")
	}
	ch.ProtocolVersion = binary.BigEndian.Uint16(data[:2])
	data = data[2:]

	// random (32 bytes)
	if len(data) < 32 {
		return nil, errors.New("missing random")
	}
	data = data[32:]

	// session_id (1-byte length + variable)
	if len(data) < 1 {
		return nil, errors.New("missing session_id length")
	}
	sidLen := int(data[0])
	data = data[1:]
	if len(data) < sidLen {
		return nil, errors.New("session_id truncated")
	}
	data = data[sidLen:]

	// cipher_suites (2-byte length + variable, each suite = 2 bytes)
	if len(data) < 2 {
		return nil, errors.New("missing cipher_suites length")
	}
	csLen := int(binary.BigEndian.Uint16(data[:2]))
	data = data[2:]
	if len(data) < csLen || csLen%2 != 0 {
		return nil, errors.New("cipher_suites truncated")
	}
	for i := 0; i < csLen; i += 2 {
		cs := binary.BigEndian.Uint16(data[i : i+2])
		ch.CipherSuites = append(ch.CipherSuites, cs)
	}
	data = data[csLen:]

	// compression_methods (1-byte length + variable)
	if len(data) < 1 {
		return nil, errors.New("missing compression length")
	}
	compLen := int(data[0])
	data = data[1:]
	if len(data) < compLen {
		return nil, errors.New("compression truncated")
	}
	data = data[compLen:]

	// extensions (2-byte length + variable)
	if len(data) < 2 {
		// No extensions — valid for very old clients.
		return ch, nil
	}
	extLen := int(binary.BigEndian.Uint16(data[:2]))
	data = data[2:]
	if len(data) < extLen {
		return nil, errors.New("extensions truncated")
	}
	extData := data[:extLen]

	// Parse each extension.
	for len(extData) >= 4 {
		extType := binary.BigEndian.Uint16(extData[:2])
		extBodyLen := int(binary.BigEndian.Uint16(extData[2:4]))
		extData = extData[4:]
		if len(extData) < extBodyLen {
			break
		}
		body := extData[:extBodyLen]
		extData = extData[extBodyLen:]

		ch.Extensions = append(ch.Extensions, extType)

		switch extType {
		case 0x0000: // server_name (SNI)
			ch.ServerName = parseSNI(body)

		case 0x0010: // application_layer_protocol_negotiation (ALPN)
			ch.ALPNProtocols = parseALPN(body)

		case 0x000d: // signature_algorithms
			ch.SignatureAlgos = parseSigAlgs(body)

		case 0x002b: // supported_versions
			ch.SupportedVersions = parseSupportedVersions(body)
		}
	}

	return ch, nil
}

// parseSNI extracts the first host_name from the server_name extension.
func parseSNI(data []byte) string {
	if len(data) < 2 {
		return ""
	}
	listLen := int(binary.BigEndian.Uint16(data[:2]))
	data = data[2:]
	if len(data) < listLen || listLen < 3 {
		return ""
	}
	// name_type (1) + name_length (2) + name
	nameType := data[0]
	if nameType != 0 { // host_name
		return ""
	}
	nameLen := int(binary.BigEndian.Uint16(data[1:3]))
	data = data[3:]
	if len(data) < nameLen {
		return ""
	}
	return string(data[:nameLen])
}

// parseALPN extracts protocol strings from the ALPN extension.
func parseALPN(data []byte) []string {
	if len(data) < 2 {
		return nil
	}
	listLen := int(binary.BigEndian.Uint16(data[:2]))
	data = data[2:]
	if len(data) < listLen {
		return nil
	}
	data = data[:listLen]
	var protos []string
	for len(data) > 0 {
		pLen := int(data[0])
		data = data[1:]
		if len(data) < pLen {
			break
		}
		protos = append(protos, string(data[:pLen]))
		data = data[pLen:]
	}
	return protos
}

// parseSigAlgs extracts signature algorithm uint16 values.
func parseSigAlgs(data []byte) []uint16 {
	if len(data) < 2 {
		return nil
	}
	listLen := int(binary.BigEndian.Uint16(data[:2]))
	data = data[2:]
	if len(data) < listLen || listLen%2 != 0 {
		return nil
	}
	var algs []uint16
	for i := 0; i < listLen; i += 2 {
		algs = append(algs, binary.BigEndian.Uint16(data[i:i+2]))
	}
	return algs
}

// parseSupportedVersions extracts version uint16 values from the
// supported_versions extension. Note: in ClientHello this is prefixed
// with a 1-byte list length (not 2-byte like most other lists).
func parseSupportedVersions(data []byte) []uint16 {
	if len(data) < 1 {
		return nil
	}
	listLen := int(data[0])
	data = data[1:]
	if len(data) < listLen || listLen%2 != 0 {
		return nil
	}
	var versions []uint16
	for i := 0; i < listLen; i += 2 {
		versions = append(versions, binary.BigEndian.Uint16(data[i:i+2]))
	}
	return versions
}

// ─── JA4 Computation ────────────────────────────────────────────────

// computeJA4 computes the JA4 fingerprint from a parsed ClientHello.
func computeJA4(ch *parsedClientHello) string {
	// ── Section a ───────────────────────────────────────────────────
	// {protocol}{version}{sni}{cipher_count}{ext_count}{alpn}

	protocol := "t" // TCP/TLS (not QUIC)

	// TLS version: use highest non-GREASE from supported_versions, else protocol version.
	version := resolveVersion(ch)

	// SNI
	sni := "i"
	if ch.ServerName != "" {
		sni = "d"
	}

	// Cipher count (excluding GREASE)
	cipherCount := 0
	for _, cs := range ch.CipherSuites {
		if !isGREASE(cs) {
			cipherCount++
		}
	}
	if cipherCount > 99 {
		cipherCount = 99
	}

	// Extension count (excluding GREASE)
	extCount := 0
	for _, ext := range ch.Extensions {
		if !isGREASE(ext) {
			extCount++
		}
	}
	if extCount > 99 {
		extCount = 99
	}

	// ALPN: first and last alphanumeric char of first ALPN value
	alpn := "00"
	if len(ch.ALPNProtocols) > 0 {
		alpn = alpnChars(ch.ALPNProtocols[0])
	}

	sectionA := fmt.Sprintf("%s%s%s%02d%02d%s", protocol, version, sni, cipherCount, extCount, alpn)

	// ── Section b ───────────────────────────────────────────────────
	// Sorted cipher suites (excluding GREASE), SHA-256 truncated to 12 hex chars.
	var ciphers []string
	for _, cs := range ch.CipherSuites {
		if !isGREASE(cs) {
			ciphers = append(ciphers, fmt.Sprintf("%04x", cs))
		}
	}
	sort.Strings(ciphers)
	sectionB := "000000000000"
	if len(ciphers) > 0 {
		sectionB = sha256Trunc12(strings.Join(ciphers, ","))
	}

	// ── Section c ───────────────────────────────────────────────────
	// Sorted extensions (excluding GREASE, SNI=0x0000, ALPN=0x0010),
	// + signature algorithms in original order.
	var exts []string
	for _, ext := range ch.Extensions {
		if isGREASE(ext) || ext == 0x0000 || ext == 0x0010 {
			continue
		}
		exts = append(exts, fmt.Sprintf("%04x", ext))
	}
	sort.Strings(exts)

	cInput := strings.Join(exts, ",")
	if len(ch.SignatureAlgos) > 0 {
		var sigAlgs []string
		for _, sa := range ch.SignatureAlgos {
			sigAlgs = append(sigAlgs, fmt.Sprintf("%04x", sa))
		}
		cInput += "_" + strings.Join(sigAlgs, ",")
	}
	sectionC := "000000000000"
	if len(exts) > 0 {
		sectionC = sha256Trunc12(cInput)
	}

	return sectionA + "_" + sectionB + "_" + sectionC
}

// resolveVersion returns the 2-char JA4 version string.
// Uses highest non-GREASE from supported_versions if available,
// otherwise falls back to the protocol_version field.
func resolveVersion(ch *parsedClientHello) string {
	v := ch.ProtocolVersion
	if len(ch.SupportedVersions) > 0 {
		highest := uint16(0)
		for _, sv := range ch.SupportedVersions {
			if !isGREASE(sv) && sv > highest {
				highest = sv
			}
		}
		if highest > 0 {
			v = highest
		}
	}
	switch v {
	case 0x0304:
		return "13"
	case 0x0303:
		return "12"
	case 0x0302:
		return "11"
	case 0x0301:
		return "10"
	case 0x0300:
		return "s3"
	case 0x0200:
		return "s2"
	default:
		return fmt.Sprintf("%02x", v&0xff)
	}
}

// alpnChars returns the first and last alphanumeric characters of an ALPN string.
// Returns "00" if the string has no alphanumeric characters.
func alpnChars(s string) string {
	first := byte('0')
	last := byte('0')
	foundFirst := false
	for i := 0; i < len(s); i++ {
		c := s[i]
		if isAlphanumeric(c) {
			if !foundFirst {
				first = c
				foundFirst = true
			}
			last = c
		}
	}
	return string([]byte{first, last})
}

func isAlphanumeric(c byte) bool {
	return (c >= '0' && c <= '9') || (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z')
}

// sha256Trunc12 computes SHA-256 and returns the first 12 hex characters.
func sha256Trunc12(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:6]) // 6 bytes = 12 hex chars
}
