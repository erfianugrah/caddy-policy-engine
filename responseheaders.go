// Response header injection — CSP and security headers.
//
// CSP headers are resolved per-service (by Host header) with merge/inherit
// semantics matching the wafctl CSP store. Security headers are applied
// globally with optional per-service overrides.
//
// Three CSP modes:
//   - "set":     always set CSP (overwrite upstream) — pre-response w.Header().Set()
//   - "default": only set if upstream didn't send one — requires ResponseWriter wrapper
//   - "none":    no CSP for this service
//
// All state is pre-compiled at rule load time for O(1) per-request lookup.
package policyengine

import (
	"bufio"
	"fmt"
	"net"
	"net/http"
	"regexp"
	"strconv"
	"strings"
)

// ─── JSON Types (deserialized from policy-rules.json) ───────────────

// ResponseHeaderConfig is the top-level response header configuration.
type ResponseHeaderConfig struct {
	CSP      *CSPConfig            `json:"csp,omitempty"`
	Security *SecurityHeaderConfig `json:"security,omitempty"`
	CORS     *CORSConfig           `json:"cors,omitempty"`
}

// CORSConfig holds CORS configuration for the policy engine.
type CORSConfig struct {
	Enabled    *bool                   `json:"enabled,omitempty"` // nil = true
	Global     CORSSettings            `json:"global"`
	PerService map[string]CORSSettings `json:"per_service,omitempty"`
}

// CORSSettings holds CORS configuration for a scope (global or per-service).
type CORSSettings struct {
	AllowedOrigins   []string `json:"allowed_origins,omitempty"` // exact strings or regex patterns
	AllowedMethods   []string `json:"allowed_methods,omitempty"` // GET, POST, PUT, etc.
	AllowedHeaders   []string `json:"allowed_headers,omitempty"` // Content-Type, Authorization, etc.
	ExposedHeaders   []string `json:"exposed_headers,omitempty"`
	MaxAge           int      `json:"max_age,omitempty"` // seconds for Access-Control-Max-Age
	AllowCredentials bool     `json:"allow_credentials,omitempty"`
}

// CSPConfig holds global and per-service CSP policies.
type CSPConfig struct {
	Enabled        *bool                       `json:"enabled,omitempty"` // nil = true
	GlobalDefaults CSPPolicy                   `json:"global_defaults"`
	Services       map[string]CSPServiceConfig `json:"services"`
}

// CSPServiceConfig holds the CSP configuration for a single service.
type CSPServiceConfig struct {
	Mode       string    `json:"mode"`        // "set", "default", "none"
	ReportOnly bool      `json:"report_only"` // Content-Security-Policy-Report-Only
	Inherit    bool      `json:"inherit"`     // merge on top of GlobalDefaults
	Policy     CSPPolicy `json:"policy"`
}

// CSPPolicy holds structured CSP directive values.
type CSPPolicy struct {
	DefaultSrc  []string `json:"default_src,omitempty"`
	ScriptSrc   []string `json:"script_src,omitempty"`
	StyleSrc    []string `json:"style_src,omitempty"`
	ImgSrc      []string `json:"img_src,omitempty"`
	FontSrc     []string `json:"font_src,omitempty"`
	ConnectSrc  []string `json:"connect_src,omitempty"`
	MediaSrc    []string `json:"media_src,omitempty"`
	FrameSrc    []string `json:"frame_src,omitempty"`
	WorkerSrc   []string `json:"worker_src,omitempty"`
	ObjectSrc   []string `json:"object_src,omitempty"`
	ChildSrc    []string `json:"child_src,omitempty"`
	ManifestSrc []string `json:"manifest_src,omitempty"`
	BaseURI     []string `json:"base_uri,omitempty"`
	FormAction  []string `json:"form_action,omitempty"`
	FrameAnc    []string `json:"frame_ancestors,omitempty"`

	UpgradeInsecureRequests bool   `json:"upgrade_insecure_requests,omitempty"`
	RawDirectives           string `json:"raw_directives,omitempty"`
}

// SecurityHeaderConfig holds static security headers applied to all responses.
type SecurityHeaderConfig struct {
	Enabled    *bool                              `json:"enabled,omitempty"` // nil = true
	Headers    map[string]string                  `json:"headers,omitempty"`
	Remove     []string                           `json:"remove,omitempty"`
	PerService map[string]SecurityServiceOverride `json:"per_service,omitempty"`
}

// SecurityServiceOverride holds per-service security header overrides.
// Non-empty Headers entries replace the global value for that header.
type SecurityServiceOverride struct {
	Headers map[string]string `json:"headers,omitempty"`
	Remove  []string          `json:"remove,omitempty"`
}

// ─── Compiled State ─────────────────────────────────────────────────

// compiledResponseHeaders is the pre-compiled response header config.
// All CSP strings are built once at load time; per-request cost is a map lookup.
type compiledResponseHeaders struct {
	csp      *compiledCSP
	security *compiledSecurity
	cors     *compiledCORS
}

type compiledCORS struct {
	enabled  bool
	services map[string]*compiledCORSSettings // per-service, keyed by host
	fallback *compiledCORSSettings            // global defaults
}

type compiledCORSSettings struct {
	allowedOrigins   []string         // exact match origins
	originPatterns   []*regexp.Regexp // regex patterns
	allowedMethods   string           // pre-joined "GET, POST, PUT"
	allowedHeaders   string           // pre-joined "Content-Type, Authorization"
	exposedHeaders   string           // pre-joined
	maxAge           string           // pre-formatted "3600"
	allowCredentials bool
}

type compiledCSP struct {
	enabled  bool
	services map[string]compiledCSPService // keyed by Host (FQDN, case-folded)
	fallback compiledCSPService            // from global_defaults
}

type compiledCSPService struct {
	mode       string // "set", "default", "none"
	reportOnly bool
	rendered   string // pre-built CSP header value
}

type compiledSecurity struct {
	enabled  bool
	headers  map[string]string         // global headers to set
	remove   []string                  // global headers to remove
	services map[string]compiledSecSvc // per-service overrides
}

type compiledSecSvc struct {
	headers map[string]string // merged headers for this service
	remove  []string          // merged remove list for this service
}

// ─── CSP Header Builder ─────────────────────────────────────────────

// buildCSPHeaderString constructs a CSP header value from a policy.
func buildCSPHeaderString(p CSPPolicy) string {
	var parts []string

	directives := []struct {
		name   string
		values []string
	}{
		{"default-src", p.DefaultSrc},
		{"script-src", p.ScriptSrc},
		{"style-src", p.StyleSrc},
		{"img-src", p.ImgSrc},
		{"font-src", p.FontSrc},
		{"connect-src", p.ConnectSrc},
		{"media-src", p.MediaSrc},
		{"frame-src", p.FrameSrc},
		{"worker-src", p.WorkerSrc},
		{"object-src", p.ObjectSrc},
		{"child-src", p.ChildSrc},
		{"manifest-src", p.ManifestSrc},
		{"base-uri", p.BaseURI},
		{"form-action", p.FormAction},
		{"frame-ancestors", p.FrameAnc},
	}

	for _, d := range directives {
		if len(d.values) > 0 {
			parts = append(parts, d.name+" "+strings.Join(d.values, " "))
		}
	}

	if p.UpgradeInsecureRequests {
		parts = append(parts, "upgrade-insecure-requests")
	}

	if p.RawDirectives != "" {
		parts = append(parts, strings.TrimSpace(p.RawDirectives))
	}

	return strings.Join(parts, "; ")
}

// ─── CSP Merge ──────────────────────────────────────────────────────

// mergeCSPPolicy overlays override on top of base.
// Non-empty override slices replace the base; empty slices keep base.
// UpgradeInsecureRequests is sticky (true in either → true).
func mergeCSPPolicy(base, override CSPPolicy) CSPPolicy {
	merged := base
	if len(override.DefaultSrc) > 0 {
		merged.DefaultSrc = override.DefaultSrc
	}
	if len(override.ScriptSrc) > 0 {
		merged.ScriptSrc = override.ScriptSrc
	}
	if len(override.StyleSrc) > 0 {
		merged.StyleSrc = override.StyleSrc
	}
	if len(override.ImgSrc) > 0 {
		merged.ImgSrc = override.ImgSrc
	}
	if len(override.FontSrc) > 0 {
		merged.FontSrc = override.FontSrc
	}
	if len(override.ConnectSrc) > 0 {
		merged.ConnectSrc = override.ConnectSrc
	}
	if len(override.MediaSrc) > 0 {
		merged.MediaSrc = override.MediaSrc
	}
	if len(override.FrameSrc) > 0 {
		merged.FrameSrc = override.FrameSrc
	}
	if len(override.WorkerSrc) > 0 {
		merged.WorkerSrc = override.WorkerSrc
	}
	if len(override.ObjectSrc) > 0 {
		merged.ObjectSrc = override.ObjectSrc
	}
	if len(override.ChildSrc) > 0 {
		merged.ChildSrc = override.ChildSrc
	}
	if len(override.ManifestSrc) > 0 {
		merged.ManifestSrc = override.ManifestSrc
	}
	if len(override.BaseURI) > 0 {
		merged.BaseURI = override.BaseURI
	}
	if len(override.FormAction) > 0 {
		merged.FormAction = override.FormAction
	}
	if len(override.FrameAnc) > 0 {
		merged.FrameAnc = override.FrameAnc
	}
	if override.UpgradeInsecureRequests {
		merged.UpgradeInsecureRequests = true
	}
	if override.RawDirectives != "" {
		merged.RawDirectives = override.RawDirectives
	}
	return merged
}

// ─── Compilation ────────────────────────────────────────────────────

// validCSPModes is the set of recognized CSP modes.
var validCSPModes = map[string]bool{
	"set":     true,
	"default": true,
	"none":    true,
	"":        true, // empty defaults to "set"
}

// compileResponseHeaders pre-compiles response header config for O(1) per-request lookup.
func compileResponseHeaders(cfg *ResponseHeaderConfig) (*compiledResponseHeaders, error) {
	if cfg == nil {
		return nil, nil
	}
	rh := &compiledResponseHeaders{}

	// Compile CSP.
	if cfg.CSP != nil {
		enabled := cfg.CSP.Enabled == nil || *cfg.CSP.Enabled
		cc := &compiledCSP{
			enabled:  enabled,
			services: make(map[string]compiledCSPService),
		}

		// Validate global defaults RawDirectives.
		if err := validateCSPPolicy(cfg.CSP.GlobalDefaults); err != nil {
			return nil, fmt.Errorf("CSP global_defaults: %w", err)
		}

		// Build fallback from global defaults.
		fallbackHeader := buildCSPHeaderString(cfg.CSP.GlobalDefaults)
		cc.fallback = compiledCSPService{
			mode:     "set",
			rendered: fallbackHeader,
		}

		// Build per-service compiled configs.
		for host, svc := range cfg.CSP.Services {
			// Validate CSP mode.
			if !validCSPModes[svc.Mode] {
				return nil, fmt.Errorf("CSP service %q: unknown mode %q (must be set, default, or none)", host, svc.Mode)
			}
			var policy CSPPolicy
			if svc.Inherit {
				policy = mergeCSPPolicy(cfg.CSP.GlobalDefaults, svc.Policy)
			} else {
				policy = svc.Policy
			}
			if err := validateCSPPolicy(policy); err != nil {
				return nil, fmt.Errorf("CSP service %q: %w", host, err)
			}
			rendered := buildCSPHeaderString(policy)
			cc.services[strings.ToLower(host)] = compiledCSPService{
				mode:       svc.Mode,
				reportOnly: svc.ReportOnly,
				rendered:   rendered,
			}
		}

		rh.csp = cc
	}

	// Compile security headers.
	if cfg.Security != nil {
		enabled := cfg.Security.Enabled == nil || *cfg.Security.Enabled
		cs := &compiledSecurity{
			enabled:  enabled,
			headers:  cfg.Security.Headers,
			remove:   cfg.Security.Remove,
			services: make(map[string]compiledSecSvc),
		}

		// Pre-merge per-service overrides.
		for host, override := range cfg.Security.PerService {
			merged := make(map[string]string, len(cfg.Security.Headers))
			for k, v := range cfg.Security.Headers {
				merged[k] = v
			}
			// Override-specific headers replace global ones.
			for k, v := range override.Headers {
				merged[k] = v
			}
			// Merge remove lists.
			removeSet := make(map[string]bool)
			for _, h := range cfg.Security.Remove {
				removeSet[h] = true
			}
			for _, h := range override.Remove {
				removeSet[h] = true
			}
			var removeList []string
			for h := range removeSet {
				removeList = append(removeList, h)
			}
			cs.services[strings.ToLower(host)] = compiledSecSvc{
				headers: merged,
				remove:  removeList,
			}
		}

		rh.security = cs
	}

	// Compile CORS.
	if cfg.CORS != nil {
		enabled := cfg.CORS.Enabled == nil || *cfg.CORS.Enabled
		fallback, err := compileCORSSettings(cfg.CORS.Global)
		if err != nil {
			return nil, fmt.Errorf("CORS global: %w", err)
		}
		cc := &compiledCORS{
			enabled:  enabled,
			services: make(map[string]*compiledCORSSettings),
			fallback: fallback,
		}
		for host, settings := range cfg.CORS.PerService {
			cs, err := compileCORSSettings(settings)
			if err != nil {
				return nil, fmt.Errorf("CORS service %q: %w", host, err)
			}
			cc.services[strings.ToLower(host)] = cs
		}
		rh.cors = cc
	}

	return rh, nil
}

// validateCSPPolicy checks that RawDirectives don't contain injection characters.
func validateCSPPolicy(p CSPPolicy) error {
	if p.RawDirectives != "" {
		raw := strings.TrimSpace(p.RawDirectives)
		if strings.ContainsAny(raw, ";\r\n") {
			return fmt.Errorf("raw_directives must not contain semicolons or control characters (potential header injection)")
		}
	}
	return nil
}

func compileCORSSettings(s CORSSettings) (*compiledCORSSettings, error) {
	cs := &compiledCORSSettings{
		allowCredentials: s.AllowCredentials,
	}
	// Separate exact origins from regex patterns.
	for _, o := range s.AllowedOrigins {
		// Reject "null" origin — allowing it enables credential theft via
		// sandboxed iframes and data: URLs.
		if strings.EqualFold(o, "null") {
			return nil, fmt.Errorf("CORS: \"null\" origin must not be allowed (enables credential theft via sandboxed iframes)")
		}
		if strings.HasPrefix(o, "^") || strings.Contains(o, ".*") || strings.Contains(o, "[") {
			// Auto-anchor regex patterns to prevent partial matches.
			pattern := o
			if !strings.HasPrefix(pattern, "^") {
				pattern = "^" + pattern
			}
			if !strings.HasSuffix(pattern, "$") {
				pattern = pattern + "$"
			}
			re, err := regexp.Compile(pattern)
			if err != nil {
				return nil, fmt.Errorf("CORS: invalid origin regex %q: %w", o, err)
			}
			cs.originPatterns = append(cs.originPatterns, re)
		} else {
			cs.allowedOrigins = append(cs.allowedOrigins, o)
		}
	}

	// Validate AllowCredentials + broad regex patterns.
	if cs.allowCredentials {
		for _, re := range cs.originPatterns {
			if re.MatchString("https://evil.example.com") {
				return nil, fmt.Errorf("CORS: AllowCredentials with broad regex %q allows credential theft; use exact origins or narrow patterns", re.String())
			}
		}
	}

	if len(s.AllowedMethods) > 0 {
		cs.allowedMethods = strings.Join(s.AllowedMethods, ", ")
	} else {
		cs.allowedMethods = "GET, POST, PUT, PATCH, DELETE, OPTIONS"
	}
	if len(s.AllowedHeaders) > 0 {
		cs.allowedHeaders = strings.Join(s.AllowedHeaders, ", ")
	} else {
		cs.allowedHeaders = "Content-Type, Authorization"
	}
	if len(s.ExposedHeaders) > 0 {
		cs.exposedHeaders = strings.Join(s.ExposedHeaders, ", ")
	}
	if s.MaxAge > 0 {
		cs.maxAge = strconv.Itoa(s.MaxAge)
	} else {
		cs.maxAge = "3600"
	}
	return cs, nil
}

// ─── Per-Request Resolution ─────────────────────────────────────────

// resolveCSP returns the compiled CSP config for the given host.
func (crh *compiledResponseHeaders) resolveCSP(host string) compiledCSPService {
	if crh == nil || crh.csp == nil || !crh.csp.enabled {
		return compiledCSPService{mode: "none"}
	}
	// Strip port from Host header.
	h := strings.ToLower(host)
	if idx := strings.IndexByte(h, ':'); idx >= 0 {
		h = h[:idx]
	}
	if svc, ok := crh.csp.services[h]; ok {
		return svc
	}
	return crh.csp.fallback
}

// resolveSecurity returns the security headers and remove list for the given host.
func (crh *compiledResponseHeaders) resolveSecurity(host string) (headers map[string]string, remove []string) {
	if crh == nil || crh.security == nil || !crh.security.enabled {
		return nil, nil
	}
	h := strings.ToLower(host)
	if idx := strings.IndexByte(h, ':'); idx >= 0 {
		h = h[:idx]
	}
	if svc, ok := crh.security.services[h]; ok {
		return svc.headers, svc.remove
	}
	return crh.security.headers, crh.security.remove
}

// ─── ResponseWriter Wrapper ─────────────────────────────────────────

// responseHeaderWriter intercepts WriteHeader to:
// 1. Inject CSP in "default" mode (only if upstream didn't set it)
// 2. Remove unwanted upstream headers (Server, X-Powered-By, etc.)
type responseHeaderWriter struct {
	http.ResponseWriter
	cspHeader       string // CSP header value to inject
	cspHeaderName   string // "Content-Security-Policy" or "Content-Security-Policy-Report-Only"
	removeHeaders   []string
	securityHeaders map[string]string // security headers to re-assert in WriteHeader
	wroteHeader     bool
	statusCode      int // captured status code for outbound rule evaluation
}

func (rw *responseHeaderWriter) WriteHeader(code int) {
	if rw.wroteHeader {
		return
	}
	rw.wroteHeader = true
	rw.statusCode = code

	// Remove unwanted upstream headers.
	for _, h := range rw.removeHeaders {
		rw.Header().Del(h)
	}

	// Re-assert security headers in case upstream overwrote them.
	for k, v := range rw.securityHeaders {
		rw.Header().Set(k, v)
	}

	// Inject CSP only if upstream didn't set it ("default" mode).
	if rw.cspHeader != "" && rw.cspHeaderName != "" {
		if rw.Header().Get(rw.cspHeaderName) == "" {
			rw.Header().Set(rw.cspHeaderName, rw.cspHeader)
		}
	}

	rw.ResponseWriter.WriteHeader(code)
}

func (rw *responseHeaderWriter) Write(b []byte) (int, error) {
	if !rw.wroteHeader {
		rw.WriteHeader(http.StatusOK)
	}
	return rw.ResponseWriter.Write(b)
}

// Unwrap returns the underlying ResponseWriter for middleware compatibility
// (e.g., Caddy's response recording, http.Flusher, http.Hijacker detection).
func (rw *responseHeaderWriter) Unwrap() http.ResponseWriter {
	return rw.ResponseWriter
}

// Hijack delegates to the underlying ResponseWriter if it supports hijacking.
// This is required for WebSocket upgrades — without it, HTTP/1.1 Upgrade
// requests fail with NS_ERROR_WEBSOCKET_CONNECTION_REFUSED.
func (rw *responseHeaderWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	if hj, ok := rw.ResponseWriter.(http.Hijacker); ok {
		return hj.Hijack()
	}
	return nil, nil, http.ErrNotSupported
}

// Flush delegates to the underlying ResponseWriter if it supports flushing.
// Required for Server-Sent Events (SSE) and chunked transfer encoding.
func (rw *responseHeaderWriter) Flush() {
	if !rw.wroteHeader {
		rw.WriteHeader(http.StatusOK)
	}
	if f, ok := rw.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// ─── CORS Resolution ────────────────────────────────────────────────

func (crh *compiledResponseHeaders) resolveCORS(host string) *compiledCORSSettings {
	if crh == nil || crh.cors == nil || !crh.cors.enabled {
		return nil
	}
	h := strings.ToLower(stripPort(host))
	if svc, ok := crh.cors.services[h]; ok {
		return svc
	}
	return crh.cors.fallback
}

// matchOrigin checks if the request Origin matches the allowed origins.
func (cs *compiledCORSSettings) matchOrigin(origin string) bool {
	if cs == nil || origin == "" {
		return false
	}
	for _, o := range cs.allowedOrigins {
		if o == origin {
			return true
		}
	}
	for _, re := range cs.originPatterns {
		if re.MatchString(origin) {
			return true
		}
	}
	return false
}

// HandlePreflight handles CORS preflight (OPTIONS) requests.
// Returns true if the request was a preflight and was handled (204 sent).
// Returns false if the request is not a preflight and should proceed normally.
func (crh *compiledResponseHeaders) HandlePreflight(w http.ResponseWriter, r *http.Request) bool {
	if crh == nil || crh.cors == nil || !crh.cors.enabled {
		return false
	}
	if r.Method != http.MethodOptions {
		return false
	}
	// Check for CORS preflight markers.
	origin := r.Header.Get("Origin")
	acrm := r.Header.Get("Access-Control-Request-Method")
	if origin == "" || acrm == "" {
		return false // Not a CORS preflight, just a normal OPTIONS request.
	}

	cors := crh.resolveCORS(r.Host)
	if cors == nil || !cors.matchOrigin(origin) {
		return false // Origin not allowed — don't add CORS headers.
	}

	h := w.Header()
	h.Set("Access-Control-Allow-Origin", origin)
	h.Set("Access-Control-Allow-Methods", cors.allowedMethods)
	h.Set("Access-Control-Allow-Headers", cors.allowedHeaders)
	h.Set("Access-Control-Max-Age", cors.maxAge)
	if cors.allowCredentials {
		h.Set("Access-Control-Allow-Credentials", "true")
	}
	h.Set("Vary", "Origin, Access-Control-Request-Method, Access-Control-Request-Headers")
	w.WriteHeader(http.StatusNoContent) // 204
	return true
}

// ApplyCORSHeaders adds CORS headers to a normal (non-preflight) response.
func (crh *compiledResponseHeaders) ApplyCORSHeaders(w http.ResponseWriter, r *http.Request) {
	if crh == nil || crh.cors == nil || !crh.cors.enabled {
		return
	}
	origin := r.Header.Get("Origin")
	cors := crh.resolveCORS(r.Host)

	// Always set Vary: Origin when CORS is configured, even when origin
	// doesn't match. This prevents cache poisoning where a CDN caches a
	// response without CORS headers and serves it to a cross-origin request.
	if cors != nil {
		w.Header().Set("Vary", "Origin")
	}

	if origin == "" || cors == nil || !cors.matchOrigin(origin) {
		return
	}
	h := w.Header()
	h.Set("Access-Control-Allow-Origin", origin)
	if cors.allowCredentials {
		h.Set("Access-Control-Allow-Credentials", "true")
	}
	if cors.exposedHeaders != "" {
		h.Set("Access-Control-Expose-Headers", cors.exposedHeaders)
	}
}

// ─── Apply Response Headers ─────────────────────────────────────────

// applyResponseHeaders sets security and CSP headers on the response.
// Returns a possibly-wrapped ResponseWriter (wraps when "default" mode CSP
// or header removal requires intercepting WriteHeader).
func applyResponseHeaders(w http.ResponseWriter, host string, r *http.Request, crh *compiledResponseHeaders) http.ResponseWriter {
	if crh == nil {
		return w
	}

	var needsWrapper bool
	var cspHeader, cspHeaderName string
	var removeHeaders []string

	// CORS headers for non-preflight requests (preflight already handled in ServeHTTP).
	if crh.cors != nil && crh.cors.enabled {
		crh.ApplyCORSHeaders(w, r)
	}

	// Security headers — always "set" mode.
	secHeaders, secRemove := crh.resolveSecurity(host)
	for k, v := range secHeaders {
		w.Header().Set(k, v)
	}
	if len(secRemove) > 0 {
		needsWrapper = true
		removeHeaders = secRemove
	}

	// CSP headers.
	cspSvc := crh.resolveCSP(host)
	switch cspSvc.mode {
	case "set":
		if cspSvc.rendered != "" {
			name := "Content-Security-Policy"
			if cspSvc.reportOnly {
				name = "Content-Security-Policy-Report-Only"
			}
			w.Header().Set(name, cspSvc.rendered)
		}
	case "default":
		if cspSvc.rendered != "" {
			needsWrapper = true
			cspHeader = cspSvc.rendered
			cspHeaderName = "Content-Security-Policy"
			if cspSvc.reportOnly {
				cspHeaderName = "Content-Security-Policy-Report-Only"
			}
		}
		// "none" — no-op
	}

	if needsWrapper {
		return &responseHeaderWriter{
			ResponseWriter:  w,
			cspHeader:       cspHeader,
			cspHeaderName:   cspHeaderName,
			removeHeaders:   removeHeaders,
			securityHeaders: secHeaders,
		}
	}

	return w
}
