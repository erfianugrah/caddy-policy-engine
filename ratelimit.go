// Package policyengine — rate limiting subsystem.
//
// Implements sliding window counter rate limiting with sharded maps for
// concurrency. Counter state is preserved across hot-reloads — only zones
// whose config (events/window) changes get fresh counters.
//
// Algorithm: fixed-window interpolation (same as nginx, envoy, cloudflare).
//
//	effectiveCount = prevCount × (1 - elapsed/window) + currCount
//
// This provides smooth rate limiting without storing per-event timestamps.
package policyengine

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"hash/fnv"
	"math"
	"math/rand"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"go.uber.org/zap"
)

// ─── Rate Limit Configuration ───────────────────────────────────────

// RateLimitConfig holds per-rule rate limit parameters.
type RateLimitConfig struct {
	Key     string `json:"key"`                // "client_ip", "path", "header:X-API-Key", etc.
	Events  int    `json:"events"`             // Max events per window
	Window  string `json:"window"`             // Duration string: "1s", "1m", "1h"
	Action  string `json:"action"`             // "deny" (default, 429) or "log_only"
	MaxKeys int    `json:"max_keys,omitempty"` // Max unique keys per zone; 0 = default (100000)
}

// RateLimitGlobalConfig holds global settings for the rate limit subsystem.
type RateLimitGlobalConfig struct {
	SweepInterval string  `json:"sweep_interval,omitempty"` // How often to evict expired counters (default "30s")
	Jitter        float64 `json:"jitter,omitempty"`         // 0.0-1.0, randomize Retry-After header
}

// ─── Sliding Window Counter ─────────────────────────────────────────

const numShards = 16

// rateLimitState holds all rate limit zones, keyed by rule ID.
// The outer map is protected by mu (for hot-reload), inner shards have
// their own locks for concurrent request processing.
type rateLimitState struct {
	mu    sync.RWMutex
	zones map[string]*zone // rule ID → zone
}

// defaultMaxKeys is the default maximum number of unique keys per zone.
// Prevents unbounded memory growth from large numbers of unique client keys.
const defaultMaxKeys = 100000

// zone is a single rate limit zone (one per rate_limit rule).
type zone struct {
	events  int
	window  time.Duration
	maxKeys int // max unique keys across all shards
	shards  [numShards]shard
}

// shard is one of numShards partitions of the counter map.
type shard struct {
	mu       sync.Mutex
	counters map[string]*counter
}

// counter tracks request counts using the sliding window algorithm.
// Two windows: previous and current. The effective count interpolates
// between them based on elapsed time in the current window.
type counter struct {
	prevCount int64
	prevStart int64 // unix nanoseconds
	currCount int64
	currStart int64
}

// newZone creates a zone with the given parameters and initialized shards.
func newZone(events int, window time.Duration, maxKeys int) *zone {
	if maxKeys <= 0 {
		maxKeys = defaultMaxKeys
	}
	z := &zone{
		events:  events,
		window:  window,
		maxKeys: maxKeys,
	}
	for i := range z.shards {
		z.shards[i].counters = make(map[string]*counter)
	}
	return z
}

// shardFor returns the shard index for the given key.
func shardFor(key string) int {
	h := fnv.New32a()
	h.Write([]byte(key))
	return int(h.Sum32()) & (numShards - 1)
}

// allow checks if a request with the given key should be allowed.
// Returns (allowed, currentCount, limit). Thread-safe.
func (z *zone) allow(key string, now time.Time) (bool, int64, int) {
	idx := shardFor(key)
	s := &z.shards[idx]

	s.mu.Lock()
	defer s.mu.Unlock()

	c, ok := s.counters[key]
	if !ok {
		// Reject new keys when the shard is at capacity to prevent
		// unbounded memory growth from key-flooding attacks.
		if len(s.counters) >= z.maxKeys/numShards {
			return false, int64(z.events), z.events
		}
		c = &counter{
			currStart: now.UnixNano(),
		}
		s.counters[key] = c
	}

	windowNanos := z.window.Nanoseconds()
	nowNanos := now.UnixNano()

	// Rotate windows if current window has expired.
	if nowNanos-c.currStart >= windowNanos {
		// Check if we need to skip a window (long gap between requests).
		if nowNanos-c.currStart >= 2*windowNanos {
			// More than 2 windows passed — both windows are stale.
			c.prevCount = 0
			c.prevStart = nowNanos - windowNanos
			c.currCount = 0
			c.currStart = nowNanos
		} else {
			// Normal rotation: current becomes previous.
			c.prevCount = c.currCount
			c.prevStart = c.currStart
			c.currCount = 0
			c.currStart = c.prevStart + windowNanos
		}
	}

	// Calculate effective count using sliding window interpolation.
	elapsed := nowNanos - c.currStart
	if elapsed < 0 {
		elapsed = 0
	}
	weight := 1.0 - float64(elapsed)/float64(windowNanos)
	if weight < 0 {
		weight = 0
	}
	effective := int64(math.Ceil(float64(c.prevCount)*weight)) + c.currCount

	if effective >= int64(z.events) {
		return false, effective, z.events
	}

	// Allow — increment counter.
	c.currCount++
	return true, effective + 1, z.events
}

// sweep removes expired counters. Called periodically by the sweep goroutine.
func (z *zone) sweep(now time.Time) int {
	swept := 0
	windowNanos := z.window.Nanoseconds()
	nowNanos := now.UnixNano()
	// A counter is expired if both windows are stale (2× window age).
	cutoff := nowNanos - 2*windowNanos

	for i := range z.shards {
		s := &z.shards[i]
		s.mu.Lock()
		for key, c := range s.counters {
			if c.currStart < cutoff {
				delete(s.counters, key)
				swept++
			}
		}
		s.mu.Unlock()
	}
	return swept
}

// ─── Rate Limit State Management ────────────────────────────────────

func newRateLimitState() *rateLimitState {
	return &rateLimitState{
		zones: make(map[string]*zone),
	}
}

// updateZones reconciles zones with the new set of compiled rules.
// Zones for rules with unchanged events/window keep their counters.
// New or changed rules get fresh zones. Removed rules' zones are dropped.
func (rls *rateLimitState) updateZones(rules []compiledRule) {
	rls.mu.Lock()
	defer rls.mu.Unlock()

	newZones := make(map[string]*zone, len(rules))

	for _, cr := range rules {
		if cr.rule.Type != "rate_limit" || cr.rlConfig == nil {
			continue
		}

		id := cr.rule.ID
		cfg := cr.rlConfig

		// Preserve existing zone if config hasn't changed.
		maxKeys := cfg.MaxKeys
		if maxKeys <= 0 {
			maxKeys = defaultMaxKeys
		}
		if existing, ok := rls.zones[id]; ok {
			if existing.events == cfg.Events && existing.window == cfg.parsedWindow && existing.maxKeys == maxKeys {
				newZones[id] = existing
				continue
			}
		}

		// New or changed — create fresh zone.
		newZones[id] = newZone(cfg.Events, cfg.parsedWindow, cfg.MaxKeys)
	}

	rls.zones = newZones
}

// getZone returns the zone for the given rule ID.
func (rls *rateLimitState) getZone(ruleID string) *zone {
	rls.mu.RLock()
	defer rls.mu.RUnlock()
	return rls.zones[ruleID]
}

// sweepAll runs sweep on all zones. Returns total expired entries removed.
func (rls *rateLimitState) sweepAll(now time.Time) int {
	rls.mu.RLock()
	defer rls.mu.RUnlock()

	total := 0
	for _, z := range rls.zones {
		total += z.sweep(now)
	}
	return total
}

// ─── Sweep Goroutine ────────────────────────────────────────────────

// sweepInterval is the default interval for sweeping expired counters.
var defaultSweepInterval = 30 * time.Second

// sweepInterval returns the effective sweep interval from the global config.
func (pe *PolicyEngine) sweepInterval() time.Duration {
	pe.mu.RLock()
	cfg := pe.rlGlobalConfig
	pe.mu.RUnlock()
	if cfg != nil && cfg.parsedSweep > 0 {
		return cfg.parsedSweep
	}
	return defaultSweepInterval
}

// startSweep starts the background goroutine that periodically evicts
// expired counters.
func (pe *PolicyEngine) startSweep() {
	if pe.rlState == nil {
		return
	}
	pe.stopSweep = make(chan struct{})
	interval := pe.sweepInterval()

	// Capture stop channel and rlState in local variables so the goroutine
	// doesn't read pe.stopSweep via closure on each select iteration.
	// Without this, restartSweep could overwrite pe.stopSweep with a new
	// channel before the old goroutine reads the closed old channel,
	// causing the old goroutine to block on the new (open) channel forever.
	stop := pe.stopSweep
	rls := pe.rlState

	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()

		for {
			select {
			case <-stop:
				return
			case <-ticker.C:
				swept := rls.sweepAll(time.Now())
				if swept > 0 && pe.logger != nil {
					pe.logger.Debug("rate limit sweep",
						zap.Int("expired", swept))
				}
			}
		}
	}()
}

// restartSweep stops the current sweep goroutine and starts a new one.
// Called during hot-reload when the global rate limit config changes.
func (pe *PolicyEngine) restartSweep() {
	if pe.stopSweep != nil {
		close(pe.stopSweep)
	}
	pe.startSweep()
}

// ─── Key Resolution ─────────────────────────────────────────────────

// resolveRateLimitKey extracts the rate limit bucket key from the request.
// Unlike the Caddyfile generator (which outputs Caddy placeholders), this
// resolves directly from the http.Request — no placeholder indirection.
// Uses the pre-parsed body (parsedBody) to avoid re-parsing JSON/form data.
func resolveRateLimitKey(keySpec string, r *http.Request, pb *parsedBody) string {
	switch keySpec {
	case "client_ip", "":
		return clientIP(r)
	case "path":
		return r.URL.Path
	case "static":
		return "static"
	case "client_ip+path":
		return clientIP(r) + "_" + r.URL.Path
	case "client_ip+method":
		return clientIP(r) + "_" + r.Method
	case "challenge_cookie":
		// Rate limit by challenge cookie token ID (jti).
		// Automatically resolves the per-service cookie name and extracts the jti.
		host := stripPort(r.Host)
		cookieName := challengeCookieName(host)
		if c, err := r.Cookie(cookieName); err == nil && c.Value != "" {
			// Extract jti from the cookie payload (base64url(json).signature).
			if parts := strings.SplitN(c.Value, ".", 2); len(parts) == 2 {
				if payload, err := base64.RawURLEncoding.DecodeString(parts[0]); err == nil {
					var cp struct {
						Jti string `json:"jti"`
					}
					if json.Unmarshal(payload, &cp) == nil && cp.Jti != "" {
						return cp.Jti
					}
				}
			}
			// Fallback: use the full cookie value as key.
			return c.Value
		}
		// No challenge cookie — fall back to client IP so the request
		// still gets rate-limited (just by IP instead of cookie).
		return clientIP(r)
	}

	// Parameterized keys.
	if strings.HasPrefix(keySpec, "header:") {
		name := strings.TrimPrefix(keySpec, "header:")
		return r.Header.Get(name)
	}
	if strings.HasPrefix(keySpec, "cookie:") {
		name := strings.TrimPrefix(keySpec, "cookie:")
		if c, err := r.Cookie(name); err == nil {
			return c.Value
		}
		return ""
	}
	if strings.HasPrefix(keySpec, "body_json:") {
		dotPath := strings.TrimPrefix(keySpec, "body_json:")
		if pb == nil || len(pb.raw) == 0 {
			return ""
		}
		root, ok := pb.getJSON()
		if !ok {
			return ""
		}
		val, found := resolveJSONPathParsed(root, dotPath)
		if !found {
			return ""
		}
		return jsonValueToString(val)
	}
	if strings.HasPrefix(keySpec, "body_form:") {
		field := strings.TrimPrefix(keySpec, "body_form:")
		if pb == nil || len(pb.raw) == 0 {
			return ""
		}
		values := pb.getForm()
		if values == nil {
			return ""
		}
		return values.Get(field)
	}

	// Fallback to client IP.
	return clientIP(r)
}

// needsBodyForKey returns true if the key spec requires reading the request body.
func needsBodyForKey(keySpec string) bool {
	return strings.HasPrefix(keySpec, "body_json:") || strings.HasPrefix(keySpec, "body_form:")
}

// ─── Compiled Rate Limit Config ─────────────────────────────────────

// compiledRLConfig is the parsed/validated rate limit configuration
// attached to a compiled rule.
type compiledRLConfig struct {
	Key          string
	Events       int
	parsedWindow time.Duration
	Action       string // "deny" or "log_only"
	MaxKeys      int    // max unique keys per zone; 0 = use default
	needsBody    bool   // true if key requires body reading
}

// parsedRLGlobalConfig is the parsed global rate limit configuration.
type parsedRLGlobalConfig struct {
	parsedSweep time.Duration
	jitter      float64
}

// compileRLConfig validates and parses a RateLimitConfig into a compiledRLConfig.
func compileRLConfig(cfg *RateLimitConfig) (*compiledRLConfig, error) {
	if cfg == nil {
		return nil, fmt.Errorf("rate_limit config is required for rate_limit rules")
	}
	if cfg.Events <= 0 {
		return nil, fmt.Errorf("rate_limit events must be > 0, got %d", cfg.Events)
	}

	window, err := parseWindow(cfg.Window)
	if err != nil {
		return nil, fmt.Errorf("invalid rate_limit window %q: %w", cfg.Window, err)
	}
	if window < time.Second {
		return nil, fmt.Errorf("rate_limit window must be >= 1s, got %s", cfg.Window)
	}

	action := cfg.Action
	if action == "" {
		action = "deny"
	}
	if action != "deny" && action != "log_only" {
		return nil, fmt.Errorf("invalid rate_limit action %q (must be deny or log_only)", action)
	}

	key := cfg.Key
	if key == "" {
		key = "client_ip"
	}
	if !isValidRLKey(key) {
		return nil, fmt.Errorf("invalid rate_limit key %q", key)
	}

	return &compiledRLConfig{
		Key:          key,
		Events:       cfg.Events,
		parsedWindow: window,
		Action:       action,
		MaxKeys:      cfg.MaxKeys,
		needsBody:    needsBodyForKey(key),
	}, nil
}

// parseWindow parses a duration string like "1s", "5m", "1h".
func parseWindow(s string) (time.Duration, error) {
	if s == "" {
		return 0, fmt.Errorf("empty window")
	}
	// Try standard Go duration parsing first.
	d, err := time.ParseDuration(s)
	if err == nil {
		return d, nil
	}
	// Try simple numeric + suffix format (e.g., "30s", "5m", "1h").
	if len(s) < 2 {
		return 0, fmt.Errorf("invalid window %q", s)
	}
	numStr := s[:len(s)-1]
	suffix := s[len(s)-1]
	n, err := strconv.Atoi(numStr)
	if err != nil {
		return 0, fmt.Errorf("invalid window %q: %w", s, err)
	}
	switch suffix {
	case 's':
		return time.Duration(n) * time.Second, nil
	case 'm':
		return time.Duration(n) * time.Minute, nil
	case 'h':
		return time.Duration(n) * time.Hour, nil
	default:
		return 0, fmt.Errorf("invalid window suffix %q (use s, m, or h)", string(suffix))
	}
}

// isValidRLKey checks if a key spec is valid.
func isValidRLKey(key string) bool {
	switch key {
	case "client_ip", "path", "static", "client_ip+path", "client_ip+method":
		return true
	}
	prefixes := []string{"header:", "cookie:", "body_json:", "body_form:"}
	for _, p := range prefixes {
		if strings.HasPrefix(key, p) && len(key) > len(p) {
			return true
		}
	}
	return false
}

// compileRLGlobalConfig parses the global rate limit config.
func compileRLGlobalConfig(cfg *RateLimitGlobalConfig) (*parsedRLGlobalConfig, error) {
	if cfg == nil {
		return nil, nil
	}
	parsed := &parsedRLGlobalConfig{
		jitter: cfg.Jitter,
	}
	if cfg.SweepInterval != "" {
		d, err := parseWindow(cfg.SweepInterval)
		if err != nil {
			return nil, fmt.Errorf("invalid sweep_interval %q: %w", cfg.SweepInterval, err)
		}
		if d > 0 {
			parsed.parsedSweep = d
		}
	}
	if parsed.jitter < 0 {
		parsed.jitter = 0
	}
	if parsed.jitter > 1 {
		parsed.jitter = 1
	}
	return parsed, nil
}

// ─── Response Helpers ───────────────────────────────────────────────

// retryAfterSeconds calculates the Retry-After value in seconds.
// Applies jitter if configured.
func retryAfterSeconds(window time.Duration, jitter float64) string {
	secs := int(math.Ceil(window.Seconds()))
	if secs < 1 {
		secs = 1
	}
	if jitter > 0 {
		// Apply jitter: multiply by random factor in [1-jitter, 1+jitter].
		factor := 1.0 + jitter*(2*rand.Float64()-1)
		secs = int(math.Ceil(float64(secs) * factor))
		if secs < 1 {
			secs = 1
		}
	}
	return strconv.Itoa(secs)
}

// setRateLimitHeaders sets standard rate limit response headers.
func setRateLimitHeaders(w http.ResponseWriter, limit, remaining int, window time.Duration, ruleName string) {
	w.Header().Set("X-RateLimit-Limit", strconv.Itoa(limit))
	rem := remaining
	if rem < 0 {
		rem = 0
	}
	w.Header().Set("X-RateLimit-Remaining", strconv.Itoa(rem))
	w.Header().Set("X-RateLimit-Reset", strconv.FormatInt(time.Now().Add(window).Unix(), 10))
	if ruleName != "" {
		w.Header().Set("X-RateLimit-Policy", fmt.Sprintf("%d;w=%s;name=%q",
			limit, formatWindow(window), ruleName))
	}
}

// formatWindow formats a duration as a compact string (e.g., "1m", "30s", "1h").
func formatWindow(d time.Duration) string {
	if d >= time.Hour && d%time.Hour == 0 {
		return fmt.Sprintf("%dh", int(d.Hours()))
	}
	if d >= time.Minute && d%time.Minute == 0 {
		return fmt.Sprintf("%dm", int(d.Minutes()))
	}
	return fmt.Sprintf("%ds", int(d.Seconds()))
}

// ─── Service Matching ───────────────────────────────────────────────

// matchService checks if a request matches a rate limit rule's service field.
// Empty service or "*" matches all requests. Otherwise, matches against Host header.
func matchService(service string, r *http.Request) bool {
	if service == "" || service == "*" {
		return true
	}
	host := r.Host
	// Strip port if present.
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	return strings.EqualFold(host, service)
}
