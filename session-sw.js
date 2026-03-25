// Session tracking service worker for cross-navigation behavioral analysis.
// Registered after challenge PoW solve, intercepts navigations to track
// page-to-page timing and session patterns. Beacons data to the server
// for session scoring.
//
// Served at /.well-known/policy-challenge/session-sw.js with
// Service-Worker-Allowed: / header so it can control the entire origin.
// Embedded in the plugin via go:embed.

const BEACON_URL = '/.well-known/policy-challenge/session';
const MAX_BUFFER = 50;

let buffer = [];
let lastNavTs = 0;

// Take control of all pages immediately on activation, including the
// page that registered us (the challenge redirect target). Without this,
// the first page after challenge would not be tracked.
// See: https://www.w3.org/TR/service-workers/ §3.1.4
self.addEventListener('activate', (event) => {
  event.waitUntil(self.clients.claim());
});

self.addEventListener('fetch', (event) => {
  const url = new URL(event.request.url);

  // Only track navigations, not subresource fetches (images, scripts, etc).
  if (event.request.mode !== 'navigate') return;

  // Skip our own endpoints to avoid infinite loops.
  if (url.pathname.startsWith('/.well-known/policy-challenge/')) return;

  const now = Date.now();
  const dwellMs = lastNavTs > 0 ? now - lastNavTs : 0;

  buffer.push({
    ts: now,
    path: url.pathname,
    ref: event.request.referrer || '',
    dwell: dwellMs,
  });

  lastNavTs = now;

  // Flush if buffer is large enough to avoid unbounded growth.
  if (buffer.length >= MAX_BUFFER) {
    flush();
  }
});

function flush() {
  if (buffer.length === 0) return;
  const payload = JSON.stringify(buffer);
  buffer = [];
  // fetch with keepalive ensures delivery even during SW termination.
  // Best-effort — if it fails, we lose some data points, which is acceptable.
  fetch(BEACON_URL, {
    method: 'POST',
    body: payload,
    keepalive: true,
    headers: { 'Content-Type': 'application/json' },
  }).catch(() => {});
}
