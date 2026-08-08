#!/usr/bin/env bash
# Runtime sensor: the ja4 listener wrapper must not park the serial accept
# loop when a connection opens TCP and sends nothing.
#
# Builds a caddy binary with the LOCAL caddy-policy-engine (same caddy-l4 /
# ddos-mitigator pins as the production edge image), then runs it inside the
# PRODUCTION caddy image (binary bind-mounted over /usr/bin/caddy) serving a
# TLS site on 127.0.0.1:18443. A silent connection is parked, then a real TLS
# handshake must complete within the curl timeout.
#
# Pre-fix: the handshake hangs forever (readClientHello has no deadline) ->
#   curl times out -> exit 1.
# Post-fix: the silent conn's peek times out (2s) and the handshake
#   completes -> exit 0.
set -u

PORT="${JA4_SENSOR_PORT:-18443}"
ADMIN_PORT="${JA4_SENSOR_ADMIN:-12029}"
NAME="ja4-sensor"
IMAGE="erfianugrah/caddy:3.97.0-2.11.4"
WORK=/tmp/ja4-sensor
BIN="$WORK/caddy"
REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"

mkdir -p "$WORK/waf"

cleanup() {
  docker rm -f "$NAME" >/dev/null 2>&1
  [ -f "$WORK/holder.pid" ] && kill "$(cat "$WORK/holder.pid")" 2>/dev/null
  true
}
trap cleanup EXIT

# Build (cached: only rebuild when any .go file is newer than the binary)
NEED_BUILD=1
if [ -x "$BIN" ]; then
  NEWER=$(find "$REPO_ROOT" -maxdepth 1 -name '*.go' -newer "$BIN" | head -1)
  [ -z "$NEWER" ] && NEED_BUILD=0
fi
if [ "$NEED_BUILD" = 1 ]; then
  echo "[sensor] building caddy with local plugin..."
  (cd "$WORK" && CGO_ENABLED=0 xcaddy build v2.11.4 \
    --with github.com/mholt/caddy-l4@v0.1.2 \
    --with github.com/erfianugrah/caddy-policy-engine="$REPO_ROOT" \
    --with github.com/erfianugrah/caddy-ddos-mitigator@v0.17.3 \
    --output "$BIN") || { echo "[sensor] BUILD FAILED"; exit 1; }
fi

cat > "$WORK/waf/jail.json" <<'EOF'
{"version":1,"entries":{},"whitelist":["127.0.0.0/8","10.0.0.0/8"],"updated_at":"2026-08-08T00:00:00Z"}
EOF

cat > "$WORK/Caddyfile" <<EOF
{
	admin 0.0.0.0:$ADMIN_PORT
	auto_https disable_redirects
	servers {
		listener_wrappers {
			layer4 {
				route {
					ddos_mitigator {
						jail_file /data/waf/jail.json
					}
				}
			}
			ja4
			tls
		}
	}
}

localhost:$PORT {
	tls internal
	respond "ok" 200
}
EOF

docker rm -f "$NAME" >/dev/null 2>&1
docker run -d --name "$NAME" \
  -p 127.0.0.1:$PORT:$PORT -p 127.0.0.1:$ADMIN_PORT:$ADMIN_PORT \
  -v "$BIN":/usr/bin/caddy:ro \
  -v "$WORK/Caddyfile":/etc/caddy/Caddyfile:ro \
  -v "$WORK/waf":/data/waf \
  "$IMAGE" caddy run --config /etc/caddy/Caddyfile --adapter caddyfile >/dev/null || {
    echo "[sensor] FAIL: container did not start"; exit 1; }
sleep 2

# Control: no silent conn -> handshake must work at all
if ! curl -sk -o /dev/null -m 5 "https://localhost:$PORT/"; then
  echo "[sensor] FAIL: baseline handshake broken (config/build issue)"
  docker logs "$NAME" 2>&1 | tail -5
  exit 1
fi

# Park a silent connection (TCP open, zero bytes, held 60s)
nohup bash -c "exec 3<>/dev/tcp/127.0.0.1/$PORT; sleep 60" >/dev/null 2>&1 &
echo $! > "$WORK/holder.pid"
sleep 1

# The gate: a real handshake must complete despite the parked conn.
# Post-fix the peek deadline (2s) applies, so allow 8s of headroom.
START=$(date +%s%N)
if curl -sk -o /dev/null -m 8 "https://localhost:$PORT/"; then
  ELAPSED_MS=$(( ($(date +%s%N) - START) / 1000000 ))
  echo "[sensor] PASS: handshake completed in ${ELAPSED_MS}ms with a silent conn parked"
  exit 0
else
  echo "[sensor] FAIL: handshake hung behind a silent connection - accept loop is parked"
  exit 1
fi
