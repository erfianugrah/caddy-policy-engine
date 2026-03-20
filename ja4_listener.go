package policyengine

import (
	"bytes"
	"io"
	"net"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"go.uber.org/zap"
)

func init() {
	caddy.RegisterModule(JA4ListenerWrapper{})
}

// JA4ListenerWrapper is a Caddy listener wrapper that computes JA4 TLS
// fingerprints from the raw ClientHello before passing connections to the
// TLS handler. The computed fingerprint is stored in a package-level
// registry (ja4Registry) keyed by the connection's remote address, readable
// by the policy engine's ServeHTTP via ja4Registry.Get(r.RemoteAddr).
//
// Caddyfile usage:
//
//	{
//	    servers {
//	        listener_wrappers {
//	            ja4
//	            tls
//	        }
//	    }
//	}
type JA4ListenerWrapper struct {
	logger *zap.Logger
}

func (JA4ListenerWrapper) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "caddy.listeners.ja4",
		New: func() caddy.Module { return new(JA4ListenerWrapper) },
	}
}

func (w *JA4ListenerWrapper) Provision(ctx caddy.Context) error {
	w.logger = ctx.Logger()
	w.logger.Info("JA4 listener wrapper provisioned")
	return nil
}

func (w *JA4ListenerWrapper) WrapListener(ln net.Listener) net.Listener {
	return &ja4Listener{Listener: ln, logger: w.logger}
}

func (w *JA4ListenerWrapper) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	d.Next() // consume "ja4"
	return nil
}

// ─── ja4Listener ────────────────────────────────────────────────────

type ja4Listener struct {
	net.Listener
	logger *zap.Logger
}

func (l *ja4Listener) Accept() (net.Conn, error) {
	conn, err := l.Listener.Accept()
	if err != nil {
		return conn, err
	}

	// Read the raw ClientHello bytes from the TCP stream.
	raw, err := readClientHello(conn)
	if err != nil {
		// Not TLS or malformed — rewind whatever was read and pass through.
		if len(raw) > 0 {
			return newJA4Conn(newRewindConn(conn, raw), conn.RemoteAddr().String()), nil
		}
		return conn, nil
	}

	// Parse the ClientHello and compute JA4.
	ch, parseErr := parseClientHello(raw)
	if parseErr == nil {
		ja4 := computeJA4(ch)
		addr := conn.RemoteAddr().String()
		ja4Registry.Set(addr, ja4)
		l.logger.Debug("JA4 fingerprint computed",
			zap.String("addr", addr),
			zap.String("ja4", ja4))
	} else {
		l.logger.Debug("JA4 ClientHello parse failed",
			zap.Error(parseErr),
			zap.String("addr", conn.RemoteAddr().String()))
	}

	// Rewind the bytes so the TLS handler can read them.
	return newJA4Conn(newRewindConn(conn, raw), conn.RemoteAddr().String()), nil
}

// ─── ja4Conn ────────────────────────────────────────────────────────
// Wraps a connection to clean up the JA4 registry entry on Close().

type ja4Conn struct {
	net.Conn
	addr string
}

func newJA4Conn(conn net.Conn, addr string) *ja4Conn {
	return &ja4Conn{Conn: conn, addr: addr}
}

func (c *ja4Conn) Close() error {
	ja4Registry.Delete(c.addr)
	return c.Conn.Close()
}

// ─── RewindConn ─────────────────────────────────────────────────────
// Replays buffered bytes before passing through to the real connection.

type rewindConn struct {
	net.Conn
	buf *bytes.Reader
}

func newRewindConn(conn net.Conn, data []byte) net.Conn {
	return &rewindConn{
		Conn: conn,
		buf:  bytes.NewReader(data),
	}
}

func (c *rewindConn) Read(p []byte) (int, error) {
	if c.buf.Len() > 0 {
		n, err := c.buf.Read(p)
		if err == io.EOF {
			// Buffer exhausted — seamless transition to real conn.
			return n, nil
		}
		return n, err
	}
	return c.Conn.Read(p)
}

// ─── Interface guards ───────────────────────────────────────────────

var (
	_ caddy.Module          = (*JA4ListenerWrapper)(nil)
	_ caddy.Provisioner     = (*JA4ListenerWrapper)(nil)
	_ caddy.ListenerWrapper = (*JA4ListenerWrapper)(nil)
	_ caddyfile.Unmarshaler = (*JA4ListenerWrapper)(nil)
)
