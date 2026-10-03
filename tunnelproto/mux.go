package tunnelproto

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/coder/websocket"
	"github.com/hashicorp/yamux"
)

// sessionReadLimit bounds a single WebSocket message once yamux runs (yamux frames are at most the
// stream window, see muxConfig).
const sessionReadLimit = 8 << 20

func muxConfig() *yamux.Config {
	cfg := yamux.DefaultConfig()
	cfg.AcceptBacklog = 1024
	cfg.EnableKeepAlive = true
	cfg.KeepAliveInterval = 30 * time.Second
	cfg.ConnectionWriteTimeout = 30 * time.Second
	cfg.StreamOpenTimeout = 30 * time.Second
	cfg.StreamCloseTimeout = 5 * time.Minute
	cfg.MaxStreamWindowSize = 4 << 20 // larger than the 256 KiB default: one session carries every tunnel
	cfg.LogOutput = io.Discard
	return cfg
}

// Session is a yamux session over an authenticated WebSocket.
type Session struct {
	*yamux.Session
	conn *recordingConn
}

// CloseError returns the error that ended reading from the WebSocket. For a close frame it is a
// websocket.CloseError, so websocket.CloseStatus(s.CloseError()) yields codes like CloseUnauthorized.
func (s *Session) CloseError() error { return s.conn.readErr() }

// recordingConn remembers the first read error, which yamux would otherwise swallow.
type recordingConn struct {
	net.Conn
	mu  sync.Mutex
	err error
}

func (c *recordingConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if err != nil {
		c.mu.Lock()
		if c.err == nil {
			c.err = err
		}
		c.mu.Unlock()
	}
	return n, err
}

func (c *recordingConn) readErr() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.err
}

// netConn turns an authenticated WebSocket into the byte stream yamux runs on. ctx bounds the
// whole session.
func netConn(ctx context.Context, c *websocket.Conn) *recordingConn {
	c.SetReadLimit(sessionReadLimit)
	return &recordingConn{Conn: websocket.NetConn(ctx, c, websocket.MessageBinary)}
}

// ServerSession starts the server side of the multiplexer after the Welcome was sent. The device
// opens the control stream first; data streams are opened by the server with OpenStream.
func ServerSession(ctx context.Context, c *websocket.Conn) (*Session, error) {
	nc := netConn(ctx, c)
	s, err := yamux.Server(nc, muxConfig())
	if err != nil {
		return nil, err
	}
	return &Session{Session: s, conn: nc}, nil
}

// ClientSession starts the device side of the multiplexer after the Welcome was received.
func ClientSession(ctx context.Context, c *websocket.Conn) (*Session, error) {
	nc := netConn(ctx, c)
	s, err := yamux.Client(nc, muxConfig())
	if err != nil {
		return nil, err
	}
	return &Session{Session: s, conn: nc}, nil
}

// PinnedTLS returns a TLS configuration that accepts exactly the certificate with the given
// SHA-256 (hex) and nothing else, regardless of names or issuers.
func PinnedTLS(certSHA256 string) *tls.Config {
	want := strings.ToLower(certSHA256)
	return &tls.Config{
		MinVersion:         tls.VersionTLS13,
		InsecureSkipVerify: true, // replaced by the pin check below
		VerifyConnection: func(cs tls.ConnectionState) error {
			if len(cs.PeerCertificates) == 0 {
				return errors.New("tunnelproto: no server certificate")
			}
			sum := sha256.Sum256(cs.PeerCertificates[0].Raw)
			if subtle.ConstantTimeCompare([]byte(hex.EncodeToString(sum[:])), []byte(want)) != 1 {
				return errors.New("tunnelproto: server certificate does not match the pinned fingerprint")
			}
			return nil
		},
	}
}

// CertSHA256 is the pin of a DER certificate.
func CertSHA256(der []byte) string {
	sum := sha256.Sum256(der)
	return hex.EncodeToString(sum[:])
}
