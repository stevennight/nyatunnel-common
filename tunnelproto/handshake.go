// Package tunnelproto is the wire protocol between a NyaTunnel device and the server
// (nyatunnel-server/docs/协议.md §4): an authenticated WebSocket handshake, then yamux
// carrying one control stream and one data stream per visitor connection.
//
// Both repositories use this package, so the protocol has exactly one implementation.
package tunnelproto

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/coder/websocket"
)

// ProtocolVersion is MAJOR.MINOR. Peers interoperate within a major version; new behaviour is
// gated by Features, never by comparing versions.
const ProtocolVersion = "1.0"

// ConnectPath is where devices open their WebSocket.
const ConnectPath = "/api/v1/device/connect"

// WebSocket close codes with a protocol meaning (协议.md §1).
const (
	// CloseUnauthorized: unknown or revoked device, disabled owner or bad signature. The client must forget its identity.
	CloseUnauthorized websocket.StatusCode = 4401
	// CloseReplaced: a newer session of the same device took over. The client should not race to reconnect.
	CloseReplaced websocket.StatusCode = 4409
	// CloseUpgradeRequired: the client is older than the server's minimum.
	CloseUpgradeRequired websocket.StatusCode = 4426
)

// handshakeReadLimit bounds every handshake message; the session raises it afterwards.
const handshakeReadLimit = 16 << 10

// Hello is the first message of a device.
type Hello struct {
	Type          string   `json:"type"`
	DeviceID      string   `json:"deviceId"`
	Protocol      string   `json:"protocol"`
	ClientVersion string   `json:"clientVersion"`
	Features      []string `json:"features,omitempty"`
}

type challenge struct {
	Type  string `json:"type"`
	Nonce string `json:"nonce"`
}

type authMsg struct {
	Type      string `json:"type"`
	Signature string `json:"signature"`
}

// Welcome ends a successful handshake.
type Welcome struct {
	Type      string   `json:"type"`
	SessionID string   `json:"sessionId"`
	Protocol  string   `json:"protocol"`
	Features  []string `json:"features,omitempty"`
}

// ErrUnauthorized is returned by ServerHandshake when the device must be refused with CloseUnauthorized.
var ErrUnauthorized = errors.New("tunnelproto: device not authorized")

// signedPayload binds the signature to this server and this nonce, so it can be neither replayed nor
// relayed to another server.
func signedPayload(host, deviceID, nonce string) []byte {
	return []byte("nyatunnel-connect-v1\n" + strings.ToLower(host) + "\n" + deviceID + "\n" + nonce)
}

// Sign returns the base64 signature a device sends in reply to a challenge.
func Sign(priv ed25519.PrivateKey, host, deviceID, nonce string) string {
	return base64.StdEncoding.EncodeToString(ed25519.Sign(priv, signedPayload(host, deviceID, nonce)))
}

// Verify checks a signature produced by Sign.
func Verify(pub ed25519.PublicKey, host, deviceID, nonce, signature string) bool {
	sig, err := base64.StdEncoding.DecodeString(signature)
	if err != nil || len(pub) != ed25519.PublicKeySize {
		return false
	}
	return ed25519.Verify(pub, signedPayload(host, deviceID, nonce), sig)
}

// ClientHandshake authenticates a device on a freshly dialed connection. host is the server host the
// device believes it is talking to (deeplink.ServerHost of the public URL).
func ClientHandshake(ctx context.Context, c *websocket.Conn, host string, hello Hello, priv ed25519.PrivateKey) (*Welcome, error) {
	c.SetReadLimit(handshakeReadLimit)
	hello.Type = "hello"
	if hello.Protocol == "" {
		hello.Protocol = ProtocolVersion
	}
	if err := writeJSON(ctx, c, hello); err != nil {
		return nil, err
	}
	var ch challenge
	if err := readJSON(ctx, c, &ch); err != nil {
		return nil, err
	}
	if ch.Type != "challenge" || ch.Nonce == "" {
		return nil, fmt.Errorf("tunnelproto: expected challenge, got %q", ch.Type)
	}
	if err := writeJSON(ctx, c, authMsg{Type: "auth", Signature: Sign(priv, host, hello.DeviceID, ch.Nonce)}); err != nil {
		return nil, err
	}
	var w Welcome
	if err := readJSON(ctx, c, &w); err != nil {
		return nil, err
	}
	if w.Type != "welcome" {
		return nil, fmt.Errorf("tunnelproto: expected welcome, got %q", w.Type)
	}
	if major(w.Protocol) != major(ProtocolVersion) {
		return nil, fmt.Errorf("tunnelproto: server speaks protocol %s, this client %s", w.Protocol, ProtocolVersion)
	}
	return &w, nil
}

// ServerHandshake reads the hello, asks lookup for the device's public key, and checks the signature.
// lookup returns ErrUnauthorized (or any error wrapping it) to refuse the device. On success the caller
// registers the session and then sends the Welcome with SendWelcome.
func ServerHandshake(ctx context.Context, c *websocket.Conn, host string, lookup func(context.Context, *Hello) (ed25519.PublicKey, error)) (*Hello, error) {
	c.SetReadLimit(handshakeReadLimit)
	var h Hello
	if err := readJSON(ctx, c, &h); err != nil {
		return nil, err
	}
	if h.Type != "hello" || h.DeviceID == "" {
		return nil, fmt.Errorf("tunnelproto: expected hello, got %q", h.Type)
	}
	if major(h.Protocol) != major(ProtocolVersion) {
		return nil, fmt.Errorf("tunnelproto: client speaks protocol %q", h.Protocol)
	}
	pub, err := lookup(ctx, &h)
	if err != nil {
		return nil, err
	}
	nonce, err := newNonce()
	if err != nil {
		return nil, err
	}
	if err := writeJSON(ctx, c, challenge{Type: "challenge", Nonce: nonce}); err != nil {
		return nil, err
	}
	var a authMsg
	if err := readJSON(ctx, c, &a); err != nil {
		return nil, err
	}
	if a.Type != "auth" || !Verify(pub, host, h.DeviceID, nonce, a.Signature) {
		return nil, ErrUnauthorized
	}
	return &h, nil
}

// SendWelcome completes the server side of the handshake.
func SendWelcome(ctx context.Context, c *websocket.Conn, w Welcome) error {
	w.Type = "welcome"
	if w.Protocol == "" {
		w.Protocol = ProtocolVersion
	}
	return writeJSON(ctx, c, w)
}

// FeatureProbe in a Hello asks for a read-only session: the server sends the configuration but
// does not replace the device's running session or route traffic to it (used by `nyatunnel status`).
const FeatureProbe = "probe"

// HasFeature reports whether a negotiated feature list contains f.
func HasFeature(features []string, f string) bool { return slices.Contains(features, f) }

func newNonce() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(b), nil
}

func major(v string) string {
	m, _, _ := strings.Cut(v, ".")
	return m
}

func writeJSON(ctx context.Context, c *websocket.Conn, v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	return c.Write(ctx, websocket.MessageText, b)
}

func readJSON(ctx context.Context, c *websocket.Conn, v any) error {
	typ, b, err := c.Read(ctx)
	if err != nil {
		return err
	}
	if typ != websocket.MessageText {
		return errors.New("tunnelproto: expected a text message during the handshake")
	}
	return json.Unmarshal(b, v)
}
