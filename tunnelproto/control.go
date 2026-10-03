package tunnelproto

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"
)

// Control message types (协议.md §4.3).
const (
	TypeConfig        = "config"         // S→C Config
	TypeNotice        = "notice"         // S→C Notice
	TypeStatus        = "status"         // C→S Status
	TypeStats         = "stats"          // C→S Stats
	TypeTunnelUpdate  = "tunnel.update"  // C→S TunnelUpdate, answered with TypeResult
	TypeRequestCreate = "request.create" // C→S TunnelRequest, answered with TypeResult
	TypeResult        = "result"         // S→C Result
	TypePing          = "ping"
	TypePong          = "pong"
)

// Tunnel types.
const (
	TunnelHTTPS = "https"
	TunnelTCP   = "tcp"
	TunnelUDP   = "udp"
)

// maxControlMessage bounds one control message.
const maxControlMessage = 1 << 20

// Message is one line on the control stream.
type Message struct {
	Type string          `json:"type"`
	ID   string          `json:"id,omitempty"`
	Data json.RawMessage `json:"data,omitempty"`
}

// Decode unmarshals the payload.
func (m *Message) Decode(v any) error {
	if len(m.Data) == 0 {
		return fmt.Errorf("tunnelproto: %s message has no data", m.Type)
	}
	return json.Unmarshal(m.Data, v)
}

// Config is the complete configuration of one device (协议.md §5). It always replaces the previous one.
type Config struct {
	Rev              int64    `json:"rev"`
	Tunnels          []Tunnel `json:"tunnels"`
	CanRequest       bool     `json:"canRequest"`
	MinClientVersion string   `json:"minClientVersion,omitempty"`
	// Direct, when set, offers a faster path that bypasses the reverse proxy (协议.md §4.5).
	Direct *DirectEndpoint `json:"direct,omitempty"`
}

// DirectEndpoint is the server's direct TLS listener. Its certificate is self-signed; the device
// pins CertSHA256, which it learned over an already authenticated session.
type DirectEndpoint struct {
	// Addr is host:port to dial.
	Addr string `json:"addr"`
	// CertSHA256 is the lowercase hex SHA-256 of the leaf certificate (DER).
	CertSHA256 string `json:"certSha256"`
}

// Tunnel is what a device needs to know about one of its tunnels.
type Tunnel struct {
	ID             string      `json:"id"`
	Name           string      `json:"name"`
	Type           string      `json:"type"`
	PublicURL      string      `json:"publicUrl"`
	LocalIP        string      `json:"localIp"`
	LocalPort      int         `json:"localPort"`
	Enabled        bool        `json:"enabled"`
	PausedByClient bool        `json:"pausedByClient"`
	ExpiresAt      *time.Time  `json:"expiresAt,omitempty"`
	Permissions    Permissions `json:"permissions"`
	Display        Display     `json:"display"`
}

// Active reports whether the device should accept data streams for this tunnel.
func (t *Tunnel) Active(now time.Time) bool {
	return t.Enabled && !t.PausedByClient && (t.ExpiresAt == nil || now.Before(*t.ExpiresAt))
}

// Permissions says what the device may change itself.
type Permissions struct {
	EditLocal    bool `json:"editLocal"`
	LoopbackOnly bool `json:"loopbackOnly"`
	Toggle       bool `json:"toggle"`
}

// Display carries read-only, human-readable policy summaries for the GUI.
type Display struct {
	AccessPolicy string `json:"accessPolicy,omitempty"`
	Limits       string `json:"limits,omitempty"`
}

// Notice is a message for the user.
type Notice struct {
	Level string `json:"level"`
	Text  string `json:"text"`
}

// Tunnel states reported in Status.
const (
	StateRunning = "running"
	StatePaused  = "paused"
	StateError   = "error"
)

// Status reports the local state of a tunnel.
type Status struct {
	TunnelID string `json:"tunnelId"`
	State    string `json:"state"`
	Error    string `json:"error,omitempty"`
}

// Stats reports traffic since the previous report.
type Stats struct {
	TunnelID string `json:"tunnelId"`
	BytesIn  int64  `json:"bytesIn"`
	BytesOut int64  `json:"bytesOut"`
	Conns    int    `json:"conns"`
}

// TunnelUpdate changes what the permissions allow; nil fields are left alone.
type TunnelUpdate struct {
	TunnelID       string  `json:"tunnelId"`
	LocalIP        *string `json:"localIp,omitempty"`
	LocalPort      *int    `json:"localPort,omitempty"`
	PausedByClient *bool   `json:"pausedByClient,omitempty"`
}

// TunnelRequest asks the administrator for a new tunnel.
type TunnelRequest struct {
	Type      string `json:"type"`
	Subdomain string `json:"subdomain,omitempty"`
	LocalIP   string `json:"localIp"`
	LocalPort int    `json:"localPort"`
	Duration  string `json:"duration,omitempty"`
	Reason    string `json:"reason,omitempty"`
}

// Result answers a request that carried an id.
type Result struct {
	OK    bool   `json:"ok"`
	Error string `json:"error,omitempty"`
}

// Control is the newline-delimited JSON codec on the control stream. Send is safe for concurrent
// use; Recv must be called from one goroutine.
type Control struct {
	rwc io.ReadWriteCloser
	r   *bufio.Reader
	mu  sync.Mutex
}

// NewControl wraps the control stream.
func NewControl(rwc io.ReadWriteCloser) *Control {
	return &Control{rwc: rwc, r: bufio.NewReaderSize(rwc, 64<<10)}
}

// Send writes one message.
func (c *Control) Send(typ, id string, data any) error {
	m := Message{Type: typ, ID: id}
	if data != nil {
		raw, err := json.Marshal(data)
		if err != nil {
			return err
		}
		m.Data = raw
	}
	line, err := json.Marshal(m)
	if err != nil {
		return err
	}
	if len(line) >= maxControlMessage {
		return errors.New("tunnelproto: control message too large")
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	_, err = c.rwc.Write(append(line, '\n'))
	return err
}

// ErrMessageTooLarge means the peer sent a control line over the limit; the stream is unusable.
var ErrMessageTooLarge = errors.New("tunnelproto: control message too large")

// Recv reads one message.
func (c *Control) Recv() (*Message, error) {
	return readMessage(c.r)
}

func readMessage(r *bufio.Reader) (*Message, error) {
	var line []byte
	for {
		chunk, err := r.ReadSlice('\n')
		line = append(line, chunk...)
		if len(line) > maxControlMessage {
			return nil, ErrMessageTooLarge
		}
		if err == nil {
			break
		}
		if !errors.Is(err, bufio.ErrBufferFull) {
			if err == io.EOF && len(line) > 0 {
				return nil, io.ErrUnexpectedEOF
			}
			return nil, err
		}
	}
	var m Message
	if err := json.Unmarshal(line, &m); err != nil {
		return nil, fmt.Errorf("tunnelproto: bad control message: %w", err)
	}
	if m.Type == "" {
		return nil, errors.New("tunnelproto: control message without type")
	}
	return &m, nil
}

// Close closes the underlying stream.
func (c *Control) Close() error { return c.rwc.Close() }
