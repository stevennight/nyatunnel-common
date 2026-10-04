package tunnelproto

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

// StreamHeader opens every data stream (协议.md §4.4). It never carries the local target: the device
// looks it up in its current Config and only dials targets its owner confirmed on the device
// (协议.md §4.6), so not even a compromised server can make a device dial arbitrary addresses.
type StreamHeader struct {
	TunnelID   string `json:"tunnelId"`
	Proto      string `json:"proto"` // "tcp" (also used for HTTPS tunnels) or "udp"
	RemoteAddr string `json:"remoteAddr,omitempty"`
}

// StreamReply is the one byte a device answers a StreamHeader with, before any payload.
type StreamReply byte

const (
	ReplyOK            StreamReply = 0
	ReplyUnknownTunnel StreamReply = 1 // not in the device's config
	ReplyInactive      StreamReply = 2 // paused, disabled or expired on the device
	ReplyDialFailed    StreamReply = 3 // the local service did not accept the connection
	ReplyForbidden     StreamReply = 4 // the local target violates the tunnel's permissions
	ReplyUnconfirmed   StreamReply = 5 // the device owner has not confirmed this tunnel's local target
)

func (r StreamReply) Error() string {
	switch r {
	case ReplyOK:
		return "ok"
	case ReplyUnknownTunnel:
		return "tunnel unknown to the device"
	case ReplyInactive:
		return "tunnel inactive on the device"
	case ReplyDialFailed:
		return "local service unreachable"
	case ReplyForbidden:
		return "local target not allowed"
	case ReplyUnconfirmed:
		return "tunnel not confirmed on the device"
	default:
		return fmt.Sprintf("stream reply %d", byte(r))
	}
}

const maxStreamHeader = 4 << 10

// WriteStreamHeader writes a 2-byte big-endian length followed by the JSON header.
func WriteStreamHeader(w io.Writer, h StreamHeader) error {
	b, err := json.Marshal(h)
	if err != nil {
		return err
	}
	if len(b) > maxStreamHeader {
		return errors.New("tunnelproto: stream header too large")
	}
	buf := make([]byte, 2+len(b))
	binary.BigEndian.PutUint16(buf, uint16(len(b)))
	copy(buf[2:], b)
	_, err = w.Write(buf)
	return err
}

// ReadStreamHeader reads what WriteStreamHeader wrote.
func ReadStreamHeader(r io.Reader) (StreamHeader, error) {
	var h StreamHeader
	var n [2]byte
	if _, err := io.ReadFull(r, n[:]); err != nil {
		return h, err
	}
	size := int(binary.BigEndian.Uint16(n[:]))
	if size == 0 || size > maxStreamHeader {
		return h, fmt.Errorf("tunnelproto: bad stream header length %d", size)
	}
	b := make([]byte, size)
	if _, err := io.ReadFull(r, b); err != nil {
		return h, err
	}
	if err := json.Unmarshal(b, &h); err != nil {
		return h, fmt.Errorf("tunnelproto: bad stream header: %w", err)
	}
	if h.TunnelID == "" || (h.Proto != "tcp" && h.Proto != "udp") {
		return h, errors.New("tunnelproto: incomplete stream header")
	}
	return h, nil
}

// WriteStreamReply sends the device's verdict on a stream.
func WriteStreamReply(w io.Writer, r StreamReply) error {
	_, err := w.Write([]byte{byte(r)})
	return err
}

// ReadStreamReply returns nil for ReplyOK, the StreamReply itself for a refusal, or a read error.
func ReadStreamReply(r io.Reader) error {
	var b [1]byte
	if _, err := io.ReadFull(r, b[:]); err != nil {
		return err
	}
	if StreamReply(b[0]) == ReplyOK {
		return nil
	}
	return StreamReply(b[0])
}

// MaxDatagram is the largest UDP payload carried on a stream.
const MaxDatagram = 65535

// WriteDatagram frames one UDP payload with a 2-byte big-endian length.
func WriteDatagram(w io.Writer, p []byte) error {
	if len(p) > MaxDatagram {
		return errors.New("tunnelproto: datagram too large")
	}
	buf := make([]byte, 2+len(p))
	binary.BigEndian.PutUint16(buf, uint16(len(p)))
	copy(buf[2:], p)
	_, err := w.Write(buf)
	return err
}

// ReadDatagram reads one framed payload into buf (which must hold MaxDatagram bytes) and returns it.
func ReadDatagram(r io.Reader, buf []byte) ([]byte, error) {
	var n [2]byte
	if _, err := io.ReadFull(r, n[:]); err != nil {
		return nil, err
	}
	size := int(binary.BigEndian.Uint16(n[:]))
	if size > len(buf) {
		return nil, errors.New("tunnelproto: datagram buffer too small")
	}
	if _, err := io.ReadFull(r, buf[:size]); err != nil {
		return nil, err
	}
	return buf[:size], nil
}
