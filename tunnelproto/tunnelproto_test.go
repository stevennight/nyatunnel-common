package tunnelproto

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"
)

const testHost = "tunnel.example.com"

// pipeServer runs serve on the server side of a real WebSocket and returns the client side.
func pipeServer(t *testing.T, serve func(ctx context.Context, c *websocket.Conn)) *websocket.Conn {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := websocket.Accept(w, r, nil)
		if err != nil {
			t.Error(err)
			return
		}
		serve(r.Context(), c)
	}))
	t.Cleanup(srv.Close)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancel)
	c, _, err := websocket.Dial(ctx, "ws"+strings.TrimPrefix(srv.URL, "http")+ConnectPath, nil)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestHandshakeAndSession(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	serverDone := make(chan error, 1)
	c := pipeServer(t, func(ctx context.Context, c *websocket.Conn) {
		_, err := ServerHandshake(ctx, c, testHost, func(_ context.Context, h *Hello) (ed25519.PublicKey, error) {
			if h.DeviceID != "dev_1" {
				return nil, ErrUnauthorized
			}
			return pub, nil
		})
		if err != nil {
			serverDone <- err
			return
		}
		if err := SendWelcome(ctx, c, Welcome{SessionID: "s1", Features: []string{"x"}}); err != nil {
			serverDone <- err
			return
		}
		sess, err := ServerSession(ctx, c)
		if err != nil {
			serverDone <- err
			return
		}
		ctl, err := sess.Accept()
		if err != nil {
			serverDone <- err
			return
		}
		control := NewControl(ctl)
		if err := control.Send(TypeConfig, "", Config{Rev: 7, Tunnels: []Tunnel{{ID: "tun_a", Type: TunnelTCP}}}); err != nil {
			serverDone <- err
			return
		}
		data, err := sess.Open()
		if err != nil {
			serverDone <- err
			return
		}
		if err := WriteStreamHeader(data, StreamHeader{TunnelID: "tun_a", Proto: "tcp", RemoteAddr: "1.2.3.4:5"}); err != nil {
			serverDone <- err
			return
		}
		if err := ReadStreamReply(data); err != nil {
			serverDone <- err
			return
		}
		_, err = data.Write([]byte("ping"))
		buf := make([]byte, 4)
		if err == nil {
			_, err = io.ReadFull(data, buf)
		}
		if err == nil && string(buf) != "pong" {
			err = errors.New("unexpected payload " + string(buf))
		}
		serverDone <- err
		<-ctx.Done()
	})

	ctx := context.Background()
	w, err := ClientHandshake(ctx, c, testHost, Hello{DeviceID: "dev_1", ClientVersion: "test"}, priv)
	if err != nil {
		t.Fatal(err)
	}
	if w.SessionID != "s1" || !HasFeature(w.Features, "x") {
		t.Fatalf("welcome: %+v", w)
	}
	sess, err := ClientSession(ctx, c)
	if err != nil {
		t.Fatal(err)
	}
	defer sess.Close()
	ctl, err := sess.Open()
	if err != nil {
		t.Fatal(err)
	}
	m, err := NewControl(ctl).Recv()
	if err != nil {
		t.Fatal(err)
	}
	var cfg Config
	if err := m.Decode(&cfg); err != nil || m.Type != TypeConfig || cfg.Rev != 7 {
		t.Fatalf("config: %+v %v", m, err)
	}
	data, err := sess.Accept()
	if err != nil {
		t.Fatal(err)
	}
	h, err := ReadStreamHeader(data)
	if err != nil || h.TunnelID != "tun_a" || h.RemoteAddr != "1.2.3.4:5" {
		t.Fatalf("header: %+v %v", h, err)
	}
	if err := WriteStreamReply(data, ReplyOK); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 4)
	if _, err := io.ReadFull(data, buf); err != nil || string(buf) != "ping" {
		t.Fatalf("payload %q %v", buf, err)
	}
	if _, err := data.Write([]byte("pong")); err != nil {
		t.Fatal(err)
	}
	if err := <-serverDone; err != nil {
		t.Fatal(err)
	}
}

func TestHandshakeRejectsWrongKey(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(nil)
	_, otherPriv, _ := ed25519.GenerateKey(nil)
	result := make(chan error, 1)
	c := pipeServer(t, func(ctx context.Context, c *websocket.Conn) {
		_, err := ServerHandshake(ctx, c, testHost, func(context.Context, *Hello) (ed25519.PublicKey, error) { return pub, nil })
		result <- err
		c.Close(CloseUnauthorized, "unauthorized")
	})
	_, err := ClientHandshake(context.Background(), c, testHost, Hello{DeviceID: "dev_1"}, otherPriv)
	if websocket.CloseStatus(err) != CloseUnauthorized {
		t.Fatalf("client error = %v, want close 4401", err)
	}
	if !errors.Is(<-result, ErrUnauthorized) {
		t.Fatal("server accepted a signature from the wrong key")
	}
}

func TestSignatureIsBoundToHostAndNonce(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	sig := Sign(priv, "A.example.com", "dev_1", "n1")
	if !Verify(pub, "a.example.com", "dev_1", "n1", sig) {
		t.Fatal("host comparison should be case-insensitive")
	}
	for _, c := range [][3]string{{"b.example.com", "dev_1", "n1"}, {"a.example.com", "dev_2", "n1"}, {"a.example.com", "dev_1", "n2"}} {
		if Verify(pub, c[0], c[1], c[2], sig) {
			t.Fatalf("signature accepted for %v", c)
		}
	}
}

func TestStreamReply(t *testing.T) {
	var b bytes.Buffer
	WriteStreamReply(&b, ReplyDialFailed)
	if err := ReadStreamReply(&b); !errors.Is(err, ReplyDialFailed) {
		t.Fatalf("got %v", err)
	}
}

func TestDatagramRoundTrip(t *testing.T) {
	var b bytes.Buffer
	for _, p := range [][]byte{{}, []byte("hello"), bytes.Repeat([]byte{7}, MaxDatagram)} {
		if err := WriteDatagram(&b, p); err != nil {
			t.Fatal(err)
		}
	}
	buf := make([]byte, MaxDatagram)
	for _, want := range []int{0, 5, MaxDatagram} {
		got, err := ReadDatagram(&b, buf)
		if err != nil || len(got) != want {
			t.Fatalf("len %d, err %v; want %d", len(got), err, want)
		}
	}
	if err := WriteDatagram(&b, make([]byte, MaxDatagram+1)); err == nil {
		t.Fatal("oversized datagram accepted")
	}
}

func TestControlRejectsOversizedLine(t *testing.T) {
	r := bufio.NewReader(strings.NewReader(`{"type":"x","data":"` + strings.Repeat("a", maxControlMessage) + "\"}\n"))
	if _, err := readMessage(r); !errors.Is(err, ErrMessageTooLarge) {
		t.Fatalf("got %v", err)
	}
}

func FuzzReadStreamHeader(f *testing.F) {
	var b bytes.Buffer
	WriteStreamHeader(&b, StreamHeader{TunnelID: "tun_a", Proto: "udp", RemoteAddr: "[::1]:53"})
	f.Add(b.Bytes())
	f.Add([]byte{0, 0})
	f.Add([]byte{0xff, 0xff, '{'})
	f.Fuzz(func(t *testing.T, in []byte) {
		h, err := ReadStreamHeader(bytes.NewReader(in))
		if err == nil && (h.TunnelID == "" || (h.Proto != "tcp" && h.Proto != "udp")) {
			t.Fatalf("accepted incomplete header %+v", h)
		}
	})
}

func FuzzReadDatagram(f *testing.F) {
	f.Add([]byte{0, 3, 'a', 'b', 'c'})
	f.Add([]byte{0xff, 0xff})
	f.Fuzz(func(t *testing.T, in []byte) {
		buf := make([]byte, MaxDatagram)
		got, err := ReadDatagram(bytes.NewReader(in), buf)
		if err == nil && len(got) > len(in)-2 {
			t.Fatalf("returned %d bytes from %d input bytes", len(got), len(in))
		}
	})
}

func FuzzControlRecv(f *testing.F) {
	f.Add([]byte(`{"type":"config","data":{"rev":1,"tunnels":[]}}` + "\n"))
	f.Add([]byte(`{"type":""}` + "\n"))
	f.Add([]byte("\n\n"))
	f.Fuzz(func(t *testing.T, in []byte) {
		m, err := readMessage(bufio.NewReader(bytes.NewReader(in)))
		if err == nil && m.Type == "" {
			t.Fatal("accepted a message without type")
		}
		if err == nil {
			var cfg Config
			_ = m.Decode(&cfg) // must not panic
		}
	})
}
