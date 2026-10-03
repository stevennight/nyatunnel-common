package deeplink

import (
	"errors"
	"reflect"
	"strings"
	"testing"
)

func TestParseValid(t *testing.T) {
	cases := []struct {
		raw  string
		want any
	}{
		{"nyatunnel://enroll?v=1&s=tunnel.example.net&c=K7QP-3XMD", &Enroll{Server: "tunnel.example.net", Code: "K7QP-3XMD"}},
		{"nyatunnel://enroll/?v=1&s=Tunnel.Example.NET:8443&c=k7qp3xmd", &Enroll{Server: "tunnel.example.net:8443", Code: "K7QP-3XMD"}},
		{"NYATUNNEL://ENROLL?v=1&s=tunnel.example.net:443&c=K7QP-3XMD", &Enroll{Server: "tunnel.example.net", Code: "K7QP-3XMD"}},
		{"nyatunnel:enroll?v=1&s=10.0.0.2&c=K7QP-3XMD", &Enroll{Server: "10.0.0.2", Code: "K7QP-3XMD"}},
		{"nyatunnel://open?s=tunnel.example.net&t=tun_01J9X4", &Open{Server: "tunnel.example.net", TunnelID: "tun_01J9X4"}},
	}
	for _, c := range cases {
		got, err := Parse(c.raw)
		if err != nil {
			t.Errorf("Parse(%q): %v", c.raw, err)
			continue
		}
		if !reflect.DeepEqual(got, c.want) {
			t.Errorf("Parse(%q) = %#v, want %#v", c.raw, got, c.want)
		}
	}
}

func TestParseRejects(t *testing.T) {
	for _, raw := range []string{
		"https://tunnel.example.net/enroll?v=1&s=tunnel.example.net&c=K7QP-3XMD", // wrong scheme
		"nyatunnel://config?v=1&s=tunnel.example.net&data=xxx",                   // links never carry configuration
		"nyatunnel://enroll?v=2&s=tunnel.example.net&c=K7QP-3XMD",                // unknown version
		"nyatunnel://enroll?s=tunnel.example.net&c=K7QP-3XMD",                    // missing version
		"nyatunnel://enroll?v=1&s=tunnel.example.net&c=K7QP-3XMD&token=abc",      // extra parameter
		"nyatunnel://enroll?v=1&s=a.example&s=b.example&c=K7QP-3XMD",             // repeated parameter
		"nyatunnel://enroll?v=1&s=https://evil.example&c=K7QP-3XMD",              // scheme in server
		"nyatunnel://enroll?v=1&s=evil.example/path&c=K7QP-3XMD",                 // path in server
		"nyatunnel://enroll?v=1&s=user@evil.example&c=K7QP-3XMD",                 // credentials in server
		"nyatunnel://enroll?v=1&s=tunnel.example.net:0&c=K7QP-3XMD",              // bad port
		"nyatunnel://enroll?v=1&s=tunnel.example.net&c=K7QP-3XM",                 // short code
		"nyatunnel://enroll?v=1&s=tunnel.example.net&c=K7QP-3XMO",                // ambiguous letter O
		"nyatunnel://enroll/extra?v=1&s=tunnel.example.net&c=K7QP-3XMD",          // unexpected path
		"nyatunnel://open?s=tunnel.example.net&t=../../etc",                      // bad tunnel id
	} {
		if _, err := Parse(raw); !errors.Is(err, ErrInvalid) {
			t.Errorf("Parse(%q) error = %v, want ErrInvalid", raw, err)
		}
	}
}

func TestNewCodeRoundTrips(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 200; i++ {
		c, err := NewCode()
		if err != nil {
			t.Fatal(err)
		}
		n, err := NormalizeCode(strings.ToLower(strings.ReplaceAll(c, "-", "")))
		if err != nil || n != c {
			t.Fatalf("NormalizeCode(%q) = %q, %v", c, n, err)
		}
		seen[c] = true
	}
	if len(seen) < 199 {
		t.Fatalf("codes repeat: %d unique of 200", len(seen))
	}
}

func TestEnrollURLParses(t *testing.T) {
	host, err := ServerHost("https://Tunnel.Example.com:443/")
	if err != nil || host != "tunnel.example.com" {
		t.Fatalf("ServerHost = %q, %v", host, err)
	}
	got, err := Parse(EnrollURL(host, "K7QP-3XMD"))
	if err != nil {
		t.Fatal(err)
	}
	if e := got.(*Enroll); e.Server != host || e.Code != "K7QP-3XMD" {
		t.Fatalf("round trip: %#v", e)
	}
	if _, err := ServerHost("ftp://x"); err == nil {
		t.Fatal("ServerHost accepted a non-HTTP URL")
	}
}
