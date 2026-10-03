// Package deeplink builds and parses nyatunnel:// links and the one-time enroll codes they carry
// (see nyatunnel-server/docs/协议.md §2).
//
// Any web page can open a nyatunnel:// link, so parsing is strict: unknown actions,
// unknown versions and unexpected parameters are rejected rather than ignored, and a
// parsed link never changes state by itself; the caller must ask the user to confirm.
package deeplink

import (
	"crypto/rand"
	"errors"
	"fmt"
	"net"
	"net/url"
	"regexp"
	"strconv"
	"strings"
)

// Scheme is the URL scheme registered with the operating system.
const Scheme = "nyatunnel"

// Version is the only enroll link version this client understands.
const Version = "1"

// Enroll asks the user to register this device with Server using a one-time Code.
type Enroll struct {
	// Server is a host name with an optional port; the client always talks HTTPS to it.
	Server string
	// Code is the normalised one-time code, e.g. "K7QP-3XMD".
	Code string
}

// Open asks the client to show a tunnel; it is ignored when Server is not the enrolled server.
type Open struct {
	Server   string
	TunnelID string
}

// ErrInvalid wraps every parse failure.
var ErrInvalid = errors.New("invalid nyatunnel link")

var (
	// Crockford Base32 without the ambiguous I, L, O and U, as 4+4 characters.
	codeRE     = regexp.MustCompile(`^[0-9A-HJKMNP-TV-Z]{4}-?[0-9A-HJKMNP-TV-Z]{4}$`)
	tunnelIDRE = regexp.MustCompile(`^tun_[0-9A-Za-z]{1,64}$`)
	hostRE     = regexp.MustCompile(`^[0-9A-Za-z]([0-9A-Za-z-]{0,61}[0-9A-Za-z])?(\.[0-9A-Za-z]([0-9A-Za-z-]{0,61}[0-9A-Za-z])?)*$`)
)

// Parse returns an *Enroll or an *Open.
func Parse(raw string) (any, error) {
	if len(raw) > 2048 {
		return nil, invalid("link is too long")
	}
	u, err := url.Parse(raw)
	if err != nil {
		return nil, invalid("%v", err)
	}
	if !strings.EqualFold(u.Scheme, Scheme) {
		return nil, invalid("scheme %q", u.Scheme)
	}
	// nyatunnel://enroll?… puts the action in Host; tolerate nyatunnel:enroll?… and a trailing slash.
	action := strings.ToLower(u.Host)
	if action == "" {
		action = strings.ToLower(strings.TrimPrefix(u.Opaque, "//"))
	}
	if p := strings.Trim(u.Path, "/"); p != "" {
		return nil, invalid("unexpected path %q", u.Path)
	}
	q, err := url.ParseQuery(u.RawQuery)
	if err != nil {
		return nil, invalid("%v", err)
	}

	switch action {
	case "enroll":
		if err := onlyKeys(q, "v", "s", "c"); err != nil {
			return nil, err
		}
		if v := q.Get("v"); v != Version {
			return nil, invalid("unsupported link version %q, please update NyaTunnel", v)
		}
		server, err := parseServer(q.Get("s"))
		if err != nil {
			return nil, err
		}
		code, err := NormalizeCode(q.Get("c"))
		if err != nil {
			return nil, err
		}
		return &Enroll{Server: server, Code: code}, nil
	case "open":
		if err := onlyKeys(q, "s", "t"); err != nil {
			return nil, err
		}
		server, err := parseServer(q.Get("s"))
		if err != nil {
			return nil, err
		}
		id := q.Get("t")
		if !tunnelIDRE.MatchString(id) {
			return nil, invalid("tunnel id %q", id)
		}
		return &Open{Server: server, TunnelID: id}, nil
	default:
		return nil, invalid("unknown action %q", action)
	}
}

// EnrollURL builds the link the admin console shows for a new enroll code.
func EnrollURL(server, code string) string {
	q := url.Values{}
	q.Set("v", Version)
	q.Set("s", server)
	q.Set("c", code)
	return Scheme + "://enroll?" + q.Encode()
}

// ServerHost turns a public URL such as "https://tunnel.example.com/" into the host form used in
// links and signatures ("tunnel.example.com", or "host:port" for a non-default port).
func ServerHost(publicURL string) (string, error) {
	u, err := url.Parse(publicURL)
	if err != nil || u.Scheme != "https" && u.Scheme != "http" || u.Host == "" {
		return "", invalid("public URL %q", publicURL)
	}
	return parseServer(u.Host)
}

// onlyKeys rejects missing, repeated and unknown parameters.
func onlyKeys(q url.Values, keys ...string) error {
	for _, k := range keys {
		if len(q[k]) != 1 {
			return invalid("parameter %q must appear exactly once", k)
		}
	}
	if len(q) != len(keys) {
		return invalid("unexpected parameters")
	}
	return nil
}

// parseServer accepts "host" or "host:port"; schemes, paths and credentials are rejected.
func parseServer(s string) (string, error) {
	host, port := s, ""
	if h, p, err := net.SplitHostPort(s); err == nil {
		host, port = h, p
	}
	host = strings.ToLower(host)
	if net.ParseIP(host) == nil && (len(host) > 253 || !hostRE.MatchString(host)) {
		return "", invalid("server %q", s)
	}
	if port != "" {
		n, err := strconv.Atoi(port)
		if err != nil || n < 1 || n > 65535 {
			return "", invalid("server port %q", port)
		}
		if n == 443 {
			return host, nil
		}
		return net.JoinHostPort(host, port), nil
	}
	return host, nil
}

// codeAlphabet is Crockford Base32: no I, L, O or U, so codes survive being read aloud or retyped.
const codeAlphabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"

// NewCode returns a uniformly random enroll code such as "K7QP-3XMD" (40 bits).
func NewCode() (string, error) {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	out := make([]byte, 0, 9)
	for i, v := range b {
		if i == 4 {
			out = append(out, '-')
		}
		out = append(out, codeAlphabet[v&31]) // 256 is a multiple of 32, so masking keeps it uniform
	}
	return string(out), nil
}

// NormalizeCode accepts lower case, surrounding spaces and a missing dash, and returns "XXXX-XXXX".
func NormalizeCode(c string) (string, error) {
	c = strings.ToUpper(strings.TrimSpace(c))
	if !codeRE.MatchString(c) {
		return "", invalid("enroll code")
	}
	c = strings.ReplaceAll(c, "-", "")
	return c[:4] + "-" + c[4:], nil
}

func invalid(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrInvalid, fmt.Sprintf(format, args...))
}
