package tunnelproto

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestPinnedTLS(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("ok")) }))
	defer srv.Close()
	pin := CertSHA256(srv.Certificate().Raw)
	get := func(pin string) error {
		c := &http.Client{Transport: &http.Transport{TLSClientConfig: PinnedTLS(pin)}}
		resp, err := c.Get(srv.URL)
		if err == nil {
			resp.Body.Close()
		}
		return err
	}
	if err := get(strings.ToUpper(pin)); err != nil {
		t.Fatalf("matching pin refused: %v", err)
	}
	if err := get(strings.Repeat("0", 64)); err == nil {
		t.Fatal("wrong pin accepted")
	}
}
