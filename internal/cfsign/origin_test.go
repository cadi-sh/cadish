package cfsign

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/cadi-sh/cadish/internal/origin"
)

func testSigner(t *testing.T, base string) *Signer {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	s, err := New(base, "K-TEST", key)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// TestOriginSignsOutgoingRequest verifies that a Fetch through the signing origin
// reaches the backend with the CloudFront canned-policy query params and the
// expected path.
func TestOriginSignsOutgoingRequest(t *testing.T) {
	var gotURL *url.URL
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotURL = r.URL
		_, _ = io.WriteString(w, "object-bytes")
	}))
	defer srv.Close()

	o := NewOrigin(testSigner(t, srv.URL), 5*time.Minute)
	resp, err := o.Fetch(context.Background(), &origin.Request{Key: "media/clip.mp4"})
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if string(body) != "object-bytes" {
		t.Errorf("body = %q", body)
	}
	if gotURL == nil {
		t.Fatal("origin never received the request")
	}
	if gotURL.Path != "/media/clip.mp4" {
		t.Errorf("path = %q, want /media/clip.mp4", gotURL.Path)
	}
	q := gotURL.Query()
	for _, p := range []string{"Expires", "Signature", "Key-Pair-Id"} {
		if q.Get(p) == "" {
			t.Errorf("outgoing request missing %s param (query=%q)", p, gotURL.RawQuery)
		}
	}
	if q.Get("Key-Pair-Id") != "K-TEST" {
		t.Errorf("Key-Pair-Id = %q, want K-TEST", q.Get("Key-Pair-Id"))
	}
}

// TestOriginExpiryUsesClock verifies the signed Expires reflects now+ttl.
func TestOriginExpiryUsesClock(t *testing.T) {
	var gotExpires string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotExpires = r.URL.Query().Get("Expires")
	}))
	defer srv.Close()

	fixed := time.Unix(1_700_000_000, 0)
	o := NewOrigin(testSigner(t, srv.URL), 10*time.Minute, WithClock(func() time.Time { return fixed }))
	resp, err := o.Fetch(context.Background(), &origin.Request{Key: "x"})
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	want := fixed.Add(10 * time.Minute).Unix()
	if gotExpires != "1700000600" {
		t.Errorf("Expires = %q, want %d (now+ttl)", gotExpires, want)
	}
}

// TestOriginStatusMapping verifies 404 -> ErrNotFound and other 4xx -> StatusError.
func TestOriginStatusMapping(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/missing":
			w.WriteHeader(http.StatusNotFound)
		default:
			w.WriteHeader(http.StatusForbidden)
		}
	}))
	defer srv.Close()
	o := NewOrigin(testSigner(t, srv.URL), time.Minute)

	if _, err := o.Fetch(context.Background(), &origin.Request{Key: "missing"}); !errors.Is(err, origin.ErrNotFound) {
		t.Errorf("404 -> %v, want ErrNotFound", err)
	}
	_, err := o.Fetch(context.Background(), &origin.Request{Key: "denied"})
	var se *origin.StatusError
	if !errors.As(err, &se) || se.Status != http.StatusForbidden {
		t.Errorf("403 -> %v, want *StatusError{403}", err)
	}
}
