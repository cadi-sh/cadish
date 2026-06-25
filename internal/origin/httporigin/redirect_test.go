package httporigin

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/cadi-sh/cadish/internal/origin"
)

// TestNoFollowRedirect verifies the SSRF guard (security review #1): a 30x from the
// origin is NOT followed — it is returned as a passthrough Response with its status
// and Location intact, and the redirect target is never dialed.
func TestNoFollowRedirect(t *testing.T) {
	var targetHits atomic.Int64
	// The forbidden redirect target — must never be fetched.
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		targetHits.Add(1)
		_, _ = io.WriteString(w, "INTERNAL-SECRET")
	}))
	defer target.Close()

	redirector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", target.URL+"/metadata")
		w.WriteHeader(http.StatusFound) // 302
		_, _ = io.WriteString(w, "moved")
	}))
	defer redirector.Close()

	o, err := New(redirector.URL)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := o.Fetch(context.Background(), &origin.Request{Key: "x"})
	if err != nil {
		t.Fatalf("Fetch returned error %v, want a passthrough 302 Response", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("StatusCode = %d, want 302", resp.StatusCode)
	}
	if loc := resp.Header.Get("Location"); loc == "" {
		t.Fatal("Location header not passed through")
	}
	if targetHits.Load() != 0 {
		t.Fatalf("redirect target was dialed %d times — SSRF guard failed", targetHits.Load())
	}
}
