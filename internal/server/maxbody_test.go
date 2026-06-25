package server

import (
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/cadi-sh/cadish/internal/config"
)

// buildHandlerOpts is buildHandler but lets the test pass extra Options (the body
// cap). It mirrors buildHandler's config splicing.
func buildHandlerOpts(t *testing.T, body, originURL string, opts Options) *Handler {
	t.Helper()
	dir := t.TempDir()
	path := dir + "/Cadishfile"
	cfgText := strings.Replace(body, "%s", originURL, 1)
	if err := writeFile(path, cfgText); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("load config: %v\n%s", err, cfgText)
	}
	t.Cleanup(func() { _ = cfg.Close() })
	if opts.Logger == nil {
		opts.Logger = discardLogger()
	}
	h := NewHandler(cfg, opts)
	t.Cleanup(h.Shutdown)
	return h
}

func writeFile(path, content string) error {
	return os.WriteFile(path, []byte(content), 0o644)
}

const echoOriginCfg = `test.local {
	cache { ram 8MiB }
	upstream b { to %s }
	cache_ttl default ttl 60s
}
`

// TestMaxRequestBody_CapsOversizedUpload verifies that with MaxRequestBodyBytes set,
// a POST body larger than the cap is rejected (the origin never receives a full
// body), while a body within the cap is forwarded intact.
func TestMaxRequestBody_CapsOversizedUpload(t *testing.T) {
	var received atomic.Int64
	origin := newCountingOrigin(t, func(w http.ResponseWriter, r *http.Request) {
		n, _ := io.Copy(io.Discard, r.Body)
		received.Store(n)
		w.WriteHeader(http.StatusOK)
	})

	h := buildHandlerOpts(t, echoOriginCfg, origin.srv.URL, Options{MaxRequestBodyBytes: 1024})

	// Within the cap: forwarded intact.
	small := strings.Repeat("x", 512)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "http://test.local/upload", strings.NewReader(small))
	req.Host = "test.local"
	h.ServeHTTP(rec, req)
	if got := received.Load(); got != 512 {
		t.Errorf("small upload: origin received %d bytes, want 512", got)
	}

	// Over the cap: the origin must NOT receive the full body (MaxBytesReader errors
	// the copy partway, so the relayed body is short / the request fails).
	received.Store(0)
	big := strings.Repeat("y", 4096)
	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "http://test.local/upload", strings.NewReader(big))
	req.Host = "test.local"
	h.ServeHTTP(rec, req)
	if got := received.Load(); got >= 4096 {
		t.Errorf("oversized upload was relayed in full (%d bytes) — cap not enforced", got)
	}
}

// TestMaxRequestBody_DefaultUnlimited verifies the DEFAULT (knob unset / 0): a large
// body is streamed through to origin in full — the media-proxy use case is not
// broken.
func TestMaxRequestBody_DefaultUnlimited(t *testing.T) {
	var received atomic.Int64
	origin := newCountingOrigin(t, func(w http.ResponseWriter, r *http.Request) {
		n, _ := io.Copy(io.Discard, r.Body)
		received.Store(n)
		w.WriteHeader(http.StatusOK)
	})

	h := buildHandlerOpts(t, echoOriginCfg, origin.srv.URL, Options{}) // no cap

	const size = 5 << 20 // 5 MiB
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "http://test.local/upload", strings.NewReader(strings.Repeat("z", size)))
	req.Host = "test.local"
	h.ServeHTTP(rec, req)
	if got := received.Load(); got != size {
		t.Errorf("default-unlimited: origin received %d bytes, want %d", got, size)
	}
}
