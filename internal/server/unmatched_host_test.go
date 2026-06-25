package server

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/cadi-sh/cadish/internal/config"
)

// twoSiteCfg has two explicit sites so the lenient single-site fallback does NOT apply: an
// unmatched Host has no site (the GW-P1 / strict_host=off, multi-site case).
const twoSiteCfg = `a.example.com {
	upstream backend { to http://127.0.0.1:9 }
	respond / 200 "a"
}
b.example.com {
	upstream backend { to http://127.0.0.1:9 }
	respond / 200 "b"
}
`

func loadTwoSite(t *testing.T) *config.Config {
	t.Helper()
	cfg, err := config.LoadString("<test>", twoSiteCfg)
	if err != nil {
		t.Fatalf("load config: %v", err)
	}
	t.Cleanup(func() { _ = cfg.Close() })
	return cfg
}

func reqHost(h *Handler, host string) *httptest.ResponseRecorder {
	req := httptest.NewRequest("GET", "http://"+host+"/", nil)
	req.Host = host
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

// TestUnmatchedHostDefault502 (GW-P1 control): the CORE server's behavior is unchanged — an
// unmatched Host (no site, strict_host off) still returns 502. Options.UnmatchedHostStatus
// is unset (0 ⇒ default).
func TestUnmatchedHostDefault502(t *testing.T) {
	cfg := loadTwoSite(t)
	h := NewHandler(cfg, Options{Logger: discardLogger()})
	t.Cleanup(h.Shutdown)

	rec := reqHost(h, "nope.example.com")
	if rec.Code != http.StatusBadGateway {
		t.Fatalf("core server: unmatched host status = %d, want 502 (unchanged)", rec.Code)
	}
}

// TestUnmatchedHostGateway404 (GW-P1): the gateway data plane opts into a 404 for an
// unmatched Host via Options.UnmatchedHostStatus, WITHOUT changing the core default.
func TestUnmatchedHostGateway404(t *testing.T) {
	cfg := loadTwoSite(t)
	h := NewHandler(cfg, Options{Logger: discardLogger(), UnmatchedHostStatus: http.StatusNotFound})
	t.Cleanup(h.Shutdown)

	rec := reqHost(h, "nope.example.com")
	if rec.Code != http.StatusNotFound {
		t.Fatalf("gateway data plane: unmatched host status = %d, want 404", rec.Code)
	}

	// A declared host still serves normally.
	if rec := reqHost(h, "a.example.com"); rec.Code != http.StatusOK {
		t.Fatalf("declared host a.example.com status = %d, want 200", rec.Code)
	}
}
