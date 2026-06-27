package server

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/cadi-sh/cadish/internal/config"
)

// cfgReadyzDeny denies every request from the default httptest client IP (192.0.2.1) so
// any NORMAL request is blocked at the security gate (403, never reaching origin). The
// reserved /.cadish/readyz probe must be intercepted ABOVE that gate, so it answers
// regardless.
const cfgReadyzDeny = `test.local {
	cache { ram 64MiB }
	upstream backend { to %s }
	@banned ip 192.0.2.1/32
	deny @banned
	cache_ttl default ttl 60s
}
`

// reqTo builds a request with an explicit method/host/path against the handler.
func readyzReq(method, host, path string) *http.Request {
	r := httptest.NewRequest(method, "http://"+host+path, nil)
	r.Host = host
	return r
}

// TestReadyzWarmGate is the core warm-readiness contract: /.cadish/readyz returns 503
// before MarkWarm and 200 after, with the documented tiny bodies + Content-Type, and the
// origin is never touched either way.
func TestReadyzWarmGate(t *testing.T) {
	origin := newCountingOrigin(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("origin"))
	})
	h, _ := buildHandler(t, nil, cfgReadyzDeny, origin.srv.URL)

	// Before MarkWarm: 503 warming.
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, readyzReq("GET", "test.local", readyzPath))
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("cold readyz: got %d, want 503", rec.Code)
	}
	if rec.Body.String() != "warming\n" {
		t.Fatalf("cold readyz body = %q, want %q", rec.Body.String(), "warming\n")
	}
	if ct := rec.Header().Get("Content-Type"); ct != "text/plain; charset=utf-8" {
		t.Fatalf("cold readyz Content-Type = %q", ct)
	}

	// Flip the warm flag (Server.MarkWarm does exactly this via s.handler.warm).
	h.warm.Store(true)

	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, readyzReq("GET", "test.local", readyzPath))
	if rec.Code != http.StatusOK {
		t.Fatalf("warm readyz: got %d, want 200", rec.Code)
	}
	if rec.Body.String() != "ok\n" {
		t.Fatalf("warm readyz body = %q, want %q", rec.Body.String(), "ok\n")
	}

	if origin.hits.Load() != 0 {
		t.Fatalf("readyz reached origin %d times, want 0", origin.hits.Load())
	}
}

// TestReadyzInterceptedBeforeRoutingAndACL proves the probe is handled at the very top of
// ServeHTTP: it answers even for a Host that matches NO site (a normal such request is
// 421/502), it is NOT blocked by the `ip` deny ACL that blocks normal traffic, and it
// never reaches an origin. It also works for any method.
func TestReadyzInterceptedBeforeRoutingAndACL(t *testing.T) {
	origin := newCountingOrigin(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("origin"))
	})
	h, _ := buildHandler(t, nil, cfgReadyzDeny, origin.srv.URL)
	h.warm.Store(true)

	// Sanity: a NORMAL request from the default IP is denied by the ip ACL (403),
	// confirming the gate is active for ordinary traffic.
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, readyzReq("GET", "test.local", "/index.html"))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("normal request: got %d, want 403 (ip deny active)", rec.Code)
	}

	// readyz answers 200 for ANY method and ANY Host (including an unmatched Host that a
	// normal request would 421/502), and is unaffected by the deny ACL.
	for _, method := range []string{"GET", "HEAD", "POST", "PUT", "DELETE", "OPTIONS"} {
		for _, host := range []string{"test.local", "no-such-host.invalid", "10.0.0.5"} {
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, readyzReq(method, host, readyzPath))
			if rec.Code != http.StatusOK {
				t.Fatalf("readyz %s host=%q: got %d, want 200 (intercepted before routing/ACL)", method, host, rec.Code)
			}
		}
	}

	if origin.hits.Load() != 0 {
		t.Fatalf("readyz reached origin %d times, want 0", origin.hits.Load())
	}
}

// TestServerMarkWarmFlipsReadyz exercises the public Server.MarkWarm seam end-to-end via
// the Server's own Handler: cold → 503, MarkWarm → 200, and a second MarkWarm is a no-op.
func TestServerMarkWarmFlipsReadyz(t *testing.T) {
	origin := newCountingOrigin(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("origin"))
	})
	cfg := fmt.Sprintf(`a.test {
	cache { ram 64MiB }
	upstream u { to %s }
	cache_ttl default ttl 60s
}
`, origin.srv.URL)
	loaded, err := config.LoadString("<base>", cfg)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	srv, err := NewServer(loaded, "127.0.0.1:0", Options{Logger: discardLogger()})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
	})

	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, readyzReq("GET", "a.test", readyzPath))
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("cold server readyz: got %d, want 503", rec.Code)
	}

	srv.MarkWarm()
	srv.MarkWarm() // idempotent

	rec = httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, readyzReq("GET", "a.test", readyzPath))
	if rec.Code != http.StatusOK {
		t.Fatalf("warm server readyz: got %d, want 200", rec.Code)
	}
}
