package server

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cadi-sh/cadish/internal/config"
)

// capture is a thread-safe slog.Handler that records every log record's level and
// message, so a test can assert which reload-time WARNINGs fired. ApplyConfig may log
// from a background goroutine (the old-config teardown), so access is mutex-guarded.
type capture struct {
	mu   sync.Mutex
	recs []captureRec
}

type captureRec struct {
	level slog.Level
	msg   string
	attrs map[string]string
}

func (c *capture) Enabled(context.Context, slog.Level) bool { return true }

func (c *capture) Handle(_ context.Context, r slog.Record) error {
	rec := captureRec{level: r.Level, msg: r.Message, attrs: map[string]string{}}
	r.Attrs(func(a slog.Attr) bool {
		rec.attrs[a.Key] = a.Value.String()
		return true
	})
	c.mu.Lock()
	c.recs = append(c.recs, rec)
	c.mu.Unlock()
	return nil
}

func (c *capture) WithAttrs([]slog.Attr) slog.Handler { return c }
func (c *capture) WithGroup(string) slog.Handler      { return c }

// warnsContaining returns the captured WARN records whose message contains sub.
func (c *capture) warnsContaining(sub string) []captureRec {
	c.mu.Lock()
	defer c.mu.Unlock()
	var out []captureRec
	for _, r := range c.recs {
		if r.level == slog.LevelWarn && strings.Contains(r.msg, sub) {
			out = append(out, r)
		}
	}
	return out
}

func captureLogger() (*slog.Logger, *capture) {
	c := &capture{}
	return slog.New(c), c
}

const cacheResizeMsg = "cache budget/path change is ignored until restart"
const plainTLSMsg = "the server started without a :443 listener"

// newServerForWarn loads cfgBody (with originURL spliced into the single %s) and builds a
// Server with the capturing logger. The drain grace is shrunk so the background old-config
// teardown does not delay the test.
func newServerForWarn(t *testing.T, cfgBody, originURL string) (*Server, *capture) {
	t.Helper()
	loaded, err := config.LoadString("<base>", fmt.Sprintf(cfgBody, originURL))
	if err != nil {
		t.Fatalf("load base: %v", err)
	}
	log, cap := captureLogger()
	srv, err := NewServer(loaded, "127.0.0.1:0", Options{Logger: log})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	old := reloadDrainGrace
	reloadDrainGrace = 10 * time.Millisecond
	t.Cleanup(func() { reloadDrainGrace = old })
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
	})
	return srv, cap
}

func applyString(t *testing.T, srv *Server, cfgBody, originURL string) {
	t.Helper()
	next, err := config.LoadString("<next>", fmt.Sprintf(cfgBody, originURL))
	if err != nil {
		t.Fatalf("load next: %v", err)
	}
	if err := srv.ApplyConfig(next); err != nil {
		t.Fatalf("ApplyConfig: %v", err)
	}
}

// TestReloadWarnsOnCacheRAMResize proves a reload that changes the RAM budget of a
// surviving site WARNs (the change is a no-op until restart), and names the site + diff.
func TestReloadWarnsOnCacheRAMResize(t *testing.T) {
	origin := newCountingOrigin(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("ok"))
	})
	const small = `a.test {
	cache { ram 64MiB }
	upstream u { to %s }
	cache_ttl default ttl 300s
}
`
	const big = `a.test {
	cache { ram 128MiB }
	upstream u { to %s }
	cache_ttl default ttl 300s
}
`
	srv, cap := newServerForWarn(t, small, origin.srv.URL)
	applyString(t, srv, big, origin.srv.URL)

	warns := cap.warnsContaining(cacheResizeMsg)
	if len(warns) != 1 {
		t.Fatalf("got %d cache-resize warnings, want 1: %+v", len(warns), warns)
	}
	if got := warns[0].attrs["site"]; got != "a.test" {
		t.Fatalf("warning site = %q, want a.test", got)
	}
	if got := warns[0].attrs["changed"]; !strings.Contains(got, "ram") {
		t.Fatalf("warning changed = %q, want it to mention ram budget", got)
	}
}

// TestReloadWarnsOnCacheDiskPathChange proves changing the disk PATH of a surviving site
// WARNs and names the disk_path diff.
func TestReloadWarnsOnCacheDiskPathChange(t *testing.T) {
	origin := newCountingOrigin(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("ok"))
	})
	dirA := filepath.Join(t.TempDir(), "a")
	dirB := filepath.Join(t.TempDir(), "b")
	bodyA := `a.test {
	cache { ram 64MiB; disk ` + dirA + ` 100MiB }
	upstream u { to %s }
	cache_ttl default ttl 300s
}
`
	bodyB := `a.test {
	cache { ram 64MiB; disk ` + dirB + ` 100MiB }
	upstream u { to %s }
	cache_ttl default ttl 300s
}
`
	srv, cap := newServerForWarn(t, bodyA, origin.srv.URL)
	applyString(t, srv, bodyB, origin.srv.URL)

	warns := cap.warnsContaining(cacheResizeMsg)
	if len(warns) != 1 {
		t.Fatalf("got %d cache-resize warnings, want 1: %+v", len(warns), warns)
	}
	if got := warns[0].attrs["changed"]; !strings.Contains(got, "disk_path") {
		t.Fatalf("warning changed = %q, want it to mention disk_path", got)
	}
}

// TestReloadNoWarnOnSameCacheConfig proves an UNCHANGED cache config (same ram/disk/path)
// is silent — the warning is high-signal, not fire-on-every-reload.
func TestReloadNoWarnOnSameCacheConfig(t *testing.T) {
	origin := newCountingOrigin(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("ok"))
	})
	// Same cache budget; reload changes only an unrelated thing (adds a host alias) so the
	// site still survives and its store is transplanted, but the budget is identical.
	const before = `a.test {
	cache { ram 64MiB }
	upstream u { to %s }
	cache_ttl default ttl 300s
}
`
	const after = `a.test, alias.test {
	cache { ram 64MiB }
	upstream u { to %s }
	cache_ttl default ttl 300s
}
`
	srv, cap := newServerForWarn(t, before, origin.srv.URL)
	applyString(t, srv, after, origin.srv.URL)

	if warns := cap.warnsContaining(cacheResizeMsg); len(warns) != 0 {
		t.Fatalf("got %d cache-resize warnings, want 0 (same budget): %+v", len(warns), warns)
	}
}

// TestReloadWarnsOnPlainToTLS proves a server that started PLAIN warns when reloaded to a
// config that newly declares TLS (the :443 listener is fixed at startup).
func TestReloadWarnsOnPlainToTLS(t *testing.T) {
	origin := newCountingOrigin(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("ok"))
	})
	const plain = `a.test {
	upstream u { to %s }
	cache_ttl default ttl 300s
}
`
	const withTLS = `a.test {
	tls { acme ops@example.com }
	upstream u { to %s }
	cache_ttl default ttl 300s
}
`
	srv, cap := newServerForWarn(t, plain, origin.srv.URL)
	if srv.tlsBoundAtStart {
		t.Fatal("precondition: server should have started plain")
	}
	applyString(t, srv, withTLS, origin.srv.URL)

	warns := cap.warnsContaining(plainTLSMsg)
	if len(warns) != 1 {
		t.Fatalf("got %d plain->TLS warnings, want 1: %+v", len(warns), warns)
	}
	if got := warns[0].attrs["hosts"]; !strings.Contains(got, "a.test") {
		t.Fatalf("warning hosts = %q, want it to name a.test", got)
	}
}

// TestReloadNoWarnPlainToPlain proves a plain->plain reload (no TLS in either config) is
// silent for the TLS footgun.
func TestReloadNoWarnPlainToPlain(t *testing.T) {
	origin := newCountingOrigin(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("ok"))
	})
	const plain = `a.test {
	upstream u { to %s }
	cache_ttl default ttl 300s
}
`
	const plain2 = `a.test, alias.test {
	upstream u { to %s }
	cache_ttl default ttl 300s
}
`
	srv, cap := newServerForWarn(t, plain, origin.srv.URL)
	applyString(t, srv, plain2, origin.srv.URL)

	if warns := cap.warnsContaining(plainTLSMsg); len(warns) != 0 {
		t.Fatalf("got %d plain->TLS warnings, want 0 (plain->plain): %+v", len(warns), warns)
	}
}
