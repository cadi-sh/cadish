package config

import (
	"testing"

	"github.com/cadi-sh/cadish/internal/lb"
	"github.com/cadi-sh/cadish/internal/origin/httporigin"
)

// TestSingleToMultiBackendBuildsPool guards a silent data-path correctness bug: a
// pool declared with ONE `to` line listing several targets and NO load-balancing
// directive must build a real (round-robin) lb pool over ALL targets — not silently
// fast-path to a single-backend httporigin using only the FIRST target (which
// dropped every other backend with no error or warning).
func TestSingleToMultiBackendBuildsPool(t *testing.T) {
	cases := []struct {
		name     string
		to       string
		backends int
	}{
		{"two", "http://127.0.0.1:9000 http://127.0.0.1:9001", 2},
		{"three", "http://127.0.0.1:9000 http://127.0.0.1:9001 http://127.0.0.1:9002", 3},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			src := "x.com {\n\tcache { ram 8MiB }\n\tupstream pool { to " + c.to + " }\n}\n"
			cfg := loadStr(t, "<gen>", src)
			t.Cleanup(func() { _ = cfg.Close() })

			o := cfg.Sites[0].Origins["pool"]
			if _, ok := o.(*httporigin.Origin); ok {
				t.Fatalf("pool built a plain *httporigin.Origin: %d-backend `to` line silently collapsed to the first target", c.backends)
			}
			up, ok := o.(*lb.Upstream)
			if !ok {
				t.Fatalf("pool origin = %T, want *lb.Upstream", o)
			}
			if got := len(up.HealthSnapshot().Backends); got != c.backends {
				t.Errorf("pool backends = %d, want %d", got, c.backends)
			}
		})
	}
}

// TestMultiToLinePoolAcceptsHostHeader pins a latent bug uncovered by the
// multi-backend fix: a genuine pool spread over several `to` lines plus the
// config-owned `host_header` directive must load. The lb parser does not know
// `host_header` (the config layer reads it), so it must be stripped before the
// block reaches lb — otherwise lb rejects it as an "unknown directive".
func TestMultiToLinePoolAcceptsHostHeader(t *testing.T) {
	src := "x.com {\n\tupstream pool {\n\t\tto http://a:80\n\t\tto http://b:80\n\t\thost_header preserve\n\t}\n}\n"
	cfg := loadStr(t, "<gen>", src)
	t.Cleanup(func() { _ = cfg.Close() })
	if _, ok := cfg.Sites[0].Origins["pool"].(*lb.Upstream); !ok {
		t.Errorf("pool origin = %T, want *lb.Upstream", cfg.Sites[0].Origins["pool"])
	}
}

// TestSingleToSingleBackendStaysTrivial pins the fast path: a genuinely single
// backend on one `to` line must STILL build a plain httporigin (no lb pool
// machinery). The multi-backend fix must not regress the hot single-origin case.
func TestSingleToSingleBackendStaysTrivial(t *testing.T) {
	src := "x.com {\n\tcache { ram 8MiB }\n\tupstream only { to http://127.0.0.1:9000 }\n}\n"
	cfg := loadStr(t, "<gen>", src)
	t.Cleanup(func() { _ = cfg.Close() })

	o := cfg.Sites[0].Origins["only"]
	if _, ok := o.(*httporigin.Origin); !ok {
		t.Errorf("single-backend upstream = %T, want *httporigin.Origin (trivial fast path)", o)
	}
	if len(cfg.pools) != 0 {
		t.Errorf("cfg.pools = %d, want 0 (single backend must not build an lb pool)", len(cfg.pools))
	}
}
