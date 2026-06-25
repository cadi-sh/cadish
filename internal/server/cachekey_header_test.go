package server

import (
	"io"
	"net/http"
	"testing"

	"github.com/cadi-sh/cadish/internal/pipeline"
)

// TestCacheKeyHeaderHash covers `header +cache_key NAME` end-to-end through the
// server deliver path: the response carries the 12-hex sha256 of the computed key,
// stable across MISS/HIT for the same key, and the value equals pipeline.CacheKeyHash
// of the key the server actually builds (cache_key method host path).
func TestCacheKeyHeaderHash(t *testing.T) {
	origin := newCountingOrigin(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "body")
	})
	cfg := `test.local {
	cache { ram 64MiB }
	upstream backend { to %s }
	cache_key method host path
	cache_ttl default ttl 60s
	header +cache_status X-Cache
	header +cache_key X-Cache-Key
}
`
	h, _ := buildHandler(t, nil, cfg, origin.srv.URL)

	want := pipeline.CacheKeyHash("GET\x1ftest.local\x1f/page")

	miss := do(h, "GET", "http://test.local/page", nil)
	if got := miss.Header().Get("X-Cache"); got != "MISS" {
		t.Fatalf("X-Cache = %q, want MISS", got)
	}
	gotMiss := miss.Header().Get("X-Cache-Key")
	if len(gotMiss) != 12 {
		t.Fatalf("X-Cache-Key = %q, want 12 hex chars", gotMiss)
	}
	if gotMiss != want {
		t.Fatalf("X-Cache-Key = %q, want %q (hash of the built key)", gotMiss, want)
	}

	hit := do(h, "GET", "http://test.local/page", nil)
	if got := hit.Header().Get("X-Cache"); got != "HIT" {
		t.Fatalf("X-Cache = %q, want HIT", got)
	}
	if gotHit := hit.Header().Get("X-Cache-Key"); gotHit != gotMiss {
		t.Fatalf("X-Cache-Key drifted between MISS (%q) and HIT (%q)", gotMiss, gotHit)
	}

	// A different path yields a different key → different hash.
	other := do(h, "GET", "http://test.local/other", nil)
	if got := other.Header().Get("X-Cache-Key"); got == gotMiss {
		t.Fatalf("distinct path produced the same hash %q", got)
	}
}

// TestCacheKeyHeaderRaw covers the `raw` modifier: the response carries the RAW key
// string (== the key the server builds), not the hash.
func TestCacheKeyHeaderRaw(t *testing.T) {
	origin := newCountingOrigin(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "body")
	})
	cfg := `test.local {
	cache { ram 64MiB }
	upstream backend { to %s }
	cache_key method host path
	cache_ttl default ttl 60s
	header +cache_key X-Cache-Key raw
}
`
	h, _ := buildHandler(t, nil, cfg, origin.srv.URL)

	rec := do(h, "GET", "http://test.local/page", nil)
	want := "GET\x1ftest.local\x1f/page"
	if got := rec.Header().Get("X-Cache-Key"); got != want {
		t.Fatalf("raw X-Cache-Key = %q, want %q", got, want)
	}
}

// TestCacheKeyHeaderAbsentByDefault covers the zero-cost default: no directive → no
// header.
func TestCacheKeyHeaderAbsentByDefault(t *testing.T) {
	origin := newCountingOrigin(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "body")
	})
	cfg := `test.local {
	cache { ram 64MiB }
	upstream backend { to %s }
	cache_ttl default ttl 60s
	header +cache_status X-Cache
}
`
	h, _ := buildHandler(t, nil, cfg, origin.srv.URL)
	rec := do(h, "GET", "http://test.local/page", nil)
	if got := rec.Header().Get("X-Cache-Key"); got != "" {
		t.Fatalf("X-Cache-Key = %q, want absent (no directive)", got)
	}
}

// TestCacheKeyHeaderOmittedOnPass covers privacy/no-key: a `pass` request has no
// cache key, so the header is omitted even though the directive is configured.
func TestCacheKeyHeaderOmittedOnPass(t *testing.T) {
	origin := newCountingOrigin(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "body")
	})
	cfg := `test.local {
	cache { ram 64MiB }
	upstream backend { to %s }
	@dyn path /api/*
	pass @dyn
	cache_key method host path
	cache_ttl default ttl 60s
	header +cache_key X-Cache-Key
}
`
	h, _ := buildHandler(t, nil, cfg, origin.srv.URL)
	rec := do(h, "GET", "http://test.local/api/x", nil)
	if got := rec.Header().Get("X-Cache-Key"); got != "" {
		t.Fatalf("pass X-Cache-Key = %q, want absent (no key)", got)
	}
}

// TestCacheKeyHeaderScoped covers scoped emission: the header appears only when the
// directive's @scope matches (e.g. an internal/debug header).
func TestCacheKeyHeaderScoped(t *testing.T) {
	origin := newCountingOrigin(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "body")
	})
	cfg := `test.local {
	cache { ram 64MiB }
	upstream backend { to %s }
	@debug header X-Debug 1
	cache_key method host path
	cache_ttl default ttl 60s
	header @debug +cache_key X-Cache-Key
}
`
	h, _ := buildHandler(t, nil, cfg, origin.srv.URL)

	off := do(h, "GET", "http://test.local/page", nil)
	if got := off.Header().Get("X-Cache-Key"); got != "" {
		t.Fatalf("unscoped request X-Cache-Key = %q, want absent", got)
	}
	on := do(h, "GET", "http://test.local/page", http.Header{"X-Debug": {"1"}})
	if got := on.Header().Get("X-Cache-Key"); got == "" {
		t.Fatal("scoped @debug request should carry X-Cache-Key")
	}
}
