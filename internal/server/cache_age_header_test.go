package server

import (
	"io"
	"net/http"
	"strconv"
	"testing"
	"time"
)

// TestCacheAgeFormulaParity pins the Go age formula — int64(duration.Seconds()) — to the
// same expected whole-second integer that the JS edge formula Math.floor(ms/1000) produces
// over the same elapsed-ms table. Both formulas truncate toward zero for non-negative elapsed
// time (Go: int64 truncation of a positive float64; JS: Math.floor of a non-negative
// quotient). A future rounding-mode change on either side would break this table.
//
// Go formula (handler.go): int64(h.now().Sub(st).Seconds())
// JS formula (entry.js):   Math.floor((Date.now() - opts.storedAt) / 1000)
func TestCacheAgeFormulaParity(t *testing.T) {
	cases := []struct {
		elapsedMs int64
		want      int64
	}{
		{0, 0},
		{999, 0},
		{1_000, 1},
		{1_500, 1},
		{45_000, 45},
		{45_999, 45},
	}
	for _, c := range cases {
		d := time.Duration(c.elapsedMs) * time.Millisecond
		got := int64(d.Seconds())
		if got != c.want {
			t.Errorf("elapsed=%dms: int64(d.Seconds()) = %d, want %d", c.elapsedMs, got, c.want)
		}
	}
}

// TestCacheAgeHeaderHitMiss covers `header +cache_age NAME`: the response carries
// an integer-seconds age on HIT and is ABSENT on MISS (no stored age on first fetch).
func TestCacheAgeHeaderHitMiss(t *testing.T) {
	origin := newCountingOrigin(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "body")
	})
	cfg := `test.local {
	cache { ram 64MiB }
	upstream backend { to %s }
	cache_key method host path
	cache_ttl default ttl 60s
	header +cache_status X-Cache
	header +cache_age X-Cache-Age
}
`
	h, _ := buildHandler(t, nil, cfg, origin.srv.URL)

	// MISS: no stored age → header absent.
	miss := do(h, "GET", "http://test.local/page", nil)
	if got := miss.Header().Get("X-Cache"); got != "MISS" {
		t.Fatalf("X-Cache = %q, want MISS", got)
	}
	if got := miss.Header().Get("X-Cache-Age"); got != "" {
		t.Fatalf("MISS X-Cache-Age = %q, want absent", got)
	}

	// HIT: age ≥ 0 as a bare integer string.
	hit := do(h, "GET", "http://test.local/page", nil)
	if got := hit.Header().Get("X-Cache"); got != "HIT" {
		t.Fatalf("X-Cache = %q, want HIT", got)
	}
	ageStr := hit.Header().Get("X-Cache-Age")
	if ageStr == "" {
		t.Fatal("HIT X-Cache-Age absent, want integer age ≥ 0")
	}
	age, err := strconv.ParseInt(ageStr, 10, 64)
	if err != nil {
		t.Fatalf("HIT X-Cache-Age = %q, want bare integer: %v", ageStr, err)
	}
	if age < 0 {
		t.Fatalf("HIT X-Cache-Age = %d, want ≥ 0", age)
	}
}

// TestCacheAgeHeaderAbsentByDefault covers the zero-cost default: no directive → no
// header even on a HIT.
func TestCacheAgeHeaderAbsentByDefault(t *testing.T) {
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
	do(h, "GET", "http://test.local/page", nil) // warm cache
	hit := do(h, "GET", "http://test.local/page", nil)
	if got := hit.Header().Get("X-Cache"); got != "HIT" {
		t.Fatalf("X-Cache = %q, want HIT", got)
	}
	if got := hit.Header().Get("X-Cache-Age"); got != "" {
		t.Fatalf("X-Cache-Age = %q, want absent (no directive)", got)
	}
}

// TestCacheAgeHeaderOnPass covers that +cache_age is absent on a pass request (no
// stored age for a pass).
func TestCacheAgeHeaderOnPass(t *testing.T) {
	origin := newCountingOrigin(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "body")
	})
	cfg := `test.local {
	cache { ram 64MiB }
	upstream backend { to %s }
	pass method POST
	cache_key method host path
	cache_ttl default ttl 60s
	header +cache_age X-Cache-Age
}
`
	h, _ := buildHandler(t, nil, cfg, origin.srv.URL)
	rec := do(h, "POST", "http://test.local/page", nil)
	if got := rec.Header().Get("X-Cache-Age"); got != "" {
		t.Fatalf("pass X-Cache-Age = %q, want absent", got)
	}
}
