package server

import (
	"fmt"
	"io"
	"net/http"
	"testing"
)

// TestStorageTierOverride proves the full path: a `storage <sel> -> disk` rule in
// the Cadishfile lands a normally-RAM object on the NVMe tier (and `-> ram` keeps
// it in memory), via pipeline StoreTier → ObjectMeta.Tier → cache routing.
func TestStorageTierOverride(t *testing.T) {
	cases := []struct {
		name     string
		storage  string
		wantDisk int
		wantRAM  int
	}{
		{"force disk", "storage default -> disk", 1, 0},
		{"force ram", "storage default -> ram", 0, 1},
		{"no rule (automatic: small text -> ram)", "", 0, 1},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			origin := newCountingOrigin(t, func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "text/plain")
				_, _ = io.WriteString(w, "small-body")
			})
			// A two-tier cache; %%s leaves the origin placeholder for buildHandler.
			body := fmt.Sprintf(`test.local {
    cache { ram 64MiB; disk %s 64MiB }
    upstream backend { to %%s }
    %s
    cache_ttl default ttl 60s
}
`, t.TempDir(), c.storage)
			h, cfg := buildHandler(t, nil, body, origin.srv.URL)

			if rec := do(h, "GET", "http://test.local/obj.txt", nil); rec.Code != 200 {
				t.Fatalf("GET = %d", rec.Code)
			}

			st := cfg.Sites[0].Store.Stats()
			if st.DiskObjects != c.wantDisk || st.RAMObjects != c.wantRAM {
				t.Errorf("after store: RAMObjects=%d DiskObjects=%d, want RAM=%d disk=%d",
					st.RAMObjects, st.DiskObjects, c.wantRAM, c.wantDisk)
			}
			// Still a cache HIT regardless of tier.
			if rec := do(h, "GET", "http://test.local/obj.txt", nil); rec.Header().Get("X-Cache") == "MISS" {
				// X-Cache header is only present if the config sets it; tolerate absence.
				if origin.hits.Load() != 1 {
					t.Errorf("second GET re-hit origin (hits=%d); object not cached", origin.hits.Load())
				}
			}
		})
	}
}
