package pipeline

import (
	"net/http"
	"net/url"
	"path/filepath"
	"testing"
	"time"

	"github.com/cadi-sh/cadish/internal/cadishfile"
)

// loadStorefront parses the canonical A-flat config, substitutes env, splices the
// imported nocache.cadish fragment, and compiles it — the full real-world path.
func loadStorefront(t *testing.T) *Pipeline {
	t.Helper()
	dir := filepath.FromSlash("testdata")
	f, err := cadishfile.ParseFile(filepath.Join(dir, "storefront.A-flat.cadish"))
	if err != nil {
		t.Fatalf("parse A-flat: %v", err)
	}
	cadishfile.SubstituteEnv(f, func(name string) (string, bool) {
		if name == "PURGE_TOKEN" {
			return "topsecret", true
		}
		return "", false
	})
	if len(f.Sites) != 1 {
		t.Fatalf("want 1 site, got %d", len(f.Sites))
	}
	site, err := SpliceImports(f.Sites[0], FileImportResolver(dir))
	if err != nil {
		t.Fatalf("splice imports: %v", err)
	}
	p, err := Compile(site)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	return p
}

func TestStorefrontCompiles(t *testing.T) {
	p := loadStorefront(t)
	if _, ok := p.matchers["nocache"]; !ok {
		t.Error("expected @nocache matcher (imported) to be present")
	}
	if _, ok := p.matchers["listings"]; !ok {
		t.Error("expected @listings matcher (imported) to be present")
	}
	if p.stickyCookie != "PHPSESSID" {
		t.Errorf("stickyCookie = %q, want PHPSESSID", p.stickyCookie)
	}
}

func TestStorefrontDecisions(t *testing.T) {
	p := loadStorefront(t)

	t.Run("panel-is-pass", func(t *testing.T) {
		dec := p.EvalRequest(&Request{Method: "GET", Host: "example.com", Path: "/panel/settings", Query: url.Values{}})
		if !dec.Pass {
			t.Error("/panel/ should Pass (matched @nocache)")
		}
	})

	t.Run("listing-is-cached", func(t *testing.T) {
		// A listing path matches @listings (path_regex), NOT @nocache, so it is not passed.
		dec := p.EvalRequest(&Request{Method: "GET", Host: "example.com", Path: "/catalog/", Query: url.Values{}})
		if dec.Pass {
			t.Error("/catalog/ listing should be cacheable (not Pass)")
		}
	})

	t.Run("post-is-pass", func(t *testing.T) {
		dec := p.EvalRequest(&Request{Method: "POST", Host: "example.com", Path: "/home", Query: url.Values{}})
		if !dec.Pass {
			t.Error("POST should Pass")
		}
	})

	t.Run("ajax-is-pass", func(t *testing.T) {
		dec := p.EvalRequest(&Request{
			Method: "GET", Host: "example.com", Path: "/home", Query: url.Values{},
			Header: http.Header{"X-Requested-With": {"XMLHttpRequest"}},
		})
		if !dec.Pass {
			t.Error("ajax request should Pass")
		}
	})

	t.Run("health-check-synthetic", func(t *testing.T) {
		dec := p.EvalRequest(&Request{Method: "GET", Host: "example.com", Path: "/health-check", Query: url.Values{}})
		if dec.Synthetic == nil || dec.Synthetic.Status != 200 || dec.Synthetic.Body != "OK" {
			t.Fatalf("health-check synthetic = %+v, want {200 OK}", dec.Synthetic)
		}
	})

	t.Run("cache-key-url-host", func(t *testing.T) {
		dec := p.EvalRequest(&Request{
			Method: "GET", Host: "Example.com", Path: "/list",
			Query: url.Values{"p": {"2"}},
		})
		// cache_key url host => "/list?p=2" SEP "example.com"
		want := "/list?p=2" + keyTokenSep + "example.com"
		if dec.CacheKey != want {
			t.Errorf("CacheKey = %q, want %q", dec.CacheKey, want)
		}
	})

	t.Run("purge-token-guarded", func(t *testing.T) {
		ok := p.EvalRequest(&Request{
			Method: "PURGE", Host: "example.com", Path: "/", Query: url.Values{},
			Header: http.Header{"X-Purge-Token": {"topsecret"}},
		})
		if ok.Purge == nil {
			t.Error("correct purge token should authorize")
		}
		bad := p.EvalRequest(&Request{
			Method: "PURGE", Host: "example.com", Path: "/", Query: url.Values{},
			Header: http.Header{"X-Purge-Token": {"guess"}},
		})
		if bad.Purge != nil {
			t.Error("wrong purge token must not authorize")
		}
	})

	t.Run("404-ttl", func(t *testing.T) {
		d := p.EvalResponse(&Request{Host: "example.com", Path: "/gone"}, 404, nil)
		if d.TTL != 60*time.Second || d.Grace != time.Hour {
			t.Errorf("404 ttl/grace = %v/%v, want 60s/1h", d.TTL, d.Grace)
		}
	})

	t.Run("5xx-hit-for-miss", func(t *testing.T) {
		d := p.EvalResponse(&Request{Host: "example.com", Path: "/x"}, 502, nil)
		if d.HitForMiss != 5*time.Second || d.Cacheable {
			t.Errorf("502 = hfm %v cacheable %v, want hfm 5s cacheable false", d.HitForMiss, d.Cacheable)
		}
	})

	t.Run("default-ttl", func(t *testing.T) {
		d := p.EvalResponse(&Request{Host: "example.com", Path: "/page"}, 200, nil)
		if d.TTL != 2*time.Second || d.Grace != 24*time.Hour {
			t.Errorf("default 200 ttl/grace = %v/%v, want 2s/24h", d.TTL, d.Grace)
		}
	})

	t.Run("images-to-disk-and-long-ttl", func(t *testing.T) {
		// Host "static..." routes to images (route @static -> images); @static is
		// host_regex ^static and @images is upstream images.
		img := &Request{Method: "GET", Host: "static.example.com", Path: "/a.jpg", Query: url.Values{}}
		if up := p.EvalRequest(img).Upstream; up != "images" {
			t.Fatalf("image Upstream = %q, want images", up)
		}
		if tier := p.EvalResponse(img, 200, nil).StoreTier; tier != "disk" {
			t.Errorf("image StoreTier = %q, want disk", tier)
		}
		if d := p.EvalResponse(img, 200, nil); d.TTL != 24*time.Hour || d.Grace != 365*24*time.Hour {
			t.Errorf("image ttl/grace = %v/%v, want 24h/365d", d.TTL, d.Grace)
		}
	})

	t.Run("non-image-to-ram", func(t *testing.T) {
		d := p.EvalResponse(&Request{Host: "example.com", Path: "/page"}, 200, nil)
		if d.StoreTier != "ram" {
			t.Errorf("page StoreTier = %q, want ram", d.StoreTier)
		}
	})

	t.Run("deliver-headers", func(t *testing.T) {
		d := p.EvalDeliver(&Request{Host: "example.com", Path: "/page", Query: url.Values{}}, nil, CacheStatusHit)
		var sawCacheStatus, sawServerRemove bool
		for _, op := range d.RespHeaderOps {
			if op.Op == OpSet && op.Name == "X-Cache" && op.Value == "HIT" {
				sawCacheStatus = true
			}
			if op.Op == OpRemove && op.Name == "Server" {
				sawServerRemove = true
			}
		}
		if !sawCacheStatus {
			t.Error("expected X-Cache: HIT op")
		}
		if !sawServerRemove {
			t.Error("expected Server removal op")
		}
		if d.CacheStatusHeader != "X-Cache" {
			t.Errorf("CacheStatusHeader = %q, want X-Cache", d.CacheStatusHeader)
		}
	})

	t.Run("strip-cookies-css", func(t *testing.T) {
		d := p.EvalDeliver(&Request{Host: "example.com", Path: "/style.css", Query: url.Values{}}, nil, CacheStatusHit)
		if !d.StripCookies {
			t.Error("css response should strip cookies")
		}
	})
}
