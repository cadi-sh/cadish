package cadishfile

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

// TestParseRealStorefront parses the canonical full "form A" config and asserts
// the key structural facts a downstream pipeline depends on.
func TestParseRealStorefront(t *testing.T) {
	path := filepath.Join("testdata", "storefront.A-flat.cadish")
	f, err := ParseFile(path)
	if err != nil {
		t.Fatalf("ParseFile(%s) error: %v", path, err)
	}
	if len(f.Sites) != 1 {
		t.Fatalf("sites = %d, want 1", len(f.Sites))
	}
	site := f.Sites[0]
	wantAddrs := []string{"example.com", "*.example.com"}
	if len(site.Addresses) != len(wantAddrs) {
		t.Fatalf("addresses = %v, want %v", site.Addresses, wantAddrs)
	}
	for i, a := range wantAddrs {
		if site.Addresses[i] != a {
			t.Errorf("address %d = %q, want %q", i, site.Addresses[i], a)
		}
	}

	// Collect directive and matcher names present in the body.
	directives := map[string]int{}
	matchers := map[string]string{} // name -> type
	for _, n := range site.Body {
		switch v := n.(type) {
		case *Directive:
			directives[v.Name]++
		case *MatcherDef:
			matchers[v.Name] = v.Type
		}
	}

	for _, name := range []string{"tls", "upstream", "cluster", "cache", "respond", "purge", "route", "pass", "cache_key", "cache_ttl", "storage", "strip_cookies", "header", "import"} {
		if directives[name] == 0 {
			t.Errorf("expected directive %q to be present", name)
		}
	}
	// pass appears multiple times, cache_ttl appears multiple times.
	if directives["pass"] < 3 {
		t.Errorf("pass count = %d, want >= 3", directives["pass"])
	}
	if directives["cache_ttl"] < 4 {
		t.Errorf("cache_ttl count = %d, want >= 4", directives["cache_ttl"])
	}

	// Matchers defined inline in the site.
	if matchers["ajax"] != "header" {
		t.Errorf("@ajax type = %q, want header", matchers["ajax"])
	}
	if matchers["static"] != "host_regex" {
		t.Errorf("@static type = %q, want host_regex", matchers["static"])
	}
	if matchers["images"] != "upstream" {
		t.Errorf("@images type = %q, want upstream", matchers["images"])
	}

	// tls block holds an acme directive.
	for _, n := range site.Body {
		if d, ok := n.(*Directive); ok && d.Name == "tls" {
			if !d.HasBlock || len(d.Block) == 0 {
				t.Errorf("tls should have a non-empty block")
			}
			acme := d.Block[0].(*Directive)
			if acme.Name != "acme" {
				t.Errorf("tls block[0] = %q, want acme", acme.Name)
			}
		}
	}

	// The purge directive should carry an env placeholder argument.
	for _, n := range site.Body {
		if d, ok := n.(*Directive); ok && d.Name == "purge" {
			found := false
			for _, a := range d.Args {
				if a.Kind == ArgPlaceholder && a.Raw == "{$PURGE_TOKEN}" {
					found = true
				}
			}
			if !found {
				t.Errorf("purge should reference {$PURGE_TOKEN} placeholder; args=%v", d.Args)
			}
		}
	}
}

// TestParseRealNocache parses the importable sub-config (no site wrapper).
func TestParseRealNocache(t *testing.T) {
	path := filepath.Join("testdata", "nocache.cadish")
	f, err := ParseFile(path)
	if err != nil {
		t.Fatalf("ParseFile(%s) error: %v", path, err)
	}
	if len(f.Sites) != 0 {
		t.Errorf("sites = %d, want 0 (fragment has no site block)", len(f.Sites))
	}
	if len(f.Body) == 0 {
		t.Fatal("expected top-level body statements in the fragment")
	}
	// Find the @nocache and @listings matcher definitions.
	matchers := map[string]string{}
	for _, n := range f.Body {
		if m, ok := n.(*MatcherDef); ok {
			matchers[m.Name] = m.Type
		}
	}
	if matchers["nocache"] != "path" {
		t.Errorf("@nocache type = %q, want path", matchers["nocache"])
	}
	if matchers["listings"] != "path_regex" {
		t.Errorf("@listings type = %q, want path_regex", matchers["listings"])
	}
}

// TestFormatRealConfigsIdempotent ensures the canonical files format stably.
func TestFormatRealConfigsIdempotent(t *testing.T) {
	for _, name := range []string{"storefront.A-flat.cadish", "nocache.cadish"} {
		path := filepath.Join("testdata", name)
		src, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		once, err := Format(src)
		if err != nil {
			t.Fatalf("Format(%s) error: %v", name, err)
		}
		twice, err := Format(once)
		if err != nil {
			t.Fatalf("re-Format(%s) error: %v", name, err)
		}
		if !bytes.Equal(once, twice) {
			t.Errorf("%s: Format not idempotent", name)
		}
		// Formatted output must still parse.
		if _, err := Parse(name, once); err != nil {
			t.Errorf("%s: formatted output failed to parse: %v", name, err)
		}
	}
}
