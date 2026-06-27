package check

import (
	"strings"
	"testing"
)

// TestDefaultKeyOmitsQueryWarns (R04): a site that caches (a store-intent cache_ttl) with
// NO cache_key relies on the default key `method host path`, which omits the query — so
// `/api?id=1` and `/api?id=2` collide. check must warn.
func TestDefaultKeyOmitsQueryWarns(t *testing.T) {
	src := []byte(`api.example.com {
    upstream api { to https://1.2.3.4:443 }
    cache_ttl default ttl 30s
}`)
	r, err := CheckSource("c.cadish", src)
	if err != nil {
		t.Fatalf("CheckSource: %v", err)
	}
	if codes(r)["default-key-omits-query"] == 0 {
		t.Fatalf("expected a default-key-omits-query warning; codes=%v", codes(r))
	}
	var msg string
	for _, s := range r.Sites {
		for _, d := range s.Diagnostics {
			if d.Code == "default-key-omits-query" {
				msg = d.Message
			}
		}
	}
	if !strings.Contains(msg, "query") {
		t.Errorf("warning should mention the query; got %q", msg)
	}
}

// TestDefaultKeyExplicitKeyClean: ANY explicit cache_key silences the warning — the
// operator made a choice (here `cache_key path`, which also omits the query, but it is a
// deliberate explicit key so we do not second-guess it).
func TestDefaultKeyExplicitKeyClean(t *testing.T) {
	for _, key := range []string{"cache_key url", "cache_key method host path query", "cache_key path"} {
		src := []byte("api.example.com {\n    upstream api { to https://1.2.3.4:443 }\n    " + key + "\n    cache_ttl default ttl 30s\n}")
		r, err := CheckSource("c.cadish", src)
		if err != nil {
			t.Fatalf("CheckSource(%q): %v", key, err)
		}
		if n := codes(r)["default-key-omits-query"]; n != 0 {
			t.Errorf("explicit %q must silence the warning; got %d (%v)", key, n, codes(r))
		}
	}
}

// TestDefaultKeyNoStoreClean: a site that does not STORE (only a hit_for_miss rule, or no
// cache_ttl) is not a caching site, so it must not warn.
func TestDefaultKeyNoStoreClean(t *testing.T) {
	cases := []string{
		`api.example.com {
    upstream api { to https://1.2.3.4:443 }
    cache_ttl status 500 hit_for_miss 5s
}`,
		`api.example.com {
    upstream api { to https://1.2.3.4:443 }
    pass
}`,
	}
	for _, src := range cases {
		r, err := CheckSource("c.cadish", []byte(src))
		if err != nil {
			t.Fatalf("CheckSource: %v", err)
		}
		if n := codes(r)["default-key-omits-query"]; n != 0 {
			t.Errorf("a non-storing site must not warn; got %d (%v) for %q", n, codes(r), src)
		}
	}
}
