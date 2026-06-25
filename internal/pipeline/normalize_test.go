package pipeline

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
)

// TestNormalizeCommaList: `map a,b,c -> bucket` maps each comma-listed value to
// the same bucket (and whitespace-separated values work too).
func TestNormalizeCommaList(t *testing.T) {
	p := compileSrc(t, `example.com {
    normalize plan {
        from    header X-Sub
        map     free,trial   -> anon
        map     premium vip  -> paid
        default anon
    }
    cache_key {plan}
}`)
	key := func(sub string) string {
		h := http.Header{}
		h.Set("X-Sub", sub)
		return p.EvalRequest(&Request{Header: h}).CacheKey
	}
	if key("free") != "anon" || key("trial") != "anon" {
		t.Errorf("free/trial should both bucket to anon: %q/%q", key("free"), key("trial"))
	}
	if key("premium") != "paid" || key("vip") != "paid" {
		t.Errorf("premium/vip should both bucket to paid: %q/%q", key("premium"), key("vip"))
	}
	if key("unknown") != "anon" {
		t.Errorf("unmapped → default anon, got %q", key("unknown"))
	}
}

func cookieHeader(kv string) http.Header {
	h := http.Header{}
	h.Set("Cookie", kv)
	return h
}

// TestNormalizeCacheKey: a `normalize` maps a request value (header/cookie/query)
// to a bounded bucket; the {NAME} key token renders that bucket, so two raw
// values that map to the same bucket share a cache key (the cardinality win).
func TestNormalizeCacheKey(t *testing.T) {
	p := compileSrc(t, `example.com {
    normalize plan {
        from   header X-Plan
        map    enterprise -> paid
        map    pro        -> paid
        map    free       -> free
        default free
    }
    cache_key host path {plan}
}`)
	keyFor := func(plan string) string {
		h := http.Header{}
		if plan != "" {
			h.Set("X-Plan", plan)
		}
		return p.EvalRequest(&Request{Host: "h", Path: "/x", Header: h}).CacheKey
	}
	// pro and enterprise both bucket to "paid" → same key.
	if keyFor("pro") != keyFor("enterprise") {
		t.Errorf("pro and enterprise should share a key (both → paid)")
	}
	// free is a different bucket → different key.
	if keyFor("pro") == keyFor("free") {
		t.Error("paid and free should differ")
	}
	// Unmapped value → default bucket (free).
	if keyFor("trialing") != keyFor("free") {
		t.Errorf("unmapped value should fall to default bucket free")
	}
	if !strings.Contains(keyFor("pro"), "paid") {
		t.Errorf("key %q should contain the bucket", keyFor("pro"))
	}
}

func TestNormalizeSources(t *testing.T) {
	// cookie source
	pc := compileSrc(t, "example.com {\n normalize theme {\n from cookie theme\n map dark -> dark\n default light\n }\n cache_key {theme}\n}")
	dark := pc.EvalRequest(&Request{Header: cookieHeader("theme=dark")}).CacheKey
	light := pc.EvalRequest(&Request{Header: cookieHeader("theme=blue")}).CacheKey // unmapped → light
	if dark == light {
		t.Error("cookie theme dark vs default should differ")
	}
	if dark != "dark" || light != "light" {
		t.Errorf("cookie buckets = %q/%q, want dark/light", dark, light)
	}
	// query source
	pq := compileSrc(t, "example.com {\n normalize v {\n from query ver\n map 2 -> v2\n default v1\n }\n cache_key {v}\n}")
	got := pq.EvalRequest(&Request{Query: url.Values{"ver": {"2"}}}).CacheKey
	if got != "v2" {
		t.Errorf("query bucket = %q, want v2", got)
	}
}

func TestNormalizeCompileErrors(t *testing.T) {
	cases := map[string]string{
		"unknown token":   "example.com {\n cache_key {nope}\n}",
		"reserved name":   "example.com {\n normalize device {\n from header X\n default a\n }\n}",
		"no source":       "example.com {\n normalize x {\n map a -> b\n }\n cache_key {x}\n}",
		"no map/default":  "example.com {\n normalize x {\n from header X\n }\n cache_key {x}\n}",
		"bad from":        "example.com {\n normalize x {\n from body X\n default a\n }\n cache_key {x}\n}",
		"bad map":         "example.com {\n normalize x {\n from header X\n map a b\n }\n cache_key {x}\n}",
		"duplicate":       "example.com {\n normalize x {\n from header A\n default a\n }\n normalize x {\n from header B\n default b\n }\n}",
		"unknown setting": "example.com {\n normalize x {\n from header X\n frob y\n }\n}",
	}
	for name, src := range cases {
		t.Run(name, func(t *testing.T) {
			if compileErr(t, src) == nil {
				t.Errorf("expected a compile error for %s", name)
			}
		})
	}
}
