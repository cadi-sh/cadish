package pipeline

import (
	"net/url"
	"testing"
)

// TestQueryParamTokenInHeader verifies that {query.NAME} resolves the first decoded
// query param value in a response header op, and is "" (consumed) when absent.
func TestQueryParamTokenInHeader(t *testing.T) {
	p := compileSrc(t, `example.com {
	cache_key host path
	cache_ttl default ttl 60s
	header X-Genre {query.genre}
	header X-Age   {query.age}
	header X-Miss  {query.missing}
}
`)

	q := url.Values{}
	q.Set("genre", "comedy")
	q.Set("age", "25")
	req := &Request{Host: "example.com", Path: "/v", Query: q}

	dec := p.EvalDeliver(req, nil, CacheStatusMiss)
	ops := make(map[string]string, len(dec.RespHeaderOps))
	for _, op := range dec.RespHeaderOps {
		ops[op.Name] = op.Value
	}
	if got := ops["X-Genre"]; got != "comedy" {
		t.Errorf("X-Genre = %q, want %q", got, "comedy")
	}
	if got := ops["X-Age"]; got != "25" {
		t.Errorf("X-Age = %q, want %q", got, "25")
	}
	// absent param: consumed as "" (not left verbatim as "{query.missing}")
	if got, ok := ops["X-Miss"]; !ok || got != "" {
		t.Errorf("X-Miss = %q ok=%v, want empty string (consumed)", got, ok)
	}
}

// TestQueryParamTokenMultiValue verifies {query.NAME} resolves to the FIRST value only
// when a param appears multiple times.
func TestQueryParamTokenMultiValue(t *testing.T) {
	p := compileSrc(t, `example.com {
	cache_key host path
	cache_ttl default ttl 60s
	header X-Tag {query.tag}
}
`)
	q := url.Values{}
	q.Add("tag", "first")
	q.Add("tag", "second")
	req := &Request{Host: "example.com", Path: "/v", Query: q}

	dec := p.EvalDeliver(req, nil, CacheStatusMiss)
	for _, op := range dec.RespHeaderOps {
		if op.Name == "X-Tag" {
			if op.Value != "first" {
				t.Errorf("X-Tag = %q, want first value %q", op.Value, "first")
			}
			return
		}
	}
	t.Error("X-Tag op not found in deliver decision")
}

// TestDeviceTokenInHeader verifies that {device} resolves to the pre-pass device class
// in a response header op, and is "" (consumed) when Device is unset.
func TestDeviceTokenInHeader(t *testing.T) {
	p := compileSrc(t, `example.com {
	cache_key host path
	cache_ttl default ttl 60s
	header X-Device {device}
}
`)

	// Device pre-set (server/harness resolves it before EvalDeliver).
	req := &Request{Host: "example.com", Path: "/v", Device: "mobile"}
	dec := p.EvalDeliver(req, nil, CacheStatusMiss)
	for _, op := range dec.RespHeaderOps {
		if op.Name == "X-Device" {
			if op.Value != "mobile" {
				t.Errorf("X-Device = %q, want %q", op.Value, "mobile")
			}
			goto empty
		}
	}
	t.Error("X-Device op not found")

empty:
	// Empty Device: consumed as "" (not kept verbatim as "{device}").
	req2 := &Request{Host: "example.com", Path: "/v", Device: ""}
	dec2 := p.EvalDeliver(req2, nil, CacheStatusMiss)
	for _, op := range dec2.RespHeaderOps {
		if op.Name == "X-Device" {
			if op.Value != "" {
				t.Errorf("empty Device: X-Device = %q, want empty string (consumed)", op.Value)
			}
			return
		}
	}
	t.Error("X-Device op not found in empty-device case")
}

// TestCacheAgeHeaderDecision verifies that EvalDeliver surfaces CacheAgeHeader
// from a `header +cache_age NAME` directive.
func TestCacheAgeHeaderDecision(t *testing.T) {
	p := compileSrc(t, `example.com {
	cache_key host path
	cache_ttl default ttl 60s
	header +cache_age X-Cache-Age
}
`)
	req := &Request{Host: "example.com", Path: "/v"}
	// CacheAgeHeader should be set regardless of cache status (the directive always
	// matches; the server/edge materializes the value only on HIT).
	for _, status := range []CacheStatus{CacheStatusMiss, CacheStatusHit, CacheStatusHitStale} {
		dec := p.EvalDeliver(req, nil, status)
		if dec.CacheAgeHeader != "X-Cache-Age" {
			t.Errorf("status=%s CacheAgeHeader = %q, want %q", status, dec.CacheAgeHeader, "X-Cache-Age")
		}
		// OpCacheAge must NOT produce a RespHeaderOp (it is not materialized by
		// applyHeaderRules; the server/edge materializes it separately).
		for _, op := range dec.RespHeaderOps {
			if op.Name == "X-Cache-Age" {
				t.Errorf("status=%s X-Cache-Age appeared as a RespHeaderOp (should NOT be emitted by applyHeaderRules)", status)
			}
		}
	}
}

// TestCacheAgeHeaderAbsentByDefault verifies that CacheAgeHeader is "" when the
// directive is not configured.
func TestCacheAgeHeaderAbsentByDefault(t *testing.T) {
	p := compileSrc(t, `example.com {
	cache_key host path
	cache_ttl default ttl 60s
	header +cache_status X-Cache
}
`)
	req := &Request{Host: "example.com", Path: "/v"}
	dec := p.EvalDeliver(req, nil, CacheStatusHit)
	if dec.CacheAgeHeader != "" {
		t.Errorf("CacheAgeHeader = %q, want empty (no directive)", dec.CacheAgeHeader)
	}
}
