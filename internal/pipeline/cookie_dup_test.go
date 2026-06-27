package pipeline

import (
	"net/http"
	"testing"
)

// TestDuplicateCookieNameDefeatsKeyingBypasses guards a residual confidentiality
// hole in the name-aware credential coverage: a `cache_key … cookie:NAME` token
// keys on req.cookie(NAME), which is net/http's FIRST occurrence — but the origin
// receives ALL occurrences. So a request sending NAME twice (uid=alice; uid=bob)
// is keyed on the first value alone; a second user sharing that first value but
// differing on the second would collide on one entry. The coverage check must treat
// a keyed cookie sent more than once as NOT covered → bypass.
func TestDuplicateCookieNameDefeatsKeyingBypasses(t *testing.T) {
	p := compileSrc(t, `example.com {
    cache_key host path cookie:uid
    cache_ttl default ttl 60s
}`)

	dupe := &Request{Host: "example.com", Path: "/", Header: http.Header{"Cookie": {"uid=alice; uid=bob"}}}
	if !p.BypassForCredentials(dupe) {
		t.Error("a request keyed by cookie:uid but sending uid TWICE must BYPASS (the key encodes only the first value while the origin sees both)")
	}

	// Control: a single keyed cookie is safely isolated per-user → no bypass.
	single := &Request{Host: "example.com", Path: "/", Header: http.Header{"Cookie": {"uid=alice"}}}
	if p.BypassForCredentials(single) {
		t.Error("a single keyed cookie:uid should be safely cacheable per-user (no bypass)")
	}

	// Control: whole-header keying (header:Cookie) captures every value, so a
	// duplicate is fully covered and may cache.
	ph := compileSrc(t, `example.com {
    cache_key host path header:Cookie
    cache_ttl default ttl 60s
}`)
	if ph.BypassForCredentials(dupe) {
		t.Error("header:Cookie keys the whole Cookie header (all values) → a duplicate is covered, should not bypass")
	}

	// A RAW cookie:NAME-keyed cookie sent twice with the SAME value STILL bypasses: the
	// SPEC-DUP-COOKIE relaxation is scoped to forward-covered cookies (keyed by a DERIVED
	// axis); a raw value enters the key, which captures only the first occurrence, so the
	// raw-keyed path keeps refusing regardless of whether the values match. Fail-closed.
	dupeSame := &Request{Host: "example.com", Path: "/", Header: http.Header{"Cookie": {"uid=alice; uid=alice"}}}
	if !p.BypassForCredentials(dupeSame) {
		t.Error("a raw cookie:uid keyed cookie sent twice (even SAME value) must BYPASS — the relaxation is forward-covered only")
	}
}
