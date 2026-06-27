package pipeline

import (
	"net/http"
	"testing"
)

// TestLenientCookieMemoSingleParse is the R28 pin: a request parses its Cookie header
// ONCE — repeated reads (the credentialed hot path reads it 3+ times: buildKey,
// cookieNames, keyCoversAllCookies) return the SAME memoized slice, not a fresh parse.
// We prove "not re-parsed" by identity: a fresh parse would allocate a new backing
// array, so a shared backing pointer means the memo was hit.
func TestLenientCookieMemoSingleParse(t *testing.T) {
	r := &Request{Header: http.Header{"Cookie": {"session=abc; uid=42"}}}

	a := r.lenientCookies()
	b := r.lenientCookies()
	if len(a) != 2 || a[0].name != "session" || a[1].name != "uid" {
		t.Fatalf("unexpected parse: %+v", a)
	}
	if &a[0] != &b[0] {
		t.Fatal("second read re-parsed (different backing array); memo not hit")
	}

	// The memoized result must be byte-identical to a non-memoized package parse.
	ref := lenientCookies(r.Header)
	if len(ref) != len(a) {
		t.Fatalf("memoized vs package parse length mismatch: %d vs %d", len(a), len(ref))
	}
	for i := range ref {
		if ref[i] != a[i] {
			t.Fatalf("memoized[%d]=%+v != package[%d]=%+v", i, a[i], i, ref[i])
		}
	}
}

// TestLenientCookieMemoInvalidatesOnHeaderChange is the correctness guard that makes the
// memo SAFE despite the server stripping cookies mid-request (StripDerivedCookies /
// cookie_allow run AFTER the key is built but BEFORE the credential check): because the
// memo is keyed on the raw Cookie bytes, a changed header re-parses — the memo can never
// hand a stale pre-strip cookie set to the post-strip credential gate (a cross-user leak).
func TestLenientCookieMemoInvalidatesOnHeaderChange(t *testing.T) {
	r := &Request{Header: http.Header{"Cookie": {"session=abc; uid=42"}}}
	if got := r.cookie("uid"); got != "42" {
		t.Fatalf("pre-strip cookie uid = %q, want 42", got)
	}

	// Simulate the mid-request strip of `uid`.
	r.Header.Set("Cookie", "session=abc")
	if got := r.cookie("uid"); got != "" {
		t.Fatalf("post-strip cookie uid = %q, want \"\" (memo must have re-parsed)", got)
	}
	if got := r.cookie("session"); got != "abc" {
		t.Fatalf("post-strip cookie session = %q, want abc", got)
	}
	names := r.cookieNames()
	if len(names) != 1 || names[0] != "session" {
		t.Fatalf("post-strip cookieNames = %v, want [session]", names)
	}
}
