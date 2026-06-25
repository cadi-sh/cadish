package vcladapt

import (
	"strings"
	"testing"

	"github.com/cadi-sh/cadish/internal/check"
)

// adaptErrorCount runs the adapt output through the (sandboxed) check pipeline and
// returns the error count. The sandboxed variant performs no filesystem access, so a
// best-effort skeleton's TLS/geo path references don't matter — we only assert the
// generated directives don't fail config-build. It is the strongest expression of the
// migration-docs promise: `cadish adapt` output is `cadish check`-clean.
func adaptErrorCount(t *testing.T, vcl string) (int, string) {
	t.Helper()
	out := Adapt("t.vcl", vcl).Cadishfile
	rep, err := check.CheckSourceSandboxed("adapted.cadish", []byte(out))
	if err != nil {
		t.Fatalf("adapted skeleton does not parse: %v\n%s", err, out)
	}
	errs, _ := rep.Counts()
	return errs, out
}

// TestAdaptStdDurationIsCheckClean (A1): a vmod call driving beresp.ttl
// (`std.duration(beresp.http.X-TTL, 60s)`) is non-mechanical — adapt must NOT emit a
// literal `std.duration` token (which fails `check` with "invalid duration") but a
// flagged TODO(adapt) carrying the original line.
func TestAdaptStdDurationIsCheckClean(t *testing.T) {
	vcl := `backend web { .host = "10.0.0.1"; .port = "8080"; }
sub vcl_backend_response { set beresp.ttl = std.duration(beresp.http.X-TTL, 60s); set beresp.grace = 2h; }`
	errs, out := adaptErrorCount(t, vcl)
	if errs != 0 {
		t.Errorf("adapt output has %d check error(s), want 0:\n%s", errs, out)
	}
	if strings.Contains(out, "std.duration") && !strings.Contains(out, "TODO(adapt)") {
		t.Errorf("std.duration leaked as a literal token, not flagged TODO(adapt):\n%s", out)
	}
	if !strings.Contains(out, "TODO(adapt)") {
		t.Errorf("expected a TODO(adapt) for the vmod-driven ttl:\n%s", out)
	}
	if strings.Contains(out, "cache_ttl default ttl std.duration") {
		t.Errorf("emitted a bogus `cache_ttl default ttl std.duration` line:\n%s", out)
	}
}

// TestAdaptHeaderValueRegexPassIsFlagged (A2): a header-VALUE regex in a return(pass)
// (`req.http.User-Agent ~ "(?i)Prerender"`) has no cadish equivalent — adapt must NOT
// collapse it to a bare `pass header User-Agent` (which passes EVERY request with that
// header) but flag it as TODO(adapt) so it's counted in "need review".
func TestAdaptHeaderValueRegexPassIsFlagged(t *testing.T) {
	vcl := `sub vcl_recv { if (req.http.User-Agent ~ "(?i)Prerender") { return(pass); } }`
	r := Adapt("t.vcl", vcl)
	out := r.Cadishfile
	if strings.Contains(out, "pass header User-Agent") {
		t.Errorf("value-regex collapsed to a bare presence pass (widens bypass to all browsers):\n%s", out)
	}
	if !strings.Contains(out, "TODO(adapt)") {
		t.Errorf("value-regex pass not flagged TODO(adapt):\n%s", out)
	}
	if r.TODOs == 0 {
		t.Errorf("TODOs = 0; the dropped value-regex must be counted in 'need review'")
	}
}

// TestAdaptCookieValueRegexVsPresenceDiffer (A2): a bare presence check and a
// value-regex check on the same header must NOT produce identical output — the
// value-regex form is the one that loses information and must be flagged.
func TestAdaptCookieValueRegexVsPresenceDiffer(t *testing.T) {
	presence := Adapt("p.vcl", `sub vcl_recv { if (req.http.Cookie) { return(pass); } }`).Cadishfile
	valueRe := Adapt("v.vcl", `sub vcl_recv { if (req.http.Cookie ~ "session=") { return(pass); } }`).Cadishfile
	if presence == valueRe {
		t.Errorf("presence and value-regex pass produce IDENTICAL output (A2 silent drop):\n%s", presence)
	}
	if !strings.Contains(presence, "pass header Cookie") {
		t.Errorf("bare presence should still map to `pass header Cookie`:\n%s", presence)
	}
	if !strings.Contains(valueRe, "TODO(adapt)") {
		t.Errorf("value-regex form must be flagged TODO(adapt):\n%s", valueRe)
	}
}

// TestAdaptStatusGE500HitForMiss (A-P1): `beresp.status >= 500 { uncacheable; ttl=5s }`
// maps to hit_for_miss over the discrete 5xx codes (cadish's status selector takes
// explicit codes, not a `>=` range), like `status != 200` maps to `status not 200`.
// The output must be check-clean (never a bogus `status >= 500` token).
func TestAdaptStatusGE500HitForMiss(t *testing.T) {
	vcl := `backend web { .host = "10.0.0.1"; .port = "8080"; }
sub vcl_backend_response { if (beresp.status >= 500) { set beresp.ttl = 5s; set beresp.uncacheable = true; } }`
	errs, out := adaptErrorCount(t, vcl)
	if errs != 0 {
		t.Errorf("adapt output has %d check error(s), want 0:\n%s", errs, out)
	}
	if !strings.Contains(out, "hit_for_miss 5s") {
		t.Errorf("status >= 500 not mapped to hit_for_miss:\n%s", out)
	}
	if !strings.Contains(out, "cache_ttl status 500 501 502 503 504 hit_for_miss 5s") {
		t.Errorf("expected the common 5xx codes expanded:\n%s", out)
	}
}
