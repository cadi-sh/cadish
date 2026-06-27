package vcladapt

import (
	"strings"
	"testing"

	"github.com/cadi-sh/cadish/internal/check"
)

// TestAdaptNegatedPresencePassNotInverted (FIDELITY A, CRITICAL): `if (!req.http.X-Foo)
// return(pass)` means "pass when the header is ABSENT". The positive extractor would emit
// `pass header X-Foo`, which passes on PRESENCE — the exact inverse, a silent bypass
// inversion. The negated form must be flagged TODO(adapt), never mapped to a presence pass.
func TestAdaptNegatedPresencePassNotInverted(t *testing.T) {
	r := Adapt("t.vcl", `sub vcl_recv { if (!req.http.X-Foo) { return(pass); } }`)
	out := r.Cadishfile
	if strings.Contains(out, "pass header X-Foo") {
		t.Errorf("negated presence inverted to a presence pass (passes the requests VCL meant to keep):\n%s", out)
	}
	if !strings.Contains(out, "TODO(adapt)") || r.TODOs == 0 {
		t.Errorf("negated-presence pass must be flagged TODO(adapt):\n%s", out)
	}
}

// TestAdaptAndCompoundPassNotWidened (FIDELITY B, CRITICAL): `if (req.url ~ "/admin" &&
// req.method == "POST") return(pass)` is an INTERSECTION (only POST /admin). The mechanical
// extractors emit each atom as an independent, OR-combined cadish rule, silently WIDENING
// the bypass to every /admin request AND every POST. A `&&` condition must be flagged, not
// split.
func TestAdaptAndCompoundPassNotWidened(t *testing.T) {
	r := Adapt("t.vcl", `sub vcl_recv { if (req.url ~ "/admin" && req.method == "POST") { return(pass); } }`)
	out := r.Cadishfile
	if strings.Contains(out, "@nocache") || strings.Contains(out, "pass method POST") {
		t.Errorf("&& intersection split into independent OR rules (widens the bypass):\n%s", out)
	}
	if !strings.Contains(out, "TODO(adapt)") || r.TODOs == 0 {
		t.Errorf("&& compound pass must be flagged TODO(adapt):\n%s", out)
	}
}

// TestAdaptPureOrPassStillMaps (FIDELITY B, no over-trigger): a pure `||` chain is a union,
// which cadish's OR-combined matchers represent faithfully — it must STILL map mechanically
// and must NOT be swept up by the &&/negation guard.
func TestAdaptPureOrPassStillMaps(t *testing.T) {
	out := Adapt("t.vcl", `sub vcl_recv { if (req.url ~ "/admin/" || req.url ~ "/panel/") { return(pass); } }`).Cadishfile
	if !strings.Contains(out, "@nocache path /admin/* /panel/*") {
		t.Errorf("pure || pass should still map to a union of globs:\n%s", out)
	}
}

// TestAdaptHashSeedsUrlHost (FIDELITY C, CRITICAL): a custom vcl_hash that omits req.url /
// req.http.host (the common `hash_data(req.http.X-Currency)` shape — see the real
// VARNISH_MAIN_ACTUAL.vcl) still keys on url+host in Varnish, because the built-in vcl_hash
// always appends them. cadish's cache_key has no implicit base, so the adapter must seed
// url+host — otherwise every URL/host collides into one bucket (cross-content poisoning).
func TestAdaptHashSeedsUrlHost(t *testing.T) {
	out := Adapt("t.vcl", `sub vcl_hash { hash_data(req.http.X-Currency); }`).Cadishfile
	line := cacheKeyLine(out)
	if line == "" {
		t.Fatalf("no cache_key emitted:\n%s", out)
	}
	if !strings.Contains(line, " url") || !strings.Contains(line, " host") {
		t.Errorf("cache_key dropped the implicit Varnish url+host base (cross-URL/host collision): %q\n%s", line, out)
	}
	if !strings.Contains(line, "header:X-Currency") {
		t.Errorf("cache_key lost the custom X-Currency term: %q", line)
	}
}

// TestAdaptHashUrlOnlySeedsHost (FIDELITY C): `hash_data(req.url)` alone still keys on host
// in Varnish (builtin appends it) — the adapter must add host so vhosts don't share a bucket.
func TestAdaptHashUrlOnlySeedsHost(t *testing.T) {
	out := Adapt("t.vcl", `sub vcl_hash { hash_data(req.url); }`).Cadishfile
	line := cacheKeyLine(out)
	if !strings.Contains(line, "host") {
		t.Errorf("cache_key dropped host (cross-host collision): %q\n%s", line, out)
	}
}

// TestAdaptHashExplicitUrlHostUnchanged (FIDELITY C, no double-add): when the VCL already
// hashes url+host explicitly, the seed is a no-op (no duplicate tokens, no note).
func TestAdaptHashExplicitUrlHostUnchanged(t *testing.T) {
	out := Adapt("t.vcl", `sub vcl_hash { hash_data(req.url); hash_data(req.http.host); hash_data(req.http.X-Currency); }`).Cadishfile
	line := cacheKeyLine(out)
	if !strings.Contains(line, "cache_key url host header:X-Currency") {
		t.Errorf("explicit url+host key changed unexpectedly: %q", line)
	}
	if strings.Count(line, " url") != 1 || strings.Count(line, " host") != 1 {
		t.Errorf("url/host duplicated by the seed: %q", line)
	}
}

// TestAdaptPCRERegexPassFlaggedNotEmitted (FIDELITY D): a PCRE-only match regex
// (backreference) is not valid RE2, the engine cadish's path_regex uses. The adapter must
// flag it TODO(adapt), never emit a `pass path_regex` that makes its own output fail
// `cadish check`.
func TestAdaptPCRERegexPassFlaggedNotEmitted(t *testing.T) {
	vcl := `backend web { .host="1.2.3.4"; .port="80"; }
sub vcl_recv { if (req.url ~ "(foo)\1bar") { return(pass); } }`
	r := Adapt("t.vcl", vcl)
	out := r.Cadishfile
	if strings.Contains(out, "pass path_regex") {
		t.Errorf("PCRE-only regex emitted as a path_regex (cadish check will reject it):\n%s", out)
	}
	if !strings.Contains(out, "TODO(adapt)") || r.TODOs == 0 {
		t.Errorf("PCRE-only regex must be flagged TODO(adapt):\n%s", out)
	}
	// The output must now be check-clean (the offending pattern is a comment, not a directive).
	rep, err := check.CheckSourceSandboxed("adapted.cadish", []byte(out))
	if err != nil {
		t.Fatalf("adapted skeleton does not parse: %v\n%s", err, out)
	}
	if errs, _ := rep.Counts(); errs != 0 {
		t.Errorf("adapt output has %d check error(s), want 0 (PCRE regex must not leak):\n%s", errs, out)
	}
}

// TestAdaptValidRE2RegexStillMaps (FIDELITY D, no over-trigger): a valid RE2 pattern must
// still map to path_regex.
func TestAdaptValidRE2RegexStillMaps(t *testing.T) {
	out := Adapt("t.vcl", `sub vcl_recv { if (req.url ~ "(?i)\.(jpg|png)$") { return(pass); } }`).Cadishfile
	if !strings.Contains(out, `pass path_regex "(?i)\.(jpg|png)$"`) {
		t.Errorf("valid RE2 regex should still map to path_regex:\n%s", out)
	}
}

// TestAdaptOrHostRouteEmitsAllAlternatives (FIDELITY E, CRITICAL): an OR-alternative host
// route `if (req.http.host ~ "a" || req.http.host ~ "b") { set req.backend_hint = x; }` is a
// union — BOTH host "a" and host "b" must route to x. recvRoute used firstMatch and silently
// dropped the 2nd (and further) alternatives with NO TODO, so a whole class of hosts never
// reached the intended backend. A pure || chain of positive host atoms is a union cadish's
// OR-combined matchers represent faithfully, so every alternative must emit a matcher+route.
func TestAdaptOrHostRouteEmitsAllAlternatives(t *testing.T) {
	r := Adapt("t.vcl", `sub vcl_recv { if (req.http.host ~ "static" || req.http.host ~ "images") { set req.backend_hint = imgpool; } }`)
	out := r.Cadishfile
	if !strings.Contains(out, `host_regex "static"`) {
		t.Errorf("first host alternative missing:\n%s", out)
	}
	if !strings.Contains(out, `host_regex "images"`) {
		t.Errorf("second host alternative silently dropped (no route, no TODO):\n%s", out)
	}
	// Both alternatives must route to the intended backend (union == both hosts → imgpool).
	if n := strings.Count(out, "-> imgpool"); n != 2 {
		t.Errorf("expected both alternatives to route to imgpool, got %d route(s):\n%s", n, out)
	}
}

// TestAdaptSingleHostRouteUnchanged (FIDELITY E, no churn): the single-alternative common
// case must stay byte-for-byte as before the OR fix — exactly one matcher and one route.
func TestAdaptSingleHostRouteUnchanged(t *testing.T) {
	out := Adapt("t.vcl", `sub vcl_recv { if (req.http.host ~ "static") { set req.backend_hint = images; } }`).Cadishfile
	if !strings.Contains(out, `@host1 host_regex "static"`) || !strings.Contains(out, "route @host1 -> images") {
		t.Errorf("single host route changed:\n%s", out)
	}
	if strings.Contains(out, "host2") {
		t.Errorf("single host route spuriously emitted a second matcher:\n%s", out)
	}
}

// cacheKeyLine returns the trimmed `cache_key …` line from an adapt skeleton (or "").
func cacheKeyLine(out string) string {
	for _, l := range strings.Split(out, "\n") {
		if t := strings.TrimSpace(l); strings.HasPrefix(t, "cache_key ") {
			return t
		}
	}
	return ""
}
