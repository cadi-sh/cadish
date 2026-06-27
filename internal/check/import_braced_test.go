package check

import (
	"os"
	"path/filepath"
	"testing"
)

// siteCounts returns the headline counts of a report's single site: matcher count,
// directive count, and per-phase directive counts. It fails if the report does not
// have exactly one site.
func siteCounts(t *testing.T, r *Report) (matchers, directives int, phases map[Phase]int) {
	t.Helper()
	if len(r.Sites) != 1 {
		t.Fatalf("want exactly 1 site, got %d", len(r.Sites))
	}
	s := r.Sites[0]
	return s.MatcherCount, s.DirectiveCount, s.PhaseCounts
}

// TestImportBracedDirectiveMatchesInline pins the bug fix: a fragment containing a
// brace-bodied directive (classify/upstream/tls/cache/geo/device_detect) imported
// into a site reports the SAME matcher/directive/per-phase counts — and the same
// clean diagnostics — as the identical content placed inline. Before the fix the
// fragment was flattened, surfacing the block's body keywords as unknown-directive
// / compile-error and inflating the directive/phase counts.
func TestImportBracedDirectiveMatchesInline(t *testing.T) {
	cases := []struct {
		name string
		frag string
	}{
		{"classify", "@verified header X-V 1\nclassify {age} {\n  when @verified -> ok\n  default -> open\n}\ncache_key {age}\n"},
		{"upstream", "upstream web {\n  to http://127.0.0.1:8080\n  timeout connect 5s\n}\n"},
		{"tls", "tls {\n  acme ops@example.com\n}\n"},
		{"cache", "cache {\n  ram 10GiB\n  disk /var/cache/cadish 2TiB\n}\n"},
		{"geo", "geo {\n  source header CF-IPCountry\n  trust_proxy 10.0.0.0/8\n}\ncache_key {geo}\n"},
		{"device_detect", "device_detect {\n  mobile ua_contains Mobile Android\n  default desktop\n}\ncache_key {device}\n"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// Inline: the fragment content placed directly in the site body.
			inlineSrc := []byte("example.com {\n" + tc.frag + "}\n")
			inlineRep, err := CheckSource("inline.cadish", inlineSrc)
			if err != nil {
				t.Fatalf("CheckSource inline: %v", err)
			}
			// Imported: the same content in a fragment, spliced via `import`.
			dir := t.TempDir()
			if err := os.WriteFile(filepath.Join(dir, "frag.cadish"), []byte(tc.frag), 0o600); err != nil {
				t.Fatalf("write frag: %v", err)
			}
			root := filepath.Join(dir, "root.Cadishfile")
			if err := os.WriteFile(root, []byte("example.com {\n  import frag.cadish\n}\n"), 0o600); err != nil {
				t.Fatalf("write root: %v", err)
			}
			importRep, err := Check(root)
			if err != nil {
				t.Fatalf("Check import: %v", err)
			}

			// No flattening symptoms in the imported form.
			ic := codes(importRep)
			if ic["unknown-directive"] != 0 || ic["compile-error"] != 0 || ic["bad-import"] != 0 {
				t.Errorf("imported fragment produced flatten symptoms: %s", render(t, importRep))
			}

			im, id, ip := siteCounts(t, inlineRep)
			xm, xd, xp := siteCounts(t, importRep)
			if im != xm {
				t.Errorf("MatcherCount: inline %d != import %d", im, xm)
			}
			if id != xd {
				t.Errorf("DirectiveCount: inline %d != import %d", id, xd)
			}
			for _, p := range PhaseOrder {
				if ip[p] != xp[p] {
					t.Errorf("PhaseCount[%s]: inline %d != import %d", p, ip[p], xp[p])
				}
			}
		})
	}
}

// realMultiBlockConfig is a realistic config exercising every brace-bodied
// directive plus matchers and per-phase directives. The "# === " banners delimit
// the fragments the round-trip test splits it into.
const realMultiBlockConfig = `example.com, *.example.com {
# === 00-tls ===
tls {
  acme ops@example.com
}
# === 01-upstreams ===
upstream web {
  to http://127.0.0.1:8080
  timeout connect 5s
}
upstream images {
  to https://static.example.com
}
# === 02-cache ===
cache {
  ram 10GiB
  disk /var/cache/cadish 2TiB
}
# === 03-classify ===
@verified header X-Verified 1
classify {age} {
  when @verified -> ok
  default -> open
}
# === 04-geo-device ===
geo {
  source header CF-IPCountry
}
device_detect {
  mobile ua_contains Mobile Android
  default desktop
}
# === 05-key ===
cache_key url host {age} {geo} {device}
# === 06-deliver ===
@static host_regex ^static
pass @static
header +X-Cache X-Cache
strip_cookies path /
}
`

// TestImportRoundTripMultiBlock splits a real multi-block config at its "# === "
// section banners into ordered fragments under conf.d/, re-imports them with
// `import conf.d/*.cadish`, and asserts the matcher/directive/per-phase counts —
// and clean diagnostics — match the single-file version exactly (behavior
// preservation across the split).
func TestImportRoundTripMultiBlock(t *testing.T) {
	// Single-file baseline.
	single, err := CheckSource("single.Cadishfile", []byte(realMultiBlockConfig))
	if err != nil {
		t.Fatalf("CheckSource single: %v", err)
	}

	// Split the site body into ordered fragments at the "# === " banners.
	dir := t.TempDir()
	confd := filepath.Join(dir, "conf.d")
	if err := os.MkdirAll(confd, 0o755); err != nil {
		t.Fatalf("mkdir conf.d: %v", err)
	}
	body := bodyOf(t, realMultiBlockConfig)
	fragments := splitBanners(body)
	if len(fragments) < 6 {
		t.Fatalf("expected at least 6 fragments, got %d", len(fragments))
	}
	for i, frag := range fragments {
		name := filepath.Join(confd, padIndex(i)+".cadish")
		if err := os.WriteFile(name, []byte(frag), 0o600); err != nil {
			t.Fatalf("write fragment %d: %v", i, err)
		}
	}
	root := filepath.Join(dir, "root.Cadishfile")
	rootSrc := "example.com, *.example.com {\n  import conf.d/*.cadish\n}\n"
	if err := os.WriteFile(root, []byte(rootSrc), 0o600); err != nil {
		t.Fatalf("write root: %v", err)
	}
	split, err := Check(root)
	if err != nil {
		t.Fatalf("Check split: %v", err)
	}

	sc := codes(split)
	if sc["unknown-directive"] != 0 || sc["compile-error"] != 0 || sc["bad-import"] != 0 || sc["missing-import"] != 0 {
		t.Fatalf("split config produced errors: %s", render(t, split))
	}

	sm, sd, sp := siteCounts(t, single)
	xm, xd, xp := siteCounts(t, split)
	if sm != xm {
		t.Errorf("MatcherCount: single %d != split %d", sm, xm)
	}
	if sd != xd {
		t.Errorf("DirectiveCount: single %d != split %d", sd, xd)
	}
	for _, p := range PhaseOrder {
		if sp[p] != xp[p] {
			t.Errorf("PhaseCount[%s]: single %d != split %d", p, sp[p], xp[p])
		}
	}
}

// bodyOf extracts the inner body (between the first "{" and the final "}") of the
// single-site config so it can be split into import fragments.
func bodyOf(t *testing.T, src string) string {
	t.Helper()
	open := -1
	for i := 0; i < len(src); i++ {
		if src[i] == '{' {
			open = i
			break
		}
	}
	closeIdx := -1
	for i := len(src) - 1; i >= 0; i-- {
		if src[i] == '}' {
			closeIdx = i
			break
		}
	}
	if open < 0 || closeIdx <= open {
		t.Fatalf("could not locate site body braces in config")
	}
	return src[open+1 : closeIdx]
}

// splitBanners splits a site body into chunks at each "# === " banner line. Each
// chunk (including its leading banner comment) becomes one fragment.
func splitBanners(body string) []string {
	var out []string
	var cur []byte
	flush := func() {
		if len(cur) > 0 {
			out = append(out, string(cur))
			cur = nil
		}
	}
	for _, line := range splitLines(body) {
		if hasPrefixTrim(line, "# === ") {
			flush()
		}
		cur = append(cur, line...)
		cur = append(cur, '\n')
	}
	flush()
	return out
}

func splitLines(s string) []string {
	var out []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == '\n' {
			out = append(out, s[start:i])
			start = i + 1
		}
	}
	if start < len(s) {
		out = append(out, s[start:])
	}
	return out
}

func hasPrefixTrim(line, prefix string) bool {
	i := 0
	for i < len(line) && (line[i] == ' ' || line[i] == '\t') {
		i++
	}
	return len(line)-i >= len(prefix) && line[i:i+len(prefix)] == prefix
}

func padIndex(i int) string {
	if i < 10 {
		return "0" + string(rune('0'+i))
	}
	return string(rune('0'+i/10)) + string(rune('0'+i%10))
}
