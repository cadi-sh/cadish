package check

import (
	"strings"
	"testing"
)

// TestNoOpTopLevelSingleLabelDrop (Finding R12) is the silent-drop catch: a comma-less
// wrapped site header whose FIRST address is a bare single-label host (`intranet`) parses
// with `intranet` dropped into the top-level body as a no-op statement — the parser cannot
// hard-reject it (a dot-less label is shape-identical to a directive name). `cadish check`
// must surface it as a loud `noop-top-level-statement` warning.
func TestNoOpTopLevelSingleLabelDrop(t *testing.T) {
	src := []byte("intranet\napi.internal {\n\tcache_key url\n\tcache_ttl default ttl 1m\n}\n")
	r, err := CheckSource("c.cadish", src)
	if err != nil {
		t.Fatalf("CheckSource: %v", err)
	}
	if codes(r)["noop-top-level-statement"] == 0 {
		t.Fatalf("expected a noop-top-level-statement warning for the dropped `intranet`; codes=%v", codes(r))
	}
	var msg string
	for _, d := range r.Diagnostics {
		if d.Code == "noop-top-level-statement" {
			msg = d.Message
		}
	}
	if !strings.Contains(msg, "intranet") || !strings.Contains(msg, "comma") {
		t.Errorf("warning should name the stray token and mention the comma fix; got %q", msg)
	}
}

// TestNoOpTopLevelCleanWhenNoStray confirms a well-formed config (every directive inside a
// site, addresses comma-separated) does NOT warn.
func TestNoOpTopLevelCleanWhenNoStray(t *testing.T) {
	src := []byte("intranet,\napi.internal {\n\tcache_key url\n\tcache_ttl default ttl 1m\n}\n")
	r, err := CheckSource("c.cadish", src)
	if err != nil {
		t.Fatalf("CheckSource: %v", err)
	}
	if n := codes(r)["noop-top-level-statement"]; n != 0 {
		t.Errorf("a comma-separated two-address site must not warn; got %d (%v)", n, codes(r))
	}
}

// TestNoOpTopLevelImportNotFlagged confirms a top-level `import` alongside site blocks is
// NOT flagged: a top-level import is a DOCUMENTED no-op that both run and check IGNORE
// (config.Load splices imports per-site only, never the root body's). Flagging it — and
// suggesting the "comma-separate every address" remedy, which is meaningless for an import —
// contradicts the documented contract. The R12 single-label-address case still warns.
func TestNoOpTopLevelImportNotFlagged(t *testing.T) {
	src := []byte("import shared.cadish\napi.internal {\n\tcache_key url\n\tcache_ttl default ttl 1m\n}\n")
	r, err := CheckSource("c.cadish", src)
	if err != nil {
		t.Fatalf("CheckSource: %v", err)
	}
	if n := codes(r)["noop-top-level-statement"]; n != 0 {
		t.Errorf("a top-level `import` must NOT be flagged as a no-op (documented ignored); got %d (%v)", n, codes(r))
	}
}

// TestNoOpTopLevelFragmentClean confirms a bare importable fragment (NO sites) is NOT
// flagged — its top-level statements are legitimate (it is meant to be `import`ed).
func TestNoOpTopLevelFragmentClean(t *testing.T) {
	src := []byte("@ajax header X-Requested-With XMLHttpRequest\nheader X-Frame-Options DENY\n")
	r, err := CheckSource("frag.cadish", src)
	if err != nil {
		t.Fatalf("CheckSource: %v", err)
	}
	if n := codes(r)["noop-top-level-statement"]; n != 0 {
		t.Errorf("a sites-less fragment must not warn; got %d (%v)", n, codes(r))
	}
}
