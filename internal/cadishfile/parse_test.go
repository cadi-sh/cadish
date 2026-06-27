package cadishfile

import (
	"strings"
	"testing"
)

func mustParse(t *testing.T, src string) *File {
	t.Helper()
	f, err := Parse("test.cadish", []byte(src))
	if err != nil {
		t.Fatalf("Parse(%q) unexpected error: %v", src, err)
	}
	return f
}

func TestParseSiteBasic(t *testing.T) {
	f := mustParse(t, `example.com {
    cache_key url host
}
`)
	if len(f.Sites) != 1 {
		t.Fatalf("sites = %d, want 1", len(f.Sites))
	}
	s := f.Sites[0]
	if len(s.Addresses) != 1 || s.Addresses[0] != "example.com" {
		t.Errorf("addresses = %v, want [example.com]", s.Addresses)
	}
	if len(s.Body) != 1 {
		t.Fatalf("body = %d, want 1", len(s.Body))
	}
	d, ok := s.Body[0].(*Directive)
	if !ok {
		t.Fatalf("body[0] type = %T, want *Directive", s.Body[0])
	}
	if d.Name != "cache_key" {
		t.Errorf("directive name = %q, want cache_key", d.Name)
	}
	if len(d.Args) != 2 || d.Args[0].Raw != "url" || d.Args[1].Raw != "host" {
		t.Errorf("args = %v, want [url host]", d.Args)
	}
}

func TestParseMultipleAddresses(t *testing.T) {
	f := mustParse(t, "a.com, *.a.com {\n}\n")
	s := f.Sites[0]
	want := []string{"a.com", "*.a.com"}
	if len(s.Addresses) != len(want) {
		t.Fatalf("addresses = %v, want %v", s.Addresses, want)
	}
	for i := range want {
		if s.Addresses[i] != want[i] {
			t.Errorf("address %d = %q, want %q", i, s.Addresses[i], want[i])
		}
	}
}

// TestParseMultiLineAddresses guards SPEC-MULTILINE-ADDR: a site whose address
// list spans multiple lines (each wrapped line ending in a trailing comma) must
// capture EVERY address, not just the last line. Before the dispatcher fix, the
// earlier lines were silently mis-parsed as top-level statements and only the
// last line's addresses survived — which registered the static TLS cert for too
// few domains and caused a production 525 at the live cutover.
func TestParseMultiLineAddresses(t *testing.T) {
	src := "a.example.com, *.a.example.com,\nb.example.com, *.b.example.com {\n}\n"
	f := mustParse(t, src)
	if len(f.Sites) != 1 {
		t.Fatalf("sites = %d, want 1 (multi-line address list must be ONE site)", len(f.Sites))
	}
	if len(f.Body) != 0 {
		t.Fatalf("top-level Body = %d, want 0 (no address line may leak into Body): %#v", len(f.Body), f.Body)
	}
	want := []string{"a.example.com", "*.a.example.com", "b.example.com", "*.b.example.com"}
	got := f.Sites[0].Addresses
	if len(got) != len(want) {
		t.Fatalf("addresses = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("address %d = %q, want %q", i, got[i], want[i])
		}
	}
}

// TestParseMultiLineAddressesAfterGlobalBlock ensures a leading global-options
// block still parses AND the following multi-line-address site captures all
// addresses — the global "{ ... }" must not be confused with a site header and
// must not swallow the address lines.
func TestParseMultiLineAddressesAfterGlobalBlock(t *testing.T) {
	src := "{\n\tadmin off\n}\na.example.com, *.a.example.com,\nb.example.com {\n\tcache_key url\n}\n"
	f := mustParse(t, src)
	if f.Global == nil {
		t.Fatalf("Global = nil, want the leading options block parsed")
	}
	if len(f.Global.Body) != 1 {
		t.Fatalf("Global.Body = %d, want 1 (admin off)", len(f.Global.Body))
	}
	if len(f.Sites) != 1 {
		t.Fatalf("sites = %d, want 1", len(f.Sites))
	}
	want := []string{"a.example.com", "*.a.example.com", "b.example.com"}
	got := f.Sites[0].Addresses
	if len(got) != len(want) {
		t.Fatalf("addresses = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("address %d = %q, want %q", i, got[i], want[i])
		}
	}
}

// TestParseTopLevelStatementNotAbsorbed ensures the multi-line dispatch fix does
// NOT mis-absorb a genuine top-level statement (an importable bare directive on
// its own line) into a following site header. The directive ends with a newline
// and no trailing comma, so it must stay in Body.
func TestParseTopLevelStatementNotAbsorbed(t *testing.T) {
	src := "header_up Host {host}\nexample.com {\n\tcache_key url\n}\n"
	f := mustParse(t, src)
	if len(f.Body) != 1 {
		t.Fatalf("top-level Body = %d, want 1 (the bare directive): %#v", len(f.Body), f.Body)
	}
	d, ok := f.Body[0].(*Directive)
	if !ok || d.Name != "header_up" {
		t.Fatalf("Body[0] = %#v, want directive header_up", f.Body[0])
	}
	if len(f.Sites) != 1 || len(f.Sites[0].Addresses) != 1 || f.Sites[0].Addresses[0] != "example.com" {
		t.Fatalf("sites = %#v, want one site [example.com]", f.Sites)
	}
}

// TestParseTrailingCommaDirectiveNotAbsorbed (Finding 2) guards that a top-level
// directive whose LAST argument happens to end in a comma is NOT mistaken for a
// wrapped address list and absorbed into the following site header. Only a bare
// address-shaped run may continue across a newline on a trailing comma.
func TestParseTrailingCommaDirectiveNotAbsorbed(t *testing.T) {
	src := "header_down X-Foo bar,\nexample.com {\n\tcache_key url\n}\n"
	f := mustParse(t, src)
	if len(f.Body) != 1 {
		t.Fatalf("top-level Body = %d, want 1 (the header_down directive): %#v", len(f.Body), f.Body)
	}
	d, ok := f.Body[0].(*Directive)
	if !ok || d.Name != "header_down" {
		t.Fatalf("Body[0] = %#v, want directive header_down", f.Body[0])
	}
	if len(f.Sites) != 1 || len(f.Sites[0].Addresses) != 1 || f.Sites[0].Addresses[0] != "example.com" {
		t.Fatalf("sites = %#v, want one site [example.com]", f.Sites)
	}
}

// TestParseQuotedCommaNotContinued (Finding 2) guards that a QUOTED arg ending in a
// comma (content, never an address separator) does not continue the address run.
func TestParseQuotedCommaNotContinued(t *testing.T) {
	src := "respond \"hi,\"\nexample.com {\n\tcache_key url\n}\n"
	f := mustParse(t, src)
	if len(f.Body) != 1 {
		t.Fatalf("top-level Body = %d, want 1 (the respond directive): %#v", len(f.Body), f.Body)
	}
	d, ok := f.Body[0].(*Directive)
	if !ok || d.Name != "respond" {
		t.Fatalf("Body[0] = %#v, want directive respond", f.Body[0])
	}
	if len(f.Sites) != 1 || len(f.Sites[0].Addresses) != 1 || f.Sites[0].Addresses[0] != "example.com" {
		t.Fatalf("sites = %#v, want one site [example.com]", f.Sites)
	}
}

// TestParseUnseparatedMultiLineAddressesError (Finding 3) guards that a comma-LESS
// multi-line site-address list (a wrapped header missing its trailing commas — the
// silent-525 outage shape) is a LOUD positioned parse error, not a silently
// truncated 1-address site.
func TestParseUnseparatedMultiLineAddressesError(t *testing.T) {
	src := "a.example.com\nb.example.com {\n\tcache_key url\n}\n"
	_, err := Parse("f.cadish", []byte(src))
	if err == nil {
		t.Fatalf("expected a parse error for the comma-less multi-line address list, got nil")
	}
	if !strings.Contains(err.Error(), "comma") {
		t.Fatalf("error = %q, want it to mention comma-separating wrapped addresses", err.Error())
	}
	pe, ok := err.(*ParseError)
	if !ok {
		t.Fatalf("error type = %T, want *ParseError", err)
	}
	if pe.Line != 1 {
		t.Errorf("error line = %d, want 1 (the first dropped address)", pe.Line)
	}
}

// TestParseCommaFirstSpaceWrappedAddressesError (Finding 1, HIGH) guards the
// comma-on-first-address + space-separated wrap shape:
//
//	example.com, www.example.com
//	api.example.com {
//	  reverse_proxy backend:8080
//	}
//
// The first line comma-separates its first address but the LAST word on the line
// (www.example.com) carries NO trailing comma, so startsSiteBlock's
// comma-after-every-element continuation abstains. Before the fix
// unseparatedAddrWrap ALSO abstained — it short-circuited on the first word's
// trailing comma — so the line fell through to a bogus top-level Body directive and
// example.com / www.example.com were SILENTLY dropped; the static TLS cert then
// covered too few hosts (the SNI/525 outage). It must instead be a LOUD positioned
// parse error.
func TestParseCommaFirstSpaceWrappedAddressesError(t *testing.T) {
	src := "example.com, www.example.com\napi.example.com {\n\treverse_proxy backend:8080\n}\n"
	_, err := Parse("f.cadish", []byte(src))
	if err == nil {
		t.Fatalf("expected a parse error for the comma-first space-wrapped address list, got nil (silent address drop)")
	}
	if !strings.Contains(err.Error(), "comma") {
		t.Fatalf("error = %q, want it to mention comma-separating wrapped addresses", err.Error())
	}
	pe, ok := err.(*ParseError)
	if !ok {
		t.Fatalf("error type = %T, want *ParseError", err)
	}
	if pe.Line != 1 {
		t.Errorf("error line = %d, want 1 (the first dropped address)", pe.Line)
	}
}

// TestParseSingleLabelWrappedAddress (Finding 1, HIGH) guards that a comma-wrapped
// multi-line site header whose NON-LAST line is a bare single-label host (a valid
// cadish site/listen address — see config/addr.go) captures EVERY address. A prior
// allAddrShaped gate rejected single-label hosts as "not address-shaped", refused to
// cross the trailing-comma newline, and silently dropped the earlier line(s) as no-op
// top-level statements — re-introducing the silent last-line-only truncation / 525
// shape. The trailing comma is the address-list continuation signal regardless of
// label count.
func TestParseSingleLabelWrappedAddress(t *testing.T) {
	f := mustParse(t, "intranet,\nexample.com {\n\tcache_key url\n}\n")
	if len(f.Sites) != 1 {
		t.Fatalf("sites = %d, want 1 (single-label wrapped header must be ONE site)", len(f.Sites))
	}
	if len(f.Body) != 0 {
		t.Fatalf("top-level Body = %d, want 0 (no address line may leak into Body): %#v", len(f.Body), f.Body)
	}
	want := []string{"intranet", "example.com"}
	got := f.Sites[0].Addresses
	if len(got) != len(want) {
		t.Fatalf("addresses = %v, want %v (intranet must NOT be silently lost)", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("address %d = %q, want %q", i, got[i], want[i])
		}
	}
}

// TestParseSingleLabelMidWrappedAddress (Finding 1, HIGH) guards a single-label host
// in the MIDDLE of a comma-wrapped run: a.example.com,\nintranet,\nexample.com {…}
// must yield all three addresses with nothing leaked to Body.
func TestParseSingleLabelMidWrappedAddress(t *testing.T) {
	f := mustParse(t, "a.example.com,\nintranet,\nexample.com {\n}\n")
	if len(f.Sites) != 1 {
		t.Fatalf("sites = %d, want 1", len(f.Sites))
	}
	if len(f.Body) != 0 {
		t.Fatalf("top-level Body = %d, want 0: %#v", len(f.Body), f.Body)
	}
	want := []string{"a.example.com", "intranet", "example.com"}
	got := f.Sites[0].Addresses
	if len(got) != len(want) {
		t.Fatalf("addresses = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("address %d = %q, want %q", i, got[i], want[i])
		}
	}
}

// TestParseSpaceSeparatedWrappedAddressError (HIGH, silent) guards the
// space-separated wrapped-address hole: a wrapped (non-final) site-header line whose
// 2+ whitespace-separated addresses end with only the LAST token carrying a "," —
// `example.com www.example.com,\napi.example.com {…}`. The conservative continuation
// rule (comma after EVERY element) correctly refuses to claim this as a site, but the
// earlier addresses must NOT silently leak into top-level Body (the silent-525 hole):
// they must produce a LOUD positioned parse error instead.
func TestParseSpaceSeparatedWrappedAddressError(t *testing.T) {
	src := "example.com www.example.com,\napi.example.com {\n\tcache_key url\n}\n"
	_, err := Parse("f.cadish", []byte(src))
	if err == nil {
		t.Fatalf("expected a loud parse error for the space-separated wrapped address list, got nil (addresses silently dropped into Body)")
	}
	if !strings.Contains(err.Error(), "comma") {
		t.Fatalf("error = %q, want it to mention comma-separating wrapped addresses", err.Error())
	}
	pe, ok := err.(*ParseError)
	if !ok {
		t.Fatalf("error type = %T, want *ParseError", err)
	}
	if pe.Line != 1 {
		t.Errorf("error line = %d, want 1 (the first dropped address)", pe.Line)
	}
}

// TestParseStandaloneCommaWrappedAddressError guards the standalone-comma wrap form
// `a.example.com ,\nb.example.com {…}`: the first line's address must not be silently
// dropped — it must be a loud positioned error (or a correct full parse), never a
// silent Body directive.
func TestParseStandaloneCommaWrappedAddressError(t *testing.T) {
	src := "a.example.com ,\nb.example.com {\n\tcache_key url\n}\n"
	f, err := Parse("f.cadish", []byte(src))
	if err != nil {
		// Loud error path: acceptable.
		if !strings.Contains(err.Error(), "comma") {
			t.Fatalf("error = %q, want it to mention comma", err.Error())
		}
		return
	}
	// Full-parse path: both addresses must be captured, nothing leaked to Body.
	if len(f.Body) != 0 {
		t.Fatalf("top-level Body = %d, want 0 (no address may silently leak): %#v", len(f.Body), f.Body)
	}
	if len(f.Sites) != 1 || len(f.Sites[0].Addresses) != 2 {
		t.Fatalf("sites = %#v, want one site with both addresses", f.Sites)
	}
}

// TestParseTopLevelDirectiveWithDottedArgsNotErrored guards that a real top-level
// directive whose args happen to be dotted (`tls cert.example.com key.pem`) before a
// site is NOT mistaken for a mis-wrapped address list: it begins with a bare directive
// NAME (no dot), so it must stay a statement, never a false error.
func TestParseTopLevelDirectiveWithDottedArgsNotErrored(t *testing.T) {
	src := "tls cert.example.com key.pem\nexample.com {\n\tcache_key url\n}\n"
	f := mustParse(t, src)
	if len(f.Body) != 1 {
		t.Fatalf("top-level Body = %d, want 1 (the tls directive): %#v", len(f.Body), f.Body)
	}
	d, ok := f.Body[0].(*Directive)
	if !ok || d.Name != "tls" {
		t.Fatalf("Body[0] = %#v, want directive tls", f.Body[0])
	}
	if len(f.Sites) != 1 || len(f.Sites[0].Addresses) != 1 || f.Sites[0].Addresses[0] != "example.com" {
		t.Fatalf("sites = %#v, want one site [example.com]", f.Sites)
	}
}

// TestParsePortFirstUnseparatedWrapError (Finding 2, MED) guards the comma-less wrap
// whose FIRST element is a bare `:port` listen form (`:8080`) — one of the most common
// cadish/Caddy address shapes. The prior `clearlyHostnameShaped` gate returned true only
// for a dotted host or "localhost", so a `:port` first word made unseparatedAddrWrap
// ABSTAIN → the first address was silently parsed as a no-op top-level Body directive and
// the site bound only `example.com` (a lost/narrowed listener that passed `cadish check`
// with no diagnostic). It must be a LOUD positioned parse error.
func TestParsePortFirstUnseparatedWrapError(t *testing.T) {
	src := ":8080\nexample.com {\n\tcache_key url\n}\n"
	_, err := Parse("f.cadish", []byte(src))
	if err == nil {
		t.Fatalf("expected a loud parse error for the comma-less `:port` wrap, got nil (listener silently dropped)")
	}
	if !strings.Contains(err.Error(), "comma") {
		t.Fatalf("error = %q, want it to mention comma-separating wrapped addresses", err.Error())
	}
	pe, ok := err.(*ParseError)
	if !ok {
		t.Fatalf("error type = %T, want *ParseError", err)
	}
	if pe.Line != 1 {
		t.Errorf("error line = %d, want 1 (the first dropped address)", pe.Line)
	}
}

// TestParseIPv6FirstUnseparatedWrapError (Finding 2, MED) guards the comma-less wrap
// whose FIRST element is a bracketed IPv6 literal (`[::1]:8080`): same silent-drop hole
// as the `:port` shape — a directive name can never begin with "[", so failing it loudly
// is false-positive-safe.
func TestParseIPv6FirstUnseparatedWrapError(t *testing.T) {
	src := "[::1]:8080\nexample.com {\n\tcache_key url\n}\n"
	_, err := Parse("f.cadish", []byte(src))
	if err == nil {
		t.Fatalf("expected a loud parse error for the comma-less `[IPv6]:port` wrap, got nil (listener silently dropped)")
	}
	if !strings.Contains(err.Error(), "comma") {
		t.Fatalf("error = %q, want it to mention comma-separating wrapped addresses", err.Error())
	}
	pe, ok := err.(*ParseError)
	if !ok {
		t.Fatalf("error type = %T, want *ParseError", err)
	}
	if pe.Line != 1 {
		t.Errorf("error line = %d, want 1 (the first dropped address)", pe.Line)
	}
}

// TestParsePortIPv6CommaWrapStillParsesBoth (Finding 2 regression) confirms the
// comma-TERMINATED variants of the same shapes still parse BOTH addresses as one site —
// the broadened loud-error trigger must not over-fire on a correctly comma-separated
// wrapped list.
func TestParsePortIPv6CommaWrapStillParsesBoth(t *testing.T) {
	for _, tc := range []struct {
		name string
		src  string
		want []string
	}{
		{"port", ":8080,\nexample.com {\n\tcache_key url\n}\n", []string{":8080", "example.com"}},
		{"ipv6", "[::1]:8080,\nexample.com {\n}\n", []string{"[::1]:8080", "example.com"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := mustParse(t, tc.src)
			if len(f.Sites) != 1 || len(f.Body) != 0 {
				t.Fatalf("sites=%d body=%d, want 1/0 (both addresses one site, nothing leaked)", len(f.Sites), len(f.Body))
			}
			got := f.Sites[0].Addresses
			if len(got) != len(tc.want) {
				t.Fatalf("addresses = %v, want %v", got, tc.want)
			}
			for i := range tc.want {
				if got[i] != tc.want[i] {
					t.Errorf("address %d = %q, want %q", i, got[i], tc.want[i])
				}
			}
		})
	}
}

// TestParseDotlessHostPortUnseparatedWrapError (Finding 4) guards the comma-less wrap
// whose FIRST element is a DOT-LESS `host:port` (`cache:6081`, `localhost:8080`): the
// colon makes it unambiguously an address (no directive name can contain ":"), so a
// forgotten comma before the next address header must fail LOUDLY instead of silently
// dropping the leading listener.
func TestParseDotlessHostPortUnseparatedWrapError(t *testing.T) {
	for _, tc := range []struct {
		name string
		src  string
	}{
		{"named-host-port", "cache:6081\nexample.com {\n\tcache_key url\n}\n"},
		{"localhost-port", "localhost:8080\nexample.com {\n\tcache_key url\n}\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Parse("f.cadish", []byte(tc.src))
			if err == nil {
				t.Fatalf("expected a loud parse error for the comma-less dot-less host:port wrap, got nil (listener silently dropped)")
			}
			if !strings.Contains(err.Error(), "comma") {
				t.Fatalf("error = %q, want it to mention comma-separating wrapped addresses", err.Error())
			}
			pe, ok := err.(*ParseError)
			if !ok {
				t.Fatalf("error type = %T, want *ParseError", err)
			}
			if pe.Line != 1 {
				t.Errorf("error line = %d, want 1 (the first dropped address)", pe.Line)
			}
		})
	}
}

// TestParseDotlessHostPortCommaWrapStillParsesBoth (Finding 4 regression) confirms the
// comma-TERMINATED variant still parses BOTH addresses as one site — the broadened
// trigger must not over-fire on a correctly comma-separated wrap.
func TestParseDotlessHostPortCommaWrapStillParsesBoth(t *testing.T) {
	f := mustParse(t, "cache:6081,\nexample.com {\n}\n")
	if len(f.Sites) != 1 || len(f.Body) != 0 {
		t.Fatalf("sites=%d body=%d, want 1/0 (both addresses one site)", len(f.Sites), len(f.Body))
	}
	want := []string{"cache:6081", "example.com"}
	got := f.Sites[0].Addresses
	if len(got) != len(want) {
		t.Fatalf("addresses = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("address %d = %q, want %q", i, got[i], want[i])
		}
	}
}

// TestParseSemicolonSeparatedAddressWrapError (Finding 5) guards the silent drop when an
// address-shaped leading run terminates at a `;` statement separator immediately before
// an address header (`example.com; api.example.com {…}`). The `;` breaks the address-run
// walk just like a newline, so the loud comma-less-wrap error must also fire there rather
// than dropping the leading `example.com` listener.
func TestParseSemicolonSeparatedAddressWrapError(t *testing.T) {
	for _, tc := range []struct {
		name string
		src  string
	}{
		{"semicolon-same-line", "example.com; api.example.com {\n}\n"},
		{"semicolon-then-newline", "example.com;\napi.example.com {\n}\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Parse("f.cadish", []byte(tc.src))
			if err == nil {
				t.Fatalf("expected a loud parse error for the `;`-separated address wrap, got nil (listener silently dropped)")
			}
			if !strings.Contains(err.Error(), "comma") {
				t.Fatalf("error = %q, want it to mention comma-separating wrapped addresses", err.Error())
			}
			pe, ok := err.(*ParseError)
			if !ok {
				t.Fatalf("error type = %T, want *ParseError", err)
			}
			if pe.Line != 1 {
				t.Errorf("error line = %d, want 1 (the first dropped address)", pe.Line)
			}
		})
	}
}

// TestParseSingleLineAddressesUnchanged is a guard that the common single-line
// case (the overwhelming majority of real configs) parses identically after the
// dispatcher change.
func TestParseSingleLineAddressesUnchanged(t *testing.T) {
	f := mustParse(t, "a.example.com, *.a.example.com, b.example.com {\n}\n")
	if len(f.Sites) != 1 || len(f.Body) != 0 {
		t.Fatalf("sites=%d body=%d, want 1/0", len(f.Sites), len(f.Body))
	}
	want := []string{"a.example.com", "*.a.example.com", "b.example.com"}
	got := f.Sites[0].Addresses
	if len(got) != len(want) {
		t.Fatalf("addresses = %v, want %v", got, want)
	}
}

func TestParseMatcherDef(t *testing.T) {
	f := mustParse(t, `x {
    @nocache path /a/* /b/*
    @ajax header X-Requested-With XMLHttpRequest
    @static host_regex ^static
}
`)
	s := f.Sites[0]
	if len(s.Body) != 3 {
		t.Fatalf("body = %d, want 3", len(s.Body))
	}
	m0 := s.Body[0].(*MatcherDef)
	if m0.Name != "nocache" || m0.Type != "path" {
		t.Errorf("m0 = @%s %s, want @nocache path", m0.Name, m0.Type)
	}
	if len(m0.Args) != 2 || m0.Args[0].Raw != "/a/*" || m0.Args[1].Raw != "/b/*" {
		t.Errorf("m0 args = %v", m0.Args)
	}
	m1 := s.Body[1].(*MatcherDef)
	if m1.Name != "ajax" || m1.Type != "header" || len(m1.Args) != 2 {
		t.Errorf("m1 = @%s %s args=%v", m1.Name, m1.Type, m1.Args)
	}
	m2 := s.Body[2].(*MatcherDef)
	if m2.Name != "static" || m2.Type != "host_regex" {
		t.Errorf("m2 = @%s %s", m2.Name, m2.Type)
	}
}

func TestParseNestedBlocks(t *testing.T) {
	f := mustParse(t, `x {
    tls {
        acme me@example.com
    }
    upstream web {
        to https://x
        sticky by cookie PHPSESSID else client_ip
    }
}
`)
	s := f.Sites[0]
	tls := s.Body[0].(*Directive)
	if tls.Name != "tls" || !tls.HasBlock {
		t.Fatalf("tls = %+v", tls)
	}
	if len(tls.Block) != 1 {
		t.Fatalf("tls block = %d, want 1", len(tls.Block))
	}
	acme := tls.Block[0].(*Directive)
	if acme.Name != "acme" || len(acme.Args) != 1 || acme.Args[0].Raw != "me@example.com" {
		t.Errorf("acme = %+v", acme)
	}
	up := s.Body[1].(*Directive)
	if up.Name != "upstream" || len(up.Args) != 1 || up.Args[0].Raw != "web" {
		t.Errorf("upstream args = %v", up.Args)
	}
	if len(up.Block) != 2 {
		t.Errorf("upstream block = %d, want 2", len(up.Block))
	}
}

func TestParseArgKinds(t *testing.T) {
	f := mustParse(t, `x {
    route @static images
    purge token {$PURGE_TOKEN} {http.X-Foo} plain "quoted @notref"
}
`)
	s := f.Sites[0]
	route := s.Body[0].(*Directive)
	if route.Args[0].Kind != ArgMatcherRef {
		t.Errorf("@static kind = %v, want matcher-ref", route.Args[0].Kind)
	}
	if route.Args[1].Kind != ArgLiteral {
		t.Errorf("images kind = %v, want literal", route.Args[1].Kind)
	}
	purge := s.Body[1].(*Directive)
	kinds := map[string]ArgKind{
		"{$PURGE_TOKEN}": ArgPlaceholder,
		"{http.X-Foo}":   ArgPlaceholder,
		"plain":          ArgLiteral,
		"quoted @notref": ArgLiteral, // quoted, so not a matcher ref
	}
	for _, a := range purge.Args {
		if want, ok := kinds[a.Raw]; ok && a.Kind != want {
			t.Errorf("arg %q kind = %v, want %v", a.Raw, a.Kind, want)
		}
	}
}

func TestParseSemicolonSeparator(t *testing.T) {
	f := mustParse(t, "x {\n cache { ram 10GiB; disk /x 2TiB }\n}\n")
	cache := f.Sites[0].Body[0].(*Directive)
	if len(cache.Block) != 2 {
		t.Fatalf("cache block = %d, want 2 (ram, disk)", len(cache.Block))
	}
	if cache.Block[0].(*Directive).Name != "ram" {
		t.Errorf("block[0] = %q, want ram", cache.Block[0].(*Directive).Name)
	}
	if cache.Block[1].(*Directive).Name != "disk" {
		t.Errorf("block[1] = %q, want disk", cache.Block[1].(*Directive).Name)
	}
}

func TestParseTopLevelFragment(t *testing.T) {
	// A sub-config (importable fragment) has no site wrapper.
	f := mustParse(t, "@nocache path /a/*\n@ajax header X Y\n")
	if len(f.Sites) != 0 {
		t.Errorf("sites = %d, want 0", len(f.Sites))
	}
	if len(f.Body) != 2 {
		t.Fatalf("body = %d, want 2", len(f.Body))
	}
	if f.Body[0].(*MatcherDef).Name != "nocache" {
		t.Errorf("body[0] = %v", f.Body[0])
	}
}

func TestParseGlobalOptions(t *testing.T) {
	f := mustParse(t, "{\n    debug on\n}\nexample.com {\n}\n")
	if f.Global == nil {
		t.Fatal("expected a global options block")
	}
	if len(f.Global.Body) != 1 {
		t.Errorf("global body = %d, want 1", len(f.Global.Body))
	}
	if len(f.Sites) != 1 {
		t.Errorf("sites = %d, want 1", len(f.Sites))
	}
}

func TestParseEmptyBlock(t *testing.T) {
	f := mustParse(t, "x {\n}\n")
	s := f.Sites[0]
	if s.Body == nil {
		t.Error("empty site body should be non-nil empty slice")
	}
	if len(s.Body) != 0 {
		t.Errorf("body = %d, want 0", len(s.Body))
	}
}

func TestParseDirectiveEmptyBlockVsNoBlock(t *testing.T) {
	f := mustParse(t, "x {\n a\n b { }\n}\n")
	s := f.Sites[0]
	a := s.Body[0].(*Directive)
	if a.HasBlock {
		t.Error("directive 'a' should have no block")
	}
	b := s.Body[1].(*Directive)
	if !b.HasBlock {
		t.Error("directive 'b' should have an (empty) block")
	}
	if b.Block == nil || len(b.Block) != 0 {
		t.Errorf("directive 'b' block = %v, want non-nil empty", b.Block)
	}
}

func TestParseErrors(t *testing.T) {
	tests := []struct {
		name    string
		src     string
		wantSub string
		line    int
		col     int
	}{
		{
			name:    "unexpected close brace at top level",
			src:     "}\n",
			wantSub: "unexpected '}'",
			line:    1, col: 1,
		},
		{
			name:    "unterminated block",
			src:     "x {\n cache_key url\n",
			wantSub: "unterminated block",
		},
		{
			name:    "site without address",
			src:     "{\n}\nexample.com {\n}\n",
			wantSub: "", // first {} is parsed as global options; no error
		},
		{
			name:    "matcher without type",
			src:     "x {\n @foo\n}\n",
			wantSub: "missing a type",
		},
		{
			name:    "unterminated string",
			src:     "x {\n header A \"oops\n}\n",
			wantSub: "unterminated quoted string",
		},
		{
			name:    "empty matcher name",
			src:     "x {\n @ path /a\n}\n",
			wantSub: "matcher",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Parse("f.cadish", []byte(tt.src))
			if tt.wantSub == "" {
				if err != nil {
					t.Fatalf("expected no error, got %v", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("expected error containing %q, got nil", tt.wantSub)
			}
			if !strings.Contains(err.Error(), tt.wantSub) {
				t.Fatalf("error = %q, want substring %q", err.Error(), tt.wantSub)
			}
			pe, ok := err.(*ParseError)
			if !ok {
				t.Fatalf("error type = %T, want *ParseError", err)
			}
			if tt.line != 0 && pe.Line != tt.line {
				t.Errorf("error line = %d, want %d (%v)", pe.Line, tt.line, pe)
			}
			if tt.col != 0 && pe.Col != tt.col {
				t.Errorf("error col = %d, want %d (%v)", pe.Col, tt.col, pe)
			}
		})
	}
}

func TestParseErrorFormat(t *testing.T) {
	_, err := Parse("conf.cadish", []byte("}\n"))
	if err == nil {
		t.Fatal("expected error")
	}
	got := err.Error()
	if !strings.HasPrefix(got, "conf.cadish:1:1: ") {
		t.Errorf("error = %q, want prefix conf.cadish:1:1: ", got)
	}
}

func TestParsePositions(t *testing.T) {
	f := mustParse(t, "example.com {\n    cache_key url\n}\n")
	s := f.Sites[0]
	if s.Pos.Line != 1 || s.Pos.Col != 1 {
		t.Errorf("site pos = %v, want 1:1", s.Pos)
	}
	d := s.Body[0].(*Directive)
	if d.Pos.Line != 2 || d.Pos.Col != 5 {
		t.Errorf("directive pos = %v, want 2:5", d.Pos)
	}
}

func TestSubstituteEnv(t *testing.T) {
	f := mustParse(t, "x {\n purge token {$TOK} {device}\n}\n")
	env := map[string]string{"TOK": "secret123"}
	SubstituteEnv(f, func(name string) (string, bool) {
		v, ok := env[name]
		return v, ok
	})
	d := f.Sites[0].Body[0].(*Directive)
	if d.Args[1].Raw != "secret123" {
		t.Errorf("env arg = %q, want secret123", d.Args[1].Raw)
	}
	if d.Args[1].Kind != ArgLiteral {
		t.Errorf("after substitution kind = %v, want literal", d.Args[1].Kind)
	}
	// generic placeholder untouched
	if d.Args[2].Raw != "{device}" {
		t.Errorf("generic placeholder = %q, want {device}", d.Args[2].Raw)
	}
	if d.Args[2].Kind != ArgPlaceholder {
		t.Errorf("generic placeholder kind = %v, want placeholder", d.Args[2].Kind)
	}
}

// TestSubstituteEnvInQuotedString is the R07 regression: a QUOTED env span "{$VAR}"
// must be substituted. A quoted token is ArgLiteral, so it was previously skipped by
// SubstituteEnv entirely — `auth_token "{$ADMIN_TOKEN}"` loaded the LITERAL text as a
// predictable bearer token (fail-open vs the unquoted form). It must substitute (and
// fail closed to "" when unset), while a quoted RUNTIME placeholder "{device}" — not an
// env span — stays an inert literal (quoting still suppresses runtime placeholders).
func TestSubstituteEnvInQuotedString(t *testing.T) {
	f := mustParse(t, "x {\n auth_token \"{$TOK}\" \"{$MISSING}\" \"{device}\" \"plain\"\n}\n")
	SubstituteEnv(f, func(name string) (string, bool) {
		if name == "TOK" {
			return "secret123", true
		}
		return "", false
	})
	d := f.Sites[0].Body[0].(*Directive)
	if d.Args[0].Raw != "secret123" {
		t.Errorf("quoted env arg = %q, want secret123 (R07: a quoted {$VAR} must substitute, not load literally)", d.Args[0].Raw)
	}
	if d.Args[0].Kind != ArgLiteral {
		t.Errorf("quoted env arg kind = %v, want literal", d.Args[0].Kind)
	}
	if d.Args[1].Raw != "" {
		t.Errorf("unset quoted env arg = %q, want \"\" (fail closed, not the literal {$MISSING})", d.Args[1].Raw)
	}
	if d.Args[2].Raw != "{device}" {
		t.Errorf("quoted runtime placeholder = %q, want untouched {device} (only {$ENV} spans expand in quotes)", d.Args[2].Raw)
	}
	if d.Args[3].Raw != "plain" {
		t.Errorf("quoted plain = %q, want plain", d.Args[3].Raw)
	}
}

func TestSubstituteEnvUnset(t *testing.T) {
	f := mustParse(t, "x {\n a {$MISSING}b\n}\n")
	SubstituteEnv(f, func(string) (string, bool) { return "", false })
	d := f.Sites[0].Body[0].(*Directive)
	if d.Args[0].Raw != "b" {
		t.Errorf("unset env -> %q, want b", d.Args[0].Raw)
	}
}

// TestSubstituteEnvDefault covers Caddy-style "{$VAR:default}" env defaults: the
// span after the first ':' is used when the variable is unset, and ignored when it
// is set. Plain "{$VAR}" (no ':') is unchanged.
func TestSubstituteEnvDefault(t *testing.T) {
	cases := []struct {
		name string
		raw  string
		set  map[string]string
		want string
	}{
		{"set-ignores-default", "{$PORT:8080}", map[string]string{"PORT": "9000"}, "9000"},
		{"unset-uses-default", "{$PORT:8080}", nil, "8080"},
		{"unset-no-default", "{$PORT}", nil, ""},
		{"empty-default", "{$PORT:}", nil, ""},
		{"set-empty-string-uses-value", "{$PORT:8080}", map[string]string{"PORT": ""}, ""},
		{"url-default", "http://localhost:{$PORT:8080}", nil, "http://localhost:8080"},
		{"default-with-colon", "{$ADDR:http://localhost:8080}", nil, "http://localhost:8080"},
		{"plain-set", "{$TOK}", map[string]string{"TOK": "secret"}, "secret"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := expandEnv(tc.raw, func(name string) (string, bool) {
				v, ok := tc.set[name]
				return v, ok
			})
			if got != tc.want {
				t.Errorf("expandEnv(%q) = %q, want %q", tc.raw, got, tc.want)
			}
		})
	}
}

func TestDirectiveRegistry(t *testing.T) {
	r := NewDefaultDirectiveRegistry()
	for _, name := range []string{"tls", "cache", "upstream", "cache_ttl"} {
		if !r.Has(name) {
			t.Errorf("expected %q to be known", name)
		}
	}
	if r.Has("frobnicate") {
		t.Error("frobnicate should be unknown")
	}
	r.Add("frobnicate")
	if !r.Has("frobnicate") {
		t.Error("frobnicate should be known after Add")
	}
	if len(r.Names()) == 0 {
		t.Error("Names() should be non-empty")
	}
}

// TestParseSingleLabelFirstWrapParsesNoError (Finding R12) documents that a bare
// single-label FIRST word in a comma-less wrap (`intranet`\n`api.internal {`) is NOT a
// hard parse error: a dot-less label is shape-indistinguishable from a directive name
// (a single-label directive followed by a single-label site formats to the identical
// shape, so erroring would break the Format round-trip — proven by FuzzParse). It parses
// with `intranet` as a no-op top-level Body statement; the silent-drop is surfaced one
// layer up, by the `cadish check` `noop-top-level-statement` warning (see internal/check).
func TestParseSingleLabelFirstWrapParsesNoError(t *testing.T) {
	f := mustParse(t, "intranet\napi.internal {\n\tcache_key url\n}\n")
	if len(f.Sites) != 1 || f.Sites[0].Addresses[0] != "api.internal" {
		t.Fatalf("sites = %#v, want one site [api.internal]", f.Sites)
	}
	// `intranet` lands as a stray top-level Body statement (the drop check warns on it).
	if len(f.Body) != 1 {
		t.Fatalf("top-level Body = %d, want 1 (the dropped `intranet`): %#v", len(f.Body), f.Body)
	}
}

// TestParseSingleLabelDirectiveNotFalseFlagged is the R12 NON-regression guard: a bona
// fide single-word top-level directive followed by a site block (multi-word run, or a
// directive whose line does not precede an address header) must NOT be flagged. The
// existing `header_down X-Foo bar,` case (TestParseTrailingCommaDirectiveNotAbsorbed)
// covers the multi-word run; this pins that a single bare word that is NOT immediately
// before an address header still parses as a top-level directive.
func TestParseSingleLabelDirectiveNotFalseFlagged(t *testing.T) {
	// `metrics` directive on its own line, then a blank line, then a NON-address-header
	// statement context: the following is a real top-level statement, not a wrapped site.
	src := "metrics\nheader_down X-Foo\nexample.com {\n\tcache_key url\n}\n"
	f := mustParse(t, src)
	if len(f.Sites) != 1 || f.Sites[0].Addresses[0] != "example.com" {
		t.Fatalf("sites = %#v, want one site [example.com]", f.Sites)
	}
	// `metrics` and `header_down` must both survive as top-level directives, not error.
	if len(f.Body) != 2 {
		t.Fatalf("top-level Body = %d, want 2 (metrics + header_down): %#v", len(f.Body), f.Body)
	}
}

// TestParseSingleLeadingTokenRoundTrips (FuzzParse `.;;0{ }`) pins the Parse/Format
// symmetry for a SINGLE lone leading address-shaped token followed by a degenerate site
// header whose own address is merely token-shaped (a bare digit/label such as `0`, NOT
// clearly hostname-shaped). Such a leading token is accepted as a no-op top-level Body
// directive (later flagged by `cadish check`), so Parse must NOT hard-error it — and its
// Format output must re-Parse identically. Before the fix Parse accepted `.;;0{ }`
// (`.` a Body directive, `0 { }` a site) yet its Format `.\n0 {` re-parsed as a
// comma-less address wrap and ERRORED — an internal Parse/Format asymmetry.
func TestParseSingleLeadingTokenRoundTrips(t *testing.T) {
	for _, in := range []string{
		".;;0{ }",
		".\n0 {\n}\n",
		"localhost\n0 {\n}\n",
		"[::1]\n0 {\n}\n",
		"host:80\n0 {\n}\n",
	} {
		// Parse must accept it (no loud error).
		if _, err := Parse("rt.cadish", []byte(in)); err != nil {
			t.Errorf("Parse(%q) errored, want accepted as no-op Body directive + site: %v", in, err)
			continue
		}
		// Format(Parse(x)) must be idempotent: re-Format of the output must not error.
		out, ferr := Format([]byte(in))
		if ferr != nil {
			t.Errorf("Format(%q) errored: %v", in, ferr)
			continue
		}
		out2, ferr2 := Format(out)
		if ferr2 != nil {
			t.Errorf("re-Format of formatted %q errored (round-trip break): %v", out, ferr2)
			continue
		}
		if string(out) != string(out2) {
			t.Errorf("Format not idempotent for %q:\n once: %q\n twice: %q", in, out, out2)
		}
	}
}

// TestParseMultiWordWrapStillLoud is the non-regression twin of the round-trip fix: a
// genuine comma-LESS wrap of TWO clearly hostname-shaped addresses must STILL be a loud
// positioned error — whether the writer separated the run with a newline OR with one or
// more ";" (Finding 5). The detector treats ";" and newline identically so Format (which
// normalizes separators to newlines) can never move such an input across the boundary.
func TestParseMultiWordWrapStillLoud(t *testing.T) {
	for _, in := range []string{
		"a.com\nb.com {\n}\n",
		"a.com;b.com {\n}\n",
		"a.com ;; b.com {\n}\n",
		"a.com;;b.com;;c.com {\n}\n",
	} {
		_, err := Parse("loud.cadish", []byte(in))
		if err == nil {
			t.Errorf("Parse(%q) accepted, want a loud comma-separate error (silent address drop)", in)
			continue
		}
		if !strings.Contains(err.Error(), "comma") {
			t.Errorf("Parse(%q) error = %q, want it to mention comma-separating", in, err.Error())
		}
	}
}
