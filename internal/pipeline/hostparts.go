package pipeline

import "strings"

// baseSuffixes is cadish's small, deterministic public-suffix table — the set of
// MULTI-label public suffixes the {host.base}/{host.sub} template tokens recognize.
//
// Why a built-in table and not golang.org/x/net/publicsuffix: the host-part tokens
// must render IDENTICALLY on the Go server AND in the JavaScript edge interpreter
// (the cross-runtime conformance contract). The full PSL is ~10k entries and cannot
// be faithfully mirrored byte-for-byte in the edge runtime, so we share a SMALL
// curated table that both runtimes embed verbatim (see edge/runtime/interpreter.js
// BASE_SUFFIXES — it MUST stay in sync with this map). Single-label TLDs need no
// entry: an unlisted final label is treated as a one-label suffix (the PSL default
// "*" rule), so `brand-a.example` → base `brand-a.example` falls out without listing `example`.
//
// The table lists common ICANN multi-label ccTLD suffixes plus selected
// private/whitelabel suffixes (the PSL's "PRIVATE DOMAINS" idiom — a vendor base
// like `tech555.io` under which every customer subdomain is a distinct registrable
// site). Without a multi-label entry, a bare registrable host on such a suffix would
// be mis-split: `cam4you.tech555.io` would naively strip to `tech555.io`; listing
// `tech555.io` keeps the whole host as the base (sub empty), which is what an
// i18n/whitelabel host-redirect family needs.
var baseSuffixes = map[string]struct{}{
	// ICANN multi-label ccTLD suffixes (common).
	"co.uk": {}, "org.uk": {}, "gov.uk": {}, "ac.uk": {}, "me.uk": {}, "net.uk": {}, "sch.uk": {},
	"com.au": {}, "net.au": {}, "org.au": {}, "edu.au": {}, "gov.au": {},
	"com.br": {}, "net.br": {}, "org.br": {},
	"com.mx": {}, "org.mx": {},
	"com.cn": {}, "net.cn": {}, "org.cn": {},
	"co.jp": {}, "ne.jp": {}, "or.jp": {},
	"co.nz": {}, "net.nz": {}, "org.nz": {},
	"co.za": {}, "org.za": {},
	"co.in": {}, "co.kr": {}, "com.tr": {}, "com.sg": {}, "com.hk": {}, "com.tw": {},
	// Private / whitelabel suffixes (PSL "PRIVATE DOMAINS" idiom): a vendor base
	// under which each customer subdomain is its own registrable site.
	"tech555.io": {},
}

// maxSuffixLabels bounds how many trailing labels hostParts will test against
// baseSuffixes — the longest multi-label suffix in the table is 2, so 4 is ample
// headroom while keeping the scan O(1).
const maxSuffixLabels = 4

// hostParts splits a host into its registrable base domain and its leading
// subdomain label(s), public-suffix aware. It backs the {host.base}/{host.sub}
// template tokens.
//
//   - base — the registrable domain: the public suffix plus one more label
//     (`es.brand-a.example` → `brand-a.example`, `www.brand-b.example` → `brand-b.example`,
//     `cam4you.tech555.io` → `cam4you.tech555.io`).
//   - sub  — the label(s) below the registrable domain (`es`, `www`, `pt`), EMPTY
//     for a bare base host (`brand-a.example` → "").
//
// The input is normally already lower-cased and port-stripped (it is the VALIDATED
// {host} value); hostParts re-normalizes defensively so it is correct on any input.
// It is a pure function shared, line-for-line, with the JS edge runtime's hostParts.
func hostParts(host string) (base, sub string) {
	h := host
	if i := strings.IndexByte(h, ':'); i >= 0 { // strip :port defensively
		h = h[:i]
	}
	h = strings.TrimSuffix(h, ".") // strip a trailing root dot
	h = strings.ToLower(h)
	if h == "" {
		return "", ""
	}
	labels := strings.Split(h, ".")
	n := len(labels)
	if n <= 1 {
		// A single label (or empty) has no subdomain and no public suffix to peel.
		return h, ""
	}
	// Default rule: the final label alone is the public suffix (one label). A LONGER
	// listed multi-label suffix overrides it. Scan from the longest candidate down so
	// the longest match wins.
	suffixLabels := 1
	maxK := n
	if maxK > maxSuffixLabels {
		maxK = maxSuffixLabels
	}
	for k := maxK; k >= 2; k-- {
		if _, ok := baseSuffixes[strings.Join(labels[n-k:], ".")]; ok {
			suffixLabels = k
			break
		}
	}
	baseStart := n - suffixLabels - 1
	if baseStart < 0 {
		// The host is itself a bare public suffix (no registrable label above it);
		// treat the whole host as the base with an empty subdomain (defensive — an
		// unusual input that should never reach a real redirect).
		return h, ""
	}
	base = strings.Join(labels[baseStart:], ".")
	if baseStart > 0 {
		sub = strings.Join(labels[:baseStart], ".")
	}
	return base, sub
}
