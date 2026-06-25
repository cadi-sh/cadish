// Package classify turns a request's User-Agent into a small, bounded device
// class ("desktop", "mobile", "tablet", "bot", …) for the `{device}` cache-key
// normalizer. It is the v2a classifier: a pure, deterministic, ordered ruleset
// (substring → class, first match wins, with a default) compiled once at config
// load and evaluated as a cheap per-request pre-pass — no I/O on the hot path.
//
// The MECHANISM (UA → enum) lives here; the DATA (which substrings map to which
// class, and which classes to FOLD together) is configurable via the Cadishfile
// `device_detect { … }` block, with a sensible built-in ruleset (Default) when
// none is given.
package classify

import "strings"

// Rule maps a device class to the User-Agent substrings that select it. A rule
// matches when ANY Substrings substring is present (OR) AND NO Exclude substring
// is present (the exclusion lets the built-in ruleset say "Android but not
// Mobile" ⇒ tablet). Rules are evaluated in order, first match wins.
// Matching is case-insensitive.
type Rule struct {
	Class      string
	Substrings []string
	Exclude    []string
}

// Fold remaps a classified class onto another (e.g. tablet→desktop) so a site
// can collapse the enum to fewer buckets (the cardinality-2 desktop/mobile case
// in the v2 plan). Folds are applied AFTER rule matching.
type Fold struct {
	From string
	Into string
}

// Classifier is a compiled, immutable UA→class ruleset (plus optional folds). The
// zero value is not usable; build one with New or Default. A nil *Classifier
// classifies everything as "desktop", so callers need not nil-check.
type Classifier struct {
	rules        []Rule // substrings/excludes stored lower-cased, blanks dropped
	defaultClass string
	folds        map[string]string
}

// builtinDefaultClass is the fallback class when no rule matches and none is set.
const builtinDefaultClass = "desktop"

// DefaultClassName is the built-in fallback class ("desktop").
func DefaultClassName() string { return builtinDefaultClass }

// DefaultRules is the built-in UA ruleset (exported so a `device_detect` block
// that only customizes folds/default can build on it). Order matters: bot is
// checked before tablet/mobile (a crawler UA may also contain "Mobile"); the
// tablet rules precede mobile (an iPad UA contains both "iPad" and "Mobile", and
// an Android TABLET sends "Android" WITHOUT "Mobile" while an Android phone
// includes "Mobile").
func DefaultRules() []Rule {
	return []Rule{
		{Class: "bot", Substrings: []string{"bot", "crawler", "spider", "slurp", "facebookexternalhit", "bingpreview"}},
		{Class: "tablet", Substrings: []string{"ipad", "tablet", "kindle", "silk", "playbook"}},
		{Class: "tablet", Substrings: []string{"android"}, Exclude: []string{"mobile"}},
		{Class: "mobile", Substrings: []string{"mobile", "android", "iphone", "ipod", "blackberry", "opera mini", "windows phone"}},
	}
}

// New compiles rules into a Classifier. Substrings/excludes are lower-cased and
// blanks dropped; a rule with no substrings never matches (but its class still
// appears in Classes). An empty defaultCls falls back to "desktop". Folds with a
// blank side are ignored.
func New(rules []Rule, defaultCls string, folds ...Fold) *Classifier {
	compiled := make([]Rule, 0, len(rules))
	for _, r := range rules {
		compiled = append(compiled, Rule{
			Class:      r.Class,
			Substrings: lowerNonEmpty(r.Substrings),
			Exclude:    lowerNonEmpty(r.Exclude),
		})
	}
	if defaultCls == "" {
		defaultCls = builtinDefaultClass
	}
	fm := make(map[string]string, len(folds))
	for _, f := range folds {
		if f.From != "" && f.Into != "" {
			fm[f.From] = f.Into
		}
	}
	return &Classifier{rules: compiled, defaultClass: defaultCls, folds: fm}
}

// Default is the built-in classifier, used when a site declares no
// `device_detect` block.
func Default() *Classifier { return New(DefaultRules(), builtinDefaultClass) }

// maxClassifyUALen bounds the User-Agent length the device classifier lower-cases and
// scans. Real User-Agents are well under a few hundred bytes; this is ~2× the longest
// plausible one, so it never truncates a genuine UA but caps the work (and the
// lower-case copy alloc) a header-limit-sized UA can force on the hot path (CLS-P2).
const maxClassifyUALen = 1024

// Classify returns the device class for a User-Agent. An empty UA (or a nil
// classifier) yields the default class. The matched class is then run through any
// configured folds.
func (c *Classifier) Classify(ua string) string {
	if c == nil {
		return builtinDefaultClass
	}
	class := c.defaultClass
	if ua != "" {
		// Cap the UA before the lower-case copy (CLS-P2): device detection only needs to
		// see short product/OS tokens near the front, and no real User-Agent approaches
		// this length, so bounding it keeps a header-limit-sized UA from forcing a large
		// allocation on the hot classification path. The cap is far above any genuine UA.
		if len(ua) > maxClassifyUALen {
			ua = ua[:maxClassifyUALen]
		}
		lua := strings.ToLower(ua)
		for _, r := range c.rules {
			if r.matches(lua) {
				class = r.Class
				break
			}
		}
	}
	return c.applyFold(class)
}

// matches reports whether the (already lower-cased) UA satisfies the rule.
func (r Rule) matches(lua string) bool {
	hit := false
	for _, s := range r.Substrings {
		if strings.Contains(lua, s) {
			hit = true
			break
		}
	}
	if !hit {
		return false
	}
	for _, x := range r.Exclude {
		if strings.Contains(lua, x) {
			return false
		}
	}
	return true
}

// applyFold follows the fold chain to its terminal class. A misconfigured CYCLE
// (a→b→a) is detected via the visited set and terminates DETERMINISTICALLY at the
// revisited class, instead of depending on an iteration-count parity (the old
// `i <= len(c.folds)` did one extra step, so a 2-cycle returned "b" not "a" — CLS-P1).
// The common no-fold classifier short-circuits with zero allocation.
func (c *Classifier) applyFold(class string) string {
	if len(c.folds) == 0 {
		return class
	}
	var seen map[string]struct{}
	for {
		next, ok := c.folds[class]
		if !ok {
			return class
		}
		if _, dup := seen[class]; dup {
			return class // cycle: stop at the revisited class
		}
		if seen == nil {
			seen = make(map[string]struct{}, len(c.folds))
		}
		seen[class] = struct{}{}
		class = next
	}
}

// Classes returns the bounded, de-duplicated set of classes this classifier can
// actually emit — every rule's class plus the default, each run through the
// folds — in first-seen order. It lets `cadish check` confirm {device} is a
// low-cardinality key normalizer.
func (c *Classifier) Classes() []string {
	if c == nil {
		return []string{builtinDefaultClass}
	}
	seen := make(map[string]bool, len(c.rules)+1)
	out := make([]string, 0, len(c.rules)+1)
	add := func(s string) {
		s = c.applyFold(s)
		if s != "" && !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	for _, r := range c.rules {
		add(r.Class)
	}
	add(c.defaultClass)
	return out
}

// Rules returns the compiled rule list (substrings/excludes already lower-cased) for
// projection into the Edge IR, so the worker can run the identical first-match scan.
// A nil classifier returns the built-in default rules.
func (c *Classifier) Rules() []Rule {
	if c == nil {
		return DefaultRules()
	}
	out := make([]Rule, len(c.rules))
	copy(out, c.rules)
	return out
}

// DefaultClass returns the fallback class used when no rule matches.
func (c *Classifier) DefaultClass() string {
	if c == nil {
		return builtinDefaultClass
	}
	return c.defaultClass
}

// Folds returns the configured class remaps (FROM -> INTO) for projection, sorted by
// FROM for deterministic output. Empty when the classifier has no folds.
func (c *Classifier) Folds() []Fold {
	if c == nil || len(c.folds) == 0 {
		return nil
	}
	froms := make([]string, 0, len(c.folds))
	for from := range c.folds {
		froms = append(froms, from)
	}
	sortStrings(froms)
	out := make([]Fold, 0, len(froms))
	for _, from := range froms {
		out = append(out, Fold{From: from, Into: c.folds[from]})
	}
	return out
}

// IsDefault reports whether this classifier is the built-in default (the standard
// rules, the "desktop" default, and no folds) — so the edge projector can OMIT the
// ruleset from the IR when it would just be the default the worker already knows,
// keeping the zero-cost-when-unused invariant for a site that never customizes it.
func (c *Classifier) IsDefault() bool {
	if c == nil {
		return true
	}
	if c.defaultClass != builtinDefaultClass || len(c.folds) != 0 {
		return false
	}
	def := New(DefaultRules(), builtinDefaultClass)
	if len(c.rules) != len(def.rules) {
		return false
	}
	for i := range c.rules {
		if !rulesEqual(c.rules[i], def.rules[i]) {
			return false
		}
	}
	return true
}

func rulesEqual(a, b Rule) bool {
	if a.Class != b.Class || len(a.Substrings) != len(b.Substrings) || len(a.Exclude) != len(b.Exclude) {
		return false
	}
	for i := range a.Substrings {
		if a.Substrings[i] != b.Substrings[i] {
			return false
		}
	}
	for i := range a.Exclude {
		if a.Exclude[i] != b.Exclude[i] {
			return false
		}
	}
	return true
}

// sortStrings sorts a string slice in place (a tiny local helper so this file needs
// no sort import in the hot classify path; the slices are bounded by the fold count).
func sortStrings(s []string) {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j-1] > s[j]; j-- {
			s[j-1], s[j] = s[j], s[j-1]
		}
	}
}

// lowerNonEmpty lower-cases and trims each string, dropping blanks.
func lowerNonEmpty(in []string) []string {
	out := make([]string, 0, len(in))
	for _, s := range in {
		if s = strings.ToLower(strings.TrimSpace(s)); s != "" {
			out = append(out, s)
		}
	}
	return out
}
