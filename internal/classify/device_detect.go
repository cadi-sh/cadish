package classify

import (
	"fmt"

	"github.com/cadi-sh/cadish/internal/cadishfile"
)

// FromSite builds the site's device classifier (for the {device} cache-key
// normalizer) from its optional `device_detect { … }` block. When the block is
// absent the built-in default ruleset is used, so `cache_key … {device}` works out
// of the box; the block overrides or extends it.
//
// This is the SINGLE source of truth for compiling a `device_detect` block: both the
// runtime config layer (internal/config) and the pipeline (internal/pipeline, which
// projects the ruleset into the Edge IR so the worker self-classifies — D70) call it,
// so the Go server and the edge worker classify a User-Agent identically.
//
// The block is an ordered ruleset (first match wins) plus optional folds:
//
//	device_detect {
//	    mobile  ua_contains Mobile Android iPhone
//	    tablet  ua_contains Android ua_excludes Mobile   # Android tablet
//	    tablet  ua_contains iPad Tablet
//	    bot     ua_contains bot crawler spider
//	    default desktop
//	}
//
// Forms:
//   - `CLASS ua_contains SUBSTR… [ua_excludes SUBSTR…]` — a rule: any contains
//     substring (OR) selects CLASS, unless an excludes substring is also present.
//   - `default CLASS` — the fallback class (default "desktop").
//   - `fold FROM INTO` — remap class FROM onto INTO after matching (collapse the
//     enum, e.g. `fold tablet desktop` / `fold bot desktop` for the cardinality-2
//     desktop/mobile case).
//
// A block with ONLY folds/default (no rules) builds on the built-in ruleset, so
// `device_detect { fold tablet desktop; fold bot desktop }` reduces the default
// four classes to two.
func FromSite(site *cadishfile.Site) (*Classifier, error) {
	var block *cadishfile.Directive
	for _, n := range site.Body {
		d, ok := n.(*cadishfile.Directive)
		if !ok || d.Name != "device_detect" {
			continue
		}
		if block != nil {
			return nil, posErr(d.Pos, "device_detect: only one block allowed per site")
		}
		block = d
	}
	if block == nil {
		return Default(), nil
	}
	if !block.HasBlock {
		return nil, posErr(block.Pos, "device_detect needs a { } block")
	}

	var rules []Rule
	var folds []Fold
	defaultClass := ""
	for _, bn := range block.Block {
		bd, ok := bn.(*cadishfile.Directive)
		if !ok {
			continue
		}
		switch bd.Name {
		case "default":
			if len(bd.Args) != 1 {
				return nil, posErr(bd.Pos, "device_detect: `default` needs exactly one class name")
			}
			if defaultClass != "" {
				return nil, posErr(bd.Pos, "device_detect: duplicate `default`")
			}
			defaultClass = bd.Args[0].Raw
		case "fold":
			if len(bd.Args) != 2 {
				return nil, posErr(bd.Pos, "device_detect: `fold` needs `FROM INTO` (e.g. `fold tablet desktop`)")
			}
			folds = append(folds, Fold{From: bd.Args[0].Raw, Into: bd.Args[1].Raw})
		default:
			rule, err := parseDeviceRule(bd)
			if err != nil {
				return nil, err
			}
			rules = append(rules, rule)
		}
	}
	if len(rules) == 0 && len(folds) == 0 && defaultClass == "" {
		return nil, posErr(block.Pos, "device_detect: empty block (add rules, a `fold`, or a `default`)")
	}
	// A block that only customizes folds/default builds on the built-in ruleset.
	if len(rules) == 0 {
		rules = DefaultRules()
		if defaultClass == "" {
			defaultClass = DefaultClassName()
		}
	}
	return New(rules, defaultClass, folds...), nil
}

// parseDeviceRule parses a `CLASS ua_contains SUBSTR… [ua_excludes SUBSTR…]`
// device-class rule.
func parseDeviceRule(bd *cadishfile.Directive) (Rule, error) {
	if len(bd.Args) < 2 || bd.Args[0].Raw != "ua_contains" {
		return Rule{}, posErr(bd.Pos, "device_detect: rule must be `CLASS ua_contains SUBSTR… [ua_excludes SUBSTR…]`, `fold FROM INTO`, or `default CLASS`")
	}
	var subs, excl []string
	excludes := false
	for _, a := range bd.Args[1:] {
		if a.Raw == "ua_excludes" {
			excludes = true
			continue
		}
		if excludes {
			excl = append(excl, a.Raw)
		} else {
			subs = append(subs, a.Raw)
		}
	}
	if len(subs) == 0 {
		return Rule{}, posErr(bd.Pos, "device_detect: `"+bd.Name+" ua_contains` needs at least one substring")
	}
	return Rule{Class: bd.Name, Substrings: subs, Exclude: excl}, nil
}

// posErr formats a Cadishfile position error (file:line:col: msg) without importing
// the pipeline/config compile-error types — classify is a leaf package.
func posErr(pos cadishfile.Pos, msg string) error {
	if pos.File != "" || pos.Line != 0 {
		return fmt.Errorf("%s:%d:%d: %s", pos.File, pos.Line, pos.Col, msg)
	}
	return fmt.Errorf("%s", msg)
}
