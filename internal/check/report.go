// Package check implements `cadish check`: it loads a Cadishfile (resolving
// `import` directives), then produces a per-site complexity report — the
// headline differentiator of cadish. The report estimates how expensive a config
// is to evaluate per request (regex evaluations, weighted cost, directive depth
// by lifecycle phase), flags dead/unreachable rules and unknown names, and offers
// optimization suggestions.
//
// The cadishfile AST is semantics-free; every classification here (which phase a
// directive runs in, whether a matcher is a regex, whether a rule is dead) is
// applied by this package using its own directive catalog.
package check

import (
	"fmt"

	"github.com/cadi-sh/cadish/internal/cadishfile"
)

// Severity classifies a diagnostic. Errors fail the check (non-zero exit);
// warnings only fail under -strict.
type Severity string

const (
	// SevError is a hard problem: a parse/import failure or a config mistake
	// that makes the report unsound.
	SevError Severity = "error"
	// SevWarning is advisory: unknown names, dead rules, light arity issues.
	SevWarning Severity = "warning"
)

// Phase is a request-lifecycle phase. Directives are grouped by the phase in
// which they execute.
type Phase string

const (
	// PhaseSetup is parse-once configuration (tls, cache, upstream, …); it does
	// not run per request.
	PhaseSetup Phase = "SETUP"
	// PhaseRECV is the request phase (respond, purge, route, pass).
	PhaseRECV Phase = "RECV"
	// PhaseKEY builds the cache key (cache_key).
	PhaseKEY Phase = "KEY"
	// PhaseORIGIN runs on a miss, against the origin response (cache_ttl, storage).
	PhaseORIGIN Phase = "ORIGIN"
	// PhaseDELIVER is the response phase (header, strip_cookies, cors).
	PhaseDELIVER Phase = "DELIVER"
)

// PhaseOrder is the canonical display order for phases.
var PhaseOrder = []Phase{PhaseSetup, PhaseRECV, PhaseKEY, PhaseORIGIN, PhaseDELIVER}

// Diagnostic is a single finding tied to a source position.
type Diagnostic struct {
	Severity Severity `json:"severity"`
	// Position is "file:line:col" (empty file renders as "<input>").
	Position string `json:"position"`
	// Code is a short stable machine code, e.g. "unknown-directive".
	Code string `json:"code"`
	// Message is the human-readable explanation.
	Message string `json:"message"`

	pos cadishfile.Pos
}

// newDiag builds a Diagnostic at pos.
func newDiag(sev Severity, pos cadishfile.Pos, code, format string, args ...any) Diagnostic {
	return Diagnostic{
		Severity: sev,
		Position: pos.String(),
		Code:     code,
		Message:  fmt.Sprintf(format, args...),
		pos:      pos,
	}
}

// CostBreakdown explains the estimated per-request cost: counts of evaluated
// predicates by weight class. Cost = Exact*1 + Glob*2 + Regex*10.
type CostBreakdown struct {
	Exact int `json:"exact"`
	Glob  int `json:"glob"`
	Regex int `json:"regex"`
}

// weightExact, weightGlob and weightRegex are the per-class weights of an
// evaluated predicate, reflecting rough relative cost: an exact set/string
// compare, a glob/trie lookup, and an RE2 regex match.
const (
	weightExact = 1
	weightGlob  = 2
	weightRegex = 10
)

// Cost returns the weighted total.
func (c CostBreakdown) Cost() int {
	return c.Exact*weightExact + c.Glob*weightGlob + c.Regex*weightRegex
}

// SiteReport is the complexity report for one site (or the synthetic
// "(top-level)" scope for a bare imported fragment).
type SiteReport struct {
	Addresses []string `json:"addresses"`
	Position  string   `json:"position"`

	// MatcherCount is the number of named matcher definitions in scope.
	MatcherCount int `json:"matcher_count"`
	// DirectiveCount is the total number of directives in scope.
	DirectiveCount int `json:"directive_count"`
	// RegexEvalsPerRequest is how many regex matchers (path_regex/host_regex/
	// regex-valued header) a request evaluates on the hot path.
	RegexEvalsPerRequest int `json:"regex_evals_per_request"`
	// PhaseCounts is directive count grouped by lifecycle phase.
	PhaseCounts map[Phase]int `json:"phase_counts"`
	// EstimatedCost is the weighted per-request cost (see CostBreakdown).
	EstimatedCost int           `json:"estimated_cost"`
	CostBreakdown CostBreakdown `json:"cost_breakdown"`

	Suggestions []string     `json:"suggestions,omitempty"`
	Diagnostics []Diagnostic `json:"diagnostics,omitempty"`
}

// Report is the full result of a check run.
type Report struct {
	Path string `json:"path"`
	// Diagnostics holds file-level findings not tied to a single site
	// (e.g. import resolution failures).
	Diagnostics []Diagnostic  `json:"diagnostics,omitempty"`
	Sites       []*SiteReport `json:"sites"`
}

// dedupe collapses diagnostics that describe the SAME underlying problem — the same
// source Position and Message — into a single finding, keeping the highest severity
// at its first occurrence (preamble before per-site). One unknown directive used to
// surface three times (a preamble [build-error], a per-site [unknown-directive]
// warning, and a per-site [compile-error]) and inflate the summary to "2 errors, 1
// warning"; after dedup it counts once (PF1). Distinct problems (different position
// or message) are untouched.
func (r *Report) dedupe() {
	// First pass: the maximum severity seen for each (position, message) key.
	maxSev := map[string]Severity{}
	note := func(d Diagnostic) {
		k := d.Position + "\x00" + d.Message
		if maxSev[k] == SevError { // error is the top severity; nothing beats it
			return
		}
		if d.Severity == SevError || maxSev[k] == "" {
			maxSev[k] = d.Severity
		}
	}
	for _, d := range r.Diagnostics {
		note(d)
	}
	for _, s := range r.Sites {
		for _, d := range s.Diagnostics {
			note(d)
		}
	}

	// Second pass: keep the first diagnostic per key whose severity equals the key's
	// max, processing the per-site diagnostics BEFORE the preamble so the more
	// specific per-site copy (e.g. a [compile-error] tied to a site) is the one kept
	// and the redundant preamble [build-error] is dropped. Emitted keys are then
	// suppressed everywhere else.
	emitted := map[string]bool{}
	keep := func(ds []Diagnostic) []Diagnostic {
		out := ds[:0]
		for _, d := range ds {
			k := d.Position + "\x00" + d.Message
			if emitted[k] || d.Severity != maxSev[k] {
				continue
			}
			emitted[k] = true
			out = append(out, d)
		}
		return out
	}
	for _, s := range r.Sites {
		s.Diagnostics = keep(s.Diagnostics)
	}
	r.Diagnostics = keep(r.Diagnostics)
}

// Counts returns the total number of error- and warning-severity diagnostics
// across the whole report.
func (r *Report) Counts() (errors, warnings int) {
	count := func(ds []Diagnostic) {
		for _, d := range ds {
			switch d.Severity {
			case SevError:
				errors++
			case SevWarning:
				warnings++
			}
		}
	}
	count(r.Diagnostics)
	for _, s := range r.Sites {
		count(s.Diagnostics)
	}
	return errors, warnings
}

// ExitCode is the process exit code: non-zero when there are errors, or — under
// strict — any warnings.
func (r *Report) ExitCode(strict bool) int {
	errs, warns := r.Counts()
	if errs > 0 {
		return 1
	}
	if strict && warns > 0 {
		return 1
	}
	return 0
}
