package check

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/cadi-sh/cadish/internal/cadishfile"
)

// WriteText renders the report as a human-readable text report to w.
func (r *Report) WriteText(w io.Writer) error {
	var b strings.Builder

	fmt.Fprintf(&b, "cadish check — %s\n", r.Path)

	// File-level diagnostics (import failures, etc.).
	if len(r.Diagnostics) > 0 {
		b.WriteString("\n")
		for _, d := range r.Diagnostics {
			writeDiag(&b, d)
		}
	}

	for _, s := range r.Sites {
		b.WriteString("\n")
		writeSite(&b, s)
	}

	errs, warns := r.Counts()
	b.WriteString("\n")
	fmt.Fprintf(&b, "Summary: %s, %d error%s, %d warning%s\n",
		plural(len(r.Sites), "site"), errs, suffix(errs), warns, suffix(warns))

	_, err := io.WriteString(w, b.String())
	return err
}

func writeSite(b *strings.Builder, s *SiteReport) {
	fmt.Fprintf(b, "Site: %s\n", strings.Join(s.Addresses, ", "))
	fmt.Fprintf(b, "  Matchers:               %d\n", s.MatcherCount)
	fmt.Fprintf(b, "  Directives:             %d\n", s.DirectiveCount)
	fmt.Fprintf(b, "  Regex evals / request:  %d   (path_regex/host_regex/regex-valued header on the hot path)\n",
		s.RegexEvalsPerRequest)

	// Phase line.
	var phaseParts []string
	for _, p := range PhaseOrder {
		phaseParts = append(phaseParts, fmt.Sprintf("%s %d", p, s.PhaseCounts[p]))
	}
	fmt.Fprintf(b, "  Directives by phase:    %s\n", strings.Join(phaseParts, "  "))

	cb := s.CostBreakdown
	fmt.Fprintf(b, "  Est. per-request cost:  %d   (%d exact×%d + %d glob×%d + %d regex×%d)\n",
		s.EstimatedCost,
		cb.Exact, weightExact, cb.Glob, weightGlob, cb.Regex, weightRegex)

	if len(s.Suggestions) > 0 {
		b.WriteString("  Suggestions:\n")
		for _, sg := range s.Suggestions {
			fmt.Fprintf(b, "    • %s\n", sg)
		}
	}

	if len(s.Diagnostics) > 0 {
		b.WriteString("  Findings:\n")
		for _, d := range s.Diagnostics {
			b.WriteString("  ")
			writeDiag(b, d)
		}
	}
}

func writeDiag(b *strings.Builder, d Diagnostic) {
	fmt.Fprintf(b, "  %-7s %s: %s  [%s]\n", d.Severity, d.Position, d.Message, d.Code)
}

// WriteJSON renders the report as indented JSON to w (for tooling). strict
// reflects whether the check ran under -strict, so the emitted JSON's outcome
// fields ("ok"/"strict") agree with the process exit code: under -strict a
// warnings-only report is a failure ("ok":false) even though "errors":0.
func (r *Report) WriteJSON(w io.Writer, strict bool) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(r.jsonView(strict))
}

// jsonView is the JSON projection of a Report. It mirrors Report/SiteReport but
// renders phase counts as an ordered object and adds the summary counts so
// tooling does not have to recompute them.
//
// Ok and Strict make the JSON agree with the process exit code: Ok is false
// exactly when ExitCode(strict) is non-zero (any error, or — under strict — any
// warning), and Strict records whether warnings were promoted to failures.
type jsonView struct {
	Path        string         `json:"path"`
	Ok          bool           `json:"ok"`
	Strict      bool           `json:"strict"`
	Errors      int            `json:"errors"`
	Warnings    int            `json:"warnings"`
	Diagnostics []Diagnostic   `json:"diagnostics,omitempty"`
	Sites       []jsonSiteView `json:"sites"`
}

type jsonSiteView struct {
	Addresses            []string       `json:"addresses"`
	Position             string         `json:"position"`
	MatcherCount         int            `json:"matcher_count"`
	DirectiveCount       int            `json:"directive_count"`
	RegexEvalsPerRequest int            `json:"regex_evals_per_request"`
	PhaseCounts          map[string]int `json:"phase_counts"`
	EstimatedCost        int            `json:"estimated_cost"`
	CostBreakdown        CostBreakdown  `json:"cost_breakdown"`
	Suggestions          []string       `json:"suggestions,omitempty"`
	Diagnostics          []Diagnostic   `json:"diagnostics,omitempty"`
}

func (r *Report) jsonView(strict bool) jsonView {
	errs, warns := r.Counts()
	v := jsonView{
		Path:        r.Path,
		Ok:          r.ExitCode(strict) == 0,
		Strict:      strict,
		Errors:      errs,
		Warnings:    warns,
		Diagnostics: r.Diagnostics,
	}
	for _, s := range r.Sites {
		phases := make(map[string]int, len(PhaseOrder))
		for _, p := range PhaseOrder {
			phases[string(p)] = s.PhaseCounts[p]
		}
		v.Sites = append(v.Sites, jsonSiteView{
			Addresses:            s.Addresses,
			Position:             s.Position,
			MatcherCount:         s.MatcherCount,
			DirectiveCount:       s.DirectiveCount,
			RegexEvalsPerRequest: s.RegexEvalsPerRequest,
			PhaseCounts:          phases,
			EstimatedCost:        s.EstimatedCost,
			CostBreakdown:        s.CostBreakdown,
			Suggestions:          s.Suggestions,
			Diagnostics:          s.Diagnostics,
		})
	}
	return v
}

// WriteJSONError renders a top-level check failure (a root-file parse or read
// error, returned by Check before any Report exists) as a structured JSON object
// to w, so a `-json` consumer always receives valid, machine-readable JSON even
// when the config does not parse — instead of empty stdout. The shape mirrors a
// failed report: ok=false, one error diagnostic, no sites. path and strict are
// echoed so the JSON is self-describing and its outcome agrees with the (non-zero)
// exit code.
func WriteJSONError(w io.Writer, path string, strict bool, err error) error {
	pos := cadishfile.Pos{File: path}
	code := "read-error"
	var pe *cadishfile.ParseError
	if errors.As(err, &pe) {
		pos = cadishfile.Pos{File: pe.File, Line: pe.Line, Col: pe.Col}
		code = "parse-error"
	}
	v := jsonView{
		Path:        path,
		Ok:          false,
		Strict:      strict,
		Errors:      1,
		Warnings:    0,
		Diagnostics: []Diagnostic{newDiag(SevError, pos, code, "%s", err.Error())},
		Sites:       []jsonSiteView{},
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

func plural(n int, noun string) string {
	if n == 1 {
		return fmt.Sprintf("%d %s", n, noun)
	}
	return fmt.Sprintf("%d %ss", n, noun)
}

func suffix(n int) string {
	if n == 1 {
		return ""
	}
	return "s"
}
