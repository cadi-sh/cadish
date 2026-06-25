package admin

import (
	"errors"
	"io"
	"net/http"
	"os"

	"github.com/cadi-sh/cadish/internal/cadishfile"
	"github.com/cadi-sh/cadish/internal/check"
	"github.com/cadi-sh/cadish/internal/pipeline"
)

// maxValidateBytes caps the request body for /api/validate. A Cadishfile is a
// human-edited config; 1 MiB is generously larger than any real one and bounds
// the in-memory work this off-datapath endpoint can be asked to do.
const maxValidateBytes = 1 << 20

// posError is a positioned diagnostic in the JSON response: a parse or compile
// failure with its "file:line:col" location split into machine-readable fields
// (the UI highlights line/col inline) plus the rendered string.
type posError struct {
	// Position is the rendered "file:line:col" string (or "<input>:line:col").
	Position string `json:"position"`
	Line     int    `json:"line"`
	Col      int    `json:"col"`
	Message  string `json:"message"`
}

// validateResponse is the one-shot compiler verdict for submitted Cadishfile
// source. It mirrors exactly what `cadish check` + `cadish fmt` would say, but
// computed purely in-memory on the posted text — it never touches the running
// server's live pipeline (zero datapath risk).
type validateResponse struct {
	// OK is true when there is no parse error and no compile error. Warnings in
	// the report do not clear OK (they are advisory, like `cadish check`).
	OK bool `json:"ok"`
	// ParseError is the single lexical/syntax failure, if any. When set, no
	// compile or report data is available (parsing is the first gate).
	ParseError *posError `json:"parse_error,omitempty"`
	// CompileErrors are per-site pipeline.Compile failures (the config parses but
	// is semantically invalid). Best-effort: every site is attempted so the
	// operator sees all of them at once.
	CompileErrors []posError `json:"compile_errors,omitempty"`
	// Report is the full complexity report (matchers, regex/req, per-phase, cost,
	// dead-rule/cardinality warnings) — the same data `cadish check` renders.
	// Present whenever the source parses, even alongside compile errors.
	Report *check.Report `json:"report,omitempty"`
	// Formatted is the canonical `cadish fmt` output of the source. Present
	// whenever the source lexes (Format works at the token level, so it tidies
	// even files that do not fully parse).
	Formatted string `json:"formatted,omitempty"`
}

// validateFilename is the synthetic filename used for positions in the
// playground (the source came from a textarea, not a path on disk).
const validateFilename = "Cadishfile"

// handleValidate is the editor/playground endpoint: it takes Cadishfile source
// in the request body and returns, in one shot, the FULL compiler verdict by
// reusing the existing in-tree pipeline VERBATIM —
//
//   - cadishfile.Parse  -> a positioned parse error (file:line:col);
//   - pipeline.Compile  -> per-site compile errors;
//   - check.CheckSource -> the complexity report (cost/phases/warnings);
//   - cadishfile.Format -> the canonical `cadish fmt` output.
//
// All of it is pure / in-memory on the SUBMITTED text. It never reads the
// running config, never mutates proxy state, and never blocks a request — the
// dashboard's read-only playground (see DECISIONS D24, extends D16).
func (s *Server) handleValidate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	// Read up to one byte PAST the limit so an oversized body is detected and
	// rejected with 413 rather than silently truncated to 1 MiB and validated as if
	// it were the whole config (D5). A body exactly at the limit is accepted.
	src, err := io.ReadAll(io.LimitReader(r.Body, maxValidateBytes+1))
	if err != nil {
		// Return a generic message: the raw transport/read error can leak internal
		// detail and is not actionable to the caller. (Config PARSE errors ARE
		// surfaced — that is the playground's purpose — via validate() below, which
		// already routes them through the position-stripping helpers.)
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}
	if len(src) > maxValidateBytes {
		http.Error(w, "request body too large", http.StatusRequestEntityTooLarge)
		return
	}
	writeJSON(w, validate(src))
}

// sourceResponse carries the running site's Cadishfile text so the editor can
// pre-load it. Path is informational; Source is the on-disk content. When the
// config file cannot be read (it was never retained on disk, or is unreadable),
// Source is empty and Error explains why — the UI then starts from a sample.
type sourceResponse struct {
	Path   string `json:"path"`
	Source string `json:"source"`
	Error  string `json:"error,omitempty"`
}

// handleSource returns the running config's Cadishfile text (read fresh from the
// path the admin server already knows, the same one /api/config re-runs `cadish
// check` against). It is read-only — it never edits the file and the validate
// endpoint never writes it — so the editor pre-loads the live config without any
// datapath or config-mutation risk.
func (s *Server) handleSource(w http.ResponseWriter, r *http.Request) {
	resp := sourceResponse{Path: s.cfgPath}
	if s.cfgPath == "" {
		resp.Error = "no config path known"
		writeJSON(w, resp)
		return
	}
	b, err := os.ReadFile(s.cfgPath)
	if err != nil {
		resp.Error = err.Error()
		writeJSON(w, resp)
		return
	}
	// Redact credentials before serving: even though the endpoint is token-gated, a
	// read-only source view must never expose auth_token / S3 secrets in plaintext.
	resp.Source = redactSecrets(string(b))
	writeJSON(w, resp)
}

// validate is the pure core of the endpoint, separated for testability: it runs
// the four reused stages over src and assembles the verdict. It performs no I/O
// and touches no server state.
func validate(src []byte) validateResponse {
	resp := validateResponse{}

	// Stage 4 (Format) only produces canonical output when the input parses
	// (Format refuses to emit a truncated result for an unparseable config, so it
	// can never corrupt a file). On any lexical/syntax error its output is omitted
	// here; that same error is reported as the parse error below.
	if out, err := cadishfile.Format(src); err == nil {
		resp.Formatted = string(out)
	}

	// Stage 1: parse. A lexical/syntax error is the first gate — nothing
	// downstream can run on an unparseable file.
	f, err := cadishfile.Parse(validateFilename, src)
	if err != nil {
		resp.ParseError = parseErrorToPos(err)
		return resp
	}

	// Stage 3: the complexity report. We use the sandboxed variant so that the
	// playground endpoint performs NO filesystem access — import directives are
	// blocked (producing a clear diagnostic) and geo/maxmind paths are never
	// probed. This prevents /api/validate from acting as an arbitrary host-file
	// read primitive. We already know src parses, so this cannot error here.
	if rep, rerr := check.CheckSourceSandboxed(validateFilename, src); rerr == nil {
		resp.Report = rep
	}

	// Stage 2: compile every site (and the top-level body as a synthetic site) so
	// the operator sees all semantic errors at once. Imports are not spliced here
	// (the playground edits a single buffer); an `import` directive compiles to a
	// clear "unresolved import" error, which is the right signal in this context.
	for _, site := range f.Sites {
		if _, cerr := pipeline.Compile(site); cerr != nil {
			resp.CompileErrors = append(resp.CompileErrors, compileErrorToPos(cerr))
		}
	}
	if len(f.Sites) == 0 && len(f.Body) > 0 {
		// A bare fragment (matcher defs + directives, no site wrapper) — compile it
		// as a synthetic site so the playground validates importable snippets too.
		synthetic := &cadishfile.Site{Body: f.Body, Pos: cadishfile.Pos{File: validateFilename}}
		if _, cerr := pipeline.Compile(synthetic); cerr != nil {
			resp.CompileErrors = append(resp.CompileErrors, compileErrorToPos(cerr))
		}
	}

	resp.OK = resp.ParseError == nil && len(resp.CompileErrors) == 0
	return resp
}

// parseErrorToPos maps a cadishfile parse failure to the JSON posError shape. A
// *cadishfile.ParseError carries explicit line/col; any other error (defensive)
// is reported message-only.
func parseErrorToPos(err error) *posError {
	var pe *cadishfile.ParseError
	if errors.As(err, &pe) {
		pos := cadishfile.Pos{File: pe.File, Line: pe.Line, Col: pe.Col}
		return &posError{
			Position: pos.String(),
			Line:     pe.Line,
			Col:      pe.Col,
			Message:  pe.Msg,
		}
	}
	return &posError{Message: err.Error()}
}

// compileErrorToPos maps a pipeline compile failure to the JSON posError shape.
// A *pipeline.CompileError carries the offending source Pos; any other error
// (defensive) is reported message-only.
func compileErrorToPos(err error) posError {
	var ce *pipeline.CompileError
	if errors.As(err, &ce) {
		return posError{
			Position: ce.Pos.String(),
			Line:     ce.Pos.Line,
			Col:      ce.Pos.Col,
			Message:  ce.Msg,
		}
	}
	return posError{Message: err.Error()}
}
