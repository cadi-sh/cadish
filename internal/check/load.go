package check

import (
	"path/filepath"
	"sort"
	"strings"

	"github.com/cadi-sh/cadish/internal/cadishfile"
)

// resolver splices `import PATH` directives by replacing each with the parsed
// fragment's top-level nodes. Paths are resolved relative to the importing file.
// Missing/unparseable imports and import cycles become error diagnostics carrying
// the import directive's source position; the offending import is then dropped so
// analysis can continue.
//
// When sandbox is true, filesystem access is disabled: each import directive
// produces a clear "import not allowed in playground" diagnostic instead of
// reading from disk. This prevents the admin /api/validate endpoint from being
// used as an arbitrary host-file read primitive.
type resolver struct {
	diags   *[]Diagnostic
	sandbox bool
}

// resolveNodes returns nodes with every `import` directive recursively replaced
// by the imported fragment's body. baseDir is the directory of the file the nodes
// came from; stack is the set of absolute paths currently being imported (cycle
// guard).
func (r *resolver) resolveNodes(nodes []cadishfile.Node, baseDir string, stack []string) []cadishfile.Node {
	out := make([]cadishfile.Node, 0, len(nodes))
	for _, n := range nodes {
		d, ok := n.(*cadishfile.Directive)
		if !ok || d.Name != "import" {
			// Recurse into nested blocks too (imports there are unusual but legal).
			if ok && d.HasBlock {
				d.Block = r.resolveNodes(d.Block, baseDir, stack)
			}
			out = append(out, n)
			continue
		}
		out = append(out, r.expandImport(d, baseDir, stack)...)
	}
	return out
}

// expandImport resolves a single import directive into its fragment nodes (or
// records a diagnostic and returns nothing).
func (r *resolver) expandImport(d *cadishfile.Directive, baseDir string, stack []string) []cadishfile.Node {
	if len(d.Args) == 0 {
		r.err(d.Pos, "bad-import", "import requires a path argument")
		return nil
	}
	// In sandbox mode, reject all imports without touching the filesystem.
	if r.sandbox {
		r.err(d.Pos, "import-not-allowed", "import is not allowed in playground mode; submitted config must be a single self-contained buffer")
		return nil
	}
	rel := d.Args[0].Raw
	path := rel
	if !filepath.IsAbs(path) {
		path = filepath.Join(baseDir, rel)
	}
	// A glob import (`import conf.d/*.Cadishfile`) splices every matching file, in
	// sorted order, exactly as the runtime resolver (pipeline.FileImportResolver)
	// does. A glob matching no files is a clear error, never a silent empty splice.
	if strings.ContainsAny(rel, "*?[") {
		matches, gerr := filepath.Glob(path)
		if gerr != nil {
			r.err(d.Pos, "bad-import", "invalid glob %q: %v", rel, gerr)
			return nil
		}
		if len(matches) == 0 {
			r.err(d.Pos, "missing-import", "import glob %q matched no files", rel)
			return nil
		}
		sort.Strings(matches)
		var out []cadishfile.Node
		for _, m := range matches {
			out = append(out, r.expandOneFile(d, m, stack)...)
		}
		return out
	}
	return r.expandOneFile(d, path, stack)
}

// expandOneFile resolves a single (non-glob) import file path into its fragment
// nodes, recording a diagnostic and returning nothing on failure or cycle.
func (r *resolver) expandOneFile(d *cadishfile.Directive, path string, stack []string) []cadishfile.Node {
	rel := d.Args[0].Raw
	abs, err := filepath.Abs(path)
	if err != nil {
		abs = path
	}
	for _, s := range stack {
		if s == abs {
			r.err(d.Pos, "import-cycle", "import cycle: %s is already being imported", path)
			return nil
		}
	}
	// Parse the fragment with the site-body grammar (ParseFragment), NOT the
	// top-level file grammar, so a brace-bodied directive in the fragment
	// (classify {…}, upstream {…}, tls {…}, …) associates its body into a
	// Directive.Block exactly as it would inline at the splice point instead of
	// being mis-read as a site header and flattened into orphaned statements.
	body, err := cadishfile.ParseFragmentFile(path)
	if err != nil {
		// A cadishfile ParseError already reads as "file:line:col: msg"; an I/O
		// error (missing file) does not, so anchor it at the import directive.
		if _, isParse := err.(*cadishfile.ParseError); isParse {
			r.errRaw(SevError, d.Pos, "bad-import", err.Error())
		} else {
			r.err(d.Pos, "missing-import", "cannot import %q: %v", rel, err)
		}
		return nil
	}
	return r.resolveNodes(body, filepath.Dir(path), append(stack, abs))
}

func (r *resolver) err(pos cadishfile.Pos, code, format string, args ...any) {
	*r.diags = append(*r.diags, newDiag(SevError, pos, code, format, args...))
}

func (r *resolver) errRaw(sev Severity, pos cadishfile.Pos, code, msg string) {
	*r.diags = append(*r.diags, Diagnostic{Severity: sev, Position: pos.String(), Code: code, Message: msg, pos: pos})
}
