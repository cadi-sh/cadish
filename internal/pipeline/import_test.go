package pipeline

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cadi-sh/cadish/internal/cadishfile"
)

// writeFile writes name under dir with content (test helper).
func writeFile(t *testing.T, dir, name, content string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o600); err != nil {
		t.Fatalf("write %s: %v", name, err)
	}
}

// spliceSrc parses src as a single site and splices its imports against dir.
func spliceSrc(t *testing.T, dir, src string) (*cadishfile.Site, error) {
	t.Helper()
	f, err := cadishfile.Parse(filepath.Join(dir, "root.Cadishfile"), []byte(src))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(f.Sites) != 1 {
		t.Fatalf("want 1 site, got %d", len(f.Sites))
	}
	return SpliceImports(f.Sites[0], FileImportResolver(dir))
}

// TestSpliceImportGlob: a glob import splices every matching file in sorted order.
func TestSpliceImportGlob(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "10-a.Cadishfile", "header +X-A a\n")
	writeFile(t, dir, "20-b.Cadishfile", "header +X-B b\n")
	site, err := spliceSrc(t, dir, "x {\n upstream { to http://o }\n import *.Cadishfile\n}\n")
	if err != nil {
		t.Fatalf("splice: %v", err)
	}
	var names []string
	for _, n := range site.Body {
		if d, ok := n.(*cadishfile.Directive); ok && d.Name == "header" {
			names = append(names, d.Args[0].Raw) // +X-A / +X-B
		}
	}
	if strings.Join(names, ",") != "+X-A,+X-B" {
		t.Errorf("glob splice order = %v, want [X-A X-B] (sorted)", names)
	}
	if _, err := Compile(site); err != nil {
		t.Fatalf("compile spliced glob: %v", err)
	}
}

// TestSpliceImportGlobNoMatch: a glob matching zero files is a clear error, not a
// silent empty splice.
func TestSpliceImportGlobNoMatch(t *testing.T) {
	dir := t.TempDir()
	_, err := spliceSrc(t, dir, "x {\n import conf.d/*.Cadishfile\n}\n")
	if err == nil {
		t.Fatal("want error for zero-match glob, got nil")
	}
	if !strings.Contains(err.Error(), "matched no files") {
		t.Errorf("error = %v, want 'matched no files'", err)
	}
}

// TestSpliceImportNested: an import that itself imports another file resolves
// transitively (no leftover unresolved import reaches Compile).
func TestSpliceImportNested(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "mid.Cadishfile", "import leaf.Cadishfile\n")
	writeFile(t, dir, "leaf.Cadishfile", "header +X-Leaf hi\n")
	site, err := spliceSrc(t, dir, "x {\n upstream { to http://o }\n import mid.Cadishfile\n}\n")
	if err != nil {
		t.Fatalf("splice nested: %v", err)
	}
	if _, err := Compile(site); err != nil {
		t.Fatalf("compile nested: %v", err)
	}
	found := false
	for _, n := range site.Body {
		if d, ok := n.(*cadishfile.Directive); ok && d.Name == "header" {
			found = true
		}
	}
	if !found {
		t.Error("nested import did not splice the leaf header directive")
	}
}

// TestSpliceImportBracedDirective: a fragment containing a brace-bodied directive
// (classify {…}, upstream {…}, …) is spliced as a single block node — exactly as
// inline — not flattened into orphaned body statements. The spliced site must
// Compile, and the classify directive must arrive with its block intact.
func TestSpliceImportBracedDirective(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "classifiers.cadish",
		"@verified header X-Verified 1\nclassify {age} {\n  when @verified -> ok\n  default -> open\n}\n")
	site, err := spliceSrc(t, dir,
		"x {\n upstream { to http://o }\n import classifiers.cadish\n cache_key {age}\n}\n")
	if err != nil {
		t.Fatalf("splice braced: %v", err)
	}
	// The classify directive must be spliced as one block node, never flattened: no
	// orphaned `when`/`default` siblings at the top level.
	var classify *cadishfile.Directive
	for _, n := range site.Body {
		d, ok := n.(*cadishfile.Directive)
		if !ok {
			continue
		}
		switch d.Name {
		case "classify":
			classify = d
		case "when", "default":
			t.Errorf("body keyword %q leaked to top level — fragment was flattened", d.Name)
		}
	}
	if classify == nil {
		t.Fatal("classify directive not spliced from fragment")
	}
	if !classify.HasBlock || len(classify.Block) != 2 {
		t.Errorf("classify block not associated: HasBlock=%v len(Block)=%d", classify.HasBlock, len(classify.Block))
	}
	if _, err := Compile(site); err != nil {
		t.Fatalf("compile spliced braced fragment: %v", err)
	}
}

// TestSpliceImportSelfCycle: a file importing itself is a clean import-cycle error,
// not a silent no-op and not a leaked internal "SpliceImports" message.
func TestSpliceImportSelfCycle(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "self.Cadishfile", "import self.Cadishfile\n")
	_, err := spliceSrc(t, dir, "x {\n import self.Cadishfile\n}\n")
	if err == nil {
		t.Fatal("self-import: want import-cycle error, got nil")
	}
	if !strings.Contains(err.Error(), "import cycle") {
		t.Errorf("self-import error = %v, want 'import cycle'", err)
	}
	if strings.Contains(err.Error(), "SpliceImports") {
		t.Errorf("self-import error leaks internal message: %v", err)
	}
}

// TestSpliceImportDirectCycle: a -> b -> a yields a clean import-cycle error with
// no leaked internal "SpliceImports before Compile" message.
func TestSpliceImportDirectCycle(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "a.Cadishfile", "import b.Cadishfile\n")
	writeFile(t, dir, "b.Cadishfile", "import a.Cadishfile\n")
	_, err := spliceSrc(t, dir, "x {\n import a.Cadishfile\n}\n")
	if err == nil {
		t.Fatal("cycle: want import-cycle error, got nil")
	}
	if !strings.Contains(err.Error(), "import cycle") {
		t.Errorf("cycle error = %v, want 'import cycle'", err)
	}
	if strings.Contains(err.Error(), "SpliceImports") {
		t.Errorf("cycle error leaks internal message: %v", err)
	}
}
