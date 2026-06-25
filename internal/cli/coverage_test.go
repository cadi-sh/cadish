package cli

// coverage_test.go: additional tests targeting the 0%/low-coverage CLI paths that
// the existing test files do not reach.  All tests are fast and deterministic; none
// start a live server or bind a network port.

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cadi-sh/cadish/internal/edgeir"
	"github.com/cadi-sh/cadish/internal/logs"
)

// ---------------------------------------------------------------------------
// Version / Usage
// ---------------------------------------------------------------------------

// TestVersionExitsZero asserts that Version() returns 0 (the process exit code).
func TestVersionExitsZero(t *testing.T) {
	if code := Version(); code != 0 {
		t.Fatalf("Version() = %d, want 0", code)
	}
}

// TestUsageWritesHelp asserts that Usage writes non-empty help text that mentions
// all canonical subcommands.
func TestUsageWritesHelp(t *testing.T) {
	var buf bytes.Buffer
	Usage(&buf)
	out := buf.String()
	if out == "" {
		t.Fatal("Usage wrote nothing")
	}
	for _, sub := range []string{"cadish run", "cadish check", "cadish edge", "cadish logs"} {
		if !strings.Contains(out, sub) {
			t.Errorf("Usage output missing %q", sub)
		}
	}
}

// ---------------------------------------------------------------------------
// Check (public dispatcher)
// ---------------------------------------------------------------------------

// TestCheckDispatcher verifies the public Check() flag-parse → runCheck wiring.
func TestCheckDispatcher(t *testing.T) {
	// A valid SERVER config needs an upstream to fetch from (cadish check is a
	// pre-flight gate — a site with no origin is a build-error). edgeNativeSrc is
	// upstream-less (edge-native, passes to the server behind), so use a real
	// server config here.
	const serverSrc = `example.com {
    upstream backend {
        to https://origin.internal:8080
    }
    cache_key url host
    cache_ttl default ttl 1m grace 1h
    header +cache_status X-Cache
}`
	cfg := writeCadishfile(t, serverSrc)
	if code := Check([]string{"-config", cfg}); code != 0 {
		t.Fatalf("Check exit = %d, want 0", code)
	}
}

// TestCheckDispatcherMissingConfig verifies exit 1 on a missing file.
func TestCheckDispatcherMissingConfig(t *testing.T) {
	code := Check([]string{"-config", filepath.Join(t.TempDir(), "no-such.cadish")})
	if code != 1 {
		t.Fatalf("Check (missing file) exit = %d, want 1", code)
	}
}

// TestCheckDispatcherBadFlag verifies exit 2 for an unknown flag.
func TestCheckDispatcherBadFlag(t *testing.T) {
	if code := Check([]string{"-unknownflag-xyz"}); code != 2 {
		t.Fatalf("Check (bad flag) exit = %d, want 2", code)
	}
}

// ---------------------------------------------------------------------------
// Adapt
// ---------------------------------------------------------------------------

const minimalVCL = `vcl 4.1;
backend default {
    .host = "10.0.0.1";
    .port = "8080";
}
`

// TestAdaptValidVCL verifies Adapt exits 0 and writes a non-empty Cadishfile
// skeleton to the -o file.
func TestAdaptValidVCL(t *testing.T) {
	dir := t.TempDir()
	vclPath := filepath.Join(dir, "test.vcl")
	if err := os.WriteFile(vclPath, []byte(minimalVCL), 0o644); err != nil {
		t.Fatal(err)
	}
	outPath := filepath.Join(dir, "out.cadish")
	if code := Adapt([]string{"-o", outPath, vclPath}); code != 0 {
		t.Fatalf("Adapt exit = %d, want 0", code)
	}
	data, err := os.ReadFile(outPath)
	if err != nil || len(data) == 0 {
		t.Fatalf("Adapt output missing or empty: %v", err)
	}
}

// TestAdaptMissingFile verifies Adapt exits 1 on a missing VCL file.
func TestAdaptMissingFile(t *testing.T) {
	if code := Adapt([]string{filepath.Join(t.TempDir(), "nope.vcl")}); code != 1 {
		t.Fatalf("Adapt (missing file) exit = %d, want 1", code)
	}
}

// TestAdaptNoArgs verifies Adapt exits 2 when no VCL path is given.
func TestAdaptNoArgs(t *testing.T) {
	if code := Adapt([]string{}); code != 2 {
		t.Fatalf("Adapt (no args) exit = %d, want 2", code)
	}
}

// TestAdaptBadFlag verifies Adapt exits 2 for an unknown flag.
func TestAdaptBadFlag(t *testing.T) {
	if code := Adapt([]string{"-unknownflag-xyz"}); code != 2 {
		t.Fatalf("Adapt (bad flag) exit = %d, want 2", code)
	}
}

// ---------------------------------------------------------------------------
// Fmt (stdin path + idempotence)
// ---------------------------------------------------------------------------

// TestFmtStdinFormatted verifies that fmtStdin formats valid Cadishfile content
// from a reader and writes the result to the output writer.
func TestFmtStdinFormatted(t *testing.T) {
	in := strings.NewReader("example.com {\ncache_key   url  host\n}\n")
	var out, errOut bytes.Buffer
	if code := fmtStdin(in, &out, &errOut); code != 0 {
		t.Fatalf("fmtStdin exit = %d, stderr = %s", code, errOut.String())
	}
	if !strings.Contains(out.String(), "cache_key url host") {
		t.Errorf("formatted output unexpected:\n%s", out.String())
	}
}

// TestFmtStdinParseError verifies fmtStdin exits non-zero for invalid input.
func TestFmtStdinParseError(t *testing.T) {
	var out, errOut bytes.Buffer
	if code := fmtStdin(strings.NewReader(`x { header "unclosed`), &out, &errOut); code == 0 {
		t.Fatal("fmtStdin: expected non-zero exit for parse error")
	}
}

// TestFmtWriteIdempotent verifies that Fmt -w on an already-formatted file does
// not rewrite it (modtime unchanged).
func TestFmtWriteIdempotent(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "Cadishfile")
	formatted := "example.com {\n    cache_key url host\n}\n"
	if err := os.WriteFile(path, []byte(formatted), 0o644); err != nil {
		t.Fatal(err)
	}
	before, _ := os.Stat(path)
	if code := Fmt([]string{"-w", path}); code != 0 {
		t.Fatalf("Fmt exit = %d", code)
	}
	after, _ := os.Stat(path)
	if after.ModTime() != before.ModTime() {
		t.Error("Fmt -w rewrote an already-formatted file (should be idempotent)")
	}
}

// TestFmtBadFlag verifies Fmt exits 2 for an unknown flag.
func TestFmtBadFlag(t *testing.T) {
	if code := Fmt([]string{"-unknownflag-xyz"}); code != 2 {
		t.Fatalf("Fmt (bad flag) exit = %d, want 2", code)
	}
}

// ---------------------------------------------------------------------------
// errorWithoutLeadingFile (non-ParseError path)
// ---------------------------------------------------------------------------

// TestErrorWithoutLeadingFileNonParse verifies the non-ParseError path returns
// ": <message>".
func TestErrorWithoutLeadingFileNonParse(t *testing.T) {
	err := &os.PathError{Op: "open", Path: "/x", Err: os.ErrNotExist}
	got := errorWithoutLeadingFile(err)
	if !strings.HasPrefix(got, ": ") {
		t.Errorf("errorWithoutLeadingFile(non-ParseError) = %q, want prefix ': '", got)
	}
}

// ---------------------------------------------------------------------------
// Edge (public dispatchers)
// ---------------------------------------------------------------------------

// TestEdgeDispatcherNoArgs verifies `cadish edge` with no args exits 2.
func TestEdgeDispatcherNoArgs(t *testing.T) {
	if code := Edge([]string{}); code != 2 {
		t.Fatalf("Edge(no args) = %d, want 2", code)
	}
}

// TestEdgeDispatcherHelp verifies `cadish edge help` exits 0.
func TestEdgeDispatcherHelp(t *testing.T) {
	if code := Edge([]string{"help"}); code != 0 {
		t.Fatalf("Edge(help) = %d, want 0", code)
	}
}

// TestEdgeDispatcherDashH verifies `cadish edge -h` exits 0.
func TestEdgeDispatcherDashH(t *testing.T) {
	if code := Edge([]string{"-h"}); code != 0 {
		t.Fatalf("Edge(-h) = %d, want 0", code)
	}
}

// TestEdgeDispatcherUnknown verifies `cadish edge bogus` exits 2.
func TestEdgeDispatcherUnknown(t *testing.T) {
	if code := Edge([]string{"bogus-xyz"}); code != 2 {
		t.Fatalf("Edge(unknown sub) = %d, want 2", code)
	}
}

// TestEdgeBuildDispatcher exercises the public EdgeBuild dispatcher with a valid
// config (routes through flag-parse → runEdgeBuild).
func TestEdgeBuildDispatcher(t *testing.T) {
	cfg := writeCadishfile(t, edgeNativeSrc)
	if code := EdgeBuild([]string{"-config", cfg, "-o", "-"}); code != 0 {
		t.Fatalf("EdgeBuild dispatch exit = %d, want 0", code)
	}
}

// TestEdgeBuildDispatcherBadFlag verifies EdgeBuild exits 2 on an unknown flag.
func TestEdgeBuildDispatcherBadFlag(t *testing.T) {
	if code := EdgeBuild([]string{"-unknownflag-xyz"}); code != 2 {
		t.Fatalf("EdgeBuild (bad flag) exit = %d, want 2", code)
	}
}

// TestEdgeDeployDispatcherBadFlag verifies EdgeDeploy exits 2 on an unknown flag.
func TestEdgeDeployDispatcherBadFlag(t *testing.T) {
	if code := EdgeDeploy([]string{"-unknownflag-xyz"}); code != 2 {
		t.Fatalf("EdgeDeploy (bad flag) exit = %d, want 2", code)
	}
}

// TestEdgeManageRoutesDispatcherBadFlag verifies EdgeManageRoutes exits 2 on an
// unknown flag.
func TestEdgeManageRoutesDispatcherBadFlag(t *testing.T) {
	if code := EdgeManageRoutes([]string{"-unknownflag-xyz"}, "enable"); code != 2 {
		t.Fatalf("EdgeManageRoutes (bad flag) exit = %d, want 2", code)
	}
}

// ---------------------------------------------------------------------------
// writeCoverageJSON
// ---------------------------------------------------------------------------

// TestWriteCoverageJSON verifies writeCoverageJSON produces valid JSON with the
// expected structure (hosts + report fields).
func TestWriteCoverageJSON(t *testing.T) {
	sites := buildEdgeSites(t, edgeNativeSrc)
	var buf bytes.Buffer
	if err := writeCoverageJSON(sites, &buf); err != nil {
		t.Fatalf("writeCoverageJSON: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, `"hosts"`) || !strings.Contains(out, `"report"`) {
		t.Errorf("coverage JSON missing expected keys: %s", out)
	}
}

// ---------------------------------------------------------------------------
// writeBundles
// ---------------------------------------------------------------------------

// TestWriteBundlesToFile verifies writeBundles writes a non-empty worker bundle
// to a named file for a single site.
func TestWriteBundlesToFile(t *testing.T) {
	sites := buildEdgeSites(t, edgeNativeSrc)
	outPath := filepath.Join(t.TempDir(), "worker.js")
	if err := writeBundles(sites, outPath, nil); err != nil {
		t.Fatalf("writeBundles (file): %v", err)
	}
	data, err := os.ReadFile(outPath)
	if err != nil || len(data) == 0 {
		t.Fatalf("bundle file missing or empty: %v", err)
	}
}

// TestWriteBundlesToStdout verifies writeBundles writes to a writer when out=="-".
func TestWriteBundlesToStdout(t *testing.T) {
	sites := buildEdgeSites(t, edgeNativeSrc)
	var buf bytes.Buffer
	if err := writeBundles(sites, "-", &buf); err != nil {
		t.Fatalf("writeBundles (stdout): %v", err)
	}
	if buf.Len() == 0 {
		t.Error("writeBundles to stdout wrote nothing")
	}
}

// TestWriteBundlesAutoCreatesPerSiteFile verifies -bundle auto writes one
// build/<host>.worker.js per site under the working directory.
func TestWriteBundlesAutoCreatesPerSiteFile(t *testing.T) {
	sites := buildEdgeSites(t, edgeNativeSrc)

	dir := t.TempDir()
	old, _ := os.Getwd()
	if err := os.Chdir(dir); err != nil {
		t.Fatalf("chdir: %v", err)
	}
	t.Cleanup(func() { _ = os.Chdir(old) })

	if err := writeBundles(sites, "auto", nil); err != nil {
		t.Fatalf("writeBundles (auto): %v", err)
	}
	name := filepath.Join("build", edgeWorkerFilename(sites[0].ir.Site.Hosts))
	if _, err := os.Stat(name); err != nil {
		t.Fatalf("expected per-site bundle %s: %v", name, err)
	}
}

// TestWriteEdgeIRDefaultWritesToBuildDir verifies that with no -o the IR lands in
// build/<host>.edgeir.json (not scattered in the cwd).
func TestWriteEdgeIRDefaultWritesToBuildDir(t *testing.T) {
	sites := buildEdgeSites(t, edgeNativeSrc)

	dir := t.TempDir()
	old, _ := os.Getwd()
	if err := os.Chdir(dir); err != nil {
		t.Fatalf("chdir: %v", err)
	}
	t.Cleanup(func() { _ = os.Chdir(old) })

	if err := writeEdgeIR(sites, "", nil); err != nil {
		t.Fatalf("writeEdgeIR (default): %v", err)
	}
	name := filepath.Join("build", edgeIRFilename(sites[0].ir.Site.Hosts))
	if _, err := os.Stat(name); err != nil {
		t.Fatalf("expected IR at %s: %v", name, err)
	}
	// And nothing scattered in the cwd itself.
	if _, err := os.Stat(edgeIRFilename(sites[0].ir.Site.Hosts)); err == nil {
		t.Errorf("IR should not be written to cwd, only under build/")
	}
}

// TestWriteBundlesStdoutMultiSiteError verifies that "-" fails with more than one
// site (we duplicate the single site to produce two entries).
func TestWriteBundlesStdoutMultiSiteError(t *testing.T) {
	single := buildEdgeSites(t, edgeNativeSrc)
	sites := []edgeSite{single[0], single[0]} // duplicate to simulate two sites
	if err := writeBundles(sites, "-", &bytes.Buffer{}); err == nil {
		t.Error("expected error writing multiple sites to stdout")
	}
}

// TestEdgeWorkerFilename verifies the filename derivation rules for worker bundles.
func TestEdgeWorkerFilename(t *testing.T) {
	tests := []struct {
		hosts []string
		want  string
	}{
		{[]string{"example.com"}, "example.com.worker.js"},
		{[]string{"*.example.com"}, "wildcard.example.com.worker.js"},
		{[]string{}, "site.worker.js"},
		{nil, "site.worker.js"},
	}
	for _, tc := range tests {
		if got := edgeWorkerFilename(tc.hosts); got != tc.want {
			t.Errorf("edgeWorkerFilename(%v) = %q, want %q", tc.hosts, got, tc.want)
		}
	}
}

// ---------------------------------------------------------------------------
// encodeIR multi-site path
// ---------------------------------------------------------------------------

// TestEncodeIRMultiSite verifies encodeIR produces a JSON array (not a single
// object) when given two sites.
func TestEncodeIRMultiSite(t *testing.T) {
	single := buildEdgeSites(t, edgeNativeSrc)
	sites := []edgeSite{single[0], single[0]}
	var buf bytes.Buffer
	if err := encodeIR(&buf, sites); err != nil {
		t.Fatalf("encodeIR: %v", err)
	}
	if trimmed := strings.TrimSpace(buf.String()); !strings.HasPrefix(trimmed, "[") {
		t.Errorf("multi-site encodeIR: expected JSON array, got prefix %q", trimmed[:minInt(len(trimmed), 20)])
	}
}

// ---------------------------------------------------------------------------
// applyGCDecision
// ---------------------------------------------------------------------------

// TestApplyGCDecisionNilLeversNoop verifies applyGCDecision with a zero decision
// is a no-op (exercises the nil-guard branches without mutating GC state).
func TestApplyGCDecisionNilLeversNoop(t *testing.T) {
	d := applyGCDecision(gcDecision{})
	if d.GCPercent != nil || d.MemLimitBytes != nil {
		t.Errorf("applyGCDecision(zero) = %+v, want both nil", d)
	}
}

// TestApplyGCDecisionSetsGCPercent exercises the GCPercent branch. We use the
// defaultGCPercent value so the runtime state is effectively unchanged.
func TestApplyGCDecisionSetsGCPercent(t *testing.T) {
	pct := defaultGCPercent
	d := applyGCDecision(gcDecision{GCPercent: &pct})
	if d.GCPercent == nil || *d.GCPercent != pct {
		t.Errorf("applyGCDecision(GCPercent=%d) returned %v", pct, d.GCPercent)
	}
}

// ---------------------------------------------------------------------------
// Logs (public dispatcher)
// ---------------------------------------------------------------------------

// TestLogsDispatcherBadFlag verifies Logs exits 2 on an unknown flag.
func TestLogsDispatcherBadFlag(t *testing.T) {
	if code := Logs([]string{"-unknownflag-xyz"}); code != 2 {
		t.Fatalf("Logs (bad flag) exit = %d, want 2", code)
	}
}

// TestLogsDispatcherBadFormat verifies Logs exits 2 for an invalid -format value.
func TestLogsDispatcherBadFormat(t *testing.T) {
	if code := Logs([]string{"-format", "badformat-xyz"}); code != 2 {
		t.Fatalf("Logs (bad format) exit = %d, want 2", code)
	}
}

// TestLogsDispatcherBadStatusClass verifies Logs exits 2 for an out-of-range
// -status-class value.
func TestLogsDispatcherBadStatusClass(t *testing.T) {
	if code := Logs([]string{"-status-class", "9"}); code != 2 {
		t.Fatalf("Logs (bad status-class) exit = %d, want 2", code)
	}
}

// TestRunLogsTooManyFiles verifies runLogs exits 2 when more than one FILE is
// given.
func TestRunLogsTooManyFiles(t *testing.T) {
	var out, errOut bytes.Buffer
	if code := runLogs([]string{"a.json", "b.json"}, false, false, "", logs.Filter{}, logs.FormatText, nil, &out, &errOut); code != 2 {
		t.Fatalf("runLogs (two files) exit = %d, want 2", code)
	}
}

// ---------------------------------------------------------------------------
// deriveRoutes edge case
// ---------------------------------------------------------------------------

// TestDeriveRoutesSkipsEmptyHost verifies deriveRoutes omits blank host entries.
func TestDeriveRoutesSkipsEmptyHost(t *testing.T) {
	routes := deriveRoutes([]string{"example.com", "", "www.example.com"})
	if len(routes) != 2 {
		t.Fatalf("deriveRoutes with empty host: got %v, want 2 entries", routes)
	}
	for _, r := range routes {
		if r == "/*" {
			t.Errorf("deriveRoutes emitted route for empty host: %v", routes)
		}
	}
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

// buildEdgeSites compiles a Cadishfile, projects each site to an EdgeIR, and
// returns the edgeSite slice.  Used by tests that need real IR+report values
// without going through runEdgeBuild's file-writing side-effects.
func buildEdgeSites(t *testing.T, src string) []edgeSite {
	t.Helper()
	cfg := writeCadishfile(t, src)
	pipelines, err := loadEdgePipelines(cfg)
	if err != nil {
		t.Fatalf("loadEdgePipelines: %v", err)
	}
	sites := make([]edgeSite, 0, len(pipelines))
	for _, p := range pipelines {
		ir, rep, perr := edgeir.Project(p)
		if perr != nil {
			t.Fatalf("edgeir.Project: %v", perr)
		}
		sites = append(sites, edgeSite{hosts: strings.Join(p.EdgeHosts(), ","), ir: ir, rep: rep})
	}
	return sites
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}
