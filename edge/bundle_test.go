package edgebundle

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cadi-sh/cadish/internal/cadishfile"
	"github.com/cadi-sh/cadish/internal/edgeir"
	"github.com/cadi-sh/cadish/internal/pipeline"
)

const storefrontSrc = `example.com {
    @ajax header X-Requested-With XMLHttpRequest
    respond /health-check 200 "OK"
    pass @ajax
    cache_key url host
    cache_ttl default ttl 2s grace 24h
    header +cache_status X-Cache
}`

func projectStorefront(t *testing.T) edgeir.EdgeIR {
	t.Helper()
	f, err := cadishfile.Parse("test.cadish", []byte(storefrontSrc))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	p, err := pipeline.Compile(f.Sites[0])
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	ir, _, err := edgeir.Project(p)
	if err != nil {
		t.Fatalf("project: %v", err)
	}
	return ir
}

// TestBundleStructure asserts the assembled worker has the IR baked in with a
// version guard, the runtime concatenated, and the intra-runtime module wiring
// stripped (no surviving `import … from "./…"`, exactly one `export default`).
func TestBundleStructure(t *testing.T) {
	ir := projectStorefront(t)
	src, err := Bundle(ir)
	if err != nil {
		t.Fatalf("Bundle: %v", err)
	}

	for _, want := range []string{
		"globalThis.__CADISH_IR__ =",
		fmt.Sprintf(`"irVersion":%d`, edgeir.IRVersion),
		"function evalRequest(", // interpreter concatenated
		"class EdgeCache",       // cache-tiers concatenated
		"function resolveGeo(",  // geo concatenated
		"export default {",      // entry's sole export survives
	} {
		if !strings.Contains(src, want) {
			t.Errorf("bundle missing %q", want)
		}
	}

	// Intra-runtime imports must be stripped, and no NAMED export may survive.
	if strings.Contains(src, `from "./`) {
		t.Error("bundle still contains an intra-runtime import (`from \"./…\"`)")
	}
	if strings.Count(src, "\nexport default ") != 1 {
		t.Errorf("bundle must have exactly one `export default`, got %d", strings.Count(src, "\nexport default "))
	}
	for _, bad := range []string{"\nexport function", "\nexport const", "\nexport class"} {
		if strings.Contains(src, bad) {
			t.Errorf("bundle leaks a named export (%q) — demodularize should strip it", strings.TrimSpace(bad))
		}
	}
}

// TestBundleRunsInNode validates the bundle is real, runnable JS: it node --checks
// it and drives a synthetic-response request end-to-end through the baked worker
// (the /health-check `respond` path, which needs neither cache nor origin). Skips
// when node is not on PATH.
func TestBundleRunsInNode(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node not on PATH; skipping bundle runtime check")
	}
	ir := projectStorefront(t)
	src, err := Bundle(ir)
	if err != nil {
		t.Fatalf("Bundle: %v", err)
	}

	dir := t.TempDir()
	workerPath := filepath.Join(dir, "worker.mjs")
	if err := os.WriteFile(workerPath, []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}

	// Syntax check.
	if out, err := exec.Command(node, "--check", workerPath).CombinedOutput(); err != nil {
		t.Fatalf("node --check failed: %v\n%s", err, out)
	}

	// End-to-end: drive the synthetic /health-check response through the bundle.
	driver := `import worker from './worker.mjs';
const res = await worker.fetch(new Request('https://example.com/health-check'), {}, { waitUntil() {} });
if (res.status !== 200) { console.error('status', res.status); process.exit(1); }
const body = await res.text();
if (body !== 'OK') { console.error('body', JSON.stringify(body)); process.exit(1); }
console.log('OK');
`
	driverPath := filepath.Join(dir, "driver.mjs")
	if err := os.WriteFile(driverPath, []byte(driver), 0o644); err != nil {
		t.Fatal(err)
	}
	out, err := exec.Command(node, driverPath).CombinedOutput()
	if err != nil {
		t.Fatalf("bundle end-to-end failed: %v\n%s", err, out)
	}
	if !strings.Contains(string(out), "OK") {
		t.Errorf("bundle end-to-end did not print OK: %s", out)
	}
}
