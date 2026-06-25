package cli

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cadi-sh/cadish/internal/edgeir"
)

// writeCadishfile writes src to a temp Cadishfile and returns its path.
func writeCadishfile(t *testing.T, src string) string {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, "Cadishfile")
	if err := os.WriteFile(p, []byte(src), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	return p
}

const edgeNativeSrc = `example.com {
    @ajax header X-Requested-With XMLHttpRequest
    pass @ajax
    cache_key url host
    cache_ttl default ttl 1m grace 1h
    header +cache_status X-Cache
}`

// edgeDelegateSrc delegates EXACTLY ONE directive. `rewrite` (origin-request URL
// rewrite) is server-only in edge v1, so it is the canonical single-delegation case.
// (NOTE: `replace` and `respond on_error` are edge-native as of D75/D76, so they are
// no longer suitable here — they project natively and delegate nothing.)
const edgeDelegateSrc = `example.com {
    rewrite strip_query utm_*
    cache_ttl default ttl 1m
}`

func TestEdgeBuildWritesIR(t *testing.T) {
	cfg := writeCadishfile(t, edgeNativeSrc)
	var out, errOut bytes.Buffer
	code := runEdgeBuild(cfg, "-", "", false, false, &out, &errOut)
	if code != 0 {
		t.Fatalf("exit = %d, want 0; stderr=%s", code, errOut.String())
	}
	// IR JSON on stdout, coverage on stderr.
	var ir map[string]any
	if err := json.Unmarshal(out.Bytes(), &ir); err != nil {
		t.Fatalf("IR not valid JSON: %v\n%s", err, out.String())
	}
	if ir["irVersion"].(float64) != float64(edgeir.IRVersion) {
		t.Errorf("irVersion = %v, want %d", ir["irVersion"], edgeir.IRVersion)
	}
	if !strings.Contains(errOut.String(), "edge-native:") {
		t.Errorf("coverage report missing: %s", errOut.String())
	}
}

func TestEdgeBuildStrictFailsOnDelegate(t *testing.T) {
	cfg := writeCadishfile(t, edgeDelegateSrc)

	// Non-strict: exit 0 (delegate is allowed, just reported).
	var out, errOut bytes.Buffer
	if code := runEdgeBuild(cfg, "-", "", false, false, &out, &errOut); code != 0 {
		t.Fatalf("non-strict exit = %d, want 0; stderr=%s", code, errOut.String())
	}
	if !strings.Contains(errOut.String(), "delegated:   1") {
		t.Errorf("expected 1 delegated in report: %s", errOut.String())
	}

	// Strict: a delegated directive is a coverage regression -> exit 1.
	out.Reset()
	errOut.Reset()
	if code := runEdgeBuild(cfg, "-", "", true, false, &out, &errOut); code != 1 {
		t.Errorf("strict exit = %d, want 1; stderr=%s", code, errOut.String())
	}
	if !strings.Contains(errOut.String(), "delegated") {
		t.Errorf("strict error should mention delegation: %s", errOut.String())
	}
}

// TestEdgeBuildStrictFailsOnRewriteEncode (P0): `rewrite` and `encode` are compiled
// in the pipeline but not edge-native. They must surface in the coverage report as
// delegated directives (never silently dropped) so -strict fails — otherwise the
// edge would serve un-rewritten/un-compressed responses while claiming coverage.
func TestEdgeBuildStrictFailsOnRewriteEncode(t *testing.T) {
	const src = `example.com {
    rewrite strip_query utm_*
    encode zstd br gzip
    cache_key url host
    cache_ttl default ttl 1m
}`
	cfg := writeCadishfile(t, src)

	// Non-strict: builds (exit 0) but reports BOTH directives as delegated.
	var out, errOut bytes.Buffer
	if code := runEdgeBuild(cfg, "-", "", false, false, &out, &errOut); code != 0 {
		t.Fatalf("non-strict exit = %d, want 0; stderr=%s", code, errOut.String())
	}
	if !strings.Contains(errOut.String(), "rewrite") || !strings.Contains(errOut.String(), "encode") {
		t.Errorf("expected rewrite AND encode in the coverage report: %s", errOut.String())
	}

	// Strict: delegated directives are a coverage regression -> exit 1.
	out.Reset()
	errOut.Reset()
	if code := runEdgeBuild(cfg, "-", "", true, false, &out, &errOut); code != 1 {
		t.Errorf("strict exit = %d, want 1; stderr=%s", code, errOut.String())
	}
}

// TestEdgeBuildStrictFailsOnSecurityGate (Fix A): a site with a security gate
// (deny @admin) must fail -strict — the ACL is NOT enforced at the edge, and a
// silent pass would turn `deny @admin` into a no-op for all edge traffic.
func TestEdgeBuildStrictFailsOnSecurityGate(t *testing.T) {
	const src = `example.com {
    @admin path /admin/*
    deny @admin
    cache_key url host
    cache_ttl default ttl 1m
}`
	cfg := writeCadishfile(t, src)

	// Non-strict: still builds (exit 0) but warns loudly.
	var out, errOut bytes.Buffer
	if code := runEdgeBuild(cfg, "-", "", false, false, &out, &errOut); code != 0 {
		t.Fatalf("non-strict exit = %d, want 0; stderr=%s", code, errOut.String())
	}
	if !strings.Contains(errOut.String(), "NOT enforced at the edge") {
		t.Errorf("expected a loud security-gate warning: %s", errOut.String())
	}

	// Strict: the unenforced security gate is a coverage regression -> exit 1.
	out.Reset()
	errOut.Reset()
	if code := runEdgeBuild(cfg, "-", "", true, false, &out, &errOut); code != 1 {
		t.Errorf("strict exit = %d, want 1; stderr=%s", code, errOut.String())
	}
}

// TestEdgeBuildStrictCleanNoSecurityGate (Fix A): a site with no security gate and
// no exposed matcher values is unaffected and stays strict-clean.
func TestEdgeBuildStrictCleanNoSecurityGate(t *testing.T) {
	const src = `example.com {
    @api path /api/*
    pass @api
    cache_key url host
    cache_ttl default ttl 1m
    header +cache_status X-Cache
}`
	cfg := writeCadishfile(t, src)
	var out, errOut bytes.Buffer
	if code := runEdgeBuild(cfg, "-", "", true, false, &out, &errOut); code != 0 {
		t.Errorf("strict exit = %d, want 0 for a clean site; stderr=%s", code, errOut.String())
	}
}

// TestEdgeBuildStrictFailsOnValueExposure (Fix B): a header matcher carrying a
// literal value (a potential baked-in secret) must fail -strict so CI catches it.
func TestEdgeBuildStrictFailsOnValueExposure(t *testing.T) {
	const src = `example.com {
    @auth header X-Internal-Auth s3cr3t
    pass @auth
    cache_key url host
    cache_ttl default ttl 1m
}`
	cfg := writeCadishfile(t, src)

	// Non-strict: builds, prints the exposure warning.
	var out, errOut bytes.Buffer
	if code := runEdgeBuild(cfg, "-", "", false, false, &out, &errOut); code != 0 {
		t.Fatalf("non-strict exit = %d, want 0; stderr=%s", code, errOut.String())
	}
	if !strings.Contains(errOut.String(), "ships its literal value") {
		t.Errorf("expected a value-exposure warning: %s", errOut.String())
	}

	// Strict: the exposed value fails the build -> exit 1.
	out.Reset()
	errOut.Reset()
	if code := runEdgeBuild(cfg, "-", "", true, false, &out, &errOut); code != 1 {
		t.Errorf("strict exit = %d, want 1; stderr=%s", code, errOut.String())
	}
}

// TestEdgeBuildStrictFailsOnEnvSecretHeaderValue (Fix 1, security completeness): an
// UNQUOTED `{$VAR}` in a `header` value is env-expanded to the secret BEFORE projection,
// baking it into the public worker IR. -strict must trip on it (the leak guard now scans
// header op values, not only matcher values). The QUOTED form `"{$VAR}"` stays the
// literal text `{$VAR}` (ships no secret) and stays strict-clean.
func TestEdgeBuildStrictFailsOnEnvSecretHeaderValue(t *testing.T) {
	t.Setenv("CADISH_TEST_ORIGIN_SECRET", "topsecret-zz1199")

	// Unquoted placeholder -> expanded -> secret in the IR -> strict fails.
	const leaky = `example.com {
    header X-Internal-Auth {$CADISH_TEST_ORIGIN_SECRET}
    cache_ttl default ttl 1m
}`
	cfg := writeCadishfile(t, leaky)
	var out, errOut bytes.Buffer
	if code := runEdgeBuild(cfg, "-", "", true, false, &out, &errOut); code != 1 {
		t.Errorf("strict exit = %d, want 1 (env secret in header value); stderr=%s", code, errOut.String())
	}
	if strings.Contains(out.String(), "topsecret-zz1199") {
		// Sanity: the secret really did get baked into the IR (the leak this guards).
	} else {
		t.Errorf("expected the env secret to have been expanded into the IR JSON; out=%s", out.String())
	}

	// Quoted placeholder -> stays literal `{$VAR}` -> no secret -> strict-clean.
	const safe = `example.com {
    header X-Internal-Auth "{$CADISH_TEST_ORIGIN_SECRET}"
    cache_ttl default ttl 1m
}`
	cfg2 := writeCadishfile(t, safe)
	out.Reset()
	errOut.Reset()
	if code := runEdgeBuild(cfg2, "-", "", true, false, &out, &errOut); code != 0 {
		t.Errorf("strict exit = %d, want 0 for quoted placeholder; stderr=%s", code, errOut.String())
	}
}

func TestEdgeBuildPerSiteFile(t *testing.T) {
	cfg := writeCadishfile(t, edgeNativeSrc)
	dir := filepath.Dir(cfg)
	// chdir so the per-site file lands under the temp dir's build/, then restore.
	old, _ := os.Getwd()
	if err := os.Chdir(dir); err != nil {
		t.Fatalf("chdir: %v", err)
	}
	t.Cleanup(func() { _ = os.Chdir(old) })

	var out, errOut bytes.Buffer
	if code := runEdgeBuild(cfg, "", "", false, false, &out, &errOut); code != 0 {
		t.Fatalf("exit = %d, want 0; stderr=%s", code, errOut.String())
	}
	want := filepath.Join(dir, "build", "example.com.edgeir.json")
	if _, err := os.Stat(want); err != nil {
		t.Fatalf("expected per-site IR file %s: %v", want, err)
	}
	data, _ := os.ReadFile(want)
	if !strings.Contains(string(data), fmt.Sprintf(`"irVersion": %d`, edgeir.IRVersion)) {
		t.Errorf("per-site IR missing irVersion:\n%s", data)
	}
}

func TestEdgeBuildMissingConfig(t *testing.T) {
	var out, errOut bytes.Buffer
	if code := runEdgeBuild("nope-xyz.cadish", "-", "", false, false, &out, &errOut); code != 1 {
		t.Errorf("exit = %d, want 1 on missing config", code)
	}
	if !strings.Contains(errOut.String(), "cadish edge build:") {
		t.Errorf("missing error prefix: %s", errOut.String())
	}
}

const edgeDeploySrc = `example.com, www.example.com {
    @html content_type text/html
    edge {
        account acc-123
        zone    example.com
        worker  cadish-edge-example
        distribute @html
    }
    cache_ttl default ttl 1m
}`

func TestEdgeDeployRequiresToken(t *testing.T) {
	t.Setenv("CF_API_TOKEN", "")
	cfg := writeCadishfile(t, edgeDeploySrc)
	var out, errOut bytes.Buffer
	if code := runEdgeDeploy(cfg, "https://o", &out, &errOut); code != 1 {
		t.Errorf("exit = %d, want 1 without CF_API_TOKEN", code)
	}
	if !strings.Contains(errOut.String(), "CF_API_TOKEN") {
		t.Errorf("error should mention CF_API_TOKEN: %s", errOut.String())
	}
}

func TestEdgeDeployRequiresOrigin(t *testing.T) {
	t.Setenv("CF_API_TOKEN", "tok")
	t.Setenv("CADISH_EDGE_ORIGIN", "")
	cfg := writeCadishfile(t, edgeDeploySrc)
	var out, errOut bytes.Buffer
	if code := runEdgeDeploy(cfg, "", &out, &errOut); code != 1 {
		t.Errorf("exit = %d, want 1 without an origin", code)
	}
	if !strings.Contains(errOut.String(), "origin") {
		t.Errorf("error should mention origin: %s", errOut.String())
	}
}

func TestEdgeEnableRequiresToken(t *testing.T) {
	t.Setenv("CF_API_TOKEN", "")
	cfg := writeCadishfile(t, edgeDeploySrc)
	var out, errOut bytes.Buffer
	if code := runEdgeManageRoutes(cfg, "enable", &out, &errOut); code != 1 {
		t.Errorf("exit = %d, want 1 without CF_API_TOKEN", code)
	}
}

func TestDeployConfigForDerivesRoutesAndKV(t *testing.T) {
	pipelines, err := loadEdgePipelines(writeCadishfile(t, edgeDeploySrc))
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	cfg, err := deployConfigFor(pipelines[0], "https://o")
	if err != nil {
		t.Fatalf("deployConfigFor: %v", err)
	}
	if cfg.AccountID != "acc-123" || cfg.WorkerName != "cadish-edge-example" {
		t.Errorf("cfg identity = %+v", cfg)
	}
	// No explicit routes -> derived from the site hosts (host/*).
	want := map[string]bool{"example.com/*": true, "www.example.com/*": true}
	if len(cfg.Routes) != 2 {
		t.Fatalf("routes = %v, want 2 derived", cfg.Routes)
	}
	for _, r := range cfg.Routes {
		if !want[r] {
			t.Errorf("unexpected derived route %q", r)
		}
	}
	// distribute @html implies a KV namespace, defaulted to <worker>-cache.
	if cfg.KVNamespace != "cadish-edge-example-cache" {
		t.Errorf("KV namespace = %q, want cadish-edge-example-cache", cfg.KVNamespace)
	}
	if cfg.OriginURL != "https://o" {
		t.Errorf("origin = %q", cfg.OriginURL)
	}
}

func TestDeployConfigForNoEdgeBlock(t *testing.T) {
	pipelines, err := loadEdgePipelines(writeCadishfile(t, edgeNativeSrc))
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if _, err := deployConfigFor(pipelines[0], "https://o"); err == nil {
		t.Error("expected an error for a site with no edge {} block")
	}
}
