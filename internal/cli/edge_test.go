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

// TestEdgeBuildStrictFailsOnEnvSecretHeaderValue (Fix 1, security completeness; updated
// for R07/D94): a `{$VAR}` in a `header` value is env-expanded to the secret BEFORE
// projection, baking it into the public worker IR. -strict must trip on it (the leak
// guard scans header op values, not only matcher values). Since R07 the QUOTED form
// `"{$VAR}"` ALSO expands — quoting no longer keeps it server-side — so it trips -strict
// too. An ESCAPED `\{$VAR}` keeps the literal text (ships no secret) and stays clean.
func TestEdgeBuildStrictFailsOnEnvSecretHeaderValue(t *testing.T) {
	t.Setenv("CADISH_TEST_ORIGIN_SECRET", "topsecret-zz1199")
	var out, errOut bytes.Buffer

	for _, name := range []string{"unquoted", "quoted"} {
		src := `example.com {
    header X-Internal-Auth {$CADISH_TEST_ORIGIN_SECRET}
    cache_ttl default ttl 1m
}`
		if name == "quoted" {
			src = `example.com {
    header X-Internal-Auth "{$CADISH_TEST_ORIGIN_SECRET}"
    cache_ttl default ttl 1m
}`
		}
		cfg := writeCadishfile(t, src)
		out.Reset()
		errOut.Reset()
		if code := runEdgeBuild(cfg, "-", "", true, false, &out, &errOut); code != 1 {
			t.Errorf("%s: strict exit = %d, want 1 (env secret in header value); stderr=%s", name, code, errOut.String())
		}
		if !strings.Contains(out.String(), "topsecret-zz1199") {
			t.Errorf("%s: expected the env secret to have been expanded into the IR JSON; out=%s", name, out.String())
		}
	}

	// Escaped placeholder -> stays literal `{$VAR}` -> no secret -> strict-clean.
	const safe = `example.com {
    header X-Internal-Auth \{$CADISH_TEST_ORIGIN_SECRET}
    cache_ttl default ttl 1m
}`
	cfg2 := writeCadishfile(t, safe)
	out.Reset()
	errOut.Reset()
	if code := runEdgeBuild(cfg2, "-", "", true, false, &out, &errOut); code != 0 {
		t.Errorf("strict exit = %d, want 0 for escaped placeholder; stderr=%s", code, errOut.String())
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
	if code := runEdgeDeploy(cfg, "https://o", &out, &errOut, false); code != 1 {
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
	if code := runEdgeDeploy(cfg, "", &out, &errOut, false); code != 1 {
		t.Errorf("exit = %d, want 1 without an origin", code)
	}
	if !strings.Contains(errOut.String(), "origin") {
		t.Errorf("error should mention origin: %s", errOut.String())
	}
}

// TestAbortEdgeDeployUnsafe is the hermetic core of the deploy safety gate: a
// non-zero ForcedPass (silent site-wide fail-open) or ValueExposed (a secret baked
// into the public bundle) must abort the upload; a clean report must not.
// (All cases here use allowPublicValues=false to verify unchanged default behavior.)
func TestAbortEdgeDeployUnsafe(t *testing.T) {
	cases := []struct {
		name string
		rep  edgeir.CoverageReport
		want bool
		msg  string
	}{
		{"clean", edgeir.CoverageReport{EdgeNative: 3}, false, ""},
		{"forced-pass", edgeir.CoverageReport{ForcedPass: 1}, true, "fail-open pass"},
		{"value-exposed", edgeir.CoverageReport{ValueExposed: 1}, true, "PUBLIC worker bundle"},
		{"security-gate-only-not-blocking", edgeir.CoverageReport{SecurityGate: 1}, false, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var errOut bytes.Buffer
			got := abortEdgeDeployUnsafe("example.com", tc.rep, &errOut, false /* allowPublicValues */)
			if got != tc.want {
				t.Fatalf("abort = %v, want %v (stderr=%s)", got, tc.want, errOut.String())
			}
			if tc.msg != "" && !strings.Contains(errOut.String(), tc.msg) {
				t.Errorf("stderr missing %q: %s", tc.msg, errOut.String())
			}
		})
	}
}

// edgeDeploySecretSrc has an `edge {}` block (so deploy resolves a target) AND a
// header matcher carrying a literal value — a potential baked-in secret that ships
// into the PUBLIC worker bundle (ValueExposed > 0).
const edgeDeploySecretSrc = `example.com {
    edge {
        account acc-123
        zone    example.com
        worker  cadish-edge-example
    }
    @auth header X-Internal-Auth s3cr3t
    pass @auth
    cache_ttl default ttl 1m
}`

// TestEdgeDeployRefusesSecretBundle (CRITICAL) proves `edge deploy` enforces the
// build safety gate BEFORE uploading: a config whose bundle would leak a literal
// into the public worker is refused (exit 1, with the gate's message — NOT a
// network error), so no script is ever PUT to Cloudflare. With token + origin set,
// the gate firing first is also what keeps this test from making a real CF call.
func TestEdgeDeployRefusesSecretBundle(t *testing.T) {
	t.Setenv("CF_API_TOKEN", "tok")
	cfg := writeCadishfile(t, edgeDeploySecretSrc)
	var out, errOut bytes.Buffer
	if code := runEdgeDeploy(cfg, "https://origin.example.com", &out, &errOut, false); code != 1 {
		t.Fatalf("exit = %d, want 1 (deploy must refuse a secret-bearing bundle); stderr=%s", code, errOut.String())
	}
	if !strings.Contains(errOut.String(), "PUBLIC worker bundle") {
		t.Errorf("expected the secret-in-bundle refusal, got: %s", errOut.String())
	}
	if strings.Contains(out.String(), "deployed worker") {
		t.Errorf("must not report a successful deploy: %s", out.String())
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

// TestDeployConfigForOriginPassthrough pins that the sentinel `-origin passthrough` is a
// VALID origin value: it is carried verbatim into the CADISH_ORIGIN binding (OriginURL), so
// the worker enters passthrough mode (fetch the original host/scheme, no rewrite) instead of
// being rejected as a non-URL. This is the front-a-multi-host-origin-in-the-same-CF-zone
// topology that avoids the canonicalize-redirect loop a host rewrite would trigger.
func TestDeployConfigForOriginPassthrough(t *testing.T) {
	pipelines, err := loadEdgePipelines(writeCadishfile(t, edgeDeploySrc))
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	cfg, err := deployConfigFor(pipelines[0], "passthrough")
	if err != nil {
		t.Fatalf("deployConfigFor with passthrough origin: %v", err)
	}
	if cfg.OriginURL != "passthrough" {
		t.Errorf("OriginURL = %q, want the passthrough sentinel carried verbatim into CADISH_ORIGIN", cfg.OriginURL)
	}
}

// TestEdgeDeployAcceptsPassthroughOrigin proves `cadish edge deploy -origin passthrough`
// passes the origin-required gate (the sentinel is a valid value, not an empty/rejected one).
// It then reaches the build safety gate; edgeDeploySecretSrc trips ValueExposed, so the
// deploy aborts there WITHOUT making a real CF call — that abort message (not the origin one)
// confirms passthrough was accepted as the origin.
func TestEdgeDeployAcceptsPassthroughOrigin(t *testing.T) {
	t.Setenv("CF_API_TOKEN", "tok")
	cfg := writeCadishfile(t, edgeDeploySecretSrc)
	var out, errOut bytes.Buffer
	code := runEdgeDeploy(cfg, "passthrough", &out, &errOut, false)
	if strings.Contains(errOut.String(), "an origin is required") {
		t.Fatalf("passthrough must be accepted as a valid origin, got: %s", errOut.String())
	}
	// It reaches and trips the value-exposure gate instead (proving origin passed).
	if code != 1 || !strings.Contains(errOut.String(), "PUBLIC worker bundle") {
		t.Fatalf("exit = %d, want the value-exposure gate to fire after accepting passthrough; stderr=%s", code, errOut.String())
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

// TestEdgeBuildFailsOnIPScopedSelectingDirective (R02): a `pass` (or cache_key / route)
// scoped by an `ip` matcher cannot be honored at the edge — the projector forces a site-wide
// fail-open pass. The build must fail NON-ZERO even WITHOUT -strict so the operator does not
// silently ship a worker that caches nothing for the whole site.
func TestEdgeBuildFailsOnIPScopedSelectingDirective(t *testing.T) {
	const src = `example.com {
    @internal ip 10.0.0.0/8
    pass @internal
    cache_key host path
    cache_ttl default ttl 1h
}`
	cfg := writeCadishfile(t, src)
	var out, errOut bytes.Buffer
	if code := runEdgeBuild(cfg, "-", "", false /* NOT strict */, false, &out, &errOut); code != 1 {
		t.Fatalf("non-strict exit = %d, want 1 (R02 ip-scoped pass must fail the build); stderr=%s", code, errOut.String())
	}
	if !strings.Contains(errOut.String(), "cannot evaluate") {
		t.Errorf("build error should explain the edge cannot evaluate the matcher: %s", errOut.String())
	}
}

// TestEdgeBuildFailsOnUntranslatableRegexScopedPass (R16): a `pass` scoped by an untranslatable
// RE2 regex (e.g. ungreedy `(?U)`) reaches the SAME fail-open path from an ordinary path_regex,
// not just Gateway. The build must fail NON-ZERO even WITHOUT -strict.
func TestEdgeBuildFailsOnUntranslatableRegexScopedPass(t *testing.T) {
	const src = `example.com {
    @ungreedy path_regex (?U)^/(live|stream)
    pass @ungreedy
    cache_key host path
    cache_ttl default ttl 1h
}`
	cfg := writeCadishfile(t, src)
	var out, errOut bytes.Buffer
	if code := runEdgeBuild(cfg, "-", "", false /* NOT strict */, false, &out, &errOut); code != 1 {
		t.Fatalf("non-strict exit = %d, want 1 (R16 untranslatable-regex-scoped pass must fail the build); stderr=%s", code, errOut.String())
	}
}

// TestEdgeBuildFailsOnUntranslatableRedirectRegex (R16): a `redirect` whose OWN path regex
// uses an untranslatable RE2 construct (e.g. ungreedy `(?U)`) delegates the redirect chain to
// the Cadish server behind — silently coarsening the operator's redirect intent. That is a
// ForcedPass the build gate must fail loud on: `cadish edge build` must exit NON-ZERO even
// WITHOUT -strict (mirroring the redirect-SCOPE-fail-closed and pass cases).
func TestEdgeBuildFailsOnUntranslatableRedirectRegex(t *testing.T) {
	const src = `example.com {
    redirect (?U)^/old$ 301 /new
    cache_key host path
    cache_ttl default ttl 1h
}`
	cfg := writeCadishfile(t, src)
	var out, errOut bytes.Buffer
	if code := runEdgeBuild(cfg, "-", "", false /* NOT strict */, false, &out, &errOut); code != 1 {
		t.Fatalf("non-strict exit = %d, want 1 (R16 untranslatable redirect regex delegates the chain → forced-pass must fail the build); stderr=%s", code, errOut.String())
	}
}

// TestEdgeBuildInlineIPNoPanic (R02): an INLINE `ip` matcher must not panic `cadish edge build`
// (it previously crashed in edgeView). It now fails the build cleanly (exit 1, fail-open).
func TestEdgeBuildInlineIPNoPanic(t *testing.T) {
	const src = `example.com {
    pass ip 10.0.0.0/8
    cache_key host path
    cache_ttl default ttl 1h
}`
	cfg := writeCadishfile(t, src)
	var out, errOut bytes.Buffer
	code := runEdgeBuild(cfg, "-", "", false, false, &out, &errOut) // must not panic
	if code != 1 {
		t.Fatalf("inline-ip build exit = %d, want 1; stderr=%s", code, errOut.String())
	}
}

// TestEdgeBuildSecurityOnlyIPDoesNotForceFail (R02): an `ip` matcher used ONLY by the security
// gate is delegated (fails -strict) but does NOT force a non-strict failure — no SELECTING
// directive references it, so a plain build of such a site still succeeds.
func TestEdgeBuildSecurityOnlyIPDoesNotForceFail(t *testing.T) {
	const src = `example.com {
    @office ip 203.0.113.43/32
    allow @office
    cache_key host path
    cache_ttl default ttl 1h
}`
	cfg := writeCadishfile(t, src)
	var out, errOut bytes.Buffer
	if code := runEdgeBuild(cfg, "-", "", false /* NOT strict */, false, &out, &errOut); code != 0 {
		t.Fatalf("non-strict exit = %d, want 0 (security-only ip must NOT force-fail the build); stderr=%s", code, errOut.String())
	}
	// But -strict still trips (the security gate / ip matcher is delegated).
	out.Reset()
	errOut.Reset()
	if code := runEdgeBuild(cfg, "-", "", true, false, &out, &errOut); code != 1 {
		t.Errorf("strict exit = %d, want 1 (delegated ip / security gate); stderr=%s", code, errOut.String())
	}
}

// edgeDeployCookieSrc has an `edge {}` block and a cookie matcher carrying a non-secret
// literal value (AdultContent 0) — a real-world case that legitimately ships non-secret
// values to the edge worker (ValueExposed > 0).
const edgeDeployCookieSrc = `example.com {
    edge {
        account acc-123
        zone    example.com
        worker  cadish-edge-example
    }
    @adult cookie AdultContent 0
    pass @adult
    cache_ttl default ttl 1m
}`

// TestAbortEdgeDeployUnsafeAllowPublicValues validates the -allow-public-values flag
// semantics directly against abortEdgeDeployUnsafe:
//   - Without the flag: ValueExposed aborts (existing behavior, unchanged).
//   - With the flag:    ValueExposed does NOT abort, but the warning is still printed.
//   - ForcedPass ALWAYS aborts regardless of the flag (correctness gate, not secrets gate).
func TestAbortEdgeDeployUnsafeAllowPublicValues(t *testing.T) {
	cases := []struct {
		name            string
		rep             edgeir.CoverageReport
		allowPublicVals bool
		wantAbort       bool
		wantInStderr    string
		wantNotInStderr string
	}{
		{
			name:            "value-exposed-without-flag-aborts",
			rep:             edgeir.CoverageReport{ValueExposed: 1},
			allowPublicVals: false,
			wantAbort:       true,
			wantInStderr:    "refusing to upload",
		},
		{
			name:            "value-exposed-with-flag-does-not-abort",
			rep:             edgeir.CoverageReport{ValueExposed: 2},
			allowPublicVals: true,
			wantAbort:       false,
			wantInStderr:    "VALUE-EXPOSURE", // warning still printed
		},
		{
			name:            "forced-pass-with-flag-still-aborts",
			rep:             edgeir.CoverageReport{ForcedPass: 1},
			allowPublicVals: true,
			wantAbort:       true,
			wantInStderr:    "fail-open pass",
		},
		{
			name:            "forced-pass-and-value-exposed-with-flag-aborts-on-forced",
			rep:             edgeir.CoverageReport{ForcedPass: 1, ValueExposed: 1},
			allowPublicVals: true,
			wantAbort:       true,
			wantInStderr:    "fail-open pass",
		},
		{
			name:            "clean-with-flag-does-not-abort",
			rep:             edgeir.CoverageReport{EdgeNative: 3},
			allowPublicVals: true,
			wantAbort:       false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var errOut bytes.Buffer
			got := abortEdgeDeployUnsafe("example.com", tc.rep, &errOut, tc.allowPublicVals)
			if got != tc.wantAbort {
				t.Fatalf("abort = %v, want %v (stderr=%s)", got, tc.wantAbort, errOut.String())
			}
			if tc.wantInStderr != "" && !strings.Contains(errOut.String(), tc.wantInStderr) {
				t.Errorf("stderr missing %q: %s", tc.wantInStderr, errOut.String())
			}
			if tc.wantNotInStderr != "" && strings.Contains(errOut.String(), tc.wantNotInStderr) {
				t.Errorf("stderr should not contain %q: %s", tc.wantNotInStderr, errOut.String())
			}
		})
	}
}

// TestEdgeDeployCookieLiteralRefusedWithoutFlag proves that a config with a
// non-secret cookie matcher literal is refused by deploy WITHOUT -allow-public-values.
func TestEdgeDeployCookieLiteralRefusedWithoutFlag(t *testing.T) {
	t.Setenv("CF_API_TOKEN", "tok")
	cfg := writeCadishfile(t, edgeDeployCookieSrc)
	var out, errOut bytes.Buffer
	if code := runEdgeDeploy(cfg, "https://origin.example.com", &out, &errOut, false); code != 1 {
		t.Fatalf("exit = %d, want 1 (cookie literal must be refused without flag); stderr=%s", code, errOut.String())
	}
	if !strings.Contains(errOut.String(), "refusing to upload") {
		t.Errorf("expected the value-exposure refusal, got: %s", errOut.String())
	}
	if strings.Contains(out.String(), "deployed worker") {
		t.Errorf("must not report a successful deploy: %s", out.String())
	}
}

// TestEdgeDeployCookieLiteralAllowedWithFlag proves that WITH -allow-public-values,
// a cookie matcher literal does NOT trigger the refusing-to-upload abort; the
// VALUE-EXPOSURE warning is still printed.
// The deploy will fail at the CF API call (fake token / no real CF), but that's the
// network gate — not the value-exposure safety gate — so we assert on the stderr
// message distinguishing the two failure modes.
func TestEdgeDeployCookieLiteralAllowedWithFlag(t *testing.T) {
	t.Setenv("CF_API_TOKEN", "tok")
	cfg := writeCadishfile(t, edgeDeployCookieSrc)
	var out, errOut bytes.Buffer
	// With allowPublicValues=true the safety gate must NOT abort on ValueExposed.
	// The call will still exit non-zero (fake CF token → network/API error), but
	// the exit must NOT be due to the "refusing to upload" value-exposure gate.
	code := runEdgeDeploy(cfg, "https://origin.example.com", &out, &errOut, true)
	if strings.Contains(errOut.String(), "refusing to upload") {
		t.Errorf("-allow-public-values must suppress the value-exposure abort; stderr=%s", errOut.String())
	}
	// VALUE-EXPOSURE warning must still be printed (operator must see the literals).
	if !strings.Contains(errOut.String(), "VALUE-EXPOSURE") {
		t.Errorf("VALUE-EXPOSURE warning must still be printed even with flag; stderr=%s", errOut.String())
	}
	// Either it succeeded (somehow) or it failed on the CF network call (not the gate).
	// In both cases we must NOT see "deployed worker" reported from a fake-token run.
	if code == 0 && !strings.Contains(out.String(), "deployed worker") {
		t.Errorf("unexpected success with no 'deployed worker' output")
	}
}
