package cli

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	edgebundle "github.com/cadi-sh/cadish/edge"
	"github.com/cadi-sh/cadish/internal/cadishfile"
	"github.com/cadi-sh/cadish/internal/edgedeploy"
	"github.com/cadi-sh/cadish/internal/edgeir"
	"github.com/cadi-sh/cadish/internal/pipeline"
)

// edgeUsage is the `cadish edge` subcommand help.
const edgeUsage = `cadish edge — Cadish Edge management plane (Cloudflare Workers).

Usage:
  cadish edge build   [-config Cadishfile] [-o FILE] [-bundle FILE] [-strict]
  cadish edge deploy  [-config Cadishfile] [-origin URL] [-allow-public-values]
  cadish edge enable  [-config Cadishfile]                 # attach routes (go-live)
  cadish edge disable [-config Cadishfile]                 # detach routes (kill switch)

  build    compile a Cadishfile, project the edge IR, and optionally assemble the
           worker bundle (generic runtime + baked IR). Prints a coverage report.
  deploy   build + upload the worker script + bindings to Cloudflare WITHOUT routes
           (testable via the *.workers.dev URL; no production traffic).
  enable   attach the site's routes to the worker (traffic flows through the edge).
  disable  detach the worker's routes (instant bypass to the cadish server behind).

Auth: a Cloudflare API token in env CF_API_TOKEN (deploy/enable/disable). The
deploy identity (account/zone/worker/route/kv) comes from the edge {} block.

Flags (build):
  -config PATH   path to the Cadishfile (default Cadishfile)
  -o FILE        write the IR JSON here (default: build/<site>.edgeir.json per site; - = stdout)
  -bundle FILE   write the worker bundle here (- = stdout; "auto" = per-site
                 build/<host>.worker.js); omitted = no bundle
  -strict        exit non-zero if anything is delegated (a coverage regression)
  -json          print the coverage report as JSON instead of text

Flags (deploy):
  -config PATH             path to the Cadishfile (default Cadishfile)
  -origin URL              the upstream the worker fetches (the cadish server behind); falls
                           back to env CADISH_EDGE_ORIGIN. Required. The literal "passthrough"
                           selects PASSTHROUGH mode: the worker fetches the ORIGINAL request
                           URL unchanged (host + scheme preserved), relying on Cloudflare
                           same-zone loop-prevention to reach the real origin — use this when
                           fronting a multi-host origin in the SAME CF zone (a host rewrite to
                           an apex/backend hostname would trigger the origin's canonicalize
                           redirect loop).
  -allow-public-values     acknowledge that the VALUE-EXPOSURE warnings printed above have been
                           reviewed and none of the listed literals is a secret; allows the
                           deploy to proceed past the value-exposure safety gate. The ForcedPass
                           correctness gate (site-wide fail-open) is NOT bypassed by this flag.
                           Only pass this after reviewing the printed VALUE-EXPOSURE warnings
                           and confirming none is a secret.
`

// Edge dispatches the `cadish edge …` subcommands. It is the management plane for
// Cadish Edge; this first slice ships only `build` (IR + coverage report).
func Edge(args []string) int {
	if len(args) == 0 {
		fmt.Fprint(os.Stderr, edgeUsage)
		return 2
	}
	sub, rest := args[0], args[1:]
	switch sub {
	case "build":
		return EdgeBuild(rest)
	case "deploy":
		return EdgeDeploy(rest)
	case "enable":
		return EdgeManageRoutes(rest, "enable")
	case "disable":
		return EdgeManageRoutes(rest, "disable")
	case "help", "-h", "--help":
		fmt.Fprint(os.Stdout, edgeUsage)
		return 0
	default:
		fmt.Fprintf(os.Stderr, "cadish edge: unknown subcommand %q\n\n", sub)
		fmt.Fprint(os.Stderr, edgeUsage)
		return 2
	}
}

// EdgeBuild compiles a Cadishfile, projects each site to an EdgeIR, writes the IR
// JSON, and prints a coverage report. With -strict it exits non-zero when anything
// is delegated (the edge equivalent of `cadish check -strict`).
func EdgeBuild(args []string) int {
	fs := flag.NewFlagSet("edge build", flag.ContinueOnError)
	cfgPath := fs.String("config", defaultConfigPath, "path to the Cadishfile")
	out := fs.String("o", "", "write the IR JSON here (default: build/<site>.edgeir.json; - = stdout)")
	bundle := fs.String("bundle", "", `write the worker bundle here (- = stdout; "auto" = per-site build/<host>.worker.js)`)
	strict := fs.Bool("strict", false, "exit non-zero if anything is delegated (coverage regression)")
	asJSON := fs.Bool("json", false, "print the coverage report as JSON")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if rejectStrayConfigArgs("edge build", fs.Args()) {
		return 2
	}
	return runEdgeBuild(*cfgPath, *out, *bundle, *strict, *asJSON, os.Stdout, os.Stderr)
}

// edgeSite pairs a site's projected IR with its coverage report.
type edgeSite struct {
	hosts string
	ir    edgeir.EdgeIR
	rep   edgeir.CoverageReport
}

// runEdgeBuild is the testable core of EdgeBuild.
func runEdgeBuild(cfgPath, out, bundle string, strict, asJSON bool, stdout, stderr io.Writer) int {
	pipelines, err := loadEdgePipelines(cfgPath)
	if err != nil {
		fmt.Fprintf(stderr, "cadish edge build: %v\n", err)
		return 1
	}

	sites := make([]edgeSite, 0, len(pipelines))
	for _, p := range pipelines {
		ir, rep, perr := edgeir.Project(p)
		if perr != nil {
			fmt.Fprintf(stderr, "cadish edge build: %v\n", perr)
			return 1
		}
		sites = append(sites, edgeSite{hosts: strings.Join(p.EdgeHosts(), ","), ir: ir, rep: rep})
	}

	// Write the IR JSON. With -o - everything goes to stdout (an array when multiple
	// sites); with -o FILE the same; otherwise one <site>.edgeir.json per site.
	if werr := writeEdgeIR(sites, out, stdout); werr != nil {
		fmt.Fprintf(stderr, "cadish edge build: %v\n", werr)
		return 1
	}

	// Optionally assemble the worker bundle(s): the generic JS runtime + the baked IR.
	if bundle != "" {
		if werr := writeBundles(sites, bundle, stdout); werr != nil {
			fmt.Fprintf(stderr, "cadish edge build: %v\n", werr)
			return 1
		}
	}

	// Coverage report.
	if asJSON {
		if werr := writeCoverageJSON(sites, stdout); werr != nil {
			fmt.Fprintf(stderr, "cadish edge build: %v\n", werr)
			return 1
		}
	} else {
		writeCoverageText(sites, stderr)
	}

	// SAFETY GATE (R02/R16) — fails the build NON-ZERO even WITHOUT -strict. A SELECTING
	// directive (pass / route / redirect / cache_key selector or token / cache_ttl / storage /
	// edge-tier / upgrade) referenced a matcher the edge cannot evaluate (a server-only
	// Gateway/lb/`ip` matcher, or an untranslatable RE2 regex), so the projector forced the SAFE
	// fallback — a site-wide fail-open `pass` or a delegated redirect chain. The runtime is safe,
	// but the operator's PRECISE intent is silently coarsened (the whole site is passed), so the
	// build refuses LOUDLY: the operator must consciously keep that directive on the Cadish server
	// behind rather than discover at runtime that the edge caches nothing. This is the WS-C
	// "fail loud at build" chokepoint the conformance suite cannot catch by construction.
	var forced int
	for _, s := range sites {
		forced += s.rep.ForcedPass
	}
	if forced > 0 {
		fmt.Fprintf(stderr, "cadish edge build: %d selecting directive(s) (pass/route/redirect/cache_key/cache_ttl/storage/edge-tier/upgrade) reference a matcher the edge cannot evaluate (a server-only Gateway/lb/`ip` matcher or an untranslatable RE2 regex) and were forced to a site-wide fail-open pass or a delegated redirect — the edge cannot honor them; keep those directives on the Cadish server behind (see the FAIL-OPEN warnings above)\n", forced)
		return 1
	}

	// Exit code: under -strict any delegated directive is a coverage regression, AND
	// two safety signals fail the build even though they are surfaced as warnings in
	// non-strict mode: a SERVER-ONLY security gate that the edge silently won't
	// enforce (Fix A), and a matcher literal value that would ship into the public
	// worker bundle (a potential baked-in secret, Fix B).
	if strict {
		var delegated, secGate, exposed int
		for _, s := range sites {
			delegated += s.rep.Delegated
			secGate += s.rep.SecurityGate
			exposed += s.rep.ValueExposed
		}
		failed := false
		if delegated > 0 {
			fmt.Fprintf(stderr, "cadish edge build: -strict: %d directive(s) delegated (not edge-native)\n", delegated)
			failed = true
		}
		if secGate > 0 {
			fmt.Fprintf(stderr, "cadish edge build: -strict: a security gate (allow/deny/block/rate_limit) is present but is NOT enforced at the edge — enforce it via Cloudflare's own security layer\n")
			failed = true
		}
		if exposed > 0 {
			fmt.Fprintf(stderr, "cadish edge build: -strict: %d literal value(s) (matcher values, header op values, on_error/respond bodies, redirect targets, or cache_key literals) would be exposed in the public worker bundle (a potential secret) — remove the literal or quote the `{$VAR}` to keep it server-side\n", exposed)
			failed = true
		}
		if failed {
			return 1
		}
	}
	return 0
}

// loadEdgePipelines reads, env-substitutes, splices imports, expands site-groups,
// and compiles every site of the Cadishfile at path — the same load sequence as
// config.Load, minus the runtime cache stores (the edge plane needs only the
// compiled Pipeline to project).
func loadEdgePipelines(path string) ([]*pipeline.Pipeline, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	file, err := cadishfile.Parse(path, data)
	if err != nil {
		return nil, err
	}
	cadishfile.SubstituteEnv(file, os.LookupEnv)
	sites, err := cadishfile.ExpandGroups(file.Sites)
	if err != nil {
		return nil, err
	}
	baseDir := filepath.Dir(path)
	var out []*pipeline.Pipeline
	for _, site := range sites {
		spliced, err := pipeline.SpliceImports(site, pipeline.FileImportResolver(baseDir))
		if err != nil {
			return nil, err
		}
		p, err := pipeline.Compile(spliced)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("%s: config defines no sites", path)
	}
	return out, nil
}

// writeEdgeIR emits the IR JSON. With out == "-" (or out == "" and stdout is the
// only sink chosen for a single combined doc) it writes to stdout; with out == ""
// it writes one <site>.edgeir.json per site into the build/ output dir; with out
// FILE it writes one combined document (an array when multiple sites).
func writeEdgeIR(sites []edgeSite, out string, stdout io.Writer) error {
	switch {
	case out == "-":
		return encodeIR(stdout, sites)
	case out != "":
		f, err := os.Create(out)
		if err != nil {
			return err
		}
		defer f.Close()
		return encodeIR(f, sites)
	default:
		// One file per site, named from the first host (sanitized), under build/ so
		// a test run leaves no scattered files in cwd — clean with `rm -rf build/`.
		if err := os.MkdirAll(edgeOutputDir, 0o755); err != nil {
			return err
		}
		for _, s := range sites {
			name := filepath.Join(edgeOutputDir, edgeIRFilename(s.ir.Site.Hosts))
			f, err := os.Create(name)
			if err != nil {
				return err
			}
			enc := json.NewEncoder(f)
			enc.SetIndent("", "  ")
			werr := enc.Encode(s.ir)
			cerr := f.Close()
			if werr != nil {
				return werr
			}
			if cerr != nil {
				return cerr
			}
		}
		return nil
	}
}

// writeBundles assembles the worker bundle(s). With out == "-" the bundle goes to
// stdout (only valid for a single site); with out == "auto" one <host>.worker.js
// is written per site into the build/ output dir; otherwise out is a single FILE
// (only valid for one site).
func writeBundles(sites []edgeSite, out string, stdout io.Writer) error {
	switch {
	case out == "-":
		if len(sites) != 1 {
			return fmt.Errorf("-bundle -: cannot write %d sites to stdout; use -bundle auto", len(sites))
		}
		src, err := edgebundle.Bundle(sites[0].ir)
		if err != nil {
			return err
		}
		_, err = io.WriteString(stdout, src)
		return err
	case out == "auto":
		if err := os.MkdirAll(edgeOutputDir, 0o755); err != nil {
			return err
		}
		for _, s := range sites {
			src, err := edgebundle.Bundle(s.ir)
			if err != nil {
				return err
			}
			name := filepath.Join(edgeOutputDir, edgeWorkerFilename(s.ir.Site.Hosts))
			if err := os.WriteFile(name, []byte(src), 0o644); err != nil {
				return err
			}
		}
		return nil
	default:
		if len(sites) != 1 {
			return fmt.Errorf("-bundle %s: cannot write %d sites to one file; use -bundle auto", out, len(sites))
		}
		src, err := edgebundle.Bundle(sites[0].ir)
		if err != nil {
			return err
		}
		return os.WriteFile(out, []byte(src), 0o644)
	}
}

// edgeOutputDir is where `edge build` drops per-site IR/bundle files when no explicit
// -o / -bundle path is given. A single gitignored dir keeps test runs from scattering
// <host>.edgeir.json / <host>.worker.js across the cwd — clean up with `rm -rf build/`.
const edgeOutputDir = "build"

// edgeWorkerFilename derives a stable worker-bundle BASENAME from a site's first
// host (same sanitization as edgeIRFilename). Callers join it under edgeOutputDir.
func edgeWorkerFilename(hosts []string) string {
	base := "site"
	if len(hosts) > 0 && hosts[0] != "" {
		base = hosts[0]
	}
	base = strings.ReplaceAll(base, "*", "wildcard")
	base = strings.ReplaceAll(base, "/", "_")
	return base + ".worker.js"
}

// encodeIR writes the IR(s) to w: a single object for one site, an array otherwise.
func encodeIR(w io.Writer, sites []edgeSite) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	if len(sites) == 1 {
		return enc.Encode(sites[0].ir)
	}
	irs := make([]edgeir.EdgeIR, 0, len(sites))
	for _, s := range sites {
		irs = append(irs, s.ir)
	}
	return enc.Encode(irs)
}

// edgeIRFilename derives a stable IR filename from a site's first host. A wildcard
// host (*.example.com) sanitizes to wildcard.example.com; an empty host set falls
// back to "site".
func edgeIRFilename(hosts []string) string {
	base := "site"
	if len(hosts) > 0 && hosts[0] != "" {
		base = hosts[0]
	}
	base = strings.ReplaceAll(base, "*", "wildcard")
	base = strings.ReplaceAll(base, "/", "_")
	return base + ".edgeir.json"
}

func writeCoverageJSON(sites []edgeSite, w io.Writer) error {
	type siteCov struct {
		Hosts  []string              `json:"hosts"`
		Report edgeir.CoverageReport `json:"report"`
	}
	out := make([]siteCov, 0, len(sites))
	for _, s := range sites {
		out = append(out, siteCov{Hosts: s.ir.Site.Hosts, Report: s.rep})
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(out)
}

// EdgeDeploy builds each site's worker bundle and uploads it (script + bindings,
// no routes) to Cloudflare. Auth: CF_API_TOKEN; origin: -origin or CADISH_EDGE_ORIGIN.
// -allow-public-values acknowledges that the VALUE-EXPOSURE warnings have been reviewed
// and none of the listed literals is a secret; the ForcedPass correctness gate is not
// bypassed by this flag.
func EdgeDeploy(args []string) int {
	fs := flag.NewFlagSet("edge deploy", flag.ContinueOnError)
	cfgPath := fs.String("config", defaultConfigPath, "path to the Cadishfile")
	origin := fs.String("origin", "", `upstream URL the worker fetches, or "passthrough" to fetch the original host/scheme via same-zone loop-prevention (else env CADISH_EDGE_ORIGIN)`)
	allowPublicValues := fs.Bool("allow-public-values", false, "acknowledge VALUE-EXPOSURE warnings and allow deploy to proceed (only after confirming no listed literal is a secret)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if rejectStrayConfigArgs("edge deploy", fs.Args()) {
		return 2
	}
	return runEdgeDeploy(*cfgPath, *origin, os.Stdout, os.Stderr, *allowPublicValues)
}

func runEdgeDeploy(cfgPath, origin string, stdout, stderr io.Writer, allowPublicValues bool) int {
	token := os.Getenv("CF_API_TOKEN")
	if token == "" {
		fmt.Fprintln(stderr, "cadish edge deploy: CF_API_TOKEN is required (a Cloudflare API token)")
		return 1
	}
	if origin == "" {
		origin = os.Getenv("CADISH_EDGE_ORIGIN")
	}
	if origin == "" {
		fmt.Fprintln(stderr, "cadish edge deploy: an origin is required (set -origin URL or CADISH_EDGE_ORIGIN)")
		return 1
	}
	pipelines, err := loadEdgePipelines(cfgPath)
	if err != nil {
		fmt.Fprintf(stderr, "cadish edge deploy: %v\n", err)
		return 1
	}
	client := edgedeploy.New(token)
	ctx := context.Background()
	for _, p := range pipelines {
		cfg, err := deployConfigFor(p, origin)
		if err != nil {
			fmt.Fprintf(stderr, "cadish edge deploy: %v\n", err)
			return 1
		}
		ir, rep, perr := edgeir.Project(p)
		if perr != nil {
			fmt.Fprintf(stderr, "cadish edge deploy: %v\n", perr)
			return 1
		}
		// SAFETY GATE — `edge deploy` is `build + upload`, so it must honor the SAME
		// fail-closed gates `edge build` enforces, BEFORE anything is uploaded. Skipping
		// them here would let `deploy` push a worker that `build` refuses: one that
		// silently fails open site-wide (ForcedPass) or that bakes a secret into the
		// PUBLIC bundle (ValueExposed). Refuse to upload such a bundle.
		// The ForcedPass gate is always enforced. The ValueExposed gate can be
		// acknowledged with -allow-public-values (only after reviewing the warnings).
		if abortEdgeDeployUnsafe(strings.Join(p.EdgeHosts(), ","), rep, stderr, allowPublicValues) {
			return 1
		}
		src, berr := edgebundle.Bundle(ir)
		if berr != nil {
			fmt.Fprintf(stderr, "cadish edge deploy: %v\n", berr)
			return 1
		}
		if err := client.Deploy(ctx, cfg, src); err != nil {
			fmt.Fprintf(stderr, "cadish edge deploy: %v\n", err)
			return 1
		}
		fmt.Fprintf(stdout, "deployed worker %q (dark — no routes; run `cadish edge enable` to go live)\n", cfg.WorkerName)
	}
	return 0
}

// abortEdgeDeployUnsafe applies the `edge build` safety gates to a deploy: it
// refuses to UPLOAD a bundle the build would have rejected. A non-zero ForcedPass
// means a selecting directive was silently coarsened to a site-wide fail-open pass
// (the edge would cache nothing) — `edge build` already fails non-zero on this even
// without -strict. ForcedPass ALWAYS aborts, regardless of allowPublicValues, because
// it is a correctness gate (the edge would cache nothing), not a secrets gate.
//
// A non-zero ValueExposed means a matcher/header literal (a potential baked-in secret)
// would ship in the PUBLIC worker bundle. By default this also aborts. When
// allowPublicValues is true (the operator has passed -allow-public-values after
// reviewing the VALUE-EXPOSURE warnings and confirming none is a secret), the
// VALUE-EXPOSURE warning is still printed but the deploy is NOT aborted on this gate.
//
// Returns true (and prints why) to abort. (SecurityGate stays advisory, mirroring
// `build`: it is enforced on the Cadish server behind the edge, so it is surfaced but
// not a deploy-blocking gate.)
func abortEdgeDeployUnsafe(hosts string, rep edgeir.CoverageReport, stderr io.Writer, allowPublicValues bool) bool {
	abort := false
	if rep.ForcedPass > 0 {
		fmt.Fprintf(stderr, "cadish edge deploy: %s: refusing to upload — %d selecting directive(s) were forced to a site-wide fail-open pass or a delegated redirect (they reference a matcher the edge cannot evaluate); the edge cannot honor them, so keep those directives on the Cadish server behind (run `cadish edge build` for detail)\n", hosts, rep.ForcedPass)
		abort = true
	}
	if rep.ValueExposed > 0 {
		if allowPublicValues {
			// VALUE-EXPOSURE advisory — operator acknowledged via -allow-public-values.
			// Still print the warning so the operator sees which literals are shipping.
			fmt.Fprintf(stderr, "cadish edge deploy: %s: VALUE-EXPOSURE advisory — %d literal value(s) will be exposed in the PUBLIC worker bundle; proceeding because -allow-public-values was set (only pass this after confirming none is a secret)\n", hosts, rep.ValueExposed)
		} else {
			fmt.Fprintf(stderr, "cadish edge deploy: %s: refusing to upload — %d literal value(s) would be exposed in the PUBLIC worker bundle (a potential baked-in secret); remove the literal or quote the {$VAR} to keep it server-side, or pass -allow-public-values after reviewing these and confirming none is a secret (run `cadish edge build -strict` for detail)\n", hosts, rep.ValueExposed)
			abort = true
		}
	}
	return abort
}

// EdgeManageRoutes attaches (enable) or detaches (disable) the worker routes.
func EdgeManageRoutes(args []string, action string) int {
	fs := flag.NewFlagSet("edge "+action, flag.ContinueOnError)
	cfgPath := fs.String("config", defaultConfigPath, "path to the Cadishfile")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if rejectStrayConfigArgs("edge "+action, fs.Args()) {
		return 2
	}
	return runEdgeManageRoutes(*cfgPath, action, os.Stdout, os.Stderr)
}

func runEdgeManageRoutes(cfgPath, action string, stdout, stderr io.Writer) int {
	token := os.Getenv("CF_API_TOKEN")
	if token == "" {
		fmt.Fprintf(stderr, "cadish edge %s: CF_API_TOKEN is required\n", action)
		return 1
	}
	pipelines, err := loadEdgePipelines(cfgPath)
	if err != nil {
		fmt.Fprintf(stderr, "cadish edge %s: %v\n", action, err)
		return 1
	}
	client := edgedeploy.New(token)
	ctx := context.Background()
	for _, p := range pipelines {
		cfg, err := deployConfigFor(p, "")
		if err != nil {
			fmt.Fprintf(stderr, "cadish edge %s: %v\n", action, err)
			return 1
		}
		// Route EXCLUSIONS (D105): the no-worker carve-outs to create on enable / remove on
		// disable. Enable creates everything the site projects — ir.RouteExclusions =
		// merge(auto, explicit): the auto-derived set (only under `edge { bypass_passes }`)
		// PLUS every operator-declared `edge { bypass … }`. Disable removes the FULL union the
		// tool could ever have created (rep.AllRouteExcludable = RouteExcludable ∪
		// RouteExcludableExplicit) so the kill switch fully reverts even an explicit-only site
		// and even if the toggle was flipped off since the routes were created (F-D4).
		ir, rep, perr := edgeir.Project(p)
		if perr != nil {
			fmt.Fprintf(stderr, "cadish edge %s: %v\n", action, perr)
			return 1
		}
		if action == "enable" {
			cfg.RouteExclusions = ir.RouteExclusions
			err = client.Enable(ctx, cfg)
		} else {
			cfg.RouteExclusions = rep.AllRouteExcludable()
			err = client.Disable(ctx, cfg)
		}
		if err != nil {
			fmt.Fprintf(stderr, "cadish edge %s: %v\n", action, err)
			return 1
		}
		verb := "enabled (routes attached — traffic flows through the edge)"
		if action == "disable" {
			verb = "disabled (routes detached — traffic bypasses the edge)"
		}
		fmt.Fprintf(stdout, "worker %q %s\n", cfg.WorkerName, verb)
	}
	return 0
}

// deployConfigFor resolves a pipeline's edge {} block (+ env fallbacks + the
// origin) into an edgedeploy.Config. origin may be "" for enable/disable (which
// do not set bindings). Routes default to the site hosts (`host/*`) when the edge
// block lists none.
func deployConfigFor(p *pipeline.Pipeline, origin string) (edgedeploy.Config, error) {
	d := p.EdgeDeployConfig()
	if !d.Configured {
		return edgedeploy.Config{}, fmt.Errorf("site %s has no `edge { }` block — add account/zone/worker/route to deploy", strings.Join(p.EdgeHosts(), ","))
	}
	account := d.Account
	if account == "" {
		account = os.Getenv("CF_ACCOUNT_ID")
	}
	if account == "" {
		return edgedeploy.Config{}, fmt.Errorf("edge: no account (set `account` in the edge block or CF_ACCOUNT_ID)")
	}
	if d.Worker == "" {
		return edgedeploy.Config{}, fmt.Errorf("edge: no worker name (set `worker` in the edge block)")
	}
	routes := d.Routes
	if len(routes) == 0 {
		routes = deriveRoutes(p.EdgeHosts())
	}
	cfg := edgedeploy.Config{
		AccountID:  account,
		Zone:       d.Zone,
		WorkerName: d.Worker,
		Routes:     routes,
		OriginURL:  origin,
	}
	if p.EdgeUsesKV() {
		ns := d.KVNamespace
		if ns == "" {
			ns = d.Worker + "-cache"
		}
		cfg.KVNamespace = ns
	}
	return cfg, nil
}

// deriveRoutes turns a site's host set into default worker route patterns
// (`host/*`), used when the edge block lists no explicit `route`.
func deriveRoutes(hosts []string) []string {
	out := make([]string, 0, len(hosts))
	for _, h := range hosts {
		if h == "" {
			continue
		}
		out = append(out, h+"/*")
	}
	return out
}

// containsStr reports whether ss contains s (small set; linear is fine).
func containsStr(ss []string, s string) bool {
	for _, x := range ss {
		if x == s {
			return true
		}
	}
	return false
}

// writeCoverageText prints a human coverage report per site (to stderr, like
// `cadish check`, so the IR on stdout stays pipeable).
func writeCoverageText(sites []edgeSite, w io.Writer) {
	for _, s := range sites {
		fmt.Fprintf(w, "edge coverage — %s (IR v%d)\n", s.hosts, s.ir.IRVersion)
		fmt.Fprintf(w, "  edge-native: %d directive(s)\n", s.rep.EdgeNative)
		fmt.Fprintf(w, "  delegated:   %d directive(s)\n", s.rep.Delegated)
		if s.rep.ForcedPass > 0 {
			fmt.Fprintf(w, "  forced-pass: %d selecting directive(s) the edge cannot honor (build FAILS)\n", s.rep.ForcedPass)
		}
		// Group delegate reasons by directive for a compact summary.
		counts := map[string]int{}
		reasons := map[string]string{}
		for _, d := range s.rep.DelegatedItems {
			counts[d.Directive]++
			reasons[d.Directive] = d.Reason
		}
		dirs := make([]string, 0, len(counts))
		for k := range counts {
			dirs = append(dirs, k)
		}
		sort.Strings(dirs)
		for _, d := range dirs {
			fmt.Fprintf(w, "    - %s x%d → pass: %s\n", d, counts[d], reasons[d])
		}
		// Route-excludable (D105): the path patterns that would skip the worker → origin
		// direct. Two sources, distinguished in the listing:
		//   ~ auto-derived  — paths the worker would ONLY ever `pass` (a path-only
		//                     unconditional pass with no edge-unique directive on it); ALWAYS
		//                     shown, projected into the IR only under `edge { bypass_passes }`.
		//   bypass operator-declared `edge { bypass PATTERN… }` carve-outs; taken at the
		//                     operator's word and ALWAYS projected into the IR.
		if len(s.rep.RouteExcludable) > 0 || len(s.rep.RouteExcludableExplicit) > 0 {
			total := len(s.rep.RouteExcludable) + len(s.rep.RouteExcludableExplicit)
			// The auto-derived set is in the IR only under `bypass_passes`; detect it by
			// membership (an auto pattern present in the projected IR exclusions).
			autoActive := false
			for _, pat := range s.rep.RouteExcludable {
				if containsStr(s.ir.RouteExclusions, pat) {
					autoActive = true
					break
				}
			}
			state := "review the ~ set then enable `edge { bypass_passes }`; bypass entries are operator-declared and active"
			switch {
			case len(s.rep.RouteExcludable) == 0:
				state = "operator-declared via `edge { bypass … }` — projected into the IR"
			case autoActive:
				state = "ACTIVE via `bypass_passes` + operator-declared — projected into the IR"
			}
			fmt.Fprintf(w, "  route-excludable: %d path pattern(s) would skip the worker → origin direct (%s)\n", total, state)
			for _, pat := range s.rep.RouteExcludable {
				fmt.Fprintf(w, "    ~ %s\n", pat)
			}
			for _, pat := range s.rep.RouteExcludableExplicit {
				fmt.Fprintf(w, "    bypass %s\n", pat)
			}
			for _, warn := range s.rep.BypassOverlapWarnings {
				fmt.Fprintf(w, "    ! WARNING: %s\n", warn)
			}
		}
		if len(s.rep.Warnings) > 0 {
			fmt.Fprintf(w, "  warnings:    %d\n", len(s.rep.Warnings))
			for _, warn := range s.rep.Warnings {
				fmt.Fprintf(w, "    ! %s\n", warn)
			}
		}
	}
}
