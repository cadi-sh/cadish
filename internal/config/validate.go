package config

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/cadi-sh/cadish/internal/cadishfile"
	"github.com/cadi-sh/cadish/internal/cluster"
	"github.com/cadi-sh/cadish/internal/pipeline"
)

// ValidateStructure performs the STRUCTURAL build validation that config.Load
// (the `cadish run` build path) does, but WITHOUT any network/DNS/bind/store
// side effects. It is the pre-flight gate behind `cadish check`: a config that
// ValidateStructure accepts will not fail config.Load at config-build time.
//
// It mirrors config.Load up to (and including) the per-site origin-layer wiring:
//   - parse + env substitute + group expansion,
//   - per-site import splice (the same FileImportResolver run uses),
//   - pipeline.Compile (pure),
//   - the origin-layer STRUCTURE: every site needs an upstream, upstream/cluster
//     names are unique, each pool's lb config parses + validates (e.g. a malformed
//     `sticky` line), and an `origin chain` only references declared upstreams.
//
// It deliberately does NOT construct origins (no lb.Upstream → no DNS resolve, no
// s3/cfsign client, no k8s API client), open cache stores, create temp dirs, or
// probe geo databases — those are either real I/O or handled by check's own
// value validators. The goal is the invariant: `cadish check` exits 0 ⇒ `cadish
// run` will not fail at config-build time.
//
// name is the diagnostic source name; baseDir is the directory imports resolve
// against (matching loadFromSource). The first structural problem is returned as
// a positioned error ("file:line:col: msg"), identical to what config.Load would
// surface, so check prints the same diagnostic run would.
func ValidateStructure(name, src, baseDir string) error {
	return validateStructure(name, src, baseDir, pipeline.FileImportResolver(baseDir), false)
}

// ValidateStructureFile is ValidateStructure for a file on disk: it reads the
// file and resolves imports/relative paths against the file's own directory,
// matching config.Load.
func ValidateStructureFile(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	return ValidateStructure(path, string(data), filepath.Dir(path))
}

// ValidateStructureSandboxed is the sandboxed variant for the admin playground:
// it performs NO filesystem access. Import directives splice to nothing (the
// playground submits self-contained buffers and blocks imports), so a site's
// own body is validated as-is. Like ValidateStructure it has no network/DNS/bind
// side effects.
func ValidateStructureSandboxed(name, src string) error {
	noImports := func(path string) ([]cadishfile.Node, error) { return nil, nil }
	return validateStructure(name, src, ".", noImports, true)
}

// validateStructure is the shared core: parse + env-substitute + group-expand,
// then validate each site's structure using the given import resolver (file-based
// for the CLI, a no-op for the sandbox).
func validateStructure(name, src, baseDir string, resolve func(string) ([]cadishfile.Node, error), sandbox bool) error {
	file, err := cadishfile.Parse(name, []byte(src))
	if err != nil {
		return err
	}
	// SANDBOX (admin /api/validate): NEVER resolve `{$VAR}` against the real environment. A
	// structural validator echoes its argument into the error message (e.g. `ram {$SECRET}` →
	// "invalid size \"<resolved value>\""), so substituting the live env would let a
	// token-authed caller exfiltrate any environment variable (S3 secret_key, auth_token,
	// signing keys) one per request — the sandbox, not the token, is the trust boundary
	// (matching /api/source's secret redaction). Resolve placeholders to empty in the sandbox;
	// the CLI `cadish check` path keeps os.LookupEnv (it already runs with the operator's env).
	lookup := os.LookupEnv
	if sandbox {
		lookup = func(string) (string, bool) { return "", false }
	}
	cadishfile.SubstituteEnv(file, lookup)

	// Run the SAME global `*FromFile` constructors loadFromSource runs, in the same
	// order. Each parses + validates one global block (admin, access_log, strict_host,
	// security, proxy_protocol) and is pure (no I/O), so check surfaces a malformed
	// global block — a missing `admin auth_token` (B2), `proxy_protocol { trust <bad
	// cidr> }` (B1), `access_log on`, a `strict_host` argument — exactly as run does,
	// closing the global slice of the check↔run divergence.
	if _, err := adminFromFile(file); err != nil {
		return err
	}
	if _, err := accessLogOffFromFile(file); err != nil {
		return err
	}
	if _, err := strictHostFromFile(file); err != nil {
		return err
	}
	if _, err := securityFromFile(file); err != nil {
		return err
	}
	if _, err := proxyProtocolFromFile(file); err != nil {
		return err
	}

	// Expand `group { … }` site-groups exactly as loadFromSource does, so a
	// per-tenant site is validated the way it will actually serve.
	sites, err := cadishfile.ExpandGroups(file.Sites)
	if err != nil {
		return err
	}

	for _, site := range sites {
		if err := validateSiteStructure(site, baseDir, resolve, sandbox); err != nil {
			return err
		}
	}
	return nil
}

// validateSiteStructure runs the side-effect-free structural validation for one
// site: import splice, pipeline compile, and the origin-layer structure. It
// reuses the SAME splice/compile entry points config.buildSite uses, so a site
// that validates here builds at run time.
func validateSiteStructure(site *cadishfile.Site, baseDir string, resolve func(string) ([]cadishfile.Node, error), sandbox bool) error {
	// Splice imports BEFORE compiling, exactly as buildSite does (a leftover
	// import is a compile error). The file resolver reads fragment files relative
	// to baseDir — the same I/O run performs; it does NOT touch the network.
	spliced, err := pipeline.SpliceImports(site, resolve)
	if err != nil {
		return err
	}
	if _, err := pipeline.Compile(spliced); err != nil {
		return err
	}
	if err := validateOriginStructure(spliced); err != nil {
		return err
	}

	// The remaining per-site constructors run does at config-build time, reused here
	// (not reimplemented) so check stays a faithful pre-flight:
	//   - standalone `trust_proxy <CIDR…>` (pure) — bad CIDR (B1),
	//   - the `cache { … }` block structure (pure) — `ram` with no size, etc.,
	//   - the `geo { … }` block: CIDRs/sources/region_header structure, and (outside
	//     the sandbox) the existence of the referenced cidr/maxmind FILE,
	//   - (outside the sandbox) the existence of a static `tls { cert … key … }`
	//     keypair on disk (TLS-D1).
	if _, err := buildSiteTrustProxies(spliced); err != nil {
		return err
	}
	if _, _, _, _, err := parseCacheBlock(spliced); err != nil {
		return err
	}
	// Validate the geo block's STRUCTURE (CIDRs, sources present, kinds, region_header)
	// WITHOUT opening any source file — openFiles=false in BOTH the CLI and sandbox
	// paths. File EXISTENCE is a deploy-time precondition, not a config-structure
	// error (configs are routinely authored on one host for a different deploy host —
	// the shipped s3-cdn example references `/etc/cadish/keys/…`), so a missing
	// cidr/maxmind/cert/key/PEM is surfaced as a WARNING by check's value pass
	// (fileExistenceWarnings in internal/check), not a hard build error here.
	if _, _, _, _, err := buildGeo(spliced, baseDir, false); err != nil {
		return err
	}
	return nil
}

// validateOriginStructure validates the origin layer of a spliced site WITHOUT
// constructing any origin (no lb pool, so no DNS resolve; no s3/cfsign/k8s
// client). It reproduces buildOrigins's structural checks against the same pure
// parse helpers, so the diagnostics match run's:
//   - a site with no upstream/cluster pool,
//   - a duplicate upstream/cluster name,
//   - an lb pool whose config fails to parse/validate (e.g. a malformed sticky),
//   - an S3 (`bucket`) upstream missing its `to` endpoint,
//   - a CloudFront `sign` upstream missing its `to`/`key`,
//   - an `origin chain` that references an undeclared upstream.
//
// It validates STRUCTURE only (no DNS, no S3/cfsign/k8s client, no filesystem): the
// existence of a referenced signing-key PEM is a deploy precondition surfaced as a
// warning by check's value pass, not a hard build error.
func validateOriginStructure(site *cadishfile.Site) error {
	declared := map[string]bool{}
	var chainNames []string

	for _, n := range site.Body {
		d, ok := n.(*cadishfile.Directive)
		if !ok {
			continue
		}
		switch d.Name {
		case "upstream", "cluster":
			// A nameless membership `cluster { peers … }` is not a pool; skip it
			// exactly as buildOrigins does.
			if d.Name == "cluster" && cluster.IsMembershipBlock(d) {
				continue
			}
			if len(d.Args) < 1 {
				return &pipeline.CompileError{Pos: d.Pos, Msg: d.Name + " needs a name"}
			}
			name := d.Args[0].Raw
			if declared[name] {
				return &pipeline.CompileError{Pos: d.Pos, Msg: "duplicate " + d.Name + " " + quoteName(name)}
			}
			declared[name] = true

			// Validate the pool's wiring without building it. S3 (`bucket`) and
			// CloudFront-signing (`sign`) upstreams are not lb pools — their lb
			// grammar (sticky/policy/health) does not apply, so skip the lb parse
			// for them (buildOne dispatches them away before parseLBConfig too). They
			// have their OWN structural requirements, which run enforces in buildOne/
			// buildSignedOrigin and we reproduce here so check catches them too.
			bucket, hasSign := scanUpstreamFlags(d)
			if bucket != "" {
				// An S3 upstream needs a `to` endpoint (buildOne).
				if firstTo(d) == "" {
					return compileErr(d.Pos, "upstream "+quoteName(name)+" has a bucket but no `to` endpoint")
				}
				continue
			}
			if hasSign {
				// A CloudFront-signing upstream needs a `to` backend and a valid
				// `sign cloudfront <key-pair-id> key <pem>` directive (buildSignedOrigin
				// → parseSign). parseSign surfaces the missing-key / bad-token STRUCTURAL
				// errors; the existence of the PEM file is a deploy precondition reported
				// as a WARNING by check's value pass (not a hard build error here).
				if firstTo(d) == "" {
					return compileErr(d.Pos, "upstream "+quoteName(name)+" has no `to` backend")
				}
				if _, perr := parseSign(d); perr != nil {
					return perr
				}
				continue
			}
			// A trivial single-`to` upstream becomes a plain httporigin at run time
			// (no lb pool) — but parsing its lb config is still pure and catches a
			// malformed sticky/policy line on a non-trivial pool. lb.ParseUpstream
			// already validates structure + values (it calls Config.Validate), the
			// same parse the runtime pool construction uses, so a config that parses
			// clean here builds there.
			if _, perr := parseLBConfig(d); perr != nil {
				return perr
			}
			// host_header / sni / http_reuse are config-layer pool keys that buildOne
			// validates separately (parseLBConfig strips them), for BOTH trivial and
			// pooled upstreams — so a malformed `host_header`/`sni`/`http_reuse` would
			// pass check but fail run. Reuse the SAME parsers here to close that gap.
			if _, perr := parseHostHeader(d); perr != nil {
				return perr
			}
			if _, _, perr := parseTransportPolicy(d); perr != nil {
				return perr
			}
		case "origin":
			names, perr := parseOriginChain(d)
			if perr != nil {
				return perr
			}
			chainNames = names
		}
	}

	if len(declared) == 0 {
		return &pipeline.CompileError{Pos: site.Pos, Msg: fmt.Sprintf("site %q has no `upstream` to fetch from", firstAddr(site))}
	}
	for _, name := range chainNames {
		if !declared[name] {
			return &pipeline.CompileError{Pos: site.Pos, Msg: fmt.Sprintf("origin chain references undeclared upstream %q", name)}
		}
	}
	return nil
}
