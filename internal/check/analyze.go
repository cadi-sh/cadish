package check

import (
	"errors"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/cadi-sh/cadish/internal/cadishfile"
	"github.com/cadi-sh/cadish/internal/config"
	"github.com/cadi-sh/cadish/internal/geo"
	"github.com/cadi-sh/cadish/internal/lb"
	"github.com/cadi-sh/cadish/internal/pipeline"
	"github.com/cadi-sh/cadish/internal/tlsacme"
)

// Check loads the Cadishfile at path, resolves its imports, and analyzes it into
// a complexity Report. A parse or read error on the *root* file is returned as
// err (a *cadishfile.ParseError or os error) so the caller can print a
// "file:line:col" diagnostic; all other findings — including import failures and
// per-site warnings — live in the returned Report.
func Check(path string) (*Report, error) {
	f, err := cadishfile.ParseFile(path)
	if err != nil {
		return nil, err
	}
	rep := analyzeFile(path, f, false)
	// Structural build validation (the `cadish run` config-build path, side-effect
	// free): catches errors the lint/AST pass cannot — a site with no `upstream`,
	// a duplicate upstream, an `origin chain` referencing an undeclared upstream, a
	// malformed `sticky` line — so `check` is a true pre-flight gate.
	addStructuralDiag(rep, config.ValidateStructureFile(path))
	rep.dedupe()
	return rep, nil
}

// CheckSource analyzes already-parsed source. filename is used for positions and
// for resolving imports relative to its directory. It is the in-memory analogue
// of Check, used in tests.
func CheckSource(filename string, src []byte) (*Report, error) {
	f, err := cadishfile.Parse(filename, src)
	if err != nil {
		return nil, err
	}
	rep := analyzeFile(filename, f, false)
	addStructuralDiag(rep, config.ValidateStructure(filename, string(src), filepath.Dir(filename)))
	rep.dedupe()
	return rep, nil
}

// CheckSourceSandboxed is the sandboxed variant of CheckSource for use in the
// admin playground (/api/validate). It performs NO filesystem access: import
// directives are blocked (a clear diagnostic is emitted instead of reading the
// file) and geo/maxmind path probes are skipped. All non-filesystem diagnostics
// (unknown directives, arity errors, matcher issues, etc.) are still produced.
//
// This prevents the admin endpoint from becoming an arbitrary host-file read
// primitive when an attacker submits a config containing `import /etc/passwd`
// or `geo { source maxmind /run/secrets/... }`.
func CheckSourceSandboxed(filename string, src []byte) (*Report, error) {
	f, err := cadishfile.Parse(filename, src)
	if err != nil {
		return nil, err
	}
	rep := analyzeFile(filename, f, true)
	// Sandboxed structural validation: no filesystem access (imports splice to
	// nothing), so the playground gets the same no-upstream/dup-upstream/chain/
	// sticky structural verdict without becoming a host-file read primitive.
	addStructuralDiag(rep, config.ValidateStructureSandboxed(filename, string(src)))
	rep.dedupe()
	return rep, nil
}

// addStructuralDiag records a config-build error (from config.ValidateStructure*)
// as a SevError "build-error" diagnostic on the report, carrying the real
// file:line:col so `check` output matches what `run` would print. A nil err is a
// no-op. The position is recovered structurally from the typed error
// (*pipeline.CompileError / *cadishfile.ParseError); any other error is recorded
// with its full message (which already reads "file:line:col: msg").
func addStructuralDiag(rep *Report, err error) {
	if err == nil {
		return
	}
	// An import failure (a cycle, or a glob that matched no files) is already reported
	// as a clean diagnostic by the check resolver (load.go): `import-cycle` for a
	// cycle, `missing-import` for an unresolved/zero-match import. The structural
	// pre-flight (config.ValidateStructure) re-discovers the SAME failure through
	// pipeline.SpliceImports; surfacing it again as a `build-error` would double-count
	// one problem (and historically leaked an internal "call SpliceImports before
	// Compile" message). Suppress the duplicate.
	if isImportCycleErr(err) && hasDiagCode(rep, "import-cycle") {
		return
	}
	if isImportResolveErr(err) && hasDiagCode(rep, "missing-import") {
		return
	}
	var ce *pipeline.CompileError
	if errors.As(err, &ce) {
		rep.Diagnostics = append(rep.Diagnostics, newDiag(SevError, ce.Pos, "build-error", "%s", ce.Msg))
		return
	}
	var pe *cadishfile.ParseError
	if errors.As(err, &pe) {
		pos := cadishfile.Pos{File: pe.File, Line: pe.Line, Col: pe.Col}
		rep.Diagnostics = append(rep.Diagnostics, newDiag(SevError, pos, "build-error", "%s", pe.Msg))
		return
	}
	rep.Diagnostics = append(rep.Diagnostics, newDiag(SevError, cadishfile.Pos{}, "build-error", "%v", err))
}

// isImportCycleErr reports whether err describes an import cycle (the structural
// pre-flight surfaces it through the splice path as a wrapped CompileError).
func isImportCycleErr(err error) bool {
	return err != nil && strings.Contains(err.Error(), "import cycle")
}

// isImportResolveErr reports whether err is an import-resolution failure surfaced
// by the structural pre-flight (pipeline.SpliceImports wraps it as "import <path>:
// <reason>"). The check resolver already reports the same failure as a positioned
// `missing-import`, so the build-error copy is a duplicate of one problem.
func isImportResolveErr(err error) bool {
	if err == nil {
		return false
	}
	var ce *pipeline.CompileError
	if errors.As(err, &ce) {
		return strings.HasPrefix(ce.Msg, "import ")
	}
	return false
}

// hasDiagCode reports whether the report already carries a diagnostic with code.
func hasDiagCode(rep *Report, code string) bool {
	for _, d := range rep.Diagnostics {
		if d.Code == code {
			return true
		}
	}
	for _, s := range rep.Sites {
		for _, d := range s.Diagnostics {
			if d.Code == code {
				return true
			}
		}
	}
	return false
}

// detectDuplicateSites flags two site blocks that declare the SAME address. The
// runtime selects a site by first-match (server.selectSite: exact host index, then
// "*." suffix), so a second site with an address already claimed by an earlier site
// is UNREACHABLE — every request for that host serves from the first block, and the
// later block's directives (a different upstream, cache policy, tls) silently never
// run. sites=2 but the operator gets one site's behavior with no signal. It is a
// file-level WARNING positioned at the shadowed (later) block. Address comparison is
// host-normalized (lower-cased, :port stripped) to match how the server indexes.
func detectDuplicateSites(sites []*cadishfile.Site, rep *Report) {
	seen := map[string]cadishfile.Pos{} // normalized address -> first site's position
	for _, s := range sites {
		for _, addr := range s.Addresses {
			key := normalizeSiteAddr(addr)
			if key == "" {
				continue
			}
			if first, dup := seen[key]; dup {
				rep.Diagnostics = append(rep.Diagnostics, newDiag(SevWarning, s.Pos, "duplicate-site",
					"duplicate site address %q (first declared at %s); the runtime selects a site by first match, so this later block is unreachable — its upstream/cache/tls never run. Merge the blocks or give this one a distinct address",
					addr, first))
				continue
			}
			seen[key] = s.Pos
		}
	}
}

// normalizeSiteAddr lower-cases a site address token and strips any :port, matching
// how the server's routing indexes hosts (server.normalizeAddr). A bare "" stays "".
func normalizeSiteAddr(addr string) string {
	addr = strings.ToLower(strings.TrimSpace(addr))
	if addr == "" {
		return ""
	}
	if h, _, err := net.SplitHostPort(addr); err == nil {
		return h
	}
	return addr
}

// analyzeFile resolves imports then analyzes every site (or the top-level body).
// sandbox disables all filesystem access: imports produce a diagnostic instead of
// reading from disk, and geo/maxmind path probes are skipped.
func analyzeFile(path string, f *cadishfile.File, sandbox bool) *Report {
	rep := &Report{Path: path}
	r := &resolver{diags: &rep.Diagnostics, sandbox: sandbox}
	baseDir := filepath.Dir(path)
	abs, err := filepath.Abs(path)
	if err != nil {
		abs = path
	}
	stack := []string{abs}

	// Resolve imports the way `cadish run` (config.Load) does, so check and run
	// agree. config.Load splices imports PER SITE only — it never resolves the
	// ROOT file's top-level body imports; a top-level `import …` (outside any site)
	// is a run-time no-op. So when the file has sites, do NOT resolve f.Body's
	// imports — otherwise a top-level `import self` would be flagged as a cycle here
	// while run starts fine (F2). When there are NO sites, the file is a bare
	// importable fragment analyzed as "(top-level)"; resolving its imports is a
	// lint convenience (not a runnable config), so keep that path.
	if len(f.Sites) == 0 {
		f.Body = r.resolveNodes(f.Body, baseDir, stack)
	}
	for _, s := range f.Sites {
		s.Body = r.resolveNodes(s.Body, baseDir, stack)
	}

	// Expand `group { … }` site-groups into per-tenant sites so the report
	// reflects what actually serves. A malformed group is left as-is here (config
	// load surfaces the real error); `tenant` is a recognized directive either way.
	if expanded, err := cadishfile.ExpandGroups(f.Sites); err == nil {
		f.Sites = expanded
	}

	detectDuplicateSites(f.Sites, rep)
	for _, s := range f.Sites {
		sr := analyzeSite(s.Addresses, s.Pos, s.Body, baseDir, sandbox)
		compileSite(s, sr)
		rep.Sites = append(rep.Sites, sr)
	}
	if len(f.Sites) == 0 && len(f.Body) > 0 {
		sr := analyzeSite([]string{"(top-level)"}, cadishfile.Pos{File: path}, f.Body, baseDir, sandbox)
		compileSite(&cadishfile.Site{Addresses: []string{"(top-level)"}, Body: f.Body, Pos: cadishfile.Pos{File: path}}, sr)
		rep.Sites = append(rep.Sites, sr)
	}
	validateValues(f, rep, baseDir, sandbox)
	return rep
}

// compileSite compiles a site into its runtime pipeline (pipeline.Compile) and,
// on failure, records the *pipeline.CompileError as a SevError "compile-error"
// diagnostic on the site report — carrying the real file:line:col so `check`
// output matches what `run` would print. This makes `cadish check` a true
// pre-flight gate: a config that lints clean at the AST level but cannot compile
// (e.g. `undefined matcher @x`, `classify value must be non-empty`) now fails
// check with a non-zero exit, instead of passing check and refusing to boot at
// `cadish run`.
//
// Compile is PURE — it builds only the in-memory pipeline (no filesystem, no
// network, no mmdb load) — so it runs in the sandboxed (admin playground) path too.
// A non-CompileError (should not happen) is still surfaced, positioned at the site.
func compileSite(s *cadishfile.Site, sr *SiteReport) {
	if _, err := pipeline.Compile(s); err != nil {
		var ce *pipeline.CompileError
		if errors.As(err, &ce) {
			sr.add(SevError, ce.Pos, "compile-error", "%s", ce.Msg)
			return
		}
		sr.add(SevError, s.Pos, "compile-error", "%v", err)
	}
}

// validateValues runs the value-level validators that `config.Load` uses (sizes,
// listen/bind addresses) directly against the AST, recording failures as positioned
// error diagnostics. This catches a bogus `cache { ram 256MiBi }` or `admin { listen
// 0.0.0.0.1:9090 }` at LINT time with a file:line, instead of leaving size errors to
// startup and address errors to net.Listen bind. It reuses config's exported validators
// (the single source of truth) rather than building the runtime, so it does no I/O and
// never trips structural requirements (e.g. "site has no upstream") that are irrelevant
// to a lint.
// sandbox disables geo/maxmind file probes (used by the admin playground).
func validateValues(f *cadishfile.File, rep *Report, baseDir string, sandbox bool) {
	scan := func(nodes []cadishfile.Node) {
		for _, n := range nodes {
			d, ok := n.(*cadishfile.Directive)
			if !ok {
				continue
			}
			// Non-block, value-bearing directives.
			if d.Name == "cache_ttl" {
				validateCacheTTL(d, rep)
				validateDeadStatusRule(d, rep)
			}
			if d.Name == "storage" {
				validateDeadStatusRule(d, rep)
			}
			if !d.HasBlock {
				continue
			}
			switch d.Name {
			case "cache":
				validateCacheBlock(d, rep)
			case "admin":
				validateAdminBlock(d, rep)
			case "upstream", "cluster":
				validateUpstreamBlock(d, rep)
			case "geo":
				if !sandbox {
					validateGeoBlock(d, rep, baseDir)
				}
			}
		}
	}
	if f.Global != nil {
		scan(f.Global.Body)
	}
	scan(f.Body)
	for _, s := range f.Sites {
		scan(s.Body)
	}
	tlsConfigWarnings(f, rep)
	if !sandbox {
		fileExistenceWarnings(f, rep, baseDir)
	}
}

// tlsConfigWarnings surfaces the soft semantic warnings tlsacme.SiteConfigFromSite
// returns — which both `cadish check` and `cadish run` previously DISCARDED — so a
// footgun in a site's `tls` configuration is no longer silent: a duplicate/conflicting
// `tls` directive whose intent is dropped (TLS-P1), an `acme` block with no contact
// email (TLS-P2), and the corrected empty-`tls {}`→`tls off` wording (TLS-P3) all now
// appear as warnings. These checks are pure (no filesystem), so they run in the
// sandbox too. Each error already carries a "file:line:col: …" prefix.
func tlsConfigWarnings(f *cadishfile.File, rep *Report) {
	for _, s := range f.Sites {
		if _, errs := tlsacme.SiteConfigFromSite(s); len(errs) > 0 {
			for _, e := range errs {
				// Each error already reads "file:line:col: …"; use the empty Pos so the
				// renderer doesn't prepend a second (site-level) position, matching how
				// addStructuralDiag surfaces a generic positioned error.
				rep.Diagnostics = append(rep.Diagnostics, newDiag(SevWarning, cadishfile.Pos{}, "tls-config", "%s", e.Error()))
			}
		}
	}
}

// fileExistenceWarnings warns (does NOT error) when a config references a file that
// is absent at check time: a static `tls { cert … key … }` keypair (TLS-D1), a
// CloudFront `sign … key <pem>` signing key (TLS-D2), or a `geo { source cidr|maxmind
// FILE }` database. File EXISTENCE is a deploy precondition, not a config-structure
// error — configs are routinely authored on one host for a different deploy host (the
// shipped `s3-cdn` example references `/etc/cadish/keys/…`), so a hard error would
// wrongly reject a valid config. A warning still catches the common typo. A path is
// considered present if it exists as written OR relative to the config's directory.
// Skipped in the sandbox (admin playground), which performs no filesystem access.
func fileExistenceWarnings(f *cadishfile.File, rep *Report, baseDir string) {
	present := func(path string) bool {
		if path == "" {
			return true // an incomplete directive is reported by the structural pass
		}
		if _, err := os.Stat(path); err == nil {
			return true
		}
		if !filepath.IsAbs(path) {
			if _, err := os.Stat(filepath.Join(baseDir, path)); err == nil {
				return true
			}
		}
		return false
	}
	warn := func(pos cadishfile.Pos, kind, path string) {
		rep.Diagnostics = append(rep.Diagnostics, newDiag(SevWarning, pos, "file-not-found",
			"%s %q not found at check time — it must exist on the host where `cadish run` loads it", kind, path))
	}
	for _, s := range f.Sites {
		// Static TLS keypair (ModeStatic). ACME / `tls off` reference no files.
		if sc, _ := tlsacme.SiteConfigFromSite(s); sc.TLS.Mode == tlsacme.ModeStatic {
			if !present(sc.TLS.CertFile) {
				warn(s.Pos, "tls cert file", sc.TLS.CertFile)
			}
			if !present(sc.TLS.KeyFile) {
				warn(s.Pos, "tls key file", sc.TLS.KeyFile)
			}
		}
		for _, n := range s.Body {
			d, ok := n.(*cadishfile.Directive)
			if !ok || !d.HasBlock {
				continue
			}
			switch d.Name {
			case "geo":
				for _, bn := range d.Block {
					bd, ok := bn.(*cadishfile.Directive)
					if !ok || bd.Name != "source" || len(bd.Args) < 2 {
						continue
					}
					if k := bd.Args[0].Raw; (k == "cidr" || k == "maxmind") && !present(bd.Args[1].Raw) {
						warn(bd.Args[1].Pos, "geo source "+k+" file", bd.Args[1].Raw)
					}
				}
			case "upstream":
				for _, bn := range d.Block {
					bd, ok := bn.(*cadishfile.Directive)
					if !ok || bd.Name != "sign" {
						continue
					}
					for i, a := range bd.Args { // sign cloudfront <kp> key <pem> [ttl D]
						if a.Raw == "key" && i+1 < len(bd.Args) && !present(bd.Args[i+1].Raw) {
							warn(bd.Args[i+1].Pos, "cloudfront signing key", bd.Args[i+1].Raw)
						}
					}
				}
			}
		}
	}
}

// validateCacheBlock validates the byte-size literals in a `cache { … }` block: the
// size is `ram`'s first arg and `disk`'s second (path then size).
func validateCacheBlock(d *cadishfile.Directive, rep *Report) {
	for _, bn := range d.Block {
		bd, ok := bn.(*cadishfile.Directive)
		if !ok {
			continue
		}
		var size *cadishfile.Arg
		switch bd.Name {
		case "ram":
			if len(bd.Args) >= 1 {
				size = &bd.Args[0]
			}
		case "disk":
			if len(bd.Args) >= 2 {
				size = &bd.Args[1]
			}
		}
		if size == nil {
			continue
		}
		v, err := config.ParseSize(size.Raw)
		if err != nil {
			rep.Diagnostics = append(rep.Diagnostics, newDiag(SevError, size.Pos, "invalid-size", "cache: %s: %v", bd.Name, err))
			continue
		}
		// A zero-size RAM tier is accepted and the site still serves, but it can hold
		// nothing — every cacheable response that would land in RAM is discarded, so
		// the site effectively caches nothing in RAM (a misconfiguration, not an error).
		if bd.Name == "ram" && v == 0 {
			rep.Diagnostics = append(rep.Diagnostics, newDiag(SevWarning, size.Pos, "zero-ram-tier",
				"cache { ram 0 } sets a zero-size RAM tier: it caches nothing in RAM (every RAM-bound object is discarded). Set a real budget (e.g. `ram 256MiB`) or remove the `ram` line to use the default"))
		}
	}
}

// validateAdminBlock validates the bind address in an `admin { listen … }` block.
func validateAdminBlock(d *cadishfile.Directive, rep *Report) {
	for _, bn := range d.Block {
		bd, ok := bn.(*cadishfile.Directive)
		if !ok || bd.Name != "listen" || len(bd.Args) != 1 {
			continue
		}
		if err := config.ValidateListenAddr(bd.Args[0].Raw); err != nil {
			rep.Diagnostics = append(rep.Diagnostics, newDiag(SevError, bd.Args[0].Pos, "invalid-listen", "admin: %v", err))
		}
	}
}

// statusRuleKeywords are the directive keywords that END the `status CODE…` selector
// of a `cache_ttl`/`storage` rule (everything before the first keyword is a code).
var statusRuleKeywords = map[string]bool{
	"ttl": true, "grace": true, "max_stale": true, "from_header": true,
	"hit_for_miss": true, "->": true,
}

// validateDeadStatusRule warns when a `cache_ttl status <code…>` (with a caching
// keyword: ttl/from_header) or `storage status <code…> -> tier` rule selects a 3xx
// REDIRECT status, which cadish never caches through ANY path — the success path
// stores only 200, and the origin-error path only 4xx/5xx (D6). So a rule like
// `cache_ttl status 301 ttl 1h` looks like it caches redirects but is silently dead.
// 4xx/5xx are NOT flagged: an explicit positive `status <code>` selector DOES make
// them storable (the operator opting into negative/error caching). The `status not …`
// form, a `@scope`/`default` selector, and a `hit_for_miss`-only rule (a deliberate
// don't-store decision) are intentionally NOT flagged.
func validateDeadStatusRule(d *cadishfile.Directive, rep *Report) {
	if len(d.Args) < 2 || d.Args[0].Raw != "status" || d.Args[1].Raw == "not" {
		return
	}
	if d.Name == "cache_ttl" {
		// Only a STORE-intent rule (ttl / from_header) is dead on a non-cacheable
		// status; a hit_for_miss rule is a valid non-store decision.
		store := false
		for _, a := range d.Args {
			if a.Raw == "ttl" || a.Raw == "from_header" {
				store = true
			}
		}
		if !store {
			return
		}
	}
	for _, a := range d.Args[1:] {
		if statusRuleKeywords[a.Raw] {
			break // reached the keyword/`->` section; codes are done
		}
		// 3xx redirects are the unambiguous dead case: never stored via any path.
		if n, err := strconv.Atoi(a.Raw); err == nil && n >= 300 && n <= 399 {
			rep.Diagnostics = append(rep.Diagnostics, newDiag(SevWarning, a.Pos, "dead-status-rule",
				"%s targets redirect status %s, which cadish never caches (3xx is stored through no path) — this rule is dead config and never takes effect",
				d.Name, a.Raw))
		}
	}
}

// validateCacheTTL validates the duration values in a `cache_ttl <selector> …`
// directive: `ttl DUR [grace DUR] [max_stale DUR]`, `from_header HEADER [grace DUR]
// [max_stale DUR]`, or `hit_for_miss DUR`. The selector (default / status … /
// @matcher) is skipped; only the keyword-introduced duration args are checked,
// reusing config.ParseDuration (the same parser the runtime compiler uses, so a
// value that lints clean also loads). It scans for the
// `ttl`/`grace`/`max_stale`/`hit_for_miss` keywords rather than re-deriving the
// selector length, which keeps it robust to selector shape without duplicating the
// compiler's grammar. (max_stale on hit_for_miss, and max_stale < grace, are
// rejected by the compiler — that semantic check is not duplicated here; this pass
// only validates each duration value parses.)
func validateCacheTTL(d *cadishfile.Directive, rep *Report) {
	for i := 0; i < len(d.Args); i++ {
		a := d.Args[i]
		switch a.Raw {
		case "ttl", "grace", "max_stale", "hit_for_miss":
			if i+1 >= len(d.Args) {
				continue // arity is reported elsewhere; nothing to validate
			}
			val := d.Args[i+1]
			if _, err := config.ParseDuration(val.Raw); err != nil {
				rep.Diagnostics = append(rep.Diagnostics, newDiag(SevError, val.Pos, "invalid-duration", "cache_ttl %s: %v", a.Raw, err))
			}
			i++ // consume the value
		}
	}
}

// poolDirectives is the set of valid inner keys of an `upstream NAME { … }` or
// `cluster NAME { … }` pool block. It mirrors the runtime parser's switch
// (internal/lb/parse.go parsePool) plus `sign` (CloudFront URL signing, attached
// to the pool by the config layer). A key not in this set is a typo footgun —
// e.g. `host_hedaer` silently falling back to the default Host (→ Apache 421) —
// so `cadish check` flags it (gap G4).
var poolDirectives = map[string]bool{
	// lb pool keys (internal/lb parsePool switch):
	"to": true, "policy": true, "lb": true, "sticky": true, "shard_by": true,
	"health": true, "timeout": true, "max_conns": true, "replicas": true,
	"sni": true, "http_reuse": true,
	// config-layer pool keys (internal/config origin.go): Host-header policy,
	// CloudFront signing, and S3-upstream bucket + credentials.
	"host_header": true, "sign": true,
	"bucket": true, "access_key": true, "secret_key": true, "region": true, "anonymous": true,
}

// clusterMembershipDirectives is the valid inner-key set of a `cluster { … }`
// MEMBERSHIP block (no name arg) — the multi-POP clustering feature, a different
// directive from a `cluster NAME { … }` pool. Kept distinct so the unknown-key
// lint does not false-positive on `self`/`region`/`mode`/`fallback`.
var clusterMembershipDirectives = map[string]bool{
	"self": true, "peers": true, "region": true, "mode": true, "fallback": true,
}

// validateUpstreamBlock validates the value-bearing directives inside an
// `upstream`/`cluster { … }` block: every `to …` backend target (URL syntax) and
// the duration args of `health … interval D`, `timeout … D`, and `sign … ttl D`.
// It reuses config.ParseUpstreamURL and config.ParseDuration so lint and runtime
// share one definition of valid target/duration syntax. It also flags any inner
// directive whose key is not in the known set (gap G4) — mirroring the top-level
// unknown-directive lint so a typo'd pool knob does not silently fall back to a
// default.
func validateUpstreamBlock(d *cadishfile.Directive, rep *Report) {
	// A `cluster { … }` with no name is the multi-POP MEMBERSHIP block, which has a
	// different inner vocabulary than a `cluster NAME { … }` pool.
	known := poolDirectives
	if d.Name == "cluster" && len(d.Args) == 0 {
		known = clusterMembershipDirectives
	}
	for _, bn := range d.Block {
		bd, ok := bn.(*cadishfile.Directive)
		if !ok {
			continue
		}
		if !known[bd.Name] {
			// An unknown pool key is rejected at the lb-build layer
			// (internal/lb/parse.go) and surfaced by the pre-flight gate as a
			// `build-error`; don't emit a second `unknown-directive` for it.
			continue
		}
		switch bd.Name {
		case "to":
			for _, a := range bd.Args {
				if err := config.ParseUpstreamURL(a.Raw, a.Pos); err != nil {
					rep.Diagnostics = append(rep.Diagnostics, newDiag(SevError, a.Pos, "invalid-upstream-url", "%s: %v", d.Name, err))
					continue
				}
				// PF-P3: a target ending in a bare ':' (e.g. `to http://localhost:`)
				// parses, but the empty port is almost certainly a missing-value typo
				// (often from a Caddy-style `{$PORT}` env default that did not exist —
				// see PF-D1). The runtime fills the scheme default port, so it is not a
				// hard error, but it is a footgun worth flagging.
				if hasEmptyPort(a.Raw) {
					rep.Diagnostics = append(rep.Diagnostics, newDiag(SevWarning, a.Pos, "empty-port",
						"%s: target %q ends in ':' with no port — the empty port is likely a typo (or an unset {$VAR} env default); the scheme's default port will be used", d.Name, a.Raw))
				}
			}
		case "health":
			validateKeyedDurations(bd, rep, d.Name+" health", "interval")
			validateHealthExpect(bd, rep, d.Name+" health")
			validateHealthWindow(bd, rep, d.Name+" health")
		case "timeout":
			validateKeyedDurations(bd, rep, d.Name+" timeout", "connect", "first_byte", "between_bytes")
		case "sign":
			validateKeyedDurations(bd, rep, d.Name+" sign", "ttl")
		}
	}
}

// hasEmptyPort reports whether a backend target token has a host authority ending
// in a bare ':' with no port digits (e.g. "http://localhost:" or "localhost:" or
// "http://localhost:/path"). It returns false for a real port ("…:8080"), for a
// portless host ("http://localhost"), and for an IPv6 literal whose ']' is the last
// authority byte ("http://[::1]"). Only the host:port boundary is inspected; query
// and fragment are ignored.
func hasEmptyPort(tok string) bool {
	s := tok
	// Drop a leading scheme "://" if present; otherwise the whole token is the
	// authority (bare host:port form).
	if i := strings.Index(s, "://"); i >= 0 {
		s = s[i+3:]
	}
	// The authority ends at the first '/', '?' or '#'.
	if i := strings.IndexAny(s, "/?#"); i >= 0 {
		s = s[:i]
	}
	// Strip userinfo if any.
	if i := strings.LastIndexByte(s, '@'); i >= 0 {
		s = s[i+1:]
	}
	// An IPv6 literal is wrapped in []; the port (if any) follows ']'. A trailing
	// ']' means no port at all.
	if j := strings.LastIndexByte(s, ']'); j >= 0 {
		return s[j+1:] == ":"
	}
	return strings.HasSuffix(s, ":")
}

// validateGeoBlock validates the value-bearing directives inside a `geo { … }` block:
// every `source maxmind PATH` must name a non-empty path that opens as a MaxMind DB
// (D40 value validation — same posture as the runtime's `geo.OpenMaxMind`, reused so a
// config that lints clean also loads). A missing/corrupt DB is flagged at LINT time
// with a file:line, instead of only failing fast at startup. The path is resolved
// relative to the Cadishfile dir, exactly like the runtime.
func validateGeoBlock(d *cadishfile.Directive, rep *Report, baseDir string) {
	for _, bn := range d.Block {
		bd, ok := bn.(*cadishfile.Directive)
		if !ok || bd.Name != "source" {
			continue
		}
		if len(bd.Args) < 2 || bd.Args[0].Raw != "maxmind" {
			continue // header/cidr forms (and arity) are validated elsewhere
		}
		pathArg := bd.Args[1]
		if pathArg.Raw == "" {
			rep.Diagnostics = append(rep.Diagnostics, newDiag(SevError, pathArg.Pos, "invalid-geo-source", "geo: source maxmind needs a .mmdb path"))
			continue
		}
		path := pathArg.Raw
		if !filepath.IsAbs(path) {
			path = filepath.Join(baseDir, path)
		}
		db, err := geo.OpenMaxMind(path)
		if err != nil {
			rep.Diagnostics = append(rep.Diagnostics, newDiag(SevError, pathArg.Pos, "invalid-geo-source", "geo: %v", err))
			continue
		}
		_ = db.Close()
	}
}

// validateKeyedDurations validates `KEY DUR` pairs within a directive's args for
// each of the given duration keywords, emitting an invalid-duration diagnostic
// positioned at the offending value. Non-matching keywords and their values are
// left to the runtime parser (this lint only checks duration syntax).
func validateKeyedDurations(bd *cadishfile.Directive, rep *Report, ctx string, keys ...string) {
	isKey := func(s string) bool {
		for _, k := range keys {
			if s == k {
				return true
			}
		}
		return false
	}
	for i := 0; i+1 < len(bd.Args); i++ {
		if !isKey(bd.Args[i].Raw) {
			continue
		}
		val := bd.Args[i+1]
		if _, err := config.ParseDuration(val.Raw); err != nil {
			rep.Diagnostics = append(rep.Diagnostics, newDiag(SevError, val.Pos, "invalid-duration", "%s %s: %v", ctx, bd.Args[i].Raw, err))
		}
	}
}

// validateHealthExpect validates the variadic `expect` acceptance list of a
// `health … expect TOKEN…` directive the same way the runtime parser does
// (internal/lb parseHealth) — each token must be an exact status code (100–599) or
// a class `Nxx` (1≤N≤5). A malformed token (`6xx`, `999`, `foo`) is flagged at LINT
// time with a file:line position, so a config that lints clean also loads (check≡run).
func validateHealthExpect(bd *cadishfile.Directive, rep *Report, ctx string) {
	for i := 0; i < len(bd.Args); i++ {
		if bd.Args[i].Raw != "expect" {
			continue
		}
		// `expect` is variadic: it consumes one or more acceptance tokens up to the
		// next health sub-key or end of args — mirror that span exactly.
		for i++; i < len(bd.Args) && !lb.HealthKeyword(bd.Args[i].Raw); i++ {
			a := bd.Args[i]
			if !lb.ValidateExpectToken(a.Raw) {
				rep.Diagnostics = append(rep.Diagnostics, newDiag(SevError, a.Pos, "invalid-health-expect",
					"%s expect: %q is not a status code or class (e.g. 200, 301, 2xx)", ctx, a.Raw))
			}
		}
		i-- // the outer loop's i++ re-checks the keyword we stopped on
	}
}

// validateHealthWindow flags an absurd `health … window N` at lint time with the SAME
// bound the runtime parser enforces (lb.MaxWindow), so a config that lints clean also
// loads (check≡run). An over-cap window would otherwise drive a ~2GB-per-backend
// `make([]bool, N)` at pool construction and fail only at `cadish run`. A non-integer
// window is left to the runtime parser's own error (this lint only checks magnitude).
func validateHealthWindow(bd *cadishfile.Directive, rep *Report, ctx string) {
	for i := 0; i+1 < len(bd.Args); i++ {
		if bd.Args[i].Raw != "window" {
			continue
		}
		val := bd.Args[i+1]
		n, err := strconv.Atoi(val.Raw)
		if err != nil {
			continue // non-integer window: runtime parser reports it
		}
		if n > lb.MaxWindow() {
			rep.Diagnostics = append(rep.Diagnostics, newDiag(SevError, val.Pos, "invalid-health-window",
				"%s window %d is too large (max %d)", ctx, n, lb.MaxWindow()))
		}
	}
}

// analyzeSite is the heart of the report: it builds the matcher/directive model
// for one site and computes its metrics, diagnostics and suggestions.
// sandbox disables geo/maxmind filesystem probes (used by the admin playground).
func analyzeSite(addrs []string, pos cadishfile.Pos, body []cadishfile.Node, baseDir string, sandbox bool) *SiteReport {
	sr := &SiteReport{
		Addresses:   addrs,
		Position:    pos.String(),
		PhaseCounts: map[Phase]int{},
	}

	// Pass 1: collect matcher definitions; flag duplicates and unknown types.
	defs := map[string]*cadishfile.MatcherDef{}
	for _, n := range body {
		m, ok := n.(*cadishfile.MatcherDef)
		if !ok {
			continue
		}
		sr.MatcherCount++
		if prev, dup := defs[m.Name]; dup {
			sr.add(SevWarning, m.Pos, "duplicate-matcher",
				"duplicate matcher @%s (first defined at %s); the later definition shadows it", m.Name, prev.Pos)
		} else {
			defs[m.Name] = m
		}
		if !isMatcherType(m.Type) {
			sr.add(SevWarning, m.Pos, "unknown-matcher-type",
				"unknown matcher type %q for @%s", m.Type, m.Name)
		}
	}

	// Pass 2: walk directives — phase counts, unknown names, arity, and the set
	// of matchers a request actually evaluates.
	referenced := map[string]bool{}

	// An `all` (AND-composite) matcher references other named matchers in its OWN args
	// (`@name all @a !@b`). Mark those sub-matchers used so they are not flagged dead, and
	// flag an undefined sub-ref. (The composite itself is counted/flagged via the normal
	// directive scan below.)
	for _, m := range defs {
		if m.Type != "all" {
			continue
		}
		for _, a := range m.Args {
			isRef := a.Kind == cadishfile.ArgMatcherRef || strings.HasPrefix(a.Raw, "!@")
			if !isRef {
				continue
			}
			name := strings.TrimPrefix(strings.TrimPrefix(a.Raw, "!"), "@")
			if name == "" {
				continue
			}
			referenced[name] = true
			if _, ok := defs[name]; !ok {
				sr.add(SevWarning, a.Pos, "undefined-matcher",
					"all matcher @%s references undefined matcher @%s", m.Name, name)
			}
		}
	}
	var cost CostBreakdown
	regexEvals := 0
	for _, n := range body {
		d, ok := n.(*cadishfile.Directive)
		if !ok {
			continue
		}
		sr.DirectiveCount++
		sr.PhaseCounts[phaseOfDirective(d)]++
		if !defaultDirectives[d.Name] {
			sr.add(SevWarning, d.Pos, "unknown-directive", "unknown directive %q", d.Name)
		}
		checkArity(d, sr)
		checkEmptyBraces(d, sr)

		// A `classify { … }` block is setup-shaped but DOES reference matchers in
		// its `when` rows: mark them used (so they are not flagged dead) and count
		// each once toward per-request cost (the derived token is resolved once per
		// request, evaluating its rows' matchers first-match-wins).
		if d.Name == "classify" {
			for _, ref := range classifyMatcherRefs(d) {
				referenced[ref.name] = true
				if _, ok := defs[ref.name]; !ok {
					sr.add(SevWarning, ref.pos, "undefined-matcher",
						"classify {%s} references undefined matcher @%s", classifyTokenOf(d), ref.name)
				}
			}
			continue
		}

		// Setup directives are parse-once: they do not contribute to per-request
		// cost, and their args are not matcher scopes.
		if phaseOf(d.Name) == PhaseSetup {
			continue
		}

		u := directiveUsages(d)
		for _, ref := range u.refs {
			referenced[ref.name] = true
			if _, ok := defs[ref.name]; !ok {
				sr.add(SevWarning, ref.pos, "undefined-matcher",
					"directive %s references undefined matcher @%s", d.Name, ref.name)
			}
		}
		for _, in := range u.inlines {
			if !isMatcherType(in.typ) {
				continue
			}
			cl, isRe := classifyMatcher(in.typ, in.args)
			cost.addClass(cl)
			if isRe {
				regexEvals++
			}
		}
		for _, sel := range u.selectors {
			if sel == "status" {
				cost.Exact++ // a cheap status compare
			}
		}
	}

	// Each referenced named matcher is evaluated once per request (results are
	// cached for the request — see pipeline MATCH phase), so count it once.
	for name := range referenced {
		m := defs[name]
		if m == nil {
			continue
		}
		cl, isRe := classifyMatcher(m.Type, m.Args)
		cost.addClass(cl)
		if isRe {
			regexEvals++
		}
	}

	sr.RegexEvalsPerRequest = regexEvals
	sr.CostBreakdown = cost
	sr.EstimatedCost = cost.Cost()

	// Unreferenced matcher definitions are dead — but only warn when the scope is
	// a real config (has directives); a bare imported fragment legitimately
	// defines matchers for its importer to use.
	if sr.DirectiveCount > 0 {
		for _, n := range body {
			if m, ok := n.(*cadishfile.MatcherDef); ok && !referenced[m.Name] && defs[m.Name] == m {
				sr.add(SevWarning, m.Pos, "unused-matcher",
					"matcher @%s is defined but never referenced", m.Name)
			}
		}
	}

	detectDeadRules(body, defs, sr)
	detectSNIWithoutHTTPS(body, sr)
	detectGeoUnconfigured(body, sr, baseDir, sandbox)
	detectIPACLWithoutTrustProxy(body, defs, sr)
	detectUnboundedKeyTokens(body, sr)
	detectCookieAllowUnkeyed(body, sr)
	sr.Suggestions = suggest(body, defs)

	return sr
}

// detectUnboundedKeyTokens warns when a cache_key varies on an UNBOUNDED input —
// a raw request header (`header:NAME`), the whole `query` string, or the per-user
// {sticky} value — which fragments the cache (one entry per distinct value). The
// fix is the flip side of the bounded-normalizer note: bucket the value with a
// `normalize { … }` (or {device}/{geo}) and key on the bounded token. The
// resource-identity tokens (url/host/path/method) and bounded normalizers are
// not flagged.
func detectUnboundedKeyTokens(body []cadishfile.Node, sr *SiteReport) {
	for _, n := range body {
		d, ok := n.(*cadishfile.Directive)
		if !ok || d.Name != "cache_key" {
			continue
		}
		for _, a := range d.Args {
			switch {
			case strings.HasPrefix(a.Raw, "header:"):
				sr.add(SevWarning, a.Pos, "unbounded-key-token",
					"cache_key %s keys on a raw header (unbounded cardinality → cache fragmentation); bucket it with `normalize NAME { from header %s; map … }` and key on {NAME}",
					a.Raw, strings.TrimPrefix(a.Raw, "header:"))
			case a.Raw == "query":
				sr.add(SevWarning, a.Pos, "unbounded-key-token",
					"cache_key query keys on the full query string (unbounded cardinality); if only a few params matter, bucket them with a `normalize NAME { from query PARAM; map … }` token")
			case a.Raw == "{sticky}":
				sr.add(SevWarning, a.Pos, "unbounded-key-token",
					"cache_key {sticky} keys per-user (unbounded cardinality); use a bounded {device}/{geo}/normalize token unless per-user caching is intended")
			case strings.HasPrefix(a.Raw, "cookie:"):
				sr.add(SevWarning, a.Pos, "unbounded-key-token",
					"cache_key %s keys per-user on a cookie value (unbounded cardinality → one entry per session); this is the intended, leak-proof way to cache credentialed requests — expect a low hit rate and confirm it is the session/identity cookie",
					a.Raw)
			}
		}
	}
}

// detectCookieAllowUnkeyed warns when a `cookie_allow NAME…` admits a request cookie that
// the cache_key does NOT vary on (no `cookie:NAME` token, and no whole-`header:Cookie`
// token). An allow-listed cookie is the one class of cookie that is NOT stripped — it is
// forwarded to the origin, so it CAN personalize the response. The runtime is SAFE either
// way (a kept-but-unkeyed cookie forces a credential bypass — never cached cross-user; see
// BypassForCredentials), so this is not a leak — it is a CACHE-EFFECTIVENESS warning: those
// requests silently never cache. It mirrors detectUnboundedKeyTokens: surface the gap so the
// operator either KEYS the cookie (`cache_key … cookie:NAME`, to actually cache it) or DROPS
// it from cookie_allow (to strip it) instead of unknowingly bypassing every such request.
//
// A whole-`header:Cookie` key covers every cookie, so it silences all of them. A glob allow
// (`NAME*`) can only be covered by `header:Cookie` (a `cookie:NAME` token is exact), so it
// warns whenever the whole header is not keyed. It is a WARNING (advisory): an allow-listed
// cookie the origin genuinely ignores is safe to leave unkeyed, and only the operator knows.
//
// Coverage is judged PER RECIPE (scoped `cache_key @sel …`): a cookie is safely covered only
// when EVERY cache_key recipe covers it. A cookie keyed by one recipe but omitted by another
// (e.g. `cache_key @ssr … cookie:lang` + a `default` recipe without it) is still uncovered for
// the requests the other recipe serves — so it warns. With no `cache_key` at all the default
// key (method host path) covers no cookie, so every allow-listed cookie warns.
func detectCookieAllowUnkeyed(body []cadishfile.Node, sr *SiteReport) {
	type recipe struct {
		cookies map[string]bool // cookie:NAME tokens (RFC 6265: case-sensitive)
		whole   bool            // header:Cookie keys the entire Cookie header
	}
	var allows []*cadishfile.Directive
	var recipes []recipe
	for _, n := range body {
		d, ok := n.(*cadishfile.Directive)
		if !ok {
			continue
		}
		switch d.Name {
		case "cookie_allow":
			allows = append(allows, d)
		case "cache_key":
			r := recipe{cookies: map[string]bool{}}
			for _, a := range d.Args {
				if strings.HasPrefix(a.Raw, "cookie:") {
					r.cookies[strings.TrimPrefix(a.Raw, "cookie:")] = true
				} else if strings.HasPrefix(a.Raw, "header:") && strings.EqualFold(strings.TrimPrefix(a.Raw, "header:"), "Cookie") {
					r.whole = true
				}
			}
			recipes = append(recipes, r)
		}
	}
	if len(allows) == 0 {
		return
	}
	// covered reports whether EVERY recipe isolates this cookie. A glob name can only be
	// covered by a whole-header key. With no recipe at all the default key covers nothing.
	covered := func(name string) bool {
		if len(recipes) == 0 {
			return false
		}
		isGlob := strings.Contains(name, "*")
		for _, r := range recipes {
			if r.whole {
				continue
			}
			if isGlob || !r.cookies[name] {
				return false
			}
		}
		return true
	}
	for _, d := range allows {
		for _, a := range d.Args {
			name := a.Raw
			if name == "" || covered(name) {
				continue
			}
			sr.add(SevWarning, a.Pos, "cookie-allow-unkeyed",
				"cookie_allow %q is forwarded to the origin but the cache_key does not vary on it, so requests carrying cookie %q BYPASS the cache (never cached — the safe default, no cross-user leak). To actually cache them, add `cookie:%s` to the cache_key (one entry per value) or `header:Cookie` (key every cookie); or drop %q from cookie_allow so it is stripped. Allowlist only cookies you key (or that you accept never caching).",
				name, name, name, name)
		}
	}
}

// detectSNIWithoutHTTPS warns when an `upstream`/`cluster` block sets a transport
// knob that only affects TLS/HTTPS dials — `sni <server-name>` or `http_reuse
// never` — but EVERY `to` backend is plaintext `http://` (gap H6). SNI lives in
// the TLS ClientHello, so on an all-plaintext upstream it has no effect; the
// connection-reuse knob is likewise pointless there. It is a WARNING, not an
// error, so a mixed-scheme pool that WILL dial an https:// backend isn't blocked.
// The warning points at the `sni`/`http_reuse` directive's own file:line.
func detectSNIWithoutHTTPS(body []cadishfile.Node, sr *SiteReport) {
	for _, n := range body {
		d, ok := n.(*cadishfile.Directive)
		if !ok || (d.Name != "upstream" && d.Name != "cluster") {
			continue
		}
		var knobs []*cadishfile.Directive
		anyTo, anyHTTPS := false, false
		for _, bn := range d.Block {
			bd, ok := bn.(*cadishfile.Directive)
			if !ok {
				continue
			}
			switch bd.Name {
			case "sni", "http_reuse":
				knobs = append(knobs, bd)
			case "to":
				for _, a := range bd.Args {
					anyTo = true
					if isHTTPSTarget(a.Raw) {
						anyHTTPS = true
					}
				}
			}
		}
		// Only warn when there IS at least one backend and none is https:// — an
		// upstream with no `to` is reported elsewhere; a mixed/https pool is fine.
		if len(knobs) == 0 || !anyTo || anyHTTPS {
			continue
		}
		for _, k := range knobs {
			sr.add(SevWarning, k.Pos, "sni-without-https",
				"`%s` has no effect without an https:// backend: every `to` in upstream %q is plaintext http://",
				k.Name, upstreamNameOf(d))
		}
	}
}

// isHTTPSTarget reports whether a `to` backend token dials over TLS — an explicit
// `https://` scheme. A bare host:port or `http://`/`dns://`/`k8s://` token is
// plaintext for the SNI-effect check (dns/k8s default to http per lb.parseTarget).
func isHTTPSTarget(tok string) bool {
	return strings.HasPrefix(strings.ToLower(strings.TrimSpace(tok)), "https://")
}

// upstreamNameOf returns an upstream/cluster directive's declared name, or "?".
func upstreamNameOf(d *cadishfile.Directive) string {
	if len(d.Args) >= 1 {
		return d.Args[0].Raw
	}
	return "?"
}

// detectGeoUnconfigured warns when a site varies on a geo granularity but the geo
// source it needs is unconfigured — the token would silently key on "" (no
// variation), a likely misconfiguration. Two cases:
//
//   - any geo token ({geo}/{geo.continent}/{geo.region}) with NO `geo { … }` block:
//     no country is resolved, so every granularity keys on "".
//   - {geo.region} used with a geo block that has NO `region_header`: the region
//     comes from an upstream CDN header (no GeoIP DB), so without one it keys on "".
//
// (Unlike {device}, geo has no built-in default source. Continent is derived in-tree
// from the country, so it needs only the country source, not a separate header.)
//
// A `source maxmind` CITY edition supplies {geo.region} directly (subdivisions), so it
// satisfies the region requirement WITHOUT a region_header (D56). A maxmind COUNTRY
// edition has no subdivisions, so it still needs a region_header — the region warning
// fires for it. The edition is sniffed from the DB metadata (D40 reuse).
func detectGeoUnconfigured(body []cadishfile.Node, sr *SiteReport, baseDir string, sandbox bool) {
	usesGeo, usesRegion, hasGeo, hasRegionHeader := false, false, false, false
	maxmindProvidesRegion := false
	var keyPos, regionPos cadishfile.Pos
	for _, n := range body {
		d, ok := n.(*cadishfile.Directive)
		if !ok {
			continue
		}
		switch d.Name {
		case "geo":
			hasGeo = true
			for _, bn := range d.Block {
				bd, ok := bn.(*cadishfile.Directive)
				if !ok {
					continue
				}
				if bd.Name == "region_header" {
					hasRegionHeader = true
				}
				// In sandbox mode, skip the filesystem probe entirely — we cannot
				// know the edition without reading the file, but that is acceptable
				// (the region warning may fire spuriously; no file is read).
				if !sandbox && bd.Name == "source" && len(bd.Args) >= 2 && bd.Args[0].Raw == "maxmind" && maxmindCityEdition(bd.Args[1].Raw, baseDir) {
					maxmindProvidesRegion = true
				}
			}
		case "cache_key":
			for _, a := range d.Args {
				switch a.Raw {
				case "{geo}", "{geo.continent}", "{geo.region}":
					usesGeo = true
					keyPos = d.Pos
				}
				if a.Raw == "{geo.region}" {
					usesRegion = true
					regionPos = d.Pos
				}
			}
		}
	}
	if usesGeo && !hasGeo {
		sr.add(SevWarning, keyPos, "geo-unconfigured",
			"cache_key uses a {geo*} token but no `geo { … }` source is configured; it will key on \"\" (no variation)")
		return
	}
	if usesRegion && hasGeo && !hasRegionHeader && !maxmindProvidesRegion {
		sr.add(SevWarning, regionPos, "geo-region-unconfigured",
			"cache_key uses {geo.region} but the `geo { … }` block supplies no region source (no `region_header NAME` and no maxmind City-edition `source`); {geo.region} will key on \"\" (region needs an upstream geo header or a MaxMind City database)")
	}
}

// maxmindCityEdition reports whether the .mmdb at path (relative to baseDir) is a City
// edition — i.e. carries subdivisions, so it supplies {geo.region}. It opens the DB and
// reads its metadata database type cheaply; a missing/corrupt DB returns false (the
// path error is reported by validateGeoBlock, so this just declines to suppress the
// region warning).
func maxmindCityEdition(rel, baseDir string) bool {
	if rel == "" {
		return false
	}
	path := rel
	if !filepath.IsAbs(path) {
		path = filepath.Join(baseDir, path)
	}
	return geo.MaxMindHasRegion(path)
}

// detectIPACLWithoutTrustProxy warns when a site has an `ip`-based `allow`/`deny`/
// `block` security rule but configures NO trusted-proxy set (neither a standalone
// `trust_proxy …` nor a `geo { trust_proxy … }` block). This is a SILENT no-op
// hazard: behind a proxy/LB the `ip` matcher resolves the REAL client only when the
// socket peer is a trusted proxy — with no trust_proxy it instead matches the
// proxy's own IP, so a `deny @badips` never fires and an `allow @office` misbehaves.
// The security control fails useless with no operator signal.
//
// It is a WARNING, not an error: when cadish IS the edge with direct client
// connections (no proxy in front), the peer IS the client and the ACL is correct.
// The fix is to declare the fronting proxy/LB/CDN CIDRs via `trust_proxy …`.
func detectIPACLWithoutTrustProxy(body []cadishfile.Node, defs map[string]*cadishfile.MatcherDef, sr *SiteReport) {
	hasTrustProxy := false
	for _, n := range body {
		d, ok := n.(*cadishfile.Directive)
		if !ok {
			continue
		}
		switch d.Name {
		case "trust_proxy":
			hasTrustProxy = true
		case "geo":
			for _, bn := range d.Block {
				if bd, ok := bn.(*cadishfile.Directive); ok && bd.Name == "trust_proxy" {
					hasTrustProxy = true
				}
			}
		}
	}
	if hasTrustProxy {
		return
	}

	// Find the first ip-based security rule (named ref to an `ip` matcher, or an
	// inline `deny ip …`) and warn at its position.
	for _, n := range body {
		d, ok := n.(*cadishfile.Directive)
		if !ok {
			continue
		}
		switch d.Name {
		case "allow", "deny", "block":
		case "rate_limit":
			// `rate_limit … key ip` (explicit or default) keys the bucket on the
			// resolved client IP — the SAME trusted-proxy dependence: without trust_proxy,
			// behind a proxy/LB every client shares the proxy's IP bucket, so one IP's
			// limit throttles ALL clients (or the limit never bites per-client). Warn too.
			if rateLimitKeysOnIP(d.Args) {
				sr.add(SevWarning, d.Pos, "ip-acl-without-trust-proxy",
					"rate_limit keys on the client IP (`key ip`) but the site declares no `trust_proxy` (and no `geo { trust_proxy … }`); behind a proxy/LB it buckets the PROXY's IP, not the real client — every client shares one bucket. Declare the fronting CIDRs with `trust_proxy …` (omit only when cadish is the edge with direct client connections)")
				return
			}
			continue
		default:
			continue
		}
		u := directiveUsages(d)
		usesIP := false
		for _, in := range u.inlines {
			if in.typ == "ip" {
				usesIP = true
			}
		}
		for _, ref := range u.refs {
			if m := defs[ref.name]; m != nil && m.Type == "ip" {
				usesIP = true
			}
		}
		if !usesIP {
			continue
		}
		sr.add(SevWarning, d.Pos, "ip-acl-without-trust-proxy",
			"%s uses an `ip` ACL but the site declares no `trust_proxy` (and no `geo { trust_proxy … }`); behind a proxy/LB the `ip` matcher will match the PROXY's IP, not the real client — the rule silently no-ops. Declare the fronting CIDRs with `trust_proxy …` (omit only when cadish is the edge with direct client connections)",
			d.Name)
		return
	}
}

// rateLimitKeysOnIP reports whether a rate_limit directive keys its bucket on the
// client IP — i.e. `key ip`, or no `key …` at all (ip is the default). It returns
// false only when an explicit `key global` or `key header …` is present.
func rateLimitKeysOnIP(args []cadishfile.Arg) bool {
	for i, a := range args {
		if a.Raw != "key" || i+1 >= len(args) {
			continue
		}
		switch args[i+1].Raw {
		case "global", "header":
			return false
		default: // "ip" or anything else (compile-time validated elsewhere)
			return true
		}
	}
	return true // default key is ip
}

// add appends a diagnostic to the site report.
func (sr *SiteReport) add(sev Severity, pos cadishfile.Pos, code, format string, args ...any) {
	sr.Diagnostics = append(sr.Diagnostics, newDiag(sev, pos, code, format, args...))
}

// checkEmptyBraces warns when a directive argument is an empty "{}" placeholder.
// The lexer keeps a brace-balanced run with no interior whitespace as a single
// word token, so writing `cache_key {}` (where a value or a real placeholder like
// `{device}` was intended) is silently accepted as a literal "{}" token rather
// than opening a block. That is almost never what the author meant, so flag it.
func checkEmptyBraces(d *cadishfile.Directive, sr *SiteReport) {
	for _, a := range d.Args {
		if !a.Quoted && a.Raw == "{}" {
			sr.add(SevWarning, a.Pos, "empty-braces",
				"directive %s has an empty `{}` argument; it is treated as a literal token, not a block or placeholder — remove it or fill in the intended value", d.Name)
		}
	}
}

// checkArity performs light, non-strict arity sanity for known directives. The
// parser is the source of truth for syntax; these only catch obviously-incomplete
// directives.
func checkArity(d *cadishfile.Directive, sr *SiteReport) {
	switch d.Name {
	case "cache_key":
		if len(d.Args) == 0 {
			// A `cache_key` with NO tokens silently falls back to the built-in default
			// key (method host path) — almost always a typo (a dropped token list or a
			// line wrapped wrong), so the operator gets the default key with no signal.
			sr.add(SevWarning, d.Pos, "cache-key-empty",
				"cache_key has no tokens; it silently falls back to the default key `method host path` — likely a typo. Add the tokens you meant (e.g. `cache_key host path`) or remove the line to use the default explicitly")
		}
	case "respond":
		if len(d.Args) >= 1 && d.Args[0].Raw == "on_error" {
			// `respond on_error [@scope] STATUS BODY` (D57): origin-error fallback page.
			if len(d.Args) < 3 {
				sr.add(SevWarning, d.Pos, "arity", "respond on_error needs STATUS and BODY (e.g. `respond on_error 503 \"maintenance\"`)")
			}
		} else if len(d.Args) < 2 {
			sr.add(SevWarning, d.Pos, "arity", "respond needs at least PATH and CODE (e.g. `respond /health 200 \"OK\"`)")
		}
	case "redirect":
		// Three forms: `PATH_REGEX CODE TARGET` / `@scope CODE TARGET` (both ≥3 args)
		// or `CODE map { … }` (block). The scoped form is disambiguated by a leading
		// @matcher but still needs at least scope+code+target.
		isMap := (len(d.Args) >= 2 && d.Args[1].Raw == "map") || d.HasBlock
		if !isMap && len(d.Args) < 3 {
			sr.add(SevWarning, d.Pos, "arity", "redirect needs `PATH_REGEX CODE TARGET` (e.g. `redirect ^/es(/.*)?$ 301 https://{host}/espanol$1`), `@scope CODE TARGET`, or `CODE map { … }`")
		}
	case "route":
		if !hasArg(d.Args, "->") {
			sr.add(SevWarning, d.Pos, "arity", "route needs `@matcher -> UPSTREAM`")
		}
	case "storage":
		if !hasArg(d.Args, "->") {
			sr.add(SevWarning, d.Pos, "arity", "storage needs `<selector> -> ram|disk`")
		}
	case "cache_ttl":
		if !hasArg(d.Args, "ttl") && !hasArg(d.Args, "hit_for_miss") && !hasArg(d.Args, "from_header") {
			sr.add(SevWarning, d.Pos, "arity", "cache_ttl needs a `ttl DUR`, `from_header HEADER`, or `hit_for_miss DUR` action")
		}
	case "cors":
		if len(d.Args) == 0 {
			sr.add(SevWarning, d.Pos, "arity", "cors needs `*` or an origin list")
		}
	case "transform":
		sr.add(SevWarning, d.Pos, "no-op-directive",
			"`transform { … }` is a no-op: use the `replace` directive directly (e.g. `replace OLD NEW`)")
	}
}

// pathGlobsOf returns the path globs a selection directive is scoped on, drawn
// from both named path matchers it references and inline path matchers. It is
// used for conservative subset-shadowing detection.
func pathGlobsOf(d *cadishfile.Directive, defs map[string]*cadishfile.MatcherDef) []string {
	var globs []string
	u := directiveUsages(d)
	for _, ref := range u.refs {
		if m := defs[ref.name]; m != nil && m.Type == "path" {
			for _, a := range m.Args {
				globs = append(globs, a.Raw)
			}
		}
	}
	for _, in := range u.inlines {
		if in.typ == "path" {
			for _, a := range in.args {
				globs = append(globs, a.Raw)
			}
		}
	}
	return globs
}

// globSubsumes reports whether glob a matches a superset of paths matched by b
// (conservatively): identical patterns, or a prefix-wildcard `…/*` whose prefix
// is a prefix of b.
func globSubsumes(a, b string) bool {
	if a == b {
		return true
	}
	if strings.HasSuffix(a, "/*") {
		prefix := strings.TrimSuffix(a, "*") // keep the trailing slash
		return strings.HasPrefix(b, prefix)
	}
	if a == "*" || a == "/*" {
		return true
	}
	return false
}
