package config

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/cadi-sh/cadish/internal/cadishfile"
	"github.com/cadi-sh/cadish/internal/cfsign"
	"github.com/cadi-sh/cadish/internal/cluster"
	"github.com/cadi-sh/cadish/internal/lb"
	"github.com/cadi-sh/cadish/internal/origin"
	"github.com/cadi-sh/cadish/internal/origin/chain"
	"github.com/cadi-sh/cadish/internal/origin/httporigin"
	"github.com/cadi-sh/cadish/internal/origin/s3origin"
)

// siteOrigins is the fully-built origin layer for one site.
type siteOrigins struct {
	origins map[string]origin.Origin  // every declared upstream/cluster, by name
	def     origin.Origin             // default backend (single, first, or chain)
	defName string                    // name of the default upstream ("" for a chain)
	sticky  map[string]*lb.StickySpec // sticky upstreams' routing-key specs, by name
	pools   []*lb.Upstream            // lb pools needing Start(ctx) for health/resolve
	epRes   lb.EndpointResolver       // shared k8s resolver (nil unless a k8s:// target exists)
}

// buildOrigins parses the site's `upstream`/`cluster` blocks and optional
// `origin chain A -> B [-> C]` directive into the runtime origin layer.
//
// Each upstream becomes one of:
//   - an s3origin (the block has a `bucket`),
//   - a cfsign.Origin (the block has a `sign cloudfront …` directive — each request
//     URL is re-signed with the CloudFront private key before fetching; see
//     buildSignedOrigin),
//   - otherwise an *lb.Upstream (the load balancer): round-robin by default, or
//     sticky/shard/least-conn/health/multi-backend per the block. A single static
//     backend is the degenerate (but fully valid) lb pool.
func buildOrigins(site *cadishfile.Site, epRes lb.EndpointResolver) (*siteOrigins, error) {
	so := &siteOrigins{
		origins: map[string]origin.Origin{},
		sticky:  map[string]*lb.StickySpec{},
		epRes:   epRes,
	}
	var order []string
	var chainNames []string

	for _, n := range site.Body {
		d, ok := n.(*cadishfile.Directive)
		if !ok {
			continue
		}
		switch d.Name {
		case "upstream", "cluster":
			// A nameless `cluster { peers … }` is a membership block (internal/cluster),
			// not an upstream pool — it is built separately by buildCluster. Skip it
			// here so it isn't mistaken for a pool needing a name.
			if d.Name == "cluster" && cluster.IsMembershipBlock(d) {
				continue
			}
			if len(d.Args) < 1 {
				return nil, compileErr(d.Pos, d.Name+" needs a name")
			}
			name := d.Args[0].Raw
			if _, dup := so.origins[name]; dup {
				return nil, compileErr(d.Pos, "duplicate "+d.Name+" "+quoteName(name))
			}
			o, err := so.buildOne(d, name)
			if err != nil {
				return nil, err
			}
			so.origins[name] = o
			order = append(order, name)
		case "origin":
			names, err := parseOriginChain(d)
			if err != nil {
				return nil, err
			}
			chainNames = names
		}
	}

	if len(so.origins) == 0 {
		return nil, fmt.Errorf("%s: site %q has no `upstream` to fetch from", site.Pos, firstAddr(site))
	}

	switch {
	case len(chainNames) > 0:
		members := make([]origin.Origin, 0, len(chainNames))
		for _, name := range chainNames {
			o, ok := so.origins[name]
			if !ok {
				return nil, fmt.Errorf("%s: origin chain references undeclared upstream %q", site.Pos, name)
			}
			members = append(members, o)
		}
		ch, err := chain.New(members)
		if err != nil {
			return nil, err
		}
		so.def = ch
		so.defName = "" // a chain has no single upstream name
	default:
		so.def = so.origins[order[0]]
		so.defName = order[0]
	}
	return so, nil
}

// buildOne builds a single upstream/cluster origin and records its sticky spec and
// lb pool (for Start) as side effects on so.
func (so *siteOrigins) buildOne(d *cadishfile.Directive, name string) (origin.Origin, error) {
	bucket, hasSign := scanUpstreamFlags(d)

	// S3-compatible upstream: a `bucket` directive selects s3origin. Credentials are
	// read from the block (`access_key`/`secret_key`/`region`, env-substituted at load),
	// or `anonymous` (also implied when no creds are given) for a public bucket. Without
	// this wiring the SDK signed with EMPTY creds and S3/MinIO returned 502.
	if bucket != "" {
		to := firstTo(d)
		if to == "" {
			return nil, compileErr(d.Pos, "upstream "+quoteName(name)+" has a bucket but no `to` endpoint")
		}
		creds := parseS3Creds(d)
		region := creds.region
		if region == "" {
			region = "us-east-1"
		}
		return s3origin.New(s3origin.Config{
			Endpoint:     to,
			Region:       region,
			Bucket:       bucket,
			AccessKey:    creds.access,
			SecretKey:    creds.secret,
			Anonymous:    creds.anonymous,
			UsePathStyle: true,
		}), nil
	}

	// Signed HTTP upstream (CloudFront): wrap the backend in a cfsign.Origin that
	// re-signs each request URL with the CloudFront private key before fetching —
	// the S3-miss → CloudFront-resign fallback. It is a plain origin.Origin, so it
	// composes with `origin chain`.
	if hasSign {
		return so.buildSignedOrigin(d, name)
	}

	// Host-header policy (backlog #11): `host_header preserve|origin|<value>` in the
	// upstream block. Default is preserve (forward the client Host).
	hh, err := parseHostHeader(d)
	if err != nil {
		return nil, err
	}

	// Transport knobs: the gap-H6 knobs (`sni <server-name>`, `http_reuse never`)
	// and the TLSVERIFY knobs (`tls_insecure`, `ca_file <path>`, `alpn <proto…>`).
	// All default to the zero value (no SNI override, keep-alive on, full origin TLS
	// verification, Go-default ALPN), so an upstream that sets none is byte-for-byte
	// unchanged. openFiles=true: the CA PEM is loaded+validated HERE (run time / config.Load)
	// so a bad CA fails loudly at startup.
	tp, err := parseTransportPolicy(d, true)
	if err != nil {
		return nil, err
	}

	// Trivial upstream — a single `to` backend with no load-balancing features
	// (no sticky/health/shard/policy/timeout/max_conns) — stays a plain httporigin
	// so the hot single-origin path never pays for the lb pool machinery. The
	// transport knobs are tweaks (not lb features), so a single-`to` upstream that
	// sets them STAYS on the fast path; we just forward the matching Options.
	if isTrivialUpstream(d) {
		// Validate + NORMALIZE the single `to` through the SAME lb.ParseTarget the pooled
		// path and `cadish check` (config.ParseUpstreamURL) use, so all three agree on
		// what a trivial upstream accepts. Two check↔run divergences came from feeding the
		// RAW token straight to httporigin.New here:
		//   - a scheme-less `to host:port` (which lb.ParseTarget normalizes by prepending
		//     http://, the documented "implies http") was rejected by httporigin.New ("base
		//     URL must be http or https") — check passed, run failed; and
		//   - an SSRF link-local / cloud-metadata literal (e.g. http://169.254.169.254) is
		//     REJECTED by lb.ParseTarget but httporigin.New proxied to it — check rejected,
		//     run silently bypassed the SSRF guard on the trivial fast path.
		// Routing through ParseTarget (and using its normalized Target.Raw as the base URL)
		// closes both while keeping the trivial httporigin fast path.
		rawTo, toPos := firstToArg(d)
		tgt, terr := lb.ParseTarget(rawTo, toPos)
		if terr != nil {
			return nil, terr
		}
		opts := []httporigin.Option{httporigin.WithHostPolicy(hh.Policy, hh.Value)}
		if tp.sni != "" {
			opts = append(opts, httporigin.WithSNI(tp.sni))
		}
		if tp.disableReuse {
			opts = append(opts, httporigin.WithDisableKeepAlives(true))
		}
		if tp.insecure {
			opts = append(opts, httporigin.WithInsecureTLS(true))
		}
		if tp.caPool != nil {
			opts = append(opts, httporigin.WithRootCAs(tp.caPool))
		}
		if len(tp.alpn) != 0 {
			opts = append(opts, httporigin.WithALPN(tp.alpn))
		}
		return httporigin.New(tgt.Raw, opts...)
	}

	// Everything else is a load-balanced pool (one or many backends).
	cfg, err := parseLBConfig(d)
	if err != nil {
		return nil, err
	}
	cfg.HostHeader = hh
	cfg.SNI = tp.sni
	cfg.DisableReuse = tp.disableReuse
	// TLSVERIFY: config is authoritative (it loads the CA pool and enforces the
	// tls_insecure⊕ca_file exclusion); set the resolved values on the pool so the
	// origin factory, health probe and fingerprint all see them.
	cfg.Insecure = tp.insecure
	cfg.CAFile = tp.caFile
	cfg.RootCAs = tp.caPool
	cfg.CAPEMHash = tp.caPEMHash
	cfg.ALPN = tp.alpn
	opts := []lb.Option{}
	if so.epRes != nil && directiveHasK8sBackend(d) {
		opts = append(opts, lb.WithEndpointResolver(so.epRes))
	}
	up, err := lb.New(cfg, opts...)
	if err != nil {
		return nil, compileErr(d.Pos, d.Name+" "+quoteName(name)+": "+err.Error())
	}
	if cfg.Sticky != nil {
		so.sticky[name] = cfg.Sticky
	}
	so.pools = append(so.pools, up)
	return up, nil
}

// buildSignedOrigin builds a CloudFront-signing origin for a `sign cloudfront …`
// upstream. The distribution is the upstream's `to` URL; the signer uses the
// directive's key-pair id, private-key PEM and optional ttl.
//
//	upstream cloudfront {
//	    to   https://d111111abcdef8.cloudfront.net
//	    sign cloudfront <key-pair-id> key <private-key.pem> [ttl 5m]
//	}
func (so *siteOrigins) buildSignedOrigin(d *cadishfile.Directive, name string) (origin.Origin, error) {
	to := firstTo(d)
	if to == "" {
		return nil, compileErr(d.Pos, "upstream "+quoteName(name)+" has no `to` backend")
	}
	sc, err := parseSign(d)
	if err != nil {
		return nil, err
	}
	signer, err := cfsign.NewFromPEM(to, sc.keyPairID, sc.pemPath)
	if err != nil {
		return nil, compileErr(d.Pos, "upstream "+quoteName(name)+": "+err.Error())
	}
	return cfsign.NewOrigin(signer, sc.ttl), nil
}

// signConfig is a parsed `sign cloudfront …` directive.
type signConfig struct {
	keyPairID string
	pemPath   string
	ttl       time.Duration
}

// parseSign reads the `sign cloudfront <key-pair-id> key <pem> [ttl DUR]` directive
// from an upstream block. Only the `cloudfront` provider is supported in v1.
func parseSign(d *cadishfile.Directive) (signConfig, error) {
	for _, bn := range d.Block {
		bd, ok := bn.(*cadishfile.Directive)
		if !ok || bd.Name != "sign" {
			continue
		}
		args := bd.Args
		if len(args) < 1 || args[0].Raw != "cloudfront" {
			return signConfig{}, compileErr(bd.Pos, "sign: only `sign cloudfront <key-pair-id> key <pem> [ttl DUR]` is supported")
		}
		if len(args) < 2 {
			return signConfig{}, compileErr(bd.Pos, "sign cloudfront needs a <key-pair-id>")
		}
		// Reject an empty/whitespace key-pair id at PARSE time (shared by `check` and
		// `run`) so an unset `{$CF_KEYPAIR_ID}` is caught by `cadish check`, not only by
		// cfsign at run-time — closing the check<->run divergence.
		keyPairID := strings.TrimSpace(args[1].Raw)
		if keyPairID == "" {
			return signConfig{}, compileErr(args[1].Pos, "sign cloudfront: empty <key-pair-id> (an unset {$CF_KEYPAIR_ID}?) — set the CloudFront key-pair id")
		}
		sc := signConfig{keyPairID: keyPairID, ttl: 5 * time.Minute}
		rest := args[2:]
		for i := 0; i < len(rest); i++ {
			switch rest[i].Raw {
			case "key":
				if i+1 >= len(rest) {
					return signConfig{}, compileErr(bd.Pos, "sign cloudfront `key` needs a PEM path")
				}
				sc.pemPath = rest[i+1].Raw
				i++
			case "ttl":
				if i+1 >= len(rest) {
					return signConfig{}, compileErr(bd.Pos, "sign cloudfront `ttl` needs a duration")
				}
				dur, derr := ParseDuration(rest[i+1].Raw)
				if derr != nil {
					return signConfig{}, compileErr(rest[i+1].Pos, "sign cloudfront ttl: "+derr.Error())
				}
				sc.ttl = dur
				i++
			default:
				return signConfig{}, compileErr(rest[i].Pos, "sign cloudfront: unexpected token "+quoteName(rest[i].Raw))
			}
		}
		if sc.pemPath == "" {
			return signConfig{}, compileErr(bd.Pos, "sign cloudfront needs `key <private-key.pem>`")
		}
		return sc, nil
	}
	return signConfig{}, compileErr(d.Pos, "internal: sign directive not found")
}

// configOwnedUpstreamDirectives are inner directives the CONFIG layer reads and
// applies itself (host policy, S3/CloudFront wiring) — not load-balancer config.
// The lb parser does not recognize them and would reject them as "unknown
// directive". buildOne already extracts these (parseHostHeader/scanUpstreamFlags/
// parseS3Creds/parseSign) and sets the resulting fields on the lb.Config after
// parsing, so they must be stripped before the block reaches lb. (`host_header` is
// the one that matters for an lb pool; the S3/sign directives only appear on
// upstreams that return earlier in buildOne, but are filtered here for safety.)
var configOwnedUpstreamDirectives = map[string]bool{
	"host_header": true,
	"bucket":      true,
	"sign":        true,
	"access_key":  true,
	"secret_key":  true,
	"region":      true,
	"anonymous":   true,
	// `ca_file` is config-owned: the config layer reads+validates the PEM file (so
	// `cadish check` fails loudly on a missing/garbage file) and sets the loaded
	// RootCAs pool on the lb.Config. The lb parser does file no I/O, so it must not
	// see `ca_file` (it would reject it as an unknown directive). `tls_insecure`/
	// `alpn` are pure and parsed by lb too (like `sni`), so they are NOT stripped.
	"ca_file": true,
}

// parseLBConfig dispatches to lb.ParseUpstream / lb.ParseCluster, after stripping
// the config-owned inner directives the lb parser does not understand.
func parseLBConfig(d *cadishfile.Directive) (lb.Config, error) {
	d = withoutConfigOwnedDirectives(d)
	if d.Name == "cluster" {
		return lb.ParseCluster(d)
	}
	return lb.ParseUpstream(d)
}

// withoutConfigOwnedDirectives returns a shallow copy of d whose Block drops the
// config-owned directives (see configOwnedUpstreamDirectives). If none are present
// the original directive is returned unchanged (no allocation on the common path).
func withoutConfigOwnedDirectives(d *cadishfile.Directive) *cadishfile.Directive {
	has := false
	for _, bn := range d.Block {
		if bd, ok := bn.(*cadishfile.Directive); ok && configOwnedUpstreamDirectives[bd.Name] {
			has = true
			break
		}
	}
	if !has {
		return d
	}
	filtered := make([]cadishfile.Node, 0, len(d.Block))
	for _, bn := range d.Block {
		if bd, ok := bn.(*cadishfile.Directive); ok && configOwnedUpstreamDirectives[bd.Name] {
			continue
		}
		filtered = append(filtered, bn)
	}
	cp := *d
	cp.Block = filtered
	return &cp
}

// isTrivialUpstream reports whether d is a plain `upstream` with exactly one
// backend target (whether on its own `to` line or sharing one) and no
// load-balancing directives — the common single-origin case that should bypass
// the lb pool and be served by a direct httporigin. A `to A B C` line carries
// three targets, so it is NOT trivial; it falls through to the round-robin pool.
// A `cluster` is never trivial (it exists to shard across peers).
func isTrivialUpstream(d *cadishfile.Directive) bool {
	if d.Name != "upstream" {
		return false
	}
	// Count TOTAL backend targets, not the number of `to` directives: a single
	// `to A B C` line is one directive carrying three targets, so it is a real
	// multi-backend pool — fast-pathing it would silently drop every target but
	// the first (no error, no warning, no load balancing).
	backendCount := 0
	for _, bn := range d.Block {
		bd, ok := bn.(*cadishfile.Directive)
		if !ok {
			continue
		}
		switch bd.Name {
		case "to":
			backendCount += len(bd.Args)
			for _, a := range bd.Args {
				// A k8s:// or dns:// backend always needs the lb pool: it carries
				// background re-resolution (k8s via the injected EndpointResolver, dns via
				// the periodic DNS resolver). A plain httporigin cannot re-resolve and
				// rejects a non-http(s) base URL outright (`dns://…` failed to load before
				// this), so never fast-path a dynamic target.
				if t, err := lb.ParseTarget(a.Raw, bd.Pos); err == nil &&
					(t.Scheme == lb.SchemeK8s || t.Scheme == lb.SchemeDNS) {
					return false
				}
			}
		case "sticky", "health", "shard_by", "policy", "lb", "timeout", "max_conns", "replicas", "resolve", "resolver":
			return false // any lb feature ⇒ build a real pool
		}
	}
	return backendCount == 1
}

// UpstreamCarriesPoolHealth reports whether the `upstream`/`cluster` block d builds
// as an lb.Upstream POOL — the only origin kind whose backend liveness the
// `upstream_healthy` matcher can actively track (a health FSM driven by an active
// `health { … }` probe or passive ejection). A named `cluster NAME { … }` pool always
// qualifies; an `upstream` qualifies UNLESS it is a trivial single-backend httporigin
// (no lb features) or an S3 (`bucket`)/CloudFront (`sign`) origin — none of which
// carry a health FSM. Exported so `cadish check` can warn (detectUpstreamHealthyNonPool)
// when `upstream_healthy NAME` references a name that resolves "assumed healthy" (the
// R03 footgun) instead of a really-probed pool. It mirrors buildOne's own dispatch
// (scanUpstreamFlags + isTrivialUpstream), the single source of truth, so check and run
// can never disagree on what becomes a pool. A nameless membership `cluster { … }`
// block is not a pool target and returns false.
func UpstreamCarriesPoolHealth(d *cadishfile.Directive) bool {
	switch d.Name {
	case "cluster":
		// A named cluster pool carries pool health; a nameless membership block does not.
		return !cluster.IsMembershipBlock(d) && len(d.Args) >= 1
	case "upstream":
		if bucket, hasSign := scanUpstreamFlags(d); bucket != "" || hasSign {
			return false // s3 / cfsign origin: not an lb pool
		}
		return !isTrivialUpstream(d)
	default:
		return false
	}
}

// scanUpstreamFlags reports the upstream block's `bucket` value (if any) and
// whether it carries a `sign` directive.
// s3Creds is the parsed credential set for an S3 (`bucket`) upstream.
type s3Creds struct {
	access    string
	secret    string
	region    string
	anonymous bool
}

// parseS3Creds reads the optional credential directives from an S3 upstream block:
// `access_key X`, `secret_key X`, `region X`, and the bare `anonymous` flag. Values are
// already env-substituted at load, so `access_key ${S3_KEY}` resolves before reaching
// here. Missing creds mean anonymous (public-bucket) access.
func parseS3Creds(d *cadishfile.Directive) s3Creds {
	var c s3Creds
	for _, bn := range d.Block {
		bd, ok := bn.(*cadishfile.Directive)
		if !ok {
			continue
		}
		switch bd.Name {
		case "access_key":
			if len(bd.Args) > 0 {
				c.access = bd.Args[0].Raw
			}
		case "secret_key":
			if len(bd.Args) > 0 {
				c.secret = bd.Args[0].Raw
			}
		case "region":
			if len(bd.Args) > 0 {
				c.region = bd.Args[0].Raw
			}
		case "anonymous":
			c.anonymous = true
		}
	}
	return c
}

func scanUpstreamFlags(d *cadishfile.Directive) (bucket string, hasSign bool) {
	for _, bn := range d.Block {
		bd, ok := bn.(*cadishfile.Directive)
		if !ok {
			continue
		}
		switch bd.Name {
		case "bucket":
			if len(bd.Args) > 0 {
				bucket = bd.Args[0].Raw
			}
		case "sign":
			hasSign = true
		}
	}
	return bucket, hasSign
}

// parseHostHeader reads the optional `host_header preserve|origin|<value>`
// directive from an upstream block into the lb/httporigin Host-header policy
// (backlog #11). Absent ⇒ the default, HostPreserve (forward the client Host).
//
//	host_header preserve    # forward the original client Host (DEFAULT)
//	host_header origin       # send the upstream base URL's host (legacy behavior)
//	host_header <value>      # send a fixed Host, e.g. `host_header origin.internal`
func parseHostHeader(d *cadishfile.Directive) (lb.HostHeaderPolicy, error) {
	for _, bn := range d.Block {
		bd, ok := bn.(*cadishfile.Directive)
		if !ok || bd.Name != "host_header" {
			continue
		}
		if len(bd.Args) != 1 {
			return lb.HostHeaderPolicy{}, compileErr(bd.Pos, "host_header takes exactly one arg: `preserve`, `origin`, or a fixed Host value")
		}
		switch v := bd.Args[0].Raw; v {
		case "preserve":
			return lb.HostHeaderPolicy{Policy: httporigin.HostPreserve}, nil
		case "origin":
			return lb.HostHeaderPolicy{Policy: httporigin.HostOrigin}, nil
		default:
			// A fixed Host value. Reject an empty string and an accidental matcher
			// ref (`@name`) so a typo doesn't silently send a bogus Host.
			if v == "" || strings.HasPrefix(v, "@") {
				return lb.HostHeaderPolicy{}, compileErr(bd.Pos, "host_header: invalid fixed Host value "+quoteName(v))
			}
			return lb.HostHeaderPolicy{Policy: httporigin.HostFixed, Value: v}, nil
		}
	}
	// Default: preserve the client Host.
	return lb.HostHeaderPolicy{Policy: httporigin.HostPreserve}, nil
}

// transportPolicy is the parsed set of per-upstream transport knobs: the gap-H6
// knobs (sni / http_reuse never) and the TLSVERIFY knobs (tls_insecure / ca_file /
// alpn). It is the single definition shared by `cadish check` (validate.go) and
// `run` (buildOne) so the two can never diverge.
type transportPolicy struct {
	sni          string
	disableReuse bool
	insecure     bool           // `tls_insecure`
	caFile       string         // `ca_file <path>` (the source path; identity/fingerprint)
	caPool       *x509.CertPool // loaded+validated RootCAs from caFile (nil ⇒ system roots)
	caPEMHash    string         // hex sha256 of the loaded ca_file PEM bytes ("" ⇒ none); folds into the pool fingerprint so an in-place CA rotation forces a fresh pool
	alpn         []string       // `alpn <proto…>`
}

// parseTransportPolicy reads the optional per-upstream transport knobs from an
// upstream block. All are explicit-only: absent ⇒ the zero value (no SNI override =
// Go's dialed-host default; keep-alive on; full origin TLS verification against the
// system roots; Go-default ALPN), so an upstream that sets none is byte-for-byte
// unchanged. It mirrors parseHostHeader and reuses the lb-package validators so lint
// and runtime share one definition. The `ca_file` PEM is loaded+validated HERE (so
// `cadish check` fails loudly on a missing/unparseable/empty file), and the
// `tls_insecure` ⊕ `ca_file` mutual exclusion is enforced as a compile error.
// S3 (`bucket`) and CloudFront (`sign`) upstreams never reach here (they return
// earlier), so they ignore all knobs, exactly like host_header.
// openFiles gates the FILESYSTEM side of the transport policy: when false (the
// structural validate / admin-sandbox path) the `ca_file` PEM is NOT read — only its
// STRUCTURE (arity, non-empty path) and the `tls_insecure` ⊕ `ca_file` exclusion are
// checked, leaving the pool nil. This keeps the sandbox a true no-filesystem trust
// boundary (no host-file read oracle, no /dev/zero DoS) and keeps `cadish check`
// portable (a config authored for another host's CA path is a deploy-time WARNING via
// fileExistenceWarnings, not a hard error). When true (`cadish run` / config.Load) the
// PEM is loaded + validated for real so a bad CA still fails loudly at startup.
func parseTransportPolicy(d *cadishfile.Directive, openFiles bool) (transportPolicy, error) {
	var tp transportPolicy
	var insecurePos, caPos cadishfile.Pos
	for _, bn := range d.Block {
		bd, ok := bn.(*cadishfile.Directive)
		if !ok {
			continue
		}
		switch bd.Name {
		case "sni":
			name, perr := lb.ParseSNIArg(bd)
			if perr != nil {
				return transportPolicy{}, perr
			}
			tp.sni = name
		case "http_reuse":
			if perr := lb.ParseHTTPReuseArg(bd); perr != nil {
				return transportPolicy{}, perr
			}
			tp.disableReuse = true
		case "tls_insecure":
			if perr := lb.ParseTLSInsecureArg(bd); perr != nil {
				return transportPolicy{}, perr
			}
			tp.insecure = true
			insecurePos = bd.Pos
		case "ca_file":
			// Structure first (arity + non-empty path) — always validated, on BOTH the
			// sandbox/validate path and the run path. The actual PEM read happens only
			// when openFiles is set (run time), so the validate/sandbox path never
			// touches the filesystem.
			path, perr := validateCAFileStructure(bd)
			if perr != nil {
				return transportPolicy{}, perr
			}
			tp.caFile = path
			caPos = bd.Pos
			if openFiles {
				pool, hash, lerr := loadCAFilePEM(bd, path)
				if lerr != nil {
					return transportPolicy{}, lerr
				}
				tp.caPool = pool
				tp.caPEMHash = hash
			}
		case "alpn":
			protos, perr := lb.ParseALPNArg(bd)
			if perr != nil {
				return transportPolicy{}, perr
			}
			tp.alpn = protos
		}
	}
	// tls_insecure (skip verification) and ca_file (verify against a private CA) are
	// contradictory — one disables verification, the other strengthens it. Reject the
	// combination at compile time rather than silently picking one.
	if tp.insecure && tp.caFile != "" {
		pos := insecurePos
		if caPos.Line > 0 {
			pos = caPos
		}
		return transportPolicy{}, compileErr(pos, "tls_insecure and ca_file are mutually exclusive: `tls_insecure` skips verification, `ca_file` verifies against a private CA — pick one")
	}
	return tp, nil
}

// validateCAFileStructure validates the STRUCTURE of a `ca_file <path>` directive
// WITHOUT touching the filesystem: exactly one argument, a non-empty path. It returns
// the trimmed source path (kept for the pool fingerprint). This is the ONLY thing the
// validate/sandbox path calls (no os.ReadFile), so the admin /api/validate endpoint
// never becomes a host-file read oracle and `cadish check` stays portable across hosts.
func validateCAFileStructure(bd *cadishfile.Directive) (string, error) {
	if len(bd.Args) != 1 {
		return "", compileErr(bd.Pos, "ca_file takes exactly one argument: a path to a PEM CA bundle (e.g. `ca_file /etc/cadish/internal-ca.pem`)")
	}
	path := strings.TrimSpace(bd.Args[0].Raw)
	if path == "" {
		return "", compileErr(bd.Args[0].Pos, "ca_file: empty path (an unset {$CA_FILE}?)")
	}
	return path, nil
}

// loadCAFilePEM reads the ca_file PEM bundle from disk and builds a RootCAs pool from
// it. It is the RUNTIME loader (config.Load / origin build), gated behind openFiles, so
// the filesystem is touched only by `cadish run`. It fails loudly on an unreadable file
// or a PEM that yields no certificates — modeled on how parseSign validates the
// CloudFront key PEM. path must already be structurally validated.
// It also returns a hex sha256 of the raw PEM bytes (the pool fingerprint's CA-content
// stand-in) so a CA rotated in place (same path, new bytes) forces a fresh pool on reload.
func loadCAFilePEM(bd *cadishfile.Directive, path string) (*x509.CertPool, string, error) {
	pemBytes, err := os.ReadFile(path)
	if err != nil {
		return nil, "", compileErr(bd.Args[0].Pos, "ca_file: cannot read "+quoteName(path)+": "+err.Error())
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pemBytes) {
		return nil, "", compileErr(bd.Args[0].Pos, "ca_file: "+quoteName(path)+" contains no valid PEM certificates")
	}
	sum := sha256.Sum256(pemBytes)
	return pool, hex.EncodeToString(sum[:]), nil
}

// firstTo returns the first `to` backend URL in an upstream block, or "".
func firstTo(d *cadishfile.Directive) string {
	for _, bn := range d.Block {
		bd, ok := bn.(*cadishfile.Directive)
		if !ok || bd.Name != "to" || len(bd.Args) == 0 {
			continue
		}
		return bd.Args[0].Raw
	}
	return ""
}

// firstToArg returns the first `to` backend URL and its source position (for a
// positioned diagnostic). When no `to` arg exists it returns ("", the block's Pos).
func firstToArg(d *cadishfile.Directive) (string, cadishfile.Pos) {
	for _, bn := range d.Block {
		bd, ok := bn.(*cadishfile.Directive)
		if !ok || bd.Name != "to" || len(bd.Args) == 0 {
			continue
		}
		return bd.Args[0].Raw, bd.Args[0].Pos
	}
	return "", d.Pos
}

// parseOriginChain parses `origin chain A -> B [-> C]` into its ordered member
// list. The arrow tokens lex as plain "->" args.
func parseOriginChain(d *cadishfile.Directive) ([]string, error) {
	if len(d.Args) < 1 || d.Args[0].Raw != "chain" {
		return nil, compileErr(d.Pos, "origin: only `origin chain A -> B` is supported")
	}
	var names []string
	for _, a := range d.Args[1:] {
		if a.Raw == "->" {
			continue
		}
		names = append(names, a.Raw)
	}
	if len(names) < 2 {
		return nil, compileErr(d.Pos, "origin chain needs at least two upstreams")
	}
	return names, nil
}

func firstAddr(site *cadishfile.Site) string {
	if len(site.Addresses) > 0 {
		return site.Addresses[0]
	}
	return ""
}

// compileErr formats a positioned config error as "file:line:col: msg".
func compileErr(pos cadishfile.Pos, msg string) error {
	return fmt.Errorf("%s: %s", pos, msg)
}

func quoteName(s string) string { return "\"" + s + "\"" }
