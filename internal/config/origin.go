package config

import (
	"fmt"
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

	// Transport knobs (gap H6): `sni <server-name>` (TLS ClientHello server name)
	// and `http_reuse never` (disable backend connection reuse). Both default to
	// the zero value (no SNI override, keep-alive on), so an upstream that sets
	// neither is byte-for-byte unchanged.
	sni, disableReuse, err := parseTransportPolicy(d)
	if err != nil {
		return nil, err
	}

	// Trivial upstream — a single `to` backend with no load-balancing features
	// (no sticky/health/shard/policy/timeout/max_conns) — stays a plain httporigin
	// so the hot single-origin path never pays for the lb pool machinery. `sni`/
	// `http_reuse` are transport tweaks (not lb features), so a single-`to` upstream
	// that sets them STAYS on the fast path; we just forward the matching Options.
	if isTrivialUpstream(d) {
		opts := []httporigin.Option{httporigin.WithHostPolicy(hh.Policy, hh.Value)}
		if sni != "" {
			opts = append(opts, httporigin.WithSNI(sni))
		}
		if disableReuse {
			opts = append(opts, httporigin.WithDisableKeepAlives(true))
		}
		return httporigin.New(firstTo(d), opts...)
	}

	// Everything else is a load-balanced pool (one or many backends).
	cfg, err := parseLBConfig(d)
	if err != nil {
		return nil, err
	}
	cfg.HostHeader = hh
	cfg.SNI = sni
	cfg.DisableReuse = disableReuse
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
				// A k8s:// backend always needs the lb pool (it carries the injected
				// EndpointResolver + background re-resolution); never fast-path it to a
				// plain httporigin.
				if t, err := lb.ParseTarget(a.Raw, bd.Pos); err == nil && t.Scheme == lb.SchemeK8s {
					return false
				}
			}
		case "sticky", "health", "shard_by", "policy", "lb", "timeout", "max_conns", "replicas":
			return false // any lb feature ⇒ build a real pool
		}
	}
	return backendCount == 1
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

// parseTransportPolicy reads the optional gap-H6 transport knobs from an upstream
// block: `sni <server-name>` (TLS ClientHello server name for HTTPS backends) and
// `http_reuse never` (disable backend connection reuse). Both are explicit-only:
// absent ⇒ the zero value (no SNI override = Go's dialed-host default; keep-alive
// on), so an upstream that sets neither is byte-for-byte unchanged. It mirrors
// parseHostHeader and reuses the lb-package validators so lint and runtime share
// one definition. S3 (`bucket`) and CloudFront (`sign`) upstreams never reach here
// (they return earlier), so they ignore both, exactly like host_header.
func parseTransportPolicy(d *cadishfile.Directive) (sni string, disableReuse bool, err error) {
	for _, bn := range d.Block {
		bd, ok := bn.(*cadishfile.Directive)
		if !ok {
			continue
		}
		switch bd.Name {
		case "sni":
			name, perr := lb.ParseSNIArg(bd)
			if perr != nil {
				return "", false, perr
			}
			sni = name
		case "http_reuse":
			if perr := lb.ParseHTTPReuseArg(bd); perr != nil {
				return "", false, perr
			}
			disableReuse = true
		}
	}
	return sni, disableReuse, nil
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
