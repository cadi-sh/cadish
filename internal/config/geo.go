package config

import (
	"net/netip"
	"os"
	"path/filepath"

	"github.com/cadi-sh/cadish/internal/cadishfile"
	"github.com/cadi-sh/cadish/internal/geo"
)

// buildGeo builds the site's geo sources (for the {geo}/{geo.continent}/{geo.region}
// tokens and the `geo` matcher) and its trusted-proxy set from the optional
// `geo { … }` block. Returns (nil, nil, nil, nil) when the site declares no geo block
// — the geo tokens then render "". Sub-directives:
//
//	geo {
//	    source        header CF-IPCountry  # read a CDN/LB-set country header, OR
//	    source        cidr   geo.csv       # longest-prefix CIDR→country table (file)
//	    region_header CF-Region            # OPTIONAL: upstream region/subdivision header
//	    trust_proxy   10.0.0.0/8 ::1/128   # CIDRs whose XFF is trusted (real client IP)
//	}
//
// Exactly one `source` is required (it yields the country, from which {geo.continent}
// is derived in-tree — no GeoIP dependency, D11). `region_header NAME` is optional and
// adds {geo.region}: a US state / subdivision can't come from a raw IP without a GeoIP
// DB, so it is sourced from an upstream CDN header exactly like the country. A `cidr`
// path is resolved relative to the Cadishfile's directory.
//
// Returns (countrySource, regionSource, trustedProxies, error). regionSource is nil
// when no `region_header` is configured.
// openFiles is threaded to buildGeoSource: true on the run/CLI-check path (open the
// cidr/maxmind file, matching run's fail-fast), false on the sandboxed admin path
// (validate structure only — no filesystem access). When false, buildGeo returns
// after structural validation with nil sources (there is nothing assembled).
func buildGeo(site *cadishfile.Site, baseDir string, openFiles bool) (geo.Source, geo.Source, []netip.Prefix, []*geo.MaxMindDB, error) {
	var block *cadishfile.Directive
	for _, n := range site.Body {
		d, ok := n.(*cadishfile.Directive)
		if !ok || d.Name != "geo" {
			continue
		}
		if block != nil {
			return nil, nil, nil, nil, compileErr(d.Pos, "geo: only one block allowed per site")
		}
		block = d
	}
	if block == nil {
		return nil, nil, nil, nil, nil
	}
	if !block.HasBlock {
		return nil, nil, nil, nil, compileErr(block.Pos, "geo needs a { } block")
	}

	var region geo.Source
	var trusted []netip.Prefix
	var sources []geoSourceSpec
	for _, bn := range block.Block {
		bd, ok := bn.(*cadishfile.Directive)
		if !ok {
			continue
		}
		switch bd.Name {
		case "source":
			s, err := buildGeoSource(bd, baseDir, openFiles)
			if err != nil {
				return nil, nil, nil, nil, err
			}
			sources = append(sources, s)
		case "region_header":
			if region != nil {
				return nil, nil, nil, nil, compileErr(bd.Pos, "geo: duplicate `region_header`")
			}
			if len(bd.Args) != 1 || bd.Args[0].Raw == "" {
				return nil, nil, nil, nil, compileErr(bd.Pos, "geo: `region_header` needs one header name (e.g. `region_header CF-Region`)")
			}
			region = geo.NewRegionSource(bd.Args[0].Raw)
		case "trust_proxy":
			if len(bd.Args) == 0 {
				return nil, nil, nil, nil, compileErr(bd.Pos, "geo: `trust_proxy` needs at least one CIDR")
			}
			for _, a := range bd.Args {
				p, err := netip.ParsePrefix(a.Raw)
				if err != nil {
					return nil, nil, nil, nil, compileErr(a.Pos, "geo: trust_proxy: bad CIDR "+a.Raw+": "+err.Error())
				}
				trusted = append(trusted, p)
			}
		default:
			return nil, nil, nil, nil, compileErr(bd.Pos, "geo: unknown setting "+bd.Name+" (want `source`, `region_header`, or `trust_proxy`)")
		}
	}
	if len(sources) == 0 {
		return nil, nil, nil, nil, compileErr(block.Pos, "geo: a `source header NAME`, `source cidr FILE`, or `source maxmind FILE` is required")
	}
	if !openFiles {
		// Sandbox / `cadish check`: the block's structure is validated (sources
		// present, kinds/arity/CIDRs/region_header, AND the source-set composition —
		// at most two, pair-only) without opening any file. The source readers were
		// not built, so there is nothing to assemble.
		if err := validateGeoComposition(sources); err != nil {
			return nil, nil, nil, nil, err
		}
		return nil, region, trusted, nil, nil
	}
	src, mmRegion, err := assembleGeoSources(sources)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	var dbs []*geo.MaxMindDB
	for _, s := range sources {
		if s.db != nil {
			dbs = append(dbs, s.db)
		}
	}
	// region precedence: an explicit `region_header` wins; otherwise a maxmind source
	// supplies {geo.region} from its City edition (Unknown on a Country edition). This
	// closes the self-hosted {geo.region} gap without an upstream header (D56).
	if region == nil {
		region = mmRegion
	}
	return src, region, trusted, dbs, nil
}

// geoSourceKind tags a parsed `source` line so assembleGeoSources can enforce the
// narrow fallback rule (exactly {maxmind, header}).
type geoSourceKind int

const (
	geoSrcHeader geoSourceKind = iota
	geoSrcCIDR
	geoSrcMaxMind
)

// geoSourceSpec is one parsed `source` line: its country Source, its kind, and (for a
// maxmind source) the region view over the same reader.
type geoSourceSpec struct {
	country geo.Source
	region  geo.Source     // non-nil only for a maxmind source
	db      *geo.MaxMindDB // non-nil only for a maxmind source (for reload/close lifecycle)
	kind    geoSourceKind
	pos     cadishfile.Pos
}

// validateGeoComposition enforces the source-SET rules that are independent of the
// source files: at most two `source` lines, and a second source is allowed only to
// pair `maxmind` with `header`. It is the PURE structural check shared by both
// `cadish check` (the file-less path) and `cadish run` (via assembleGeoSources), so
// an invalid multi-source block is caught at check time too — not only at startup.
func validateGeoComposition(sources []geoSourceSpec) error {
	switch len(sources) {
	case 0, 1:
		return nil
	case 2:
		a, b := sources[0], sources[1]
		isPair := (a.kind == geoSrcMaxMind && b.kind == geoSrcHeader) ||
			(a.kind == geoSrcHeader && b.kind == geoSrcMaxMind)
		if !isPair {
			return compileErr(b.pos, "geo: a second `source` is allowed only to pair `maxmind` with `header` (a declared-order fallback)")
		}
		return nil
	default:
		return compileErr(sources[2].pos, "geo: at most two `source` lines (a `maxmind`+`header` fallback pair); got more")
	}
}

// assembleGeoSources turns the parsed `source` lines into the site's country source
// (and, for a maxmind source, its region source). A single source is the norm. To
// honour "CDN AND MaxMind", exactly the pair {maxmind, header} is assembled into a
// declared-order fallback chain (first wins; on Unknown it falls through to the
// second). Composition (count + pair-only) is validated up front by
// validateGeoComposition, shared with the check path.
func assembleGeoSources(sources []geoSourceSpec) (country, region geo.Source, err error) {
	if err := validateGeoComposition(sources); err != nil {
		return nil, nil, err
	}
	switch len(sources) {
	case 1:
		return sources[0].country, sources[0].region, nil
	case 2:
		a, b := sources[0], sources[1]
		// composition already validated: sources[0] is primary, sources[1] the fallback.
		country = geo.NewFallbackSource(a.country, b.country)
		// region comes from whichever source is maxmind (the header carries no region).
		if a.kind == geoSrcMaxMind {
			region = a.region
		} else {
			region = b.region
		}
		return country, region, nil
	default:
		// Unreachable: validateGeoComposition rejects >2 sources above.
		return nil, nil, compileErr(sources[0].pos, "geo: too many `source` lines")
	}
}

// buildSiteTrustProxies parses the STANDALONE site-level `trust_proxy <CIDR…>`
// directive(s) — independent of any `geo { … }` block. It populates
// Site.TrustedProxies so a PURE-SECURITY deployment (an `ip` ACL with no geo
// block) can still declare the proxies whose X-Forwarded-For is trusted, and the
// `ip` matcher / {geo} then resolve the REAL client behind a CDN/LB instead of
// silently ACLing the proxy. Returns nil when the site declares none.
//
// Merge semantics (when both forms are present): the standalone directive and the
// `geo { trust_proxy … }` block UNION — both contribute, deduplicated. Union is the
// fail-safe rule for a security control: declaring a proxy trusted can only make
// the resolver walk PAST it to the real client, never the other way round. The
// caller (buildSite) unions this with buildGeo's geo-block prefixes.
func buildSiteTrustProxies(site *cadishfile.Site) ([]netip.Prefix, error) {
	var out []netip.Prefix
	for _, n := range site.Body {
		d, ok := n.(*cadishfile.Directive)
		if !ok || d.Name != "trust_proxy" {
			continue
		}
		if d.HasBlock {
			return nil, compileErr(d.Pos, "trust_proxy is a site-level directive (CIDR list), not a block")
		}
		if len(d.Args) == 0 {
			return nil, compileErr(d.Pos, "trust_proxy needs at least one CIDR (e.g. `trust_proxy 10.0.0.0/8 ::1/128`)")
		}
		for _, a := range d.Args {
			p, err := netip.ParsePrefix(a.Raw)
			if err != nil {
				return nil, compileErr(a.Pos, "trust_proxy: bad CIDR "+a.Raw+": "+err.Error())
			}
			out = append(out, p)
		}
	}
	return out, nil
}

// unionPrefixes returns the de-duplicated union of two prefix sets, preserving the
// order of a followed by the new entries of b. The masked Prefix value is the
// dedup key (netip.Prefix is comparable).
func unionPrefixes(a, b []netip.Prefix) []netip.Prefix {
	if len(a) == 0 {
		return b
	}
	if len(b) == 0 {
		return a
	}
	seen := make(map[netip.Prefix]struct{}, len(a)+len(b))
	out := make([]netip.Prefix, 0, len(a)+len(b))
	for _, p := range append(append([]netip.Prefix(nil), a...), b...) {
		m := p.Masked()
		if _, dup := seen[m]; dup {
			continue
		}
		seen[m] = struct{}{}
		out = append(out, p)
	}
	return out
}

// buildGeoSource parses `source header NAME`, `source cidr FILE`, or
// `source maxmind FILE`. A maxmind source memory-maps the operator-supplied `.mmdb`
// (cadish bundles none, D11/D56) and FAILS FAST on a missing/corrupt DB; the opened
// reader is registered on the config so it is reloaded on SIGHUP and closed on
// shutdown.
// openFiles distinguishes the run/CLI-check path (true: open the cidr/maxmind file
// so a missing/corrupt DB fails fast, matching run) from the sandboxed admin-
// playground path (false: validate the source's STRUCTURE — arity, kind, header
// name, path non-empty — without touching the filesystem, so the endpoint can't be
// turned into a host-file read primitive). A header source is pure either way.
func buildGeoSource(bd *cadishfile.Directive, baseDir string, openFiles bool) (geoSourceSpec, error) {
	spec := geoSourceSpec{pos: bd.Pos}
	if len(bd.Args) < 2 {
		return spec, compileErr(bd.Pos, "geo: `source` needs `header NAME`, `cidr FILE`, or `maxmind FILE`")
	}
	switch bd.Args[0].Raw {
	case "header":
		name := bd.Args[1].Raw
		if name == "" {
			return spec, compileErr(bd.Args[1].Pos, "geo: source header needs a header name")
		}
		spec.kind = geoSrcHeader
		spec.country = geo.NewHeaderSource(name)
		return spec, nil
	case "cidr":
		path := bd.Args[1].Raw
		if path == "" {
			return spec, compileErr(bd.Args[1].Pos, "geo: source cidr needs a file path")
		}
		spec.kind = geoSrcCIDR
		if !openFiles {
			return spec, nil // structure-only (sandbox): do not read the file
		}
		if !filepath.IsAbs(path) {
			path = filepath.Join(baseDir, path)
		}
		f, err := os.Open(path)
		if err != nil {
			return spec, compileErr(bd.Args[1].Pos, "geo: source cidr: "+err.Error())
		}
		defer f.Close()
		entries, err := geo.LoadCIDRTable(f)
		if err != nil {
			return spec, compileErr(bd.Args[1].Pos, err.Error())
		}
		if len(entries) == 0 {
			return spec, compileErr(bd.Args[1].Pos, "geo: source cidr file "+bd.Args[1].Raw+" has no entries")
		}
		spec.country = geo.NewCIDRSource(entries)
		return spec, nil
	case "maxmind":
		path := bd.Args[1].Raw
		if path == "" {
			return spec, compileErr(bd.Args[1].Pos, "geo: source maxmind needs a .mmdb path")
		}
		spec.kind = geoSrcMaxMind
		if !openFiles {
			return spec, nil // structure-only (sandbox): do not memory-map the DB
		}
		if !filepath.IsAbs(path) {
			path = filepath.Join(baseDir, path)
		}
		db, err := geo.OpenMaxMind(path)
		if err != nil {
			return spec, compileErr(bd.Args[1].Pos, err.Error())
		}
		spec.country = geo.NewMaxMindCountrySource(db)
		spec.region = geo.NewMaxMindRegionSource(db)
		spec.db = db
		return spec, nil
	default:
		return spec, compileErr(bd.Args[0].Pos, "geo: source must be `header NAME`, `cidr FILE`, or `maxmind FILE`, got "+bd.Args[0].Raw)
	}
}
