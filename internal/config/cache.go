package config

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"strings"

	"github.com/cadi-sh/cadish/internal/cache"
	"github.com/cadi-sh/cadish/internal/cadishfile"
)

// cacheKeyVocabDirectives are the site-level directives that define the cache-KEY
// namespace: the `cache_key` recipe itself plus every block its tokens can
// reference — user normalizers, classifiers, the tenant resolver, the device
// classifier, and the geo source. A change to ANY of them can remap which content
// a given key addresses, so cacheKeyFingerprint folds them all in.
var cacheKeyVocabDirectives = map[string]bool{
	"cache_key":     true,
	"normalize":     true,
	"classify":      true,
	"tenant":        true,
	"device_detect": true,
	"geo":           true,
}

// cacheKeyFingerprint returns a stable hash of the directives that define a site's
// cache-key namespace (cacheKeyVocabDirectives), in source order. Two configs whose
// sites produce the SAME fingerprint compute byte-identical keys for the same
// request, so a warm cache store is safe to carry across a reload between them;
// when the fingerprint DIFFERS the old store's entries are keyed under a different
// recipe and must NOT be reused (see Site.cacheKeyFP / TransplantStoresFrom). It is
// purely structural (directive names + args + nested blocks); positions, comments and
// unrelated directives (header ops, ttl, routing, upstreams) are intentionally
// excluded so an unrelated edit still preserves the warm cache.
func cacheKeyFingerprint(site *cadishfile.Site) string {
	var b strings.Builder
	for _, n := range site.Body {
		d, ok := n.(*cadishfile.Directive)
		if !ok || !cacheKeyVocabDirectives[d.Name] {
			continue
		}
		writeDirectiveFingerprint(&b, d)
	}
	sum := sha256.Sum256([]byte(b.String()))
	return hex.EncodeToString(sum[:])
}

// writeDirectiveFingerprint renders a directive subtree (name, args, nested block)
// into b deterministically, using control bytes as separators so distinct shapes can
// never collide. Recurses into nested blocks (e.g. a `normalize NAME { … }` body).
func writeDirectiveFingerprint(b *strings.Builder, d *cadishfile.Directive) {
	b.WriteByte(0x01)
	b.WriteString(d.Name)
	for _, a := range d.Args {
		b.WriteByte(0x02)
		b.WriteString(a.Raw)
	}
	if d.HasBlock {
		b.WriteByte(0x03)
		for _, n := range d.Block {
			if sub, ok := n.(*cadishfile.Directive); ok {
				writeDirectiveFingerprint(b, sub)
			}
		}
		b.WriteByte(0x04)
	}
}

// buildStore constructs the site's two-tier cache.Store from its `cache { … }`
// block. Recognized sub-directives:
//
//	ram SIZE              total RAM-tier budget
//	disk PATH SIZE        NVMe-tier directory + budget
//	tier EXT… -> ram|disk per-extension placement hint (parsed + validated; see note)
//
// A site with no `cache` block (or no `disk`) still gets a working store: the disk
// tier always needs a directory, so a scratch temp dir is created and tracked for
// removal on Close, and a zero disk budget simply means large objects stream
// through uncached.
//
// `tier .ext… -> ram|disk` directives ARE wired into placement: each extension's
// target is collected into tierExt below and handed to the store as
// cache.RouterConfig.TierExtensions, which Store.tierFor honors as a per-extension
// default (a per-request `storage <sel> -> ram|disk` pipeline rule, carried on
// ObjectMeta.Tier, still wins over it). The built-in size policy (always-RAM
// extensions + a small-object threshold; see internal/cache) is the fallback when
// neither override matches.
func (c *Config) buildStore(site *cadishfile.Site) (*cache.Store, error) {
	ramBytes, diskBytes, diskDir, tierExt, err := parseCacheBlock(site)
	if err != nil {
		return nil, err
	}

	// The disk tier always needs a directory. When none was configured, create a
	// scratch dir (tracked for Close) so a RAM-only config still works; a zero disk
	// budget makes the disk tier refuse writes (objects stream through uncached).
	if diskDir == "" {
		tmp, err := os.MkdirTemp("", "cadish-cache-")
		if err != nil {
			return nil, err
		}
		c.tempDirs = append(c.tempDirs, tmp)
		diskDir = tmp
	}

	rc := cache.DefaultRouterConfig(diskDir)
	rc.RAMMaxBytes = ramBytes
	rc.DiskMaxBytes = diskBytes
	if len(tierExt) > 0 {
		rc.TierExtensions = tierExt
	}
	return cache.NewStore(rc)
}

// parseCacheBlock parses and validates a site's `cache { … }` block WITHOUT any
// I/O (no temp dir, no store open). It returns the parsed RAM/disk budgets, the
// configured disk directory (empty when none), and the per-extension tier hints,
// surfacing the FIRST structural problem as a positioned error. buildStore uses it
// to construct the real store; `cadish check` uses it as the side-effect-free
// pre-flight, so a malformed cache block (e.g. `ram` with no size, `disk` missing
// path/size, a bad `tier` arrow, an unknown sub-directive) fails check exactly as
// it fails run. RAM defaults to the same budget buildStore uses when `cache` is
// omitted, so callers that only need validation can ignore the returned values.
func parseCacheBlock(site *cadishfile.Site) (ramBytes, diskBytes int64, diskDir string, tierExt map[string]string, err error) {
	ramBytes = 2 << 30 // sensible default RAM budget when `cache` is omitted
	tierExt = map[string]string{}

	for _, n := range site.Body {
		d, ok := n.(*cadishfile.Directive)
		if !ok || d.Name != "cache" {
			continue
		}
		for _, bn := range d.Block {
			bd, ok := bn.(*cadishfile.Directive)
			if !ok {
				continue
			}
			switch bd.Name {
			case "ram":
				if len(bd.Args) < 1 {
					return 0, 0, "", nil, compileErr(bd.Pos, "cache: `ram` needs a size")
				}
				v, perr := ParseSize(bd.Args[0].Raw)
				if perr != nil {
					return 0, 0, "", nil, compileErr(bd.Args[0].Pos, "cache: ram: "+perr.Error())
				}
				ramBytes = v
			case "disk":
				if len(bd.Args) < 2 {
					return 0, 0, "", nil, compileErr(bd.Pos, "cache: `disk` needs a path and a size")
				}
				diskDir = bd.Args[0].Raw
				v, perr := ParseSize(bd.Args[1].Raw)
				if perr != nil {
					return 0, 0, "", nil, compileErr(bd.Args[1].Pos, "cache: disk: "+perr.Error())
				}
				diskBytes = v
			case "tier":
				if terr := validateTier(bd); terr != nil {
					return 0, 0, "", nil, terr
				}
				// `tier .ext… -> ram|disk`: record each extension's placement.
				tgt := bd.Args[len(bd.Args)-1].Raw
				for _, a := range bd.Args[:len(bd.Args)-2] { // args before the "->" target
					tierExt[normalizeExt(a.Raw)] = tgt
				}
			default:
				return 0, 0, "", nil, compileErr(bd.Pos, "cache: unknown directive "+quoteName(bd.Name))
			}
		}
	}
	return ramBytes, diskBytes, diskDir, tierExt, nil
}

// normalizeExt lower-cases an extension token and ensures a single leading dot, so
// `tier .MP4 -> disk` and `tier mp4 -> disk` both key on ".mp4".
func normalizeExt(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	if s == "" {
		return s
	}
	if s[0] != '.' {
		s = "." + s
	}
	return s
}

// validateTier checks a `tier EXT… -> ram|disk` directive's shape: one or more
// extension tokens, an arrow, and a ram|disk target.
func validateTier(d *cadishfile.Directive) error {
	arrow := -1
	for i, a := range d.Args {
		if a.Raw == "->" {
			arrow = i
			break
		}
	}
	if arrow < 1 || arrow != len(d.Args)-2 {
		return compileErr(d.Pos, "cache: tier syntax is `tier EXT… -> ram|disk`")
	}
	switch d.Args[arrow+1].Raw {
	case "ram", "disk":
	default:
		return compileErr(d.Args[arrow+1].Pos, "cache: tier target must be `ram` or `disk`")
	}
	return nil
}
