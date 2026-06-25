package config

import (
	"os"
	"strings"

	"github.com/cadi-sh/cadish/internal/cache"
	"github.com/cadi-sh/cadish/internal/cadishfile"
)

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
