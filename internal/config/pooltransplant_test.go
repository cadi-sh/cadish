package config

import (
	"fmt"
	"testing"

	"github.com/cadi-sh/cadish/internal/lb"
)

// poolByName finds the lb pool with the given name in a config, or nil.
func poolByName(c *Config, name string) *lb.Upstream {
	for _, p := range c.Pools() {
		if p.Name() == name {
			return p
		}
	}
	return nil
}

// loadStr is a test helper that loads a Cadishfile from a string or fails.
func loadStr(t *testing.T, name, src string) *Config {
	t.Helper()
	c, err := LoadString(name, src)
	if err != nil {
		t.Fatalf("load %s: %v", name, err)
	}
	return c
}

// Two upstreams, each multi-backend so they build real lb pools (not the trivial
// single-origin fast path). poolA is the default (first declared).
const twoPoolSite = `site.local {
	upstream poolA { to http://a1:80
		to http://a2:80 }
	upstream poolB { to %s
		to http://b2:80 }
}
`

// TestTransplantPoolsFrom_KeepsUnchanged proves an identical reload transplants BOTH
// pools by instance identity (same *lb.Upstream pointer) into the new config, and
// repoints the new config's origin graph (Origins map + default Origin) at the
// survivors — so nothing cold is left behind.
func TestTransplantPoolsFrom_KeepsUnchanged(t *testing.T) {
	old := loadStr(t, "<old>", fmt.Sprintf(twoPoolSite, "http://b1:80"))
	t.Cleanup(func() { _ = old.Close() })
	next := loadStr(t, "<next>", fmt.Sprintf(twoPoolSite, "http://b1:80"))
	t.Cleanup(func() { _ = next.Close() })

	oldA, oldB := poolByName(old, "poolA"), poolByName(old, "poolB")
	coldA, coldB := poolByName(next, "poolA"), poolByName(next, "poolB")
	if oldA == nil || oldB == nil || coldA == nil || coldB == nil {
		t.Fatal("expected poolA and poolB in both configs")
	}
	if coldA == oldA || coldB == oldB {
		t.Fatal("freshly loaded pools must be distinct instances before transplant")
	}

	next.TransplantPoolsFrom(old)

	if got := poolByName(next, "poolA"); got != oldA {
		t.Errorf("poolA not transplanted: got %p want %p (old)", got, oldA)
	}
	if got := poolByName(next, "poolB"); got != oldB {
		t.Errorf("poolB not transplanted: got %p want %p (old)", got, oldB)
	}
	// Origin graph repointed: the site's default Origin (poolA) and the Origins map
	// entries must be the SURVIVOR instances, not the cold ones.
	site := next.Sites[0]
	if site.Origins["poolA"] != oldA {
		t.Error("Origins[poolA] not repointed to survivor")
	}
	if site.Origins["poolB"] != oldB {
		t.Error("Origins[poolB] not repointed to survivor")
	}
	if site.Origin != oldA {
		t.Error("default Origin not repointed to survivor poolA")
	}
}

// TestTransplantPoolsFrom_RebuildsChanged proves a reload that changes ONE pool's
// backend set rebuilds only that pool (a fresh instance, different fingerprint) while
// the sibling survives by instance identity.
func TestTransplantPoolsFrom_RebuildsChanged(t *testing.T) {
	old := loadStr(t, "<old>", fmt.Sprintf(twoPoolSite, "http://b1:80"))
	t.Cleanup(func() { _ = old.Close() })
	// poolB's first backend changes; poolA is untouched.
	next := loadStr(t, "<next>", fmt.Sprintf(twoPoolSite, "http://CHANGED:80"))
	t.Cleanup(func() { _ = next.Close() })

	oldA, oldB := poolByName(old, "poolA"), poolByName(old, "poolB")
	coldB := poolByName(next, "poolB")

	next.TransplantPoolsFrom(old)

	if got := poolByName(next, "poolA"); got != oldA {
		t.Errorf("unchanged poolA must be transplanted; got %p want %p", got, oldA)
	}
	if got := poolByName(next, "poolB"); got != coldB {
		t.Errorf("changed poolB must keep its NEW instance; got %p want %p (cold)", got, coldB)
	}
	if got := poolByName(next, "poolB"); got == oldB {
		t.Error("changed poolB must NOT reuse the old instance")
	}
	if next.Sites[0].Origins["poolB"] != coldB {
		t.Error("Origins[poolB] must point at the rebuilt cold instance")
	}
}

// TestTransplantPoolsFrom_AddRemove proves an added pool stays cold (for the server
// to Start) and a removed pool simply does not appear in the new config's pools (the
// server cancels its context after the swap).
func TestTransplantPoolsFrom_AddRemove(t *testing.T) {
	old := loadStr(t, "<old>", fmt.Sprintf(twoPoolSite, "http://b1:80"))
	t.Cleanup(func() { _ = old.Close() })
	// next drops poolB and adds poolC.
	const addRemove = `site.local {
	upstream poolA { to http://a1:80
		to http://a2:80 }
	upstream poolC { to http://c1:80
		to http://c2:80 }
}
`
	next := loadStr(t, "<next>", addRemove)
	t.Cleanup(func() { _ = next.Close() })

	oldA := poolByName(old, "poolA")
	coldC := poolByName(next, "poolC")

	next.TransplantPoolsFrom(old)

	if got := poolByName(next, "poolA"); got != oldA {
		t.Errorf("survivor poolA must be transplanted; got %p want %p", got, oldA)
	}
	if got := poolByName(next, "poolC"); got != coldC {
		t.Error("added poolC must keep its cold instance for the server to Start")
	}
	if poolByName(next, "poolB") != nil {
		t.Error("removed poolB must not be present in the new config's pools")
	}
}
