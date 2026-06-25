package cluster

import (
	"net/http"
	"strconv"
	"testing"

	"github.com/cadi-sh/cadish/internal/cadishfile"
	"github.com/cadi-sh/cadish/internal/lb"
)

func pos(i int) cadishfile.Pos { return cadishfile.Pos{File: "test", Line: i + 1} }

func itoa(i int) string { return strconv.Itoa(i) }

func staticCfg(t *testing.T, self string, mode Mode, fb Fallback, peers ...string) Config {
	t.Helper()
	cfg := Config{Self: self, Region: "gra", Mode: mode, Fallback: fb}
	for i, p := range peers {
		tg, err := lb.ParseTarget(p, pos(i))
		if err != nil {
			t.Fatalf("target: %v", err)
		}
		cfg.Peers = append(cfg.Peers, tg)
	}
	// Normalize self through the same parser the validator uses.
	st, _ := lb.ParseTarget(self, pos(0))
	cfg.Self = st.Raw
	return cfg
}

func TestMembership_OwnerVsSelf(t *testing.T) {
	a := "http://10.0.0.1:6081"
	b := "http://10.0.0.2:6081"
	c := "http://10.0.0.3:6081"
	m, err := New(staticCfg(t, a, ModeOwner, FallbackDegraded, a, b, c))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer m.Close()

	// Every key must have exactly one owner, and ownership is deterministic.
	owner1, ok := m.Owner("/videos/clip.mp4")
	if !ok {
		t.Fatal("no owner for key")
	}
	owner2, _ := m.Owner("/videos/clip.mp4")
	if owner1 != owner2 {
		t.Errorf("non-deterministic owner: %q vs %q", owner1, owner2)
	}
	if owner1 != a && owner1 != b && owner1 != c {
		t.Errorf("owner %q not a configured peer", owner1)
	}

	// IsSelf agrees with Owner for our own URL.
	if m.IsSelf(a) != true {
		t.Errorf("IsSelf(self) = false")
	}
	if m.IsSelf(b) {
		t.Errorf("IsSelf(peer) = true")
	}

	// Across many keys, ownership is distributed (not all on one node) — a sanity
	// check on the ring, not an exact split.
	counts := map[string]int{}
	for i := 0; i < 300; i++ {
		o, _ := m.Owner(string(rune('a'+i%26)) + "/" + itoa(i))
		counts[o]++
	}
	if len(counts) < 2 {
		t.Errorf("ownership not distributed across peers: %v", counts)
	}
}

func TestMembership_ModeReadThrough(t *testing.T) {
	a := "http://10.0.0.1:6081"
	b := "http://10.0.0.2:6081"
	m, err := New(staticCfg(t, a, ModeReadThrough, FallbackDegraded, a, b))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer m.Close()
	if m.Mode() != ModeReadThrough {
		t.Errorf("mode = %v", m.Mode())
	}
	// Read-through always provides a peer origin (composed before the real origin).
	if m.PeerOrigin() == nil {
		t.Fatal("PeerOrigin is nil")
	}
}

func TestMembership_HopGuard(t *testing.T) {
	a := "http://10.0.0.1:6081"
	m, err := New(staticCfg(t, a, ModeOwner, FallbackStrict, a))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer m.Close()

	// A request stamped for our region is a forwarded hop: do not re-forward.
	h := http.Header{HopHeader: {"gra"}}
	if !m.IsForwardedHop(h) {
		t.Error("same-region hop not detected")
	}
	// A request stamped for a different region is foreign; treat as a fresh client
	// request (a different cluster). Our region is "gra".
	h2 := http.Header{HopHeader: {"other"}}
	if m.IsForwardedHop(h2) {
		t.Error("foreign-region hop wrongly treated as our forwarded hop")
	}
	// No header at all: a fresh client request.
	if m.IsForwardedHop(http.Header{}) {
		t.Error("unstamped request treated as a hop")
	}
}

func TestMembership_Fallback(t *testing.T) {
	a := "http://10.0.0.1:6081"
	b := "http://10.0.0.2:6081"
	strict, _ := New(staticCfg(t, a, ModeOwner, FallbackStrict, a, b))
	defer strict.Close()
	if strict.Fallback() != FallbackStrict {
		t.Errorf("fallback = %v", strict.Fallback())
	}
	deg, _ := New(staticCfg(t, a, ModeOwner, FallbackDegraded, a, b))
	defer deg.Close()
	if deg.Fallback() != FallbackDegraded {
		t.Errorf("fallback = %v", deg.Fallback())
	}
}
