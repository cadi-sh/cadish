package cli

import (
	"testing"

	"github.com/cadi-sh/cadish/internal/ingress"
)

// fakeStatsSource is a stand-in for *ingress.Controller's Stats() so the adapter's
// mapping is testable without spinning up a real controller + clientset.
type fakeStatsSource struct{ s ingress.Stats }

func (f fakeStatsSource) Stats() ingress.Stats { return f.s }

// TestIngressStatsAdapterMaps proves ingress.Stats → admin.IngressStats is a faithful
// field-for-field copy and reports present=true.
func TestIngressStatsAdapterMaps(t *testing.T) {
	a := ingressStatsAdapter{src: fakeStatsSource{s: ingress.Stats{
		WatchedIngresses: 5,
		LastAppliedHash:  "abcdef0123456789",
		Rejects:          3,
		LastError:        "render failed",
		IsLeader:         true,
	}}}
	got, ok := a.IngressStats()
	if !ok {
		t.Fatal("ok = false, want true")
	}
	if got.WatchedIngresses != 5 || got.LastAppliedHash != "abcdef0123456789" ||
		got.Rejects != 3 || got.LastError != "render failed" || !got.IsLeader {
		t.Errorf("mapped stats = %+v", got)
	}
}

// TestIngressStatsAdapterNilSource proves a nil source reports present=false (defensive;
// the wired path always passes a live controller).
func TestIngressStatsAdapterNilSource(t *testing.T) {
	a := ingressStatsAdapter{}
	if _, ok := a.IngressStats(); ok {
		t.Fatal("ok = true for nil source, want false")
	}
}

// TestIngressUsageOnNoArgs proves flag parsing/dispatch is wired (help exits cleanly).
func TestIngressUsageOnNoArgs(t *testing.T) {
	if code := Ingress([]string{"-h"}); code != 0 && code != 2 {
		t.Fatalf("unexpected exit %d", code)
	}
}

// TestIngressMissingConfig proves a missing base Cadishfile fails fast (exit 1) rather
// than panicking or hanging on a cluster connection.
func TestIngressMissingConfig(t *testing.T) {
	if code := Ingress([]string{"-config", "/no/such/cadishfile-xyz"}); code != 1 {
		t.Fatalf("missing config: exit %d, want 1", code)
	}
}

// TestIngressInvalidLabelSelector proves a malformed -secret-label-selector fails fast
// (exit 2) before any cluster connection — a typo must not silently degrade to watch-all.
func TestIngressInvalidLabelSelector(t *testing.T) {
	if code := Ingress([]string{"-secret-label-selector", "!!bad=="}); code != 2 {
		t.Fatalf("invalid secret selector: exit %d, want 2", code)
	}
	if code := Ingress([]string{"-configmap-label-selector", "a=b=c"}); code != 2 {
		t.Fatalf("invalid configmap selector: exit %d, want 2", code)
	}
}

// TestFirstNonEmpty covers the -watch-label-selector precedence helper.
func TestFirstNonEmpty(t *testing.T) {
	if got := firstNonEmpty("", "  ", "x"); got != "x" {
		t.Fatalf("got %q want x", got)
	}
	if got := firstNonEmpty(" specific ", "shared"); got != "specific" {
		t.Fatalf("per-resource selector should win, got %q", got)
	}
	if got := firstNonEmpty("", ""); got != "" {
		t.Fatalf("got %q want empty", got)
	}
}

func TestSplitCSV(t *testing.T) {
	got := splitCSV(" a, b ,,c ")
	want := []string{"a", "b", "c"}
	if len(got) != len(want) {
		t.Fatalf("got %v want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got %v want %v", got, want)
		}
	}
}
