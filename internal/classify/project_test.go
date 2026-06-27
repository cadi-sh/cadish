package classify

import (
	"reflect"
	"testing"
)

// TestIsDefault guards the edge-projection optimization: IsDefault MUST be true
// ONLY for the exact built-in classifier, because when it is true the edge
// projector OMITS the ruleset from the IR and the worker falls back to its own
// built-in default. A false positive here = the edge silently classifies with the
// WRONG (default) ruleset → a cross-variant cache bug at the edge.
func TestIsDefault(t *testing.T) {
	if !Default().IsDefault() {
		t.Errorf("Default() must report IsDefault()=true")
	}
	var nilC *Classifier
	if !nilC.IsDefault() {
		t.Errorf("nil classifier must report IsDefault()=true")
	}

	// Same rules but a non-default fallback class => NOT default.
	if New(DefaultRules(), "mobile").IsDefault() {
		t.Errorf("non-default fallback class must report IsDefault()=false")
	}
	// Default rules + a fold => NOT default.
	if New(DefaultRules(), "desktop", Fold{From: "tablet", Into: "desktop"}).IsDefault() {
		t.Errorf("presence of a fold must report IsDefault()=false")
	}
	// A different ruleset (fewer rules) => NOT default.
	if New([]Rule{{Class: "bot", Substrings: []string{"bot"}}}, "desktop").IsDefault() {
		t.Errorf("a shorter custom ruleset must report IsDefault()=false")
	}

	// SAME rules in a DIFFERENT order => NOT default (rulesEqual is order-sensitive;
	// order is load-bearing for first-match-wins, so a reorder is a real difference).
	reordered := DefaultRules()
	reordered[0], reordered[1] = reordered[1], reordered[0]
	if New(reordered, "desktop").IsDefault() {
		t.Errorf("reordered default rules must report IsDefault()=false (order matters)")
	}

	// Same classes but a different substring => NOT default.
	mutated := DefaultRules()
	mutated[0].Substrings = []string{"bot", "crawler", "spider", "slurp", "facebookexternalhit", "evilbot"}
	if New(mutated, "desktop").IsDefault() {
		t.Errorf("a mutated default substring must report IsDefault()=false")
	}
}

// TestFoldsSortedDeterministic: Folds() returns the remaps sorted by FROM so the
// projected IR is byte-stable run to run (an unstable projection would churn the
// edge bundle / its hash).
func TestFoldsSortedDeterministic(t *testing.T) {
	c := New(DefaultRules(), "desktop",
		Fold{From: "tablet", Into: "desktop"},
		Fold{From: "bot", Into: "desktop"},
		Fold{From: "amp", Into: "mobile"},
	)
	got := c.Folds()
	want := []Fold{
		{From: "amp", Into: "mobile"},
		{From: "bot", Into: "desktop"},
		{From: "tablet", Into: "desktop"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("Folds() = %v, want %v (sorted by FROM)", got, want)
	}

	// A blank-sided fold is dropped at New() time and never appears.
	c2 := New(DefaultRules(), "desktop", Fold{From: "", Into: "x"}, Fold{From: "y", Into: ""})
	if got := c2.Folds(); got != nil {
		t.Errorf("blank-sided folds must be dropped, got %v", got)
	}
	// nil classifier => no folds.
	var nilC *Classifier
	if got := nilC.Folds(); got != nil {
		t.Errorf("nil Folds() = %v, want nil", got)
	}
}

// TestRulesProjection: Rules() returns the compiled (lower-cased) rule list for the
// edge projector, and a nil classifier returns the built-in default rules so the
// worker classifies identically.
func TestRulesProjection(t *testing.T) {
	c := New([]Rule{{Class: "bot", Substrings: []string{"CURL", " wget "}, Exclude: []string{"GoodBot"}}}, "desktop")
	rules := c.Rules()
	if len(rules) != 1 {
		t.Fatalf("Rules() len = %d, want 1", len(rules))
	}
	// Substrings/excludes are lower-cased and trimmed at compile time.
	if !reflect.DeepEqual(rules[0].Substrings, []string{"curl", "wget"}) {
		t.Errorf("projected substrings = %v, want [curl wget]", rules[0].Substrings)
	}
	if !reflect.DeepEqual(rules[0].Exclude, []string{"goodbot"}) {
		t.Errorf("projected excludes = %v, want [goodbot]", rules[0].Exclude)
	}

	// Mutating the returned slice must not corrupt the classifier (defensive copy).
	rules[0].Class = "HACKED"
	if c.Rules()[0].Class != "bot" {
		t.Errorf("Rules() returned an aliased slice; mutation leaked into the classifier")
	}

	// nil classifier => the built-in default rules.
	var nilC *Classifier
	if !reflect.DeepEqual(nilC.Rules(), DefaultRules()) {
		t.Errorf("nil Rules() must equal DefaultRules()")
	}
}

// TestDefaultClassAndName: the fallback-class accessors used by the projector.
func TestDefaultClassAndName(t *testing.T) {
	if DefaultClassName() != "desktop" {
		t.Errorf("DefaultClassName() = %q, want desktop", DefaultClassName())
	}
	var nilC *Classifier
	if nilC.DefaultClass() != "desktop" {
		t.Errorf("nil DefaultClass() = %q, want desktop", nilC.DefaultClass())
	}
	if New(nil, "mobile").DefaultClass() != "mobile" {
		t.Errorf("custom DefaultClass not reported")
	}
}
