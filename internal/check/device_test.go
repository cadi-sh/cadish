package check

import "testing"

// TestDeviceDetectRecognized: `device_detect` is a known SETUP directive (no
// unknown-directive warning), and a cache_key using {device} draws the
// bounded-normalizer note.
func TestDeviceDetectRecognized(t *testing.T) {
	src := []byte(`example.com {
    device_detect {
        mobile  ua_contains Mobile Android
        default desktop
    }
    cache_key host path {device}
}`)
	r, err := CheckSource("device.cadish", src)
	if err != nil {
		t.Fatalf("CheckSource: %v", err)
	}
	if n := codes(r)["unknown-directive"]; n != 0 {
		t.Errorf("device_detect should be a known directive, got %d unknown-directive warnings", n)
	}
	s := firstSite(t, r)
	if s.PhaseCounts[PhaseSetup] < 1 {
		t.Errorf("PhaseCounts[SETUP] = %d, want >=1 (device_detect)", s.PhaseCounts[PhaseSetup])
	}
	if !hasSuggestion(s, "varies on a bounded device class") {
		t.Errorf("expected a bounded-normalizer note for {device}; got %v", s.Suggestions)
	}
}
