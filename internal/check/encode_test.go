package check

import "testing"

// TestEncodeIsDeliverPhase verifies `cadish check` recognizes `encode` as a known
// directive in the DELIVER phase (so it is not flagged unknown and is counted in
// the right phase bucket).
func TestEncodeIsDeliverPhase(t *testing.T) {
	if got := phaseOf("encode"); got != PhaseDELIVER {
		t.Fatalf("phaseOf(encode) = %s, want DELIVER", got)
	}
	src := []byte(`example.com {
		upstream b { to http://x:80 }
		encode zstd br gzip
		cache_ttl default ttl 5m
	}`)
	r, err := CheckSource("enc.cadish", src)
	if err != nil {
		t.Fatalf("CheckSource: %v", err)
	}
	if n := codes(r)["unknown-directive"]; n != 0 {
		t.Fatalf("encode flagged as unknown-directive (%d)\n%s", n, render(t, r))
	}
	s := firstSite(t, r)
	if got := s.PhaseCounts[PhaseDELIVER]; got < 1 {
		t.Errorf("PhaseCounts[DELIVER] = %d, want >=1 (encode)", got)
	}
}
