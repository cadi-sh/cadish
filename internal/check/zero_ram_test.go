package check

import "testing"

// TestZeroRAMTierWarns: `cache { ram 0 }` is accepted and the site still serves,
// but the RAM tier holds nothing — a zero-size RAM tier caches nothing. check must
// warn that a zero-size RAM tier caches nothing.
func TestZeroRAMTierWarns(t *testing.T) {
	src := "example.com {\n  upstream web { to http://127.0.0.1:8080 }\n  cache { ram 0 }\n}\n"
	rep, err := CheckSource("c.cadish", []byte(src))
	if err != nil {
		t.Fatalf("CheckSource: %v", err)
	}
	found := false
	for _, d := range rep.Diagnostics {
		if d.Code == "zero-ram-tier" {
			found = true
			if d.Severity != SevWarning {
				t.Errorf("zero-ram-tier severity = %s, want warning", d.Severity)
			}
		}
	}
	if !found {
		t.Errorf("expected a zero-ram-tier warning; report diagnostics: %+v", rep.Diagnostics)
	}
}

// TestNonZeroRAMTierNoWarn: a normal `cache { ram 256MiB }` must NOT warn.
func TestNonZeroRAMTierNoWarn(t *testing.T) {
	src := "example.com {\n  upstream web { to http://127.0.0.1:8080 }\n  cache { ram 256MiB }\n}\n"
	rep, err := CheckSource("c.cadish", []byte(src))
	if err != nil {
		t.Fatalf("CheckSource: %v", err)
	}
	for _, d := range rep.Diagnostics {
		if d.Code == "zero-ram-tier" {
			t.Errorf("unexpected zero-ram-tier warning for a non-zero RAM tier: %+v", d)
		}
	}
}
