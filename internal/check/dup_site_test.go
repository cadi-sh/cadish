package check

import "testing"

// TestDuplicateSiteAddressWarns: two site blocks with the same address load with
// sites=2, but the second is unreachable (first-match site selection). check must
// warn that the address is duplicated and the later block is shadowed.
func TestDuplicateSiteAddressWarns(t *testing.T) {
	src := "" +
		"example.com {\n  upstream web { to http://127.0.0.1:8080 }\n}\n" +
		"example.com {\n  upstream web { to http://127.0.0.1:9090 }\n}\n"
	rep, err := CheckSource("c.cadish", []byte(src))
	if err != nil {
		t.Fatalf("CheckSource: %v", err)
	}
	found := false
	for _, d := range rep.Diagnostics {
		if d.Code == "duplicate-site" {
			found = true
			if d.Severity != SevWarning {
				t.Errorf("duplicate-site severity = %s, want warning", d.Severity)
			}
		}
	}
	if !found {
		t.Errorf("expected a duplicate-site warning; report diagnostics: %+v", rep.Diagnostics)
	}
}

// TestDistinctSiteAddressesNoWarn: two sites with different addresses must NOT warn.
func TestDistinctSiteAddressesNoWarn(t *testing.T) {
	src := "" +
		"a.example.com {\n  upstream web { to http://127.0.0.1:8080 }\n}\n" +
		"b.example.com {\n  upstream web { to http://127.0.0.1:9090 }\n}\n"
	rep, err := CheckSource("c.cadish", []byte(src))
	if err != nil {
		t.Fatalf("CheckSource: %v", err)
	}
	for _, d := range rep.Diagnostics {
		if d.Code == "duplicate-site" {
			t.Errorf("unexpected duplicate-site warning for distinct addresses: %+v", d)
		}
	}
}
