package check

import "testing"

// `resp_header` is a known matcher type (no unknown-matcher-type warning) and is
// classified for the cost report (exact for a literal value, glob for a `*` value).
func TestRespHeaderMatcherRecognized(t *testing.T) {
	src := []byte(`example.com {
    cache_ttl resp_header X-Powered-By Express ttl 1m grace 2w
    cache_ttl default ttl 5s
    storage default -> ram
}`)
	r, err := CheckSource("resp_header.cadish", src)
	if err != nil {
		t.Fatalf("CheckSource: %v", err)
	}
	if n := codes(r)["unknown-matcher-type"]; n != 0 {
		t.Errorf("resp_header should be a known matcher type, got %d unknown-matcher-type", n)
	}
	if n := codes(r)["compile-error"]; n != 0 {
		t.Errorf("a valid resp_header cache_ttl must not be a compile error, got %d", n)
	}
}

// A request-phase use of `resp_header` (scoping a RECV directive) is a check ERROR:
// the origin response is not yet known in RECV. Mirrors the status/content_type/
// set_cookie phase guard.
func TestRespHeaderRequestPhaseIsCheckError(t *testing.T) {
	src := []byte(`example.com {
    @ssr resp_header X-Powered-By Express
    pass @ssr
}`)
	r, err := CheckSource("resp_header_phase.cadish", src)
	if err != nil {
		t.Fatalf("CheckSource: %v", err)
	}
	if n := codes(r)["compile-error"]; n == 0 {
		t.Errorf("a request-phase use of resp_header must be a check error (compile-error), got none")
	}
}
