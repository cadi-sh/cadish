package pipeline

import (
	"strings"
	"testing"
)

// TestClientCacheControlAbsentHonors: without the directive, the site honors
// client-forced revalidation (the RFC 9111 §5.2.1.4 default).
func TestClientCacheControlAbsentHonors(t *testing.T) {
	p := compileSrc(t, `example.com {
		cache_key path
		cache_ttl default ttl 5m
	}`)
	if p.IgnoreClientRevalidation() {
		t.Error("absent client_cache_control => IgnoreClientRevalidation()=true, want false (honor)")
	}
}

// TestClientCacheControlIgnoreParses: `client_cache_control ignore` compiles to
// the per-site opt-out flag (SETUP-phase parse-once toggle).
func TestClientCacheControlIgnoreParses(t *testing.T) {
	p := compileSrc(t, `example.com {
		client_cache_control ignore
		cache_key path
		cache_ttl default ttl 5m
	}`)
	if !p.IgnoreClientRevalidation() {
		t.Error("`client_cache_control ignore` => IgnoreClientRevalidation()=false, want true")
	}
}

// TestClientCacheControlRejectsBadValue: any value other than `ignore` (or a
// missing value) is a clear compile error.
func TestClientCacheControlRejectsBadValue(t *testing.T) {
	for _, src := range []string{
		"example.com {\n  client_cache_control\n}",          // no value
		"example.com {\n  client_cache_control honor\n}",    // unsupported value
		"example.com {\n  client_cache_control ignore x\n}", // too many values
	} {
		ce := compileErr(t, src)
		if !strings.Contains(ce.Msg, "client_cache_control") {
			t.Errorf("error should mention client_cache_control; got %q (src=%q)", ce.Msg, src)
		}
	}
}
