package check

import "testing"

// Finding 8: `resolve` only governs dynamically re-resolved targets (dns:// / k8s://).
// On a pool whose every `to` is a static http(s):// address it is a silent no-op, so
// `cadish check` warns (resolve-no-effect) to surface the misconfiguration.
func TestResolveNoEffectOnStaticPoolWarns(t *testing.T) {
	src := []byte("example.com {\n" +
		"  upstream blog {\n" +
		"    to https://1.2.3.4:443\n" +
		"    resolve 10s\n" +
		"  }\n" +
		"  cache_ttl default ttl 1m\n" +
		"}\n")
	r, err := CheckSource("Cadishfile", src)
	if err != nil {
		t.Fatalf("CheckSource: %v", err)
	}
	if n := codes(r)["resolve-no-effect"]; n != 1 {
		t.Fatalf("got %d resolve-no-effect diagnostics, want 1", n)
	}
}

// A `resolve` on a pool WITH a dns:// target is meaningful — no warning.
func TestResolveOnDynamicPoolNoWarn(t *testing.T) {
	src := []byte("example.com {\n" +
		"  upstream blog {\n" +
		"    to dns://backend.svc:8080\n" +
		"    resolve 10s nameserver 10.0.0.1:53\n" +
		"  }\n" +
		"  cache_ttl default ttl 1m\n" +
		"}\n")
	r, err := CheckSource("Cadishfile", src)
	if err != nil {
		t.Fatalf("CheckSource: %v", err)
	}
	if n := codes(r)["resolve-no-effect"]; n != 0 {
		t.Fatalf("got %d resolve-no-effect diagnostics, want 0", n)
	}
}
