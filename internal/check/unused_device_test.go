package check

import "testing"

// A `device_detect { … }` block whose {device} token is keyed by no cache_key recipe is
// dead config: its only effect is to shape the {device} cache-key token, so an unkeyed
// device_detect means the cache silently does not segment by device class. check must warn.
func TestUnusedDeviceDetectWarns(t *testing.T) {
	src := []byte("example.com {\n" +
		"  upstream app { to http://127.0.0.1:8080 }\n" +
		"  device_detect {\n" +
		"    mobile ua_contains Mobile Android\n" +
		"    default desktop\n" +
		"  }\n" +
		"  cache_key host path\n" +
		"  cache_ttl default ttl 1m\n" +
		"}\n")
	r, err := CheckSource("Cadishfile", src)
	if err != nil {
		t.Fatalf("CheckSource: %v", err)
	}
	if n := codes(r)["unused-device-detect"]; n != 1 {
		t.Fatalf("got %d unused-device-detect diagnostics, want 1; diags=%+v", n, r.Sites[0].Diagnostics)
	}
}

// device_detect whose {device} token IS keyed must NOT warn.
func TestKeyedDeviceDetectNoWarn(t *testing.T) {
	src := []byte("example.com {\n" +
		"  upstream app { to http://127.0.0.1:8080 }\n" +
		"  device_detect {\n" +
		"    mobile ua_contains Mobile Android\n" +
		"    default desktop\n" +
		"  }\n" +
		"  cache_key host path {device}\n" +
		"  cache_ttl default ttl 1m\n" +
		"}\n")
	r, err := CheckSource("Cadishfile", src)
	if err != nil {
		t.Fatalf("CheckSource: %v", err)
	}
	if n := codes(r)["unused-device-detect"]; n != 0 {
		t.Fatalf("got %d unused-device-detect diagnostics, want 0", n)
	}
}

// F-D1: a device_detect whose {device} token is reflected in a HEADER value (but not
// keyed) is a legitimate use — check must NOT misfire the unused-device-detect warning
// and tell the operator to remove the still-referenced block.
func TestDeviceDetectReflectedInHeaderNoWarn(t *testing.T) {
	src := []byte("example.com {\n" +
		"  upstream app { to http://127.0.0.1:8080 }\n" +
		"  device_detect {\n" +
		"    mobile ua_contains Mobile Android\n" +
		"    default desktop\n" +
		"  }\n" +
		"  cache_key host path\n" +
		"  header X-Device-Class {device}\n" +
		"  cache_ttl default ttl 1m\n" +
		"}\n")
	r, err := CheckSource("Cadishfile", src)
	if err != nil {
		t.Fatalf("CheckSource: %v", err)
	}
	if n := codes(r)["unused-device-detect"]; n != 0 {
		t.Fatalf("got %d unused-device-detect diagnostics, want 0 ({device} reflected in a header is a use)", n)
	}
}

// F-A1: a {device} reflected in a REQUEST-phase header (before cache_key, forwarded to
// origin) but NOT keyed must WARN (class-token-forwarded-unkeyed) — it is a cross-device
// cache-leak footgun, rendered empty at runtime.
func TestForwardedDeviceUnkeyedWarns(t *testing.T) {
	src := []byte("example.com {\n" +
		"  upstream app { to http://127.0.0.1:8080 }\n" +
		"  device_detect { mobile ua_contains Mobile; default desktop }\n" +
		"  header X-Device {device}\n" + // before cache_key => request-phase => forwarded
		"  cache_key host path\n" +
		"  cache_ttl default ttl 1m\n" +
		"}\n")
	r, err := CheckSource("Cadishfile", src)
	if err != nil {
		t.Fatalf("CheckSource: %v", err)
	}
	if n := codes(r)["class-token-forwarded-unkeyed"]; n != 1 {
		t.Fatalf("got %d class-token-forwarded-unkeyed, want 1; diags=%+v", n, r.Sites[0].Diagnostics)
	}
}

// F-A1: the same {device} header AFTER cache_key (response-phase, not forwarded) must NOT
// warn — it is applied per-request at delivery, safe to vary an unkeyed object.
func TestResponsePhaseDeviceUnkeyedNoWarn(t *testing.T) {
	src := []byte("example.com {\n" +
		"  upstream app { to http://127.0.0.1:8080 }\n" +
		"  device_detect { mobile ua_contains Mobile; default desktop }\n" +
		"  cache_key host path\n" +
		"  header X-Device {device}\n" + // after cache_key => response-phase
		"  cache_ttl default ttl 1m\n" +
		"}\n")
	r, err := CheckSource("Cadishfile", src)
	if err != nil {
		t.Fatalf("CheckSource: %v", err)
	}
	if n := codes(r)["class-token-forwarded-unkeyed"]; n != 0 {
		t.Fatalf("got %d class-token-forwarded-unkeyed, want 0 (response-phase is safe)", n)
	}
}

// F-A1: a request-phase {device} header that IS keyed must NOT warn (forwarding is safe).
func TestForwardedDeviceKeyedNoWarn(t *testing.T) {
	src := []byte("example.com {\n" +
		"  upstream app { to http://127.0.0.1:8080 }\n" +
		"  device_detect { mobile ua_contains Mobile; default desktop }\n" +
		"  header X-Device {device}\n" +
		"  cache_key host path {device}\n" +
		"  cache_ttl default ttl 1m\n" +
		"}\n")
	r, err := CheckSource("Cadishfile", src)
	if err != nil {
		t.Fatalf("CheckSource: %v", err)
	}
	if n := codes(r)["class-token-forwarded-unkeyed"]; n != 0 {
		t.Fatalf("got %d class-token-forwarded-unkeyed, want 0 (keyed forwarding is safe)", n)
	}
}

// F-E1: a {device} embedded in a respond body (emitted verbatim, never template-expanded)
// must NOT count as a reference — the device_detect is genuinely dead, so the
// unused-device-detect warning MUST still fire.
func TestDeviceInRespondBodyStillUnused(t *testing.T) {
	src := []byte("example.com {\n" +
		"  upstream app { to http://127.0.0.1:8080 }\n" +
		"  device_detect { mobile ua_contains Mobile; default desktop }\n" +
		"  cache_key host path\n" +
		"  respond /x 200 \"class: {device}\"\n" +
		"  cache_ttl default ttl 1m\n" +
		"}\n")
	r, err := CheckSource("Cadishfile", src)
	if err != nil {
		t.Fatalf("CheckSource: %v", err)
	}
	if n := codes(r)["unused-device-detect"]; n != 1 {
		t.Fatalf("got %d unused-device-detect, want 1 (a respond-body {device} does not expand, so device_detect is dead)", n)
	}
}

// F-E2: a {geo} reflected in a header with no geo source must warn (geo-unconfigured),
// mirroring the device check — not only a keyed {geo}.
func TestReflectedGeoUnconfiguredWarns(t *testing.T) {
	src := []byte("example.com {\n" +
		"  upstream app { to http://127.0.0.1:8080 }\n" +
		"  cache_key host path\n" +
		"  header X-Geo {geo}\n" +
		"  cache_ttl default ttl 1m\n" +
		"}\n")
	r, err := CheckSource("Cadishfile", src)
	if err != nil {
		t.Fatalf("CheckSource: %v", err)
	}
	if n := codes(r)["geo-unconfigured"]; n != 1 {
		t.Fatalf("got %d geo-unconfigured, want 1 (reflected {geo} with no geo source)", n)
	}
}

// A site with no device_detect block at all (the built-in {device} default is unused)
// must NOT warn — the warning is only for an explicitly-configured-but-unkeyed block.
func TestNoDeviceDetectNoWarn(t *testing.T) {
	src := []byte("example.com {\n" +
		"  upstream app { to http://127.0.0.1:8080 }\n" +
		"  cache_key host path\n" +
		"  cache_ttl default ttl 1m\n" +
		"}\n")
	r, err := CheckSource("Cadishfile", src)
	if err != nil {
		t.Fatalf("CheckSource: %v", err)
	}
	if n := codes(r)["unused-device-detect"]; n != 0 {
		t.Fatalf("got %d unused-device-detect diagnostics, want 0", n)
	}
}
