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
