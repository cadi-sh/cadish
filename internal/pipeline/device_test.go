package pipeline

import (
	"strings"
	"testing"
)

// TestCacheKeyDeviceToken: the {device} key token renders Request.Device, so two
// requests with different device classes get different cache keys.
func TestCacheKeyDeviceToken(t *testing.T) {
	p := compileSrc(t, "example.com {\n cache_key host path {device}\n}")
	if !p.UsesDeviceToken() {
		t.Fatal("UsesDeviceToken() = false, want true")
	}
	mobile := p.EvalRequest(&Request{Host: "h", Path: "/x", Device: "mobile"}).CacheKey
	desktop := p.EvalRequest(&Request{Host: "h", Path: "/x", Device: "desktop"}).CacheKey
	if mobile == desktop {
		t.Fatalf("{device} did not vary the key: both = %q", mobile)
	}
	if !strings.Contains(mobile, "mobile") {
		t.Errorf("mobile key %q does not contain the device class", mobile)
	}
	// Empty Device (no classifier ran) renders an empty token, not a panic.
	_ = p.EvalRequest(&Request{Host: "h", Path: "/x"}).CacheKey
}

// TestUsesDeviceTokenFalse: a key without {device} reports false (so the server
// skips the UA-classification pre-pass).
func TestUsesDeviceTokenFalse(t *testing.T) {
	p := compileSrc(t, "example.com {\n cache_key host path\n}")
	if p.UsesDeviceToken() {
		t.Error("UsesDeviceToken() = true, want false")
	}
}
