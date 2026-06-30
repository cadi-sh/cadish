package pipeline

import (
	"net/http"
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

// TestUsesDeviceClassificationHeaderUnkeyed (F-D1): a {device} token reflected in a
// header value but ABSENT from the cache key must still trigger classification —
// UsesDeviceClassification() reports true (so the server pre-pass runs and the edge
// projector ships the classifier), even though UsesDeviceToken() (cache-key only) is
// false. Otherwise `header X-Device {device}` silently renders empty.
func TestUsesDeviceClassificationHeaderUnkeyed(t *testing.T) {
	src := "dev.example.com {\n device_detect {\n  mobile ua_contains iPhone\n  default desktop\n }\n cache_key host path\n header X-Device-Class {device}\n}"
	p := compileSrc(t, src)
	if p.UsesDeviceToken() {
		t.Error("UsesDeviceToken() = true, want false (device is not in the cache key)")
	}
	if !p.UsesDeviceClassification() {
		t.Fatal("UsesDeviceClassification() = false, want true (device reflected in a header)")
	}
	if _, ok := p.EdgeDeviceClassifier(); !ok {
		t.Error("EdgeDeviceClassifier() ok = false, want true (classifier must ship to the edge for header reflection)")
	}
}

// TestUsesDeviceClassificationRequestHeaderUnkeyedIsSafe (F-A1): a {device} reflected in
// a REQUEST-phase header (BEFORE cache_key, forwarded to origin) but NOT keyed must NOT
// trigger classification — resolving + forwarding it to origin while unkeyed is a
// cross-device cache leak. The gate stays false so the token renders empty (fail-safe);
// `cadish check` warns separately. A response-phase header (after cache_key) is safe and
// still resolves.
func TestUsesDeviceClassificationRequestHeaderUnkeyedIsSafe(t *testing.T) {
	// header BEFORE cache_key => request-phase => forwarded to origin => must stay false.
	reqPhase := "dev.example.com {\n device_detect {\n  mobile ua_contains iPhone\n  default desktop\n }\n header X-Device {device}\n cache_key host path\n}"
	if p := compileSrc(t, reqPhase); p.UsesDeviceClassification() {
		t.Error("UsesDeviceClassification() = true for an unkeyed REQUEST-phase {device} header; must be false (fail-safe: render empty, not forward an unkeyed class to origin)")
	}
	// Same token AFTER cache_key => response-phase => safe to resolve.
	respPhase := "dev.example.com {\n device_detect {\n  mobile ua_contains iPhone\n  default desktop\n }\n cache_key host path\n header X-Device {device}\n}"
	if p := compileSrc(t, respPhase); !p.UsesDeviceClassification() {
		t.Error("UsesDeviceClassification() = false for a response-phase {device} header; must be true (safe to resolve at delivery)")
	}
	// Request-phase BUT keyed => resolves via UsesDeviceToken (forwarding is safe when keyed).
	keyed := "dev.example.com {\n device_detect {\n  mobile ua_contains iPhone\n  default desktop\n }\n header X-Device {device}\n cache_key host path {device}\n}"
	if p := compileSrc(t, keyed); !p.UsesDeviceClassification() {
		t.Error("UsesDeviceClassification() = false for a keyed {device}; must be true")
	}
}

// TestUsesDeviceClassificationRedirectUnkeyed (F-D1): a {device} token in a redirect
// target (not in the cache key) is a use too.
func TestUsesDeviceClassificationRedirectUnkeyed(t *testing.T) {
	src := "dev.example.com {\n device_detect {\n  mobile ua_contains iPhone\n  default desktop\n }\n cache_key host path\n redirect ^/d$ 302 /by/{device}\n}"
	p := compileSrc(t, src)
	if !p.UsesDeviceClassification() {
		t.Fatal("UsesDeviceClassification() = false, want true (device reflected in a redirect target)")
	}
}

// TestUsesGeoTokenHeaderUnkeyed (F-D1 geo twin): a {geo} token reflected in a header
// value but absent from the cache key must still set UsesGeoToken() so the server geo
// pre-pass runs and the token does not render empty.
func TestUsesGeoTokenHeaderUnkeyed(t *testing.T) {
	src := "geo.example.com {\n cache_key host path\n header X-Country {geo}\n}"
	p := compileSrc(t, src)
	if !p.UsesGeoToken() {
		t.Fatal("UsesGeoToken() = false, want true ({geo} reflected in a header)")
	}
}

// reqHeaderOpValue returns the value of the named request-phase header op (or "" + false).
func reqHeaderOpValue(ops []HeaderOp, name string) (string, bool) {
	for _, op := range ops {
		if op.Name == name {
			return op.Value, true
		}
	}
	return "", false
}

// TestRequestHeaderUnkeyedClassNeutralized (F-A1 runtime): an unkeyed {device}/{geo*}
// reflected in a REQUEST-phase header (forwarded to origin) must render EMPTY even when
// the classifier/geo pre-pass ran for another reason (a deliver-phase reference, or a
// coarser keyed geo granularity) — otherwise the resolved class is forwarded to origin
// under a class-independent key (cross-class cache leak).
func TestRequestHeaderUnkeyedClassNeutralized(t *testing.T) {
	// device: request-phase header (unkeyed) + a deliver-phase redirect turns the gate on.
	devSrc := "dev.example.com {\n" +
		" device_detect { mobile ua_contains iPhone\n default desktop }\n" +
		" header X-Device {device}\n" + // request-phase (before cache_key)
		" cache_key host path\n" + // NOT keyed on device
		" redirect ^/r$ 302 /d/{device}\n" + // deliver-phase ref → classifier runs
		"}"
	p := compileSrc(t, devSrc)
	dec := p.EvalRequest(&Request{Host: "dev.example.com", Path: "/x", Device: "mobile"})
	if v, ok := reqHeaderOpValue(dec.ReqHeaderOps, "X-Device"); !ok || v != "" {
		t.Errorf("request-phase X-Device = %q (ok=%v), want empty (unkeyed device must not be forwarded)", v, ok)
	}

	// geo: keyed on COUNTRY {geo}, but the request-phase header reflects the finer
	// {geo.region} which is NOT keyed → region must be blanked, country forwarded.
	geoSrc := "geo.example.com {\n" +
		" header X-Region {geo.region}\n" +
		" header X-Country {geo}\n" +
		" cache_key host path {geo}\n" + // keyed on country only
		"}"
	pg := compileSrc(t, geoSrc)
	dg := pg.EvalRequest(&Request{Host: "geo.example.com", Path: "/x", Geo: "US", GeoRegion: "US-CA"})
	if v, _ := reqHeaderOpValue(dg.ReqHeaderOps, "X-Region"); v != "" {
		t.Errorf("request-phase X-Region = %q, want empty (unkeyed {geo.region} must not be forwarded)", v)
	}
	if v, _ := reqHeaderOpValue(dg.ReqHeaderOps, "X-Country"); v != "US" {
		t.Errorf("request-phase X-Country = %q, want US (keyed {geo} is safe to forward)", v)
	}
}

// TestRequestHeaderScopedKeyNeutralized (F-A1/ISO-1): with a scoped cache_key where one
// recipe keys on {device} and the catch-all does not, a request that SELECTS the catch-all
// must NOT forward {device} to origin — the mask is per-SELECTED-recipe, not the union.
func TestRequestHeaderScopedKeyNeutralized(t *testing.T) {
	src := "x.example.com {\n" +
		" @ssr header X-Is-Ssr true\n" +
		" device_detect { mobile ua_contains iPhone\n default desktop }\n" +
		" header X-Device {device}\n" + // request-phase
		" cache_key @ssr host path {device}\n" + // SSR recipe keys on device
		" cache_key default host path\n" + // catch-all does NOT
		"}"
	p := compileSrc(t, src)
	d1 := p.EvalRequest(&Request{Host: "x.example.com", Path: "/p", Device: "mobile"})
	if v, _ := reqHeaderOpValue(d1.ReqHeaderOps, "X-Device"); v != "" {
		t.Errorf("non-SSR X-Device = %q, want empty (selected recipe does not key on device)", v)
	}
	d2 := p.EvalRequest(&Request{Host: "x.example.com", Path: "/p", Device: "mobile",
		Header: http.Header{"X-Is-Ssr": {"true"}}})
	if v, _ := reqHeaderOpValue(d2.ReqHeaderOps, "X-Device"); v != "mobile" {
		t.Errorf("SSR X-Device = %q, want mobile (selected recipe keys on device)", v)
	}
}

// TestRequestHeaderClassifyNeutralized (F-A1/ISO-2): a request-phase {classify.NAME}
// whose classifier buckets on an UNKEYED geo dimension must resolve class-independently
// (the geo matcher sees blanked geo → default bucket), so DE and US forward the SAME value.
func TestRequestHeaderClassifyNeutralized(t *testing.T) {
	src := "x.example.com {\n" +
		" @de geo country DE\n" +
		" classify {tier} {\n  when @de -> eu\n  default -> row\n }\n" +
		" header X-Tier {classify.tier}\n" + // request-phase
		" cache_key host path\n" + // NOT keyed on geo
		"}"
	p := compileSrc(t, src)
	de := p.EvalRequest(&Request{Host: "x.example.com", Path: "/p", Geo: "DE"})
	us := p.EvalRequest(&Request{Host: "x.example.com", Path: "/p", Geo: "US"})
	vDE, _ := reqHeaderOpValue(de.ReqHeaderOps, "X-Tier")
	vUS, _ := reqHeaderOpValue(us.ReqHeaderOps, "X-Tier")
	if vDE != vUS {
		t.Errorf("classify token forwarded a geo-specific value: DE=%q US=%q (must be class-independent)", vDE, vUS)
	}
	if vDE == "eu" {
		t.Errorf("DE X-Tier = %q leaked the geo-specific bucket; want the geo-independent default", vDE)
	}
}

// TestResponseHeaderUnkeyedClassResolves (F-A1): a RESPONSE-phase header reflecting an
// unkeyed class still resolves — it is applied per-request at delivery, never poisoning a
// shared cache entry.
func TestResponseHeaderUnkeyedClassResolves(t *testing.T) {
	src := "dev.example.com {\n" +
		" device_detect { mobile ua_contains iPhone\n default desktop }\n" +
		" cache_key host path\n" +
		" header X-Device {device}\n" + // response-phase (after cache_key)
		"}"
	p := compileSrc(t, src)
	dec := p.EvalDeliver(&Request{Host: "dev.example.com", Path: "/x", Device: "mobile"}, http.Header{}, CacheStatusMiss)
	if v, ok := reqHeaderOpValue(dec.RespHeaderOps, "X-Device"); !ok || v != "mobile" {
		t.Errorf("response-phase X-Device = %q (ok=%v), want mobile (deliver-phase resolves)", v, ok)
	}
}

// TestUsesDeviceClassificationUnusedStillFalse: a device_detect with no {device}
// reference anywhere keeps both predicates false (no needless classification).
func TestUsesDeviceClassificationUnusedStillFalse(t *testing.T) {
	src := "dev.example.com {\n device_detect {\n  mobile ua_contains iPhone\n  default desktop\n }\n cache_key host path\n}"
	p := compileSrc(t, src)
	if p.UsesDeviceClassification() {
		t.Error("UsesDeviceClassification() = true, want false (device referenced nowhere)")
	}
}
