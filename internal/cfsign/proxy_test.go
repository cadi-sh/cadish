package cfsign

import (
	"net/http"
	"testing"
)

// TestPooledHTTPClient_NoAmbientProxy verifies the CloudFront-signing origin client
// does NOT honour ambient HTTP_PROXY/HTTPS_PROXY (SSRF-adjacent footgun). Mirrors
// httporigin.
func TestPooledHTTPClient_NoAmbientProxy(t *testing.T) {
	c := pooledHTTPClient()
	tr, ok := c.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("transport is %T, want *http.Transport", c.Transport)
	}
	if tr.Proxy != nil {
		t.Fatalf("cfsign origin transport honours ambient proxy; want Proxy == nil")
	}
}
