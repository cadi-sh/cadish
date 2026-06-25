package httporigin

import (
	"net/http"
	"testing"
)

// TestPooledHTTPClient_NoAmbientProxy verifies the origin client does NOT honour
// ambient HTTP_PROXY / HTTPS_PROXY environment variables. Origin fetches are
// explicit upstream connections; silently routing them through an env-configured
// proxy is an SSRF-adjacent footgun (a misconfigured or attacker-influenced proxy
// could divert origin traffic), so Proxy must be nil.
func TestPooledHTTPClient_NoAmbientProxy(t *testing.T) {
	c := pooledHTTPClient()
	tr, ok := c.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("transport is %T, want *http.Transport", c.Transport)
	}
	if tr.Proxy != nil {
		t.Fatalf("origin transport honours ambient HTTP(S)_PROXY; want Proxy == nil")
	}
}
