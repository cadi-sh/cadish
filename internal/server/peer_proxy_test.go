package server

import (
	"net/http"
	"testing"
)

// TestNewPeerClient_NoAmbientProxy verifies the peer reverse-proxy client does NOT
// honour ambient HTTP_PROXY/HTTPS_PROXY (SSRF-adjacent footgun). Mirrors the shared
// outbound-client SSRF posture.
func TestNewPeerClient_NoAmbientProxy(t *testing.T) {
	c := newPeerClient()
	tr, ok := c.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("transport is %T, want *http.Transport", c.Transport)
	}
	if tr.Proxy != nil {
		t.Fatalf("peer client transport honours ambient proxy; want Proxy == nil")
	}
}
