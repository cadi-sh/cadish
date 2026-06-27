package lb

import (
	"net/http"
	"testing"
)

// TestUpstreamClients_NoAmbientProxy verifies the LB dial client and the health
// probe client do NOT honour ambient HTTP_PROXY/HTTPS_PROXY: upstream connections
// are explicit, so an env-configured proxy diverting them is an SSRF-adjacent
// footgun. Mirrors httporigin and the shared redirect SSRF guard.
func TestUpstreamClients_NoAmbientProxy(t *testing.T) {
	t.Run("dial client", func(t *testing.T) {
		c := clientForTimeouts(Timeouts{})
		tr, ok := c.Transport.(*http.Transport)
		if !ok {
			t.Fatalf("transport is %T", c.Transport)
		}
		if tr.Proxy != nil {
			t.Fatalf("LB dial transport honours ambient proxy; want Proxy == nil")
		}
	})
	t.Run("health probe client", func(t *testing.T) {
		c, ok := defaultProbeDoer(Timeouts{}, nil).(*http.Client)
		if !ok {
			t.Skipf("probe doer is not *http.Client")
		}
		tr, ok := c.Transport.(*http.Transport)
		if !ok {
			t.Fatalf("transport is %T", c.Transport)
		}
		if tr.Proxy != nil {
			t.Fatalf("health probe transport honours ambient proxy; want Proxy == nil")
		}
	})
}
