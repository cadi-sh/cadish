package server

import (
	"io"
	"net"
	"net/http"
	"time"

	"github.com/cadi-sh/cadish/internal/cluster"
)

// clusterRoute is the SINGLE handler seam for cluster ownership routing (#8). It
// is called once per request, only when the site declares a `cluster` membership,
// after the cache key is known and BEFORE the local LOOKUP. It returns true when
// it fully handled the request (reverse-proxied it to the owning peer); false to
// let the normal local lifecycle proceed (we own the key, the request is a
// forwarded hop, the mode is read-through, or fallback says serve locally).
//
// The whole feature is gated by site.Cluster != nil, so a non-clustered cadish
// never reaches here.
//
// Loop/storm safety: a request already forwarded to us by a peer (the
// X-Cadish-Peer hop guard) is NEVER re-routed — it is served locally — so a key
// can hop at most once.
func (h *Handler) clusterRoute(rec *statusRecorder, r *http.Request, site *boundSite, ownerKey string, info *reqInfo) bool {
	m := site.Cluster

	// A request a peer already forwarded to us: serve it locally, do not re-forward.
	// This guard prevents owner-routing loops and read-through storms.
	if m.IsForwardedHop(r.Header) {
		return false
	}
	// Read-through mode does its peer work via the origin chain on a local miss;
	// there is no request re-routing.
	if m.Mode() != cluster.ModeOwner {
		return false
	}

	// Owner routing. If we are the healthy owner, serve locally.
	if owner, ok := m.Owner(ownerKey); ok {
		if m.IsSelf(owner) {
			return false
		}
		return h.proxyToPeer(rec, r, m, owner, info)
	}

	// No healthy owner for this key. Apply the fallback policy.
	switch m.Fallback() {
	case cluster.FallbackStrict:
		// Serve locally (this node's cache → origin); accept a transient duplicate.
		return false
	default: // FallbackDegraded
		// Try the topological owner anyway IF it differs from us — it may answer even
		// while flagged unhealthy (health is sampled, not certain). Otherwise serve
		// locally. We never chain a second proxy hop (the hop guard would stop the
		// peer re-forwarding regardless).
		if owner, ok := m.IntendedOwner(ownerKey); ok && !m.IsSelf(owner) {
			if h.proxyToPeer(rec, r, m, owner, info) {
				return true
			}
		}
		return false
	}
}

// proxyToPeer reverse-proxies r to the owning peer cadish node and streams the
// response back to the client without buffering (the zero-extra-copy contract).
// It stamps the X-Cadish-Peer hop header so the peer serves locally and does not
// re-forward. It returns true when the peer answered (any status, streamed
// through); false on a connection-class failure, so the caller serves locally
// instead — a peer outage degrades to local service rather than a 502.
func (h *Handler) proxyToPeer(rec *statusRecorder, r *http.Request, m *cluster.Membership, peerURL string, info *reqInfo) bool {
	info.cacheStatus = "CLUSTER"
	info.upstream = "peer:" + peerURL

	target := peerURL + r.URL.RequestURI()
	preq, err := http.NewRequestWithContext(r.Context(), r.Method, target, r.Body)
	if err != nil {
		return false
	}
	// Forward client headers minus hop-by-hop + Host, then stamp the loop guard.
	for k, vs := range r.Header {
		if hopByHop[http.CanonicalHeaderKey(k)] || http.CanonicalHeaderKey(k) == "Host" {
			continue
		}
		for _, v := range vs {
			preq.Header.Add(k, v)
		}
	}
	preq.Header.Set(cluster.HopHeader, m.Region())

	resp, err := h.peerClient.Do(preq)
	if err != nil {
		// Peer unreachable: let the caller serve locally (degraded availability).
		return false
	}
	defer resp.Body.Close()

	hdr := rec.Header()
	for k, vs := range resp.Header {
		if hopByHop[http.CanonicalHeaderKey(k)] {
			continue
		}
		for _, v := range vs {
			hdr.Add(k, v)
		}
	}
	rec.WriteHeader(resp.StatusCode)
	if r.Method != http.MethodHead {
		_, _ = io.Copy(rec, resp.Body) // streamed, no buffering
	}
	return true
}

// newPeerClient builds the HTTP client used to reverse-proxy to peer cadish nodes.
// Establishment phases are bounded; the body transfer is uncapped (governed by the
// request context) per the streaming contract. Redirects are not followed (the
// SSRF guard shared across cadish's outbound clients).
func newPeerClient() *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			// No ambient proxy (security): peer dials are explicit; an env-configured
			// HTTP(S)_PROXY diverting them is an SSRF-adjacent footgun. Pairs with the
			// no-follow-redirect SSRF guard shared across cadish's outbound clients.
			Proxy:                 nil,
			DialContext:           (&net.Dialer{Timeout: 5 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
			ForceAttemptHTTP2:     true,
			MaxIdleConns:          256,
			MaxIdleConnsPerHost:   64,
			IdleConnTimeout:       90 * time.Second,
			TLSHandshakeTimeout:   5 * time.Second,
			ResponseHeaderTimeout: 30 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
		},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}
