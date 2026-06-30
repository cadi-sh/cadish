package server

import (
	"io"
	"net"
	"net/http"
	"net/netip"
	"time"

	"github.com/cadi-sh/cadish/internal/cluster"
	"github.com/cadi-sh/cadish/internal/geo"
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
//
// credentialed + credCookie carry the cache_credentialed (D101) origin-authoritative state:
// when credentialed, the request's ORIGINAL (pre-cookie_allow) Cookie is forwarded to the
// owning peer so the per-user routes authenticate behind it. The local node never restores the
// cookie onto r.Header (EvalResponse must see the normalized request), and it does NOT run
// EvalResponse on a routed request, so injecting the original cookie ONLY into the peer-bound
// request (proxyToPeer) is both necessary and safe.
func (h *Handler) clusterRoute(rec *statusRecorder, r *http.Request, site *boundSite, ownerKey string, info *reqInfo, credentialed bool, credCookie string) bool {
	m := site.Cluster

	// Resolve the original client IP via the SAME trusted-proxy/XFF logic the rest of
	// the pipeline uses, so a request reverse-proxied to the owner carries it (below).
	// Computed here rather than reusing preq.RealClientIP because that field is only
	// populated when a security gate is configured; ownership routing needs it always.
	clientIP := geo.ClientIP(r.RemoteAddr, r.Header, site.TrustedProxies)

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

	// Only owner-route the cacheable, body-less methods (GET/HEAD). Owner routing
	// exists for cache coherence ("cached once per region"), and only GET/HEAD are
	// cached — a write gains nothing from the owner. Crucially, proxyToPeer streams
	// r.Body to the peer with no GetBody replay; if the peer accepts then fails
	// mid-upload, the body is partially consumed and the local fallback (the unsafe-
	// method origin path) would forward a TRUNCATED body to origin (F-D3). Writes
	// therefore take the normal local origin path, where the body is read once.
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		return false
	}

	// Owner routing. If we are the healthy owner, serve locally.
	if owner, ok := m.Owner(ownerKey); ok {
		if m.IsSelf(owner) {
			return false
		}
		return h.proxyToPeer(rec, r, m, owner, clientIP, info, credentialed, credCookie)
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
			if h.proxyToPeer(rec, r, m, owner, clientIP, info, credentialed, credCookie) {
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
func (h *Handler) proxyToPeer(rec *statusRecorder, r *http.Request, m *cluster.Membership, peerURL string, clientIP netip.Addr, info *reqInfo, credentialed bool, credCookie string) bool {
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
	// Preserve the ORIGINAL client Host on the peer-bound request. http.NewRequest set
	// preq.Host from the peer URL (the dial target), but the owner derives its cache key
	// (and its own site/host_header) from Host: leaving it as the peer URL makes the
	// owner key a proxied request under the PEER host while a direct client request keys
	// under the CLIENT host — two entries for one object, so the "cached once per region"
	// guarantee silently degrades to twice-on-the-owner whenever the cache key includes
	// host (the default). Forwarding the client Host makes proxied and direct requests
	// hash to the same key. The dial target is unaffected (it is preq.URL.Host = peer).
	preq.Host = r.Host
	// Preserve the ORIGINAL client IP. The owner re-derives the client IP from the
	// inbound socket + X-Forwarded-For; without an XFF entry it would see the PEER's IP
	// (the dial source), which (a) diverges the cache key for IP-based tokens ({geo},
	// {sticky} by client_ip) — a second store-multiple bug like the Host one — and
	// (b) feeds the wrong IP to ACL / rate-limit / geo decisions on the owner. We set
	// XFF to the already-resolved client IP; the owner, which MUST trust the peer subnet
	// (`trust_proxy` — the same trust that lets it honor the X-Cadish-Peer hop guard),
	// then derives the identical client IP. A single resolved entry is exact because the
	// non-owner already collapsed any upstream proxy chain into this address, and the
	// one-hop guard guarantees no second cadish hop. (Scheme/X-Forwarded-Proto is NOT
	// reconstructed: the cache pipeline derives scheme from the real connection, not a
	// header, so a proxied request is seen as http — documented as a deploy constraint;
	// it is not a cache-key input, so store-once is unaffected.)
	if clientIP.IsValid() {
		preq.Header.Set("X-Forwarded-For", clientIP.String())
	}
	// cache_credentialed (D101): r.Header carries the NORMALIZED (cookie_allow-filtered)
	// Cookie — the local node keeps it normalized so its own EvalResponse evaluates the
	// normalized request. The owning peer is a full cadish that re-derives the cache key and
	// re-runs the response phase from the cookie it receives, so it needs the ORIGINAL cookie
	// to authenticate the per-user routes. Inject it onto the PEER-bound request only (never
	// r.Header), mirroring the origin-only header op the foreground/background fetches use.
	if credentialed {
		restoreClientCookie(preq.Header, credCookie)
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
