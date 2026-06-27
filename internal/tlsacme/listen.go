package tlsacme

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/http"
	"time"
)

// DefaultHTTPAddr and DefaultHTTPSAddr are the conventional edge ports.
const (
	DefaultHTTPAddr  = ":80"
	DefaultHTTPSAddr = ":443"
)

// MaxHeaderBytes caps the total request-header block on the TLS data-plane
// listeners (:443 site handler and the :80 ACME/redirect server), replacing
// net/http's 1 MiB default. 64 KiB is generous for a cache edge's request headers
// while blunting a header-flood DoS. It mirrors the plain-HTTP listener's cap in
// internal/server. For the HTTP/2 (:443) listener net/http additionally derives the
// advertised SETTINGS_MAX_HEADER_LIST_SIZE from this value, so the same 64 KiB ceiling
// bounds an HPACK header-list bomb (a flood of small h2 header fields) — no separate
// h2 knob is needed for that case.
const MaxHeaderBytes = 64 << 10 // 64 KiB

// MaxConcurrentStreams bounds the number of simultaneously-open HTTP/2 streams a
// single client connection may drive on the :443 listener. cadish serves h2 here via
// ALPN (TLSConfig.NextProtos advertises "h2") using net/http's built-in HTTP/2 server;
// this pins the concurrent-stream ceiling EXPLICITLY rather than relying on the
// implicit net/http default (also 250), so the stream-flood / rapid-reset DoS bound
// (CVE-2023-44487 class) is an auditable, fixed value. With Go 1.21+'s rapid-reset fix a
// stream still occupies a slot until its handler returns even after RST_STREAM, so this
// equally caps the number of concurrent per-stream origin fetches one connection can
// drive — a reset-after-HEADERS flood cannot amplify into unbounded origin work or
// goroutines. h2 runs ONLY on this TLS listener; the plain :80 redirect/ACME server and
// the no-TLS data-plane listener are HTTP/1.1 only (no h2c — Server.Protocols never opts
// into UnencryptedHTTP2).
const MaxConcurrentStreams = 250

// Servers is the pair of HTTP servers a TLS deployment runs: the :80 server for
// ACME challenges + HTTPS redirect, and the :443 server for the actual site
// handler over a hardened TLS config.
type Servers struct {
	HTTP  *http.Server // :80 — challenge + redirect
	HTTPS *http.Server // :443 — site handler over TLS

	// WrapListener, when non-nil, wraps each raw TCP listener BEFORE it is used (and,
	// for HTTPS, before the TLS listener is layered on top). It is the seam the opt-in
	// PROXY-protocol listener installs: the wire order is PROXY -> TLS ClientHello ->
	// HTTP, so the PROXY wrapper must sit BENEATH TLS — it consumes the PROXY header
	// and rewrites RemoteAddr, then the TLS listener sees a clean stream. Nil (the
	// default) means the bare net.Listen path (zero cost when the feature is off).
	WrapListener func(net.Listener) (net.Listener, error)
}

// BuildServers constructs the :80 and :443 servers for handler (the caching
// reverse proxy). The HTTPS handler is wrapped with the HSTS middleware; the
// HTTP server serves challenges and redirects. Addresses default to :80/:443 when
// empty. Conservative header-read timeouts are set to blunt Slowloris.
//
// The server (M5b) calls this once it has built its site handler and a Manager.
func (m *Manager) BuildServers(handler http.Handler, httpAddr, httpsAddr string) *Servers {
	if httpAddr == "" {
		httpAddr = DefaultHTTPAddr
	}
	if httpsAddr == "" {
		httpsAddr = DefaultHTTPSAddr
	}
	https := &http.Server{
		Addr:              httpsAddr,
		Handler:           m.HSTSMiddleware(handler),
		TLSConfig:         m.TLSConfig(),
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    MaxHeaderBytes,
		// Explicitly bound the inbound HTTP/2 server (DoS hardening, Go 1.24+ dependency-free
		// http.HTTP2Config). h2 is negotiated here via ALPN with otherwise-default settings;
		// pinning MaxConcurrentStreams keeps the stream-flood / rapid-reset ceiling auditable
		// instead of relying on the implicit net/http default. The HPACK header-list size is
		// bounded automatically from MaxHeaderBytes (64 KiB) by net/http's h2 server.
		HTTP2: &http.HTTP2Config{MaxConcurrentStreams: MaxConcurrentStreams},
	}
	httpSrv := &http.Server{
		Addr:              httpAddr,
		Handler:           m.HTTPHandler(handler),
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    MaxHeaderBytes,
	}
	return &Servers{HTTP: httpSrv, HTTPS: https}
}

// ListenAndServe starts both servers and blocks until ctx is cancelled or one of
// them fails, then gracefully shuts both down. The HTTPS server uses the
// Manager's GetCertificate (so empty cert/key file arguments are correct).
func (s *Servers) ListenAndServe(ctx context.Context) error {
	// Default path (no listener wrap): the standard net/http listen helpers, exactly
	// as before. This keeps the common case byte-for-byte unchanged.
	if s.WrapListener == nil {
		errCh := make(chan error, 2)
		go func() { errCh <- serveErr(s.HTTP.ListenAndServe()) }()
		go func() { errCh <- serveErr(s.HTTPS.ListenAndServeTLS("", "")) }()
		return s.awaitAndShutdown(ctx, errCh)
	}

	// Wrapped path: build the raw listeners, apply WrapListener (the PROXY-protocol
	// wrapper) BENEATH TLS, then layer the TLS listener on the HTTPS one so the
	// handshake sees a clean stream after the PROXY header is consumed.
	httpLn, err := s.listen(s.HTTP.Addr, DefaultHTTPAddr)
	if err != nil {
		return err
	}
	httpsRaw, err := s.listen(s.HTTPS.Addr, DefaultHTTPSAddr)
	if err != nil {
		_ = httpLn.Close()
		return err
	}
	httpsLn := tls.NewListener(httpsRaw, s.HTTPS.TLSConfig)

	errCh := make(chan error, 2)
	go func() { errCh <- serveErr(s.HTTP.Serve(httpLn)) }()
	go func() { errCh <- serveErr(s.HTTPS.Serve(httpsLn)) }()
	return s.awaitAndShutdown(ctx, errCh)
}

// listen opens a TCP listener on addr (defaulting to def when empty) and applies the
// configured WrapListener (the PROXY-protocol wrapper) beneath any TLS.
func (s *Servers) listen(addr, def string) (net.Listener, error) {
	if addr == "" {
		addr = def
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}
	wrapped, werr := s.WrapListener(ln)
	if werr != nil {
		_ = ln.Close()
		return nil, werr
	}
	return wrapped, nil
}

func (s *Servers) awaitAndShutdown(ctx context.Context, errCh <-chan error) error {
	var err error
	select {
	case <-ctx.Done():
	case err = <-errCh:
	}

	shutCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	_ = s.HTTP.Shutdown(shutCtx)
	_ = s.HTTPS.Shutdown(shutCtx)
	return err
}

// serveErr normalizes http.ErrServerClosed (a clean shutdown) to nil.
func serveErr(err error) error {
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}
