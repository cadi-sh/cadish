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
// internal/server.
const MaxHeaderBytes = 64 << 10 // 64 KiB

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
