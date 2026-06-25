// Package admin is cadish's opt-in observability / command-center surface: a
// separate HTTP server (its own listener, off by default, auth-gated) that serves
// a single-page dashboard from embedded assets plus a JSON API and an optional
// Prometheus endpoint.
//
// It is strictly OFF the datapath:
//
//   - Its own net.Listener on a separate bind (never the proxy's listener).
//   - Started only when an `admin { … }` block is present; otherwise this package
//     is never constructed and the request handler's metrics seam stays nil.
//   - Every endpoint requires a bearer token (crypto/subtle compare).
//   - It only READS already-cheap live state (atomic metrics counters, on-demand
//     cache/lb snapshots) and re-runs `cadish check` for the config view;
//     it never mutates proxy state and never blocks a request.
package admin

import (
	"context"
	"crypto/subtle"
	"net"
	"net/http"
	"time"

	"github.com/cadi-sh/cadish/internal/config"
	"github.com/cadi-sh/cadish/internal/lb"
	"github.com/cadi-sh/cadish/internal/metrics"
)

// LiveSource is the read seam the admin server uses to render per-site live state
// (two-tier cache fill). *server.Handler satisfies it via LiveState;
// admin depends on this interface rather than importing internal/server, keeping
// the dependency direction one-way (server does not import admin).
type LiveSource interface {
	LiveState() []SiteState
}

// IngressSource is the OPTIONAL read seam for the Kubernetes Ingress controller's
// reconcile stats (mirrors LiveSource). The CLI's `cadish ingress` mode wires an
// adapter over the running *ingress.Controller; plain `cadish run` passes nil and the
// dashboard simply omits the "Kubernetes Ingress" panel (zero cost off that path). The
// bool reports whether stats are currently available (false ⇒ panel hidden).
type IngressSource interface {
	IngressStats() (IngressStats, bool)
}

// IngressStats mirrors ingress.Stats's JSON shape. It is duplicated here (a small,
// stable record) so internal/admin needs no compile-time dependency on
// internal/ingress; the CLI adapts the controller's snapshot into this type.
type IngressStats struct {
	WatchedIngresses int    `json:"watched_ingresses"`
	LastAppliedHash  string `json:"last_applied_hash"`
	Rejects          int    `json:"rejects"`
	LastError        string `json:"last_error"`
	IsLeader         bool   `json:"is_leader"`
}

// SiteState mirrors server.SiteState's JSON shape. It is duplicated here (a small,
// stable record) so internal/admin needs no compile-time dependency on
// internal/server; the CLI adapts the server's slice into this type.
type SiteState struct {
	Name      string     `json:"name"`
	Addresses []string   `json:"addresses"`
	Cache     CacheStats `json:"cache"`
}

// CacheStats mirrors cache.Stats for the JSON projection (no internal/cache import
// needed by consumers of the admin API).
type CacheStats struct {
	RAMObjects        int   `json:"ram_objects"`
	DiskObjects       int   `json:"disk_objects"`
	RAMBytes          int64 `json:"ram_bytes"`
	DiskBytes         int64 `json:"disk_bytes"`
	RAMMaxBytes       int64 `json:"ram_max_bytes"`
	DiskMaxBytes      int64 `json:"disk_max_bytes"`
	DiskPersistErrors int64 `json:"disk_persist_errors"`
}

// Server is the admin/dashboard HTTP server. Construct with New and run with
// ListenAndServe; stop with Shutdown.
type Server struct {
	cfg     *config.AdminConfig
	metrics *metrics.Metrics
	live    LiveSource
	ingress IngressSource // nil outside `cadish ingress` mode ⇒ no Ingress panel
	pools   []*lb.Upstream
	cfgPath string

	httpSrv *http.Server
	ln      net.Listener
}

// New builds the admin server.
//
//   - ac is the parsed `admin` block (its Listen + AuthToken + Metrics flag).
//   - m is the live metrics seam (the same *Metrics passed to server.Options).
//   - live reads per-site cache state (the running *server.Handler).
//   - ing reads the Kubernetes Ingress controller's reconcile stats; nil outside
//     `cadish ingress` mode ⇒ the dashboard omits the Ingress panel.
//   - pools are the lb upstream pools for the health view (config.Pools()).
//   - cfgPath is the Cadishfile path, re-read for the config view (cadish check).
func New(ac *config.AdminConfig, m *metrics.Metrics, live LiveSource, ing IngressSource, pools []*lb.Upstream, cfgPath string) *Server {
	s := &Server{
		cfg:     ac,
		metrics: m,
		live:    live,
		ingress: ing,
		pools:   pools,
		cfgPath: cfgPath,
	}
	s.httpSrv = &http.Server{
		Handler:           s.routes(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		IdleTimeout:       120 * time.Second,
	}
	return s
}

// routes builds the admin mux. Every route is wrapped in auth.
func (s *Server) routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/config", s.handleConfig)
	mux.HandleFunc("/api/source", s.handleSource)
	mux.HandleFunc("/api/validate", s.handleValidate)
	mux.HandleFunc("/api/metrics", s.handleMetrics)
	mux.HandleFunc("/api/live", s.handleLive)
	mux.HandleFunc("/api/upstreams", s.handleUpstreams)
	mux.HandleFunc("/api/ingress", s.handleIngress)
	mux.HandleFunc("/api/stream", s.handleStream)
	if s.cfg.Metrics {
		mux.HandleFunc("/metrics", s.handlePrometheus)
	}
	mux.HandleFunc("/", s.handleIndex)
	return s.withAuth(mux)
}

// withAuth gates every request on the bearer token, with ONE exception: GET / (the
// SPA shell) is the login page — it carries no secrets and no live data, so it is
// served unauthenticated. That is what lets a browser load the dashboard and have
// the operator paste the token into the in-page form, so the token never has to
// ride in a URL (no ?token=, see tokenOK). Every data/API route stays gated;
// unmatched paths (the SPA catch-all) are gated too. A constant-time compare avoids
// leaking the token via timing (mirrors the purge-token check, security batch 1).
func (s *Server) withAuth(next http.Handler) http.Handler {
	want := []byte(s.cfg.AuthToken)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if isPublicShell(r) {
			next.ServeHTTP(w, r)
			return
		}
		if !tokenOK(r, want) {
			w.Header().Set("WWW-Authenticate", "Bearer")
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// isPublicShell reports whether the request is for the unauthenticated SPA login
// shell: exactly GET / (or HEAD). Nothing else is public — every API route and any
// other path requires the token.
func isPublicShell(r *http.Request) bool {
	return (r.Method == http.MethodGet || r.Method == http.MethodHead) && r.URL.Path == "/"
}

// tokenOK reports whether the request carries the expected bearer token via the
// "Authorization: Bearer <t>" header, compared in constant time. The token is
// accepted ONLY from this header — never from a query string, which would leak it
// into access logs, browser history and the Referer header.
func tokenOK(r *http.Request, want []byte) bool {
	var got string
	if h := r.Header.Get("Authorization"); h != "" {
		const p = "Bearer "
		if len(h) > len(p) && h[:len(p)] == p {
			got = h[len(p):]
		}
	}
	if got == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(got), want) == 1
}

// ListenAndServe binds the admin listener and serves until Shutdown. A clean
// shutdown returns nil. The listener bind happens here (not in New) so a bad bind
// address surfaces as a start error.
func (s *Server) ListenAndServe() error {
	ln, err := net.Listen("tcp", s.cfg.Listen)
	if err != nil {
		return err
	}
	s.ln = ln
	err = s.httpSrv.Serve(ln)
	if err == http.ErrServerClosed {
		return nil
	}
	return err
}

// Addr returns the actual bound address (useful when Listen used :0 in tests).
// Returns "" before ListenAndServe has bound.
func (s *Server) Addr() string {
	if s.ln == nil {
		return ""
	}
	return s.ln.Addr().String()
}

// Shutdown gracefully drains the admin server.
func (s *Server) Shutdown(ctx context.Context) error {
	return s.httpSrv.Shutdown(ctx)
}
