package cli

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/cadi-sh/cadish/internal/admin"
	"github.com/cadi-sh/cadish/internal/config"
	"github.com/cadi-sh/cadish/internal/ingress"
	"github.com/cadi-sh/cadish/internal/k8s"
	"github.com/cadi-sh/cadish/internal/metrics"
	"github.com/cadi-sh/cadish/internal/server"
)

// Ingress runs cadish in-cluster as an Ingress controller: it serves traffic from
// routing translated out of Kubernetes Ingress objects (the cluster is the source of
// truth), while the base Cadishfile supplies only globals (admin/ACME/access-log). It
// watches Ingress/IngressClass/Secret/ConfigMap and hot-swaps the live routing through
// Server.ApplyConfig. Serves until SIGINT/SIGTERM; SIGHUP re-reads the base Cadishfile
// and re-reconciles.
func Ingress(args []string) int {
	fs := flag.NewFlagSet("ingress", flag.ContinueOnError)
	cfgPath := fs.String("config", defaultConfigPath, "path to the BASE Cadishfile (globals only; sites come from Ingress objects)")
	className := fs.String("ingress-class", "cadish", "the IngressClass this controller serves")
	namespaces := fs.String("namespace", "", "comma-separated namespaces to watch (empty = all namespaces)")
	publishService := fs.String("publish-service", "", "ns/name of the Service whose address is written to Ingress status.loadBalancer (leader-only)")
	kubeconfig := fs.String("kubeconfig", "", "path to a kubeconfig (else KUBECONFIG / in-cluster / ~/.kube/config)")
	addr := fs.String("addr", ":80", "HTTP listen address (ACME HTTP-01 challenge + HTTPS redirect)")
	httpsAddr := fs.String("https-addr", ":443", "HTTPS listen address; ingress mode always binds it so Ingress spec.tls hosts (BYO Secrets and ACME) go live on reconcile")
	idle := fs.Duration("idle-timeout", 60*time.Second, "abort an origin body that stalls this long (0 disables)")
	acmeCacheDir := fs.String("acme-cache", "", "ACME cert cache dir for Ingress spec.tls hosts without a Secret (auto-issued); empty = default resolution")
	acmeEmail := fs.String("acme-email", "", "ACME account contact email for auto-issued Ingress spec.tls hosts (optional)")
	acmeDomainPolicy := fs.String("acme-domain-policy", "", "per-namespace ACME domain allow-list: 'ns=suffix[,suffix];ns2=...' (empty = off; any watched host eligible — single-trust-domain default)")
	maxSites := fs.Int("max-sites-per-namespace", 0, "max distinct hosts (sites) a single namespace may render; excess rejected oldest-wins with an Event (0 = unlimited)")
	maxRoutes := fs.Int("max-routes-per-namespace", 0, "max routes (paths) a single namespace may render; excess rejected oldest-wins with an Event (0 = unlimited)")
	maxFragmentBytes := fs.Int("max-fragment-bytes", 0, "max size in bytes of a cadi.sh/policy fragment; an over-size fragment is rejected with an Event before compiling (0 = unlimited)")
	secretLabelSelector := fs.String("secret-label-selector", "", "label selector scoping which Secrets the controller watches/reads (e.g. 'cadi.sh/managed=true'); empty = off (watch all). When set, label your BYO/cert-manager TLS Secrets or they fall through to ACME")
	configMapLabelSelector := fs.String("configmap-label-selector", "", "label selector scoping which ConfigMaps the controller watches/reads; empty = off (watch all). When set, label your cadi.sh/policy ConfigMaps or their fragments are treated as not-found")
	watchLabelSelector := fs.String("watch-label-selector", "", "shorthand applying ONE selector to BOTH Secrets and ConfigMaps (overridden by -secret-label-selector / -configmap-label-selector when those are set); empty = off")
	debounce := fs.Duration("resync-debounce", 250*time.Millisecond, "quiet window after the last watched change before a reconcile")
	leaderElect := fs.Bool("leader-elect", true, "leader-elect the status writer (only the leader writes Ingress status; serving is never gated)")
	leaderNS := fs.String("leader-namespace", "", "namespace for the leader-election Lease (default: the controller's namespace / 'default')")
	leaderName := fs.String("leader-name", "cadish-ingress-leader", "name of the leader-election Lease")
	identity := fs.String("identity", "", "unique identity for leader election (default: POD_NAME / hostname)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	// Reject stray positional args: Go's flag.Parse STOPS at the first non-flag token
	// and silently drops every flag after it. The classic mistake `-leader-elect true`
	// (two tokens) would otherwise leave `true` as a positional and quietly ignore all
	// later flags — exactly the staging bug. Fail loudly instead.
	if fs.NArg() > 0 {
		fmt.Fprintf(os.Stderr, "cadish ingress: unexpected argument(s): %v\n(bool flags take `=`, e.g. -leader-elect=false)\n", fs.Args())
		return 2
	}

	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))

	// Parse the optional per-namespace ACME domain allow-list (A2). Empty ⇒ nil (off).
	acmePolicy, err := ingress.ParseACMEDomainPolicy(*acmeDomainPolicy)
	if err != nil {
		fmt.Fprintf(os.Stderr, "cadish ingress: -acme-domain-policy: %v\n", err)
		return 2
	}

	// Resolve the C1 label selectors: the per-resource flags take precedence over the
	// -watch-label-selector shorthand. Validate each up front so a typo fails loudly here
	// rather than silently watching all (the controller would otherwise warn + fall back).
	secretSelector := firstNonEmpty(*secretLabelSelector, *watchLabelSelector)
	configMapSelector := firstNonEmpty(*configMapLabelSelector, *watchLabelSelector)
	if err := ingress.ValidateLabelSelector(secretSelector); err != nil {
		fmt.Fprintf(os.Stderr, "cadish ingress: -secret-label-selector: %v\n", err)
		return 2
	}
	if err := ingress.ValidateLabelSelector(configMapSelector); err != nil {
		fmt.Fprintf(os.Stderr, "cadish ingress: -configmap-label-selector: %v\n", err)
		return 2
	}

	// Read the BASE Cadishfile (globals only).
	baseBytes, err := os.ReadFile(*cfgPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "cadish ingress: %v\n", err)
		return 1
	}
	base := string(baseBytes)

	// Build the initial (site-less) config from the base globals; the controller's first
	// reconcile applies the real sites. AllowNoSites lets a globals-only base load.
	initCfg, err := config.LoadStringWithOptions(*cfgPath, base, config.LoadOptions{
		Kubeconfig:   *kubeconfig,
		AllowNoSites: true,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "cadish ingress: base config: %v\n", err)
		return 1
	}

	var mx *metrics.Metrics
	if initCfg.Admin != nil {
		mx = metrics.New()
	}

	srv, err := server.NewServer(initCfg, *addr, server.Options{
		Logger:       log,
		IdleTimeout:  *idle,
		HTTPSAddr:    *httpsAddr,
		ACMECacheDir: *acmeCacheDir,
		ACMEEmail:    *acmeEmail,
		// Ingress mode is always TLS-capable: spec.tls hosts (BYO Secrets and
		// ACME-issued) arrive via reconcile, so the :443 listener + autocert source
		// must already exist at startup (D55).
		ForceTLS:     true,
		Metrics:      mx,
		AccessLogOff: initCfg.AccessLogOff,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "cadish ingress: %v\n", err)
		_ = initCfg.Close()
		return 1
	}

	// The shared clientset (the controller builds its own informer factories from it).
	cs, err := k8s.NewClientset(k8s.Options{Kubeconfig: *kubeconfig})
	if err != nil {
		fmt.Fprintf(os.Stderr, "cadish ingress: kubernetes: %v\n", err)
		return 1
	}

	ctrl := ingress.New(cs, srv, base, ingress.Config{
		ClassName:        *className,
		Namespaces:       splitCSV(*namespaces),
		PublishService:   *publishService,
		ResyncDebounce:   *debounce,
		Kubeconfig:       *kubeconfig,
		LeaderElection:   *leaderElect,
		LeaderNamespace:  *leaderNS,
		LeaderName:       *leaderName,
		Identity:         leaderIdentity(*identity),
		ACMEEmail:        *acmeEmail,
		ACMEDomainPolicy: acmePolicy,
		Caps: ingress.ResourceCaps{
			MaxSitesPerNamespace:  *maxSites,
			MaxRoutesPerNamespace: *maxRoutes,
			MaxFragmentBytes:      *maxFragmentBytes,
		},
		SecretLabelSelector:    secretSelector,
		ConfigMapLabelSelector: configMapSelector,
	})
	ctrl.SetLogger(log)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	hup := make(chan os.Signal, 1)
	signal.Notify(hup, syscall.SIGHUP)
	defer signal.Stop(hup)

	// Run the controller (informers → debounce → render → ApplyConfig) in the background.
	ctrlErr := make(chan error, 1)
	go func() { ctrlErr <- ctrl.Run(ctx) }()

	// Serve traffic (every replica serves; leadership only gates status writes).
	errCh := make(chan error, 1)
	go func() { errCh <- srv.ListenAndServe() }()
	log.Info("cadish ingress controller", "class", *className, "addr", *addr, "publish-service", *publishService)

	// Optional admin dashboard (when the base declares an `admin` block).
	var adminSrv *admin.Server
	if initCfg.Admin != nil {
		// NOTE: admin's pool view is seeded from the initial (empty) config; the live
		// per-site state (liveAdapter) reflects applied routing. A live pool view across
		// ApplyConfig swaps is a follow-up (Task 9 dashboard work).
		adminSrv = admin.New(initCfg.Admin, mx, liveAdapter{srv}, ingressStatsAdapter{ctrl}, initCfg.Pools(), initCfg.ConfigPath)
		go func() {
			if aerr := adminSrv.ListenAndServe(); aerr != nil {
				log.Error("admin server", "err", aerr)
			}
		}()
		log.Info("cadish admin", "listen", initCfg.Admin.Listen)
	}
	shutdownAdmin := func() {
		if adminSrv != nil {
			actx, acancel := context.WithTimeout(context.Background(), 5*time.Second)
			_ = adminSrv.Shutdown(actx)
			acancel()
		}
	}

	for {
		select {
		case <-hup:
			log.Info("cadish ingress: re-reading base config (SIGHUP)", "config", *cfgPath)
			if b, rerr := os.ReadFile(*cfgPath); rerr != nil {
				log.Error("cadish ingress: re-read base failed; keeping current", "err", rerr)
			} else {
				ctrl.UpdateBase(string(b))
			}
		case err := <-ctrlErr:
			if err != nil {
				log.Error("cadish ingress: controller stopped", "err", err)
				shutdownAdmin()
				sctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
				_ = srv.Shutdown(sctx)
				cancel()
				return 1
			}
		case err := <-errCh:
			shutdownAdmin()
			if err != nil {
				fmt.Fprintf(os.Stderr, "cadish ingress: %v\n", err)
				return 1
			}
			return 0
		case <-ctx.Done():
			log.Info("cadish ingress: shutting down")
			shutdownAdmin()
			sctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			if err := srv.Shutdown(sctx); err != nil {
				fmt.Fprintf(os.Stderr, "cadish ingress: shutdown: %v\n", err)
				return 1
			}
			return 0
		}
	}
}

// statsSource is the minimal seam ingressStatsAdapter reads — *ingress.Controller
// satisfies it via Stats(). Narrowing to this interface (rather than the concrete
// *Controller) keeps the adapter unit-testable with a fake snapshot.
type statsSource interface{ Stats() ingress.Stats }

// ingressStatsAdapter bridges the running Ingress controller's reconcile Stats to the
// admin.IngressSource seam, mapping ingress.Stats → admin.IngressStats (a copy that
// keeps internal/admin free of an internal/ingress import). It is wired ONLY in
// `cadish ingress` mode; plain `cadish run` passes nil, so the dashboard omits the
// Kubernetes Ingress panel.
type ingressStatsAdapter struct{ src statsSource }

func (a ingressStatsAdapter) IngressStats() (admin.IngressStats, bool) {
	if a.src == nil {
		return admin.IngressStats{}, false
	}
	st := a.src.Stats()
	return admin.IngressStats{
		WatchedIngresses: st.WatchedIngresses,
		LastAppliedHash:  st.LastAppliedHash,
		Rejects:          st.Rejects,
		LastError:        st.LastError,
		IsLeader:         st.IsLeader,
	}, true
}

// firstNonEmpty returns the first non-empty (after trimming) of its arguments, else "".
func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

// splitCSV splits a comma-separated flag value into trimmed, non-empty items.
func splitCSV(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// leaderIdentity resolves the leader-election identity: the explicit flag, else
// POD_NAME, else the hostname, else a constant.
func leaderIdentity(explicit string) string {
	if explicit != "" {
		return explicit
	}
	if v := os.Getenv("POD_NAME"); v != "" {
		return v
	}
	if h, err := os.Hostname(); err == nil && h != "" {
		return h
	}
	return "cadish-ingress"
}
