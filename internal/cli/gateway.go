package cli

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/cadi-sh/cadish/internal/config"
	"github.com/cadi-sh/cadish/internal/gateway"
	"github.com/cadi-sh/cadish/internal/k8s"
	"github.com/cadi-sh/cadish/internal/metrics"
	"github.com/cadi-sh/cadish/internal/server"
	gwclient "sigs.k8s.io/gateway-api/pkg/client/clientset/versioned"
)

// Gateway runs cadish in-cluster as a Kubernetes Gateway API controller: it serves traffic
// from routing translated out of GatewayClass / Gateway / HTTPRoute objects (the cluster
// is the source of truth), while the base Cadishfile supplies only globals (admin/ACME/
// access-log). It watches those resources and hot-swaps the live routing through
// Server.ApplyConfig — the SAME atomic swap `cadish ingress` uses. It runs as a SEPARATE
// process from `cadish ingress` (a separate Deployment / GatewayClass controllerName), so
// the two controllers do not contend for the same objects. Serves until SIGINT/SIGTERM;
// SIGHUP re-reads the base Cadishfile and re-reconciles.
//
// Scope (slices 1+2): GatewayClass acceptance; Gateway HTTP + HTTPS (TLS Terminate)
// listeners with certificateRefs (BYO Secret termination, the SAME Server.SetDynamicCerts
// path the Ingress controller uses); HTTPRoute host + path (Exact / PathPrefix) routing with
// advanced matchers (headers / queryParams / method); cross-namespace refs gated by a
// ReferenceGrant; weighted multi-backend pools; and status conditions. See docs/gateway-api.md.
func Gateway(args []string) int {
	fs := flag.NewFlagSet("gateway", flag.ContinueOnError)
	cfgPath := fs.String("config", defaultConfigPath, "path to the BASE Cadishfile (globals only; sites come from Gateway/HTTPRoute objects)")
	namespaces := fs.String("namespace", "", "comma-separated namespaces to watch (empty = all namespaces)")
	kubeconfig := fs.String("kubeconfig", "", "path to a kubeconfig (else KUBECONFIG / in-cluster / ~/.kube/config)")
	addr := fs.String("addr", ":80", "HTTP listen address")
	httpsAddr := fs.String("https-addr", ":443", "HTTPS listen address; bound so HTTPS listener certificateRefs (BYO Secrets) go live on reconcile")
	idle := fs.Duration("idle-timeout", 60*time.Second, "abort an origin body that stalls this long (0 disables)")
	debounce := fs.Duration("resync-debounce", 250*time.Millisecond, "quiet window after the last watched change before a reconcile")
	leaderElect := fs.Bool("leader-elect", true, "leader-elect the status writer (only the leader writes Gateway/HTTPRoute status; serving is never gated)")
	leaderNS := fs.String("leader-namespace", "", "namespace for the leader-election Lease (default: 'default')")
	leaderName := fs.String("leader-name", "cadish-gateway-leader", "name of the leader-election Lease")
	identity := fs.String("identity", "", "unique identity for leader election (default: POD_NAME / hostname)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() > 0 {
		fmt.Fprintf(os.Stderr, "cadish gateway: unexpected argument(s): %v\n(bool flags take `=`, e.g. -leader-elect=false)\n", fs.Args())
		return 2
	}

	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))

	// Read the BASE Cadishfile (globals only).
	baseBytes, err := os.ReadFile(*cfgPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "cadish gateway: %v\n", err)
		return 1
	}
	base := string(baseBytes)

	// Build the initial (site-less) config from the base globals; the controller's first
	// reconcile applies the real sites.
	initCfg, err := config.LoadStringWithOptions(*cfgPath, base, config.LoadOptions{
		Kubeconfig:   *kubeconfig,
		AllowNoSites: true,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "cadish gateway: base config: %v\n", err)
		return 1
	}

	var mx *metrics.Metrics
	if initCfg.Admin != nil {
		mx = metrics.New()
	}

	srv, err := server.NewServer(initCfg, *addr, server.Options{
		Logger:      log,
		IdleTimeout: *idle,
		HTTPSAddr:   *httpsAddr,
		// Gateway mode is TLS-capable: HTTPS listener certificateRefs (BYO Secrets) arrive
		// via reconcile, so the :443 listener must exist at startup for the dynamic-cert
		// injection (Server.SetDynamicCerts) to go live — the SAME posture as Ingress mode.
		ForceTLS:     true,
		Metrics:      mx,
		AccessLogOff: initCfg.AccessLogOff,
		// Gateway data plane returns 404 for an unmatched Host (GW-P1) — Gateway API clients
		// expect not-found, not the core server's 502. Gateway-scoped: the core server keeps
		// 502 (this option is only set here and in nowhere else).
		UnmatchedHostStatus: http.StatusNotFound,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "cadish gateway: %v\n", err)
		_ = initCfg.Close()
		return 1
	}

	// The core clientset (Layer-1 k8s:// resolution + status-writer Lease) and the
	// gateway-api clientset (the GatewayClass/Gateway/HTTPRoute objects), both over the
	// SAME auth resolved by internal/k8s.
	cs, err := k8s.NewClientset(k8s.Options{Kubeconfig: *kubeconfig})
	if err != nil {
		fmt.Fprintf(os.Stderr, "cadish gateway: kubernetes: %v\n", err)
		return 1
	}
	restCfg, err := k8s.RESTConfig(*kubeconfig)
	if err != nil {
		fmt.Fprintf(os.Stderr, "cadish gateway: kubernetes config: %v\n", err)
		return 1
	}
	gwcs, err := gwclient.NewForConfig(restCfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "cadish gateway: gateway-api client: %v\n", err)
		return 1
	}

	ctrl := gateway.New(cs, gwcs, srv, base, gateway.Config{
		Namespaces:      splitCSV(*namespaces),
		ResyncDebounce:  *debounce,
		Kubeconfig:      *kubeconfig,
		LeaderElection:  *leaderElect,
		LeaderNamespace: *leaderNS,
		LeaderName:      *leaderName,
		Identity:        leaderIdentity(*identity),
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
	log.Info("cadish gateway controller", "addr", *addr, "controllerName", gateway.ControllerName)

	for {
		select {
		case <-hup:
			log.Info("cadish gateway: re-reading base config (SIGHUP)", "config", *cfgPath)
			if b, rerr := os.ReadFile(*cfgPath); rerr != nil {
				log.Error("cadish gateway: re-read base failed; keeping current", "err", rerr)
			} else {
				ctrl.UpdateBase(string(b))
			}
		case err := <-ctrlErr:
			if err != nil {
				log.Error("cadish gateway: controller stopped", "err", err)
				sctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
				_ = srv.Shutdown(sctx)
				cancel()
				return 1
			}
		case err := <-errCh:
			if err != nil {
				fmt.Fprintf(os.Stderr, "cadish gateway: %v\n", err)
				return 1
			}
			return 0
		case <-ctx.Done():
			log.Info("cadish gateway: shutting down")
			sctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			if err := srv.Shutdown(sctx); err != nil {
				fmt.Fprintf(os.Stderr, "cadish gateway: shutdown: %v\n", err)
				return 1
			}
			return 0
		}
	}
}
