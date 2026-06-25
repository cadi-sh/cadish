//go:build integration

// Layer-2 envtest integration test: drive the Ingress controller against a REAL
// Kubernetes apiserver — apply an IngressClass, an Ingress (with a policy ConfigMap and
// a kubernetes.io/tls Secret), a backend EndpointSlice and a publish Service, then assert
// the controller (1) translates and applies the served routing, (2) injects the BYO TLS
// Secret keypair, and (3) — as the (unelected, single-replica) leader — writes the
// load-balancer address onto the Ingress's status.loadBalancer.
//
// REQUIREMENTS — a real apiserver + etcd binary via controller-runtime's setup-envtest.
// Gated behind the `integration` build tag, so EXCLUDED from the default build and the
// green gate (`go test ./...`); runs only where the binary is present:
//
//	go run sigs.k8s.io/controller-runtime/tools/setup-envtest@latest use
//	export KUBEBUILDER_ASSETS="$(go run sigs.k8s.io/controller-runtime/tools/setup-envtest@latest use -i -p path)"
//	go test -tags integration ./internal/ingress
//
// The bootstrap SKIPS when the binary is unavailable, so a lane without setup-envtest is
// a clean skip rather than a red build.
package ingress

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"testing"
	"time"

	"github.com/cadi-sh/cadish/internal/config"
	"github.com/cadi-sh/cadish/internal/tlsacme"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
)

// startAPIServer boots a real apiserver+etcd via envtest and returns its rest.Config,
// SKIPping when the binary is unavailable (graceful degradation in lanes without
// setup-envtest).
func startAPIServer(t *testing.T) *rest.Config {
	t.Helper()
	env := &envtest.Environment{}
	cfg, err := env.Start()
	if err != nil {
		if os.Getenv("KUBEBUILDER_ASSETS") == "" {
			t.Skipf("envtest apiserver unavailable; run `setup-envtest use` and set KUBEBUILDER_ASSETS (%v)", err)
		}
		t.Fatalf("start envtest apiserver: %v", err)
	}
	t.Cleanup(func() { _ = env.Stop() })
	return cfg
}

// captureApplier records the configs the controller applies AND the dynamic TLS certs it
// injects. Implementing TLSInjector exercises the BYO-Secret path end-to-end (a bare
// Applier would disable it). All sends are non-blocking over buffered channels so a busy
// reconcile loop never blocks on a slow test reader.
type captureApplier struct {
	configs chan *config.Config
	certs   chan []tlsacme.DynamicCert
}

func (a *captureApplier) ApplyConfig(c *config.Config) error {
	select {
	case a.configs <- c:
	default:
	}
	return nil
}

func (a *captureApplier) SetDynamicCerts(d []tlsacme.DynamicCert) error {
	select {
	case a.certs <- d:
	default:
	}
	return nil
}

// genSelfSigned returns a PEM-encoded self-signed keypair for host (a usable
// kubernetes.io/tls Secret payload).
func genSelfSigned(t *testing.T, host string) (crt, key []byte) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("genkey: %v", err)
	}
	tmpl := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: host},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{host},
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	keyDER, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	crt = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	key = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	return crt, key
}

// TestControllerServesIngressAndWritesStatus drives the full Layer-2 reconcile loop
// against a real apiserver.
func TestControllerServesIngressAndWritesStatus(t *testing.T) {
	cfg := startAPIServer(t)
	cs, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		t.Fatalf("clientset: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	const ns = "default"
	const host = "tls.example.com"

	// IngressClass the controller serves.
	if _, err := cs.NetworkingV1().IngressClasses().Create(ctx, &networkingv1.IngressClass{
		ObjectMeta: metav1.ObjectMeta{Name: "cadish"},
		Spec:       networkingv1.IngressClassSpec{Controller: "cadi.sh/ingress"},
	}, metav1.CreateOptions{}); err != nil {
		t.Fatalf("create ingressclass: %v", err)
	}

	// Policy ConfigMap (layered onto the host via the cadi.sh/policy annotation).
	if _, err := cs.CoreV1().ConfigMaps(ns).Create(ctx, &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{Name: "pol", Namespace: ns},
		Data:       map[string]string{policyConfigMapKey: validPolicyFragment},
	}, metav1.CreateOptions{}); err != nil {
		t.Fatalf("create configmap: %v", err)
	}

	// kubernetes.io/tls Secret (a usable BYO keypair → injected, not pushed to ACME).
	crt, key := genSelfSigned(t, host)
	if _, err := cs.CoreV1().Secrets(ns).Create(ctx, &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "tls-secret", Namespace: ns},
		Type:       corev1.SecretTypeTLS,
		Data:       map[string][]byte{"tls.crt": crt, "tls.key": key},
	}, metav1.CreateOptions{}); err != nil {
		t.Fatalf("create secret: %v", err)
	}

	// Backend EndpointSlice so the generated k8s:// upstream resolves.
	ready := true
	if _, err := cs.DiscoveryV1().EndpointSlices(ns).Create(ctx,
		sliceFor("web", ns, []epSpec{{ip: "10.1.2.3", ready: &ready}}, portSpec{name: "", num: 80}),
		metav1.CreateOptions{}); err != nil {
		t.Fatalf("create endpointslice: %v", err)
	}

	// The Ingress: policy annotation + spec.tls referencing the Secret.
	ing := ingress(ns, "site", host, []pathRule{{path: "/", pathType: prefix, svc: "web", port: 80}})
	ing.Annotations = map[string]string{policyAnnotation: ns + "/pol"}
	ing.Spec.TLS = []networkingv1.IngressTLS{{Hosts: []string{host}, SecretName: "tls-secret"}}
	if _, err := cs.NetworkingV1().Ingresses(ns).Create(ctx, ing, metav1.CreateOptions{}); err != nil {
		t.Fatalf("create ingress: %v", err)
	}

	// Publish Service with a provisioned load-balancer address (the leader writes this
	// onto the Ingress's status.loadBalancer).
	svc, err := cs.CoreV1().Services(ns).Create(ctx, &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{Name: "cadish-lb", Namespace: ns},
		Spec: corev1.ServiceSpec{
			Type:  corev1.ServiceTypeLoadBalancer,
			Ports: []corev1.ServicePort{{Port: 80}},
		},
	}, metav1.CreateOptions{})
	if err != nil {
		t.Fatalf("create service: %v", err)
	}
	svc.Status.LoadBalancer.Ingress = []corev1.LoadBalancerIngress{{IP: "203.0.113.7"}}
	if _, err := cs.CoreV1().Services(ns).UpdateStatus(ctx, svc, metav1.UpdateOptions{}); err != nil {
		t.Fatalf("update service status: %v", err)
	}

	// Run the controller (single replica: status writer runs unconditionally).
	app := &captureApplier{
		configs: make(chan *config.Config, 16),
		certs:   make(chan []tlsacme.DynamicCert, 16),
	}
	ctrl := New(cs, app, "", Config{
		ClassName:      "cadish",
		PublishService: ns + "/cadish-lb",
		ResyncDebounce: 10 * time.Millisecond,
		LeaderElection: false,
	})
	go func() { _ = ctrl.Run(ctx) }()

	// (1) the served routing matches the Ingress (host present in the applied config).
	select {
	case c := <-app.configs:
		if !hasSiteHost(c, host) {
			t.Fatalf("applied config missing site %q", host)
		}
	case <-time.After(60 * time.Second):
		t.Fatal("controller never applied a config")
	}

	// (2) the BYO TLS Secret keypair is injected for the host (not pushed to ACME).
	injected := false
	injDeadline := time.Now().Add(30 * time.Second)
	for !injected && time.Now().Before(injDeadline) {
		select {
		case certs := <-app.certs:
			for _, dc := range certs {
				for _, h := range dc.Hosts {
					if h == host {
						injected = true
					}
				}
			}
		case <-time.After(time.Second):
		}
	}
	if !injected {
		t.Fatal("controller never injected the BYO TLS Secret keypair for the host")
	}

	// (3) the leader writes the load-balancer address onto the Ingress status.
	statusDeadline := time.Now().Add(60 * time.Second)
	for {
		got, gerr := cs.NetworkingV1().Ingresses(ns).Get(ctx, "site", metav1.GetOptions{})
		if gerr == nil && len(got.Status.LoadBalancer.Ingress) == 1 &&
			got.Status.LoadBalancer.Ingress[0].IP == "203.0.113.7" {
			break
		}
		if time.Now().After(statusDeadline) {
			t.Fatalf("leader never wrote status.loadBalancer: %+v (err %v)", got.Status.LoadBalancer.Ingress, gerr)
		}
		time.Sleep(200 * time.Millisecond)
	}

	if s := ctrl.Stats(); !s.IsLeader || s.WatchedIngresses != 1 || s.Rejects != 0 || s.LastError != "" {
		t.Errorf("unexpected stats after healthy reconcile: %+v", s)
	}
}
