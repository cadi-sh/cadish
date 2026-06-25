package gateway

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"sync"
	"testing"
	"time"

	"github.com/cadi-sh/cadish/internal/config"
	"github.com/cadi-sh/cadish/internal/tlsacme"
	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	k8sfake "k8s.io/client-go/kubernetes/fake"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
	gwfake "sigs.k8s.io/gateway-api/pkg/client/clientset/versioned/fake"
)

// applierFunc adapts a func to the Applier interface.
type applierFunc func(*config.Config) error

func (f applierFunc) ApplyConfig(c *config.Config) error { return f(c) }

func hasSiteHost(cfg *config.Config, host string) bool {
	for _, s := range cfg.Sites {
		for _, a := range s.Addresses {
			if a == host {
				return true
			}
		}
	}
	return false
}

// sliceFor builds an EndpointSlice for service in namespace (so k8s:// resolves offline,
// mirroring the Ingress controller test helper).
func sliceFor(service, namespace, ip string, port int32) *discoveryv1.EndpointSlice {
	ready := true
	pname := ""
	pnum := port
	return &discoveryv1.EndpointSlice{
		ObjectMeta: metav1.ObjectMeta{
			Name:      service + "-" + ip,
			Namespace: namespace,
			Labels:    map[string]string{"kubernetes.io/service-name": service},
		},
		AddressType: discoveryv1.AddressTypeIPv4,
		Endpoints:   []discoveryv1.Endpoint{{Addresses: []string{ip}, Conditions: discoveryv1.EndpointConditions{Ready: &ready}}},
		Ports:       []discoveryv1.EndpointPort{{Name: &pname, Port: &pnum}},
	}
}

// TestControllerReconcileAndStatus is the end-to-end controller guard: an owned
// GatewayClass + HTTP Gateway + HTTPRoute is reconciled into an applied config serving the
// route's host, and the Accepted/Programmed/ResolvedRefs status conditions are written.
func TestControllerReconcileAndStatus(t *testing.T) {
	gc := gatewayClass("cadish", ControllerName)
	g := gw("prod", "gw", "cadish", "")
	rt := httpRoute("prod", "api", "gw", "example.com", "web", 80, []match{{"/api", gatewayv1.PathMatchPathPrefix}})

	// NOTE: the gateway-api fake clientset's constructor uses a naive pluralizer that
	// stores a seeded *Gateway under the wrong resource ("gatewaies"); the typed
	// client/informer use "gateways". Seeding via Create (the typed path) lands the objects
	// under the correct resource, so the informer sees them. (See the deferred-tooling note
	// in the package tests.)
	gwcs := gwfake.NewSimpleClientset()
	mustCreate(t, gwcs, gc, g, rt)
	cs := k8sfake.NewSimpleClientset(svc("prod", "web"), sliceFor("web", "prod", "10.0.0.1", 80))

	applied := make(chan *config.Config, 8)
	applier := applierFunc(func(c *config.Config) error { applied <- c; return nil })
	ctrl := New(cs, gwcs, applier, ``, Config{ResyncDebounce: 10 * time.Millisecond})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = ctrl.Run(ctx) }()

	select {
	case cfg := <-applied:
		if !hasSiteHost(cfg, "example.com") {
			t.Fatalf("applied config missing example.com site")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("controller never applied a config")
	}

	// GatewayClass Accepted=True.
	waitCond(t, func() bool {
		got, err := gwcs.GatewayV1().GatewayClasses().Get(ctx, "cadish", metav1.GetOptions{})
		if err != nil {
			return false
		}
		return condTrue(got.Status.Conditions, string(gatewayv1.GatewayClassConditionStatusAccepted))
	}, "GatewayClass Accepted=True")

	// Gateway Accepted=True + Programmed=True, listener attachedRoutes=1.
	waitCond(t, func() bool {
		got, err := gwcs.GatewayV1().Gateways("prod").Get(ctx, "gw", metav1.GetOptions{})
		if err != nil {
			return false
		}
		if !condTrue(got.Status.Conditions, string(gatewayv1.GatewayConditionAccepted)) {
			return false
		}
		if !condTrue(got.Status.Conditions, string(gatewayv1.GatewayConditionProgrammed)) {
			return false
		}
		return len(got.Status.Listeners) == 1 && got.Status.Listeners[0].AttachedRoutes == 1
	}, "Gateway Accepted+Programmed with attachedRoutes=1")

	// HTTPRoute parent Accepted=True + ResolvedRefs=True.
	waitCond(t, func() bool {
		got, err := gwcs.GatewayV1().HTTPRoutes("prod").Get(ctx, "api", metav1.GetOptions{})
		if err != nil || len(got.Status.Parents) == 0 {
			return false
		}
		p := got.Status.Parents[0]
		return condTrue(p.Conditions, string(gatewayv1.RouteConditionAccepted)) &&
			condTrue(p.Conditions, string(gatewayv1.RouteConditionResolvedRefs))
	}, "HTTPRoute Accepted+ResolvedRefs")
}

// TestControllerForeignClassNoStatus: a foreign GatewayClass gets NO status written (we
// only own classes whose controllerName is ours) and serves nothing.
func TestControllerForeignClassNoStatus(t *testing.T) {
	gc := gatewayClass("nginx", "example.com/other")
	g := gw("prod", "gw", "nginx", "")
	rt := httpRoute("prod", "api", "gw", "example.com", "web", 80, []match{{"/", gatewayv1.PathMatchPathPrefix}})
	gwcs := gwfake.NewSimpleClientset()
	mustCreate(t, gwcs, gc, g, rt)
	cs := k8sfake.NewSimpleClientset()

	applier := applierFunc(func(c *config.Config) error {
		if hasSiteHost(c, "example.com") {
			t.Errorf("a foreign GatewayClass must not produce a served site")
		}
		return nil
	})
	ctrl := New(cs, gwcs, applier, ``, Config{ResyncDebounce: 10 * time.Millisecond})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = ctrl.Run(ctx) }()

	// Give the controller time to reconcile, then assert no GatewayClass status was set.
	time.Sleep(300 * time.Millisecond)
	got, err := gwcs.GatewayV1().GatewayClasses().Get(ctx, "nginx", metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Status.Conditions) != 0 {
		t.Fatalf("a foreign GatewayClass must not get status conditions, got %+v", got.Status.Conditions)
	}
}

// mustCreate seeds gateway-api objects via the TYPED client (the correct resource path),
// working around the fake constructor's naive pluralizer (it mis-stores a seeded Gateway
// under "gatewaies").
func mustCreate(t *testing.T, gwcs *gwfake.Clientset, objs ...any) {
	t.Helper()
	ctx := context.Background()
	for _, o := range objs {
		var err error
		switch v := o.(type) {
		case *gatewayv1.GatewayClass:
			_, err = gwcs.GatewayV1().GatewayClasses().Create(ctx, v, metav1.CreateOptions{})
		case *gatewayv1.Gateway:
			_, err = gwcs.GatewayV1().Gateways(v.Namespace).Create(ctx, v, metav1.CreateOptions{})
		case *gatewayv1.HTTPRoute:
			_, err = gwcs.GatewayV1().HTTPRoutes(v.Namespace).Create(ctx, v, metav1.CreateOptions{})
		default:
			t.Fatalf("mustCreate: unsupported type %T", o)
		}
		if err != nil {
			t.Fatalf("mustCreate %T: %v", o, err)
		}
	}
}

func condTrue(conds []metav1.Condition, t string) bool {
	for _, c := range conds {
		if c.Type == t {
			return c.Status == metav1.ConditionTrue
		}
	}
	return false
}

func waitCond(t *testing.T, cond func() bool, what string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		if cond() {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for: %s", what)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// tlsApplier is an Applier that ALSO implements TLSInjector, capturing injected certs.
type tlsApplier struct {
	applyFn  func(*config.Config) error
	mu       sync.Mutex
	lastSeen []tlsacme.DynamicCert
}

func (a *tlsApplier) ApplyConfig(c *config.Config) error { return a.applyFn(c) }
func (a *tlsApplier) SetDynamicCerts(certs []tlsacme.DynamicCert) error {
	a.mu.Lock()
	a.lastSeen = certs
	a.mu.Unlock()
	return nil
}
func (a *tlsApplier) seen() []tlsacme.DynamicCert {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.lastSeen
}

// tlsSecret builds a kubernetes.io/tls Secret carrying a self-signed cert for sans.
func tlsSecret(ns, name string, sans ...string) *corev1.Secret {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: sans[0]},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		DNSNames:     sans,
	}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	kder, _ := x509.MarshalECPrivateKey(key)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kder})
	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns},
		Type:       corev1.SecretTypeTLS,
		Data:       map[string][]byte{"tls.crt": certPEM, "tls.key": keyPEM},
	}
}

// TestControllerHTTPSInjectsBYOCert: an HTTPS listener with a BYO Secret whose cert covers
// the hostname drives a SetDynamicCerts injection of that cert for that host.
func TestControllerHTTPSInjectsBYOCert(t *testing.T) {
	gc := gatewayClass("cadish", ControllerName)
	mode := gatewayv1.TLSModeTerminate
	g := gw("prod", "gw", "cadish", "")
	g.Spec.Listeners = []gatewayv1.Listener{{
		Name: "https", Port: 443, Protocol: gatewayv1.HTTPSProtocolType,
		Hostname: ptr(gatewayv1.Hostname("secure.example.com")),
		TLS: &gatewayv1.ListenerTLSConfig{Mode: &mode, CertificateRefs: []gatewayv1.SecretObjectReference{
			{Name: gatewayv1.ObjectName("tls-secret")},
		}},
	}}
	rt := httpRoute("prod", "api", "gw", "secure.example.com", "web", 80, []match{{"/", gatewayv1.PathMatchPathPrefix}})

	gwcs := gwfake.NewSimpleClientset()
	mustCreate(t, gwcs, gc, g, rt)
	cs := k8sfake.NewSimpleClientset(
		svc("prod", "web"),
		sliceFor("web", "prod", "10.0.0.1", 80),
		tlsSecret("prod", "tls-secret", "secure.example.com"),
	)

	applier := &tlsApplier{applyFn: func(*config.Config) error { return nil }}
	ctrl := New(cs, gwcs, applier, ``, Config{ResyncDebounce: 10 * time.Millisecond})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = ctrl.Run(ctx) }()

	waitCond(t, func() bool {
		for _, c := range applier.seen() {
			for _, h := range c.Hosts {
				if h == "secure.example.com" && len(c.CertPEM) > 0 {
					return true
				}
			}
		}
		return false
	}, "BYO cert injected for secure.example.com")
}

// TestControllerReferenceGrantBackend: a cross-namespace backendRef resolves only with a
// ReferenceGrant. Without it the route is ResolvedRefs=False (RefNotPermitted); adding the
// grant flips it to True.
func TestControllerReferenceGrantBackend(t *testing.T) {
	gc := gatewayClass("cadish", ControllerName)
	g := gw("team-a", "gw", "cadish", "")
	rt := crossNSRoute("team-a", "api", "gw", "example.com", "team-b", "web", 80)

	gwcs := gwfake.NewSimpleClientset()
	mustCreate(t, gwcs, gc, g, rt)
	cs := k8sfake.NewSimpleClientset(svc("team-b", "web"), sliceFor("web", "team-b", "10.0.0.9", 80))

	applier := applierFunc(func(*config.Config) error { return nil })
	ctrl := New(cs, gwcs, applier, ``, Config{ResyncDebounce: 10 * time.Millisecond})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = ctrl.Run(ctx) }()

	// Without a grant: ResolvedRefs=False with RefNotPermitted.
	waitCond(t, func() bool {
		got, err := gwcs.GatewayV1().HTTPRoutes("team-a").Get(ctx, "api", metav1.GetOptions{})
		if err != nil || len(got.Status.Parents) == 0 {
			return false
		}
		for _, c := range got.Status.Parents[0].Conditions {
			if c.Type == string(gatewayv1.RouteConditionResolvedRefs) {
				return c.Status == metav1.ConditionFalse && c.Reason == string(gatewayv1.RouteReasonRefNotPermitted)
			}
		}
		return false
	}, "ResolvedRefs=False RefNotPermitted without a grant")

	// Add the grant in team-b → ResolvedRefs flips True.
	rg := grant("team-b", "team-a", "HTTPRoute", "Service", "")
	if _, err := gwcs.GatewayV1().ReferenceGrants("team-b").Create(ctx, rg, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	waitCond(t, func() bool {
		got, err := gwcs.GatewayV1().HTTPRoutes("team-a").Get(ctx, "api", metav1.GetOptions{})
		if err != nil || len(got.Status.Parents) == 0 {
			return false
		}
		return condTrue(got.Status.Parents[0].Conditions, string(gatewayv1.RouteConditionResolvedRefs))
	}, "ResolvedRefs=True after adding the ReferenceGrant")
}
