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
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cadi-sh/cadish/internal/config"
	"github.com/cadi-sh/cadish/internal/tlsacme"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

// --- fakes / helpers ---------------------------------------------------------

// tlsApplier is an Applier that ALSO implements TLSInjector, recording the latest
// applied config and the latest injected dynamic cert set.
type tlsApplier struct {
	mu        sync.Mutex
	lastCfg   *config.Config
	lastCerts []tlsacme.DynamicCert
	applyN    int
}

func (a *tlsApplier) ApplyConfig(c *config.Config) error {
	a.mu.Lock()
	a.lastCfg = c
	a.applyN++
	a.mu.Unlock()
	return nil
}

func (a *tlsApplier) SetDynamicCerts(certs []tlsacme.DynamicCert) error {
	a.mu.Lock()
	a.lastCerts = append([]tlsacme.DynamicCert(nil), certs...)
	a.mu.Unlock()
	return nil
}

func (a *tlsApplier) dynamicCertFor(host string) (tlsacme.DynamicCert, bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	for _, c := range a.lastCerts {
		for _, h := range c.Hosts {
			if h == host {
				return c, true
			}
		}
	}
	return tlsacme.DynamicCert{}, false
}

func (a *tlsApplier) appliedText(host string) string {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.lastCfg == nil {
		return ""
	}
	for _, s := range a.lastCfg.Sites {
		for _, addr := range s.Addresses {
			if addr == host {
				return host // present
			}
		}
	}
	return ""
}

// certPEMFor returns a self-signed in-memory keypair for dnsNames (the tls.crt /
// tls.key shape of a kubernetes.io/tls Secret).
func certPEMFor(t *testing.T, dnsNames ...string) (certPEM, keyPEM []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: dnsNames[0]},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              dnsNames,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
}

// tlsSecret builds a kubernetes.io/tls Secret for dnsNames.
func tlsSecret(t *testing.T, ns, name string, dnsNames ...string) *corev1.Secret {
	certPEM, keyPEM := certPEMFor(t, dnsNames...)
	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns},
		Type:       corev1.SecretTypeTLS,
		Data:       map[string][]byte{"tls.crt": certPEM, "tls.key": keyPEM},
	}
}

// ingTLS builds an Ingress with a rule (host→web:80) AND a spec.tls entry.
func ingTLS(ns, name, host, secret string) *networkingv1.Ingress {
	in := ingress(ns, name, host, []pathRule{{path: "/", pathType: prefix, svc: "web", port: 80}})
	in.Spec.TLS = []networkingv1.IngressTLS{{SecretName: secret, Hosts: []string{host}}}
	return in
}

func runController(t *testing.T, cs *fake.Clientset, applier Applier, cfg Config) *Controller {
	t.Helper()
	if cfg.ResyncDebounce == 0 {
		cfg.ResyncDebounce = 10 * time.Millisecond
	}
	if cfg.ClassName == "" {
		cfg.ClassName = "cadish"
	}
	ctrl := New(cs, applier, "", cfg)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go func() { _ = ctrl.Run(ctx) }()
	return ctrl
}

func eventually(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		if cond() {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for: %s", what)
		}
		time.Sleep(15 * time.Millisecond)
	}
}

func warningEventContains(cs *fake.Clientset, ns, substr string) bool {
	evs, _ := cs.CoreV1().Events(ns).List(context.Background(), metav1.ListOptions{})
	for _, e := range evs.Items {
		if e.Type == corev1.EventTypeWarning && strings.Contains(strings.ToLower(e.Message), strings.ToLower(substr)) {
			return true
		}
	}
	return false
}

// --- tests -------------------------------------------------------------------

// TestController_BYOSecretServed: a spec.tls host whose Secret EXISTS gets its BYO
// keypair injected (the side-channel), and its site carries NO `tls acme` directive.
func TestController_BYOSecretServed(t *testing.T) {
	ready := true
	cs := fake.NewSimpleClientset(
		ingTLS("prod", "site", "example.com", "web-cert"),
		tlsSecret(t, "prod", "web-cert", "example.com"),
		sliceFor("web", "prod", []epSpec{{ip: "10.0.0.1", ready: &ready}}, portSpec{name: "", num: 80}),
	)
	a := &tlsApplier{}
	runController(t, cs, a, Config{ACMEEmail: "ops@example.com"})

	eventually(t, "BYO cert injected for example.com", func() bool {
		_, ok := a.dynamicCertFor("example.com")
		return ok
	})
	// The rendered (applied) config must serve example.com WITHOUT a tls acme directive.
	eventually(t, "example.com site applied", func() bool { return a.appliedText("example.com") != "" })
	a.mu.Lock()
	defer a.mu.Unlock()
	for _, s := range a.lastCfg.TLS {
		for _, h := range s.Hosts {
			if h == "example.com" && s.TLS.Mode == tlsacme.ModeACME {
				t.Fatal("BYO host must NOT be ACME-mode (no tls acme directive)")
			}
		}
	}
}

// TestController_MissingSecretFallsToACME: a spec.tls host whose Secret is ABSENT gets
// a `tls acme` directive (ACME-mode in cfg.TLS) and no BYO cert.
func TestController_MissingSecretFallsToACME(t *testing.T) {
	ready := true
	cs := fake.NewSimpleClientset(
		ingTLS("prod", "site", "api.example.com", "missing-cert"),
		sliceFor("web", "prod", []epSpec{{ip: "10.0.0.1", ready: &ready}}, portSpec{name: "", num: 80}),
	)
	a := &tlsApplier{}
	runController(t, cs, a, Config{ACMEEmail: "ops@example.com"})

	eventually(t, "api.example.com applied as ACME", func() bool {
		a.mu.Lock()
		defer a.mu.Unlock()
		if a.lastCfg == nil {
			return false
		}
		for _, s := range a.lastCfg.TLS {
			for _, h := range s.Hosts {
				if h == "api.example.com" && s.TLS.Mode == tlsacme.ModeACME {
					return true
				}
			}
		}
		return false
	})
	if _, ok := a.dynamicCertFor("api.example.com"); ok {
		t.Fatal("a Secret-less ACME host must not receive a BYO cert")
	}
}

// TestController_ACMEDomainPolicyExcludesDisallowed is the A2 end-to-end guard: with a
// per-namespace ACME domain allow-list set, a Secret-less (ACME) host whose OWNING
// namespace is not permitted that domain is NOT rendered as ACME-mode TLS (excluded from
// the issuer HostPolicy) and a warning Event is emitted; a permitted host stays ACME.
func TestController_ACMEDomainPolicyExcludesDisallowed(t *testing.T) {
	ready := true
	// ns-a owns both hosts; both Secrets are absent so both would otherwise go ACME.
	permitted := ingTLS("ns-a", "ok", "ok.example.com", "missing-a")
	disallowed := ingTLS("ns-a", "evil", "evil.victim.com", "missing-b")
	cs := fake.NewSimpleClientset(
		permitted, disallowed,
		sliceFor("web", "ns-a", []epSpec{{ip: "10.0.0.1", ready: &ready}}, portSpec{name: "", num: 80}),
	)
	a := &tlsApplier{}
	runController(t, cs, a, Config{
		ACMEEmail:        "ops@example.com",
		ACMEDomainPolicy: ACMEDomainPolicy{"ns-a": {"example.com"}},
	})

	// The permitted host is ACME-mode.
	eventually(t, "ok.example.com applied as ACME", func() bool { return a.hostIsACME("ok.example.com") })
	// The disallowed host must NEVER be ACME-mode (excluded from the issuer HostPolicy).
	if a.hostIsACME("evil.victim.com") {
		t.Fatal("evil.victim.com must be excluded from ACME (namespace not permitted that domain)")
	}
	// A warning Event surfaces the exclusion.
	eventually(t, "warning Event for the disallowed ACME host", func() bool {
		return warningEventContains(cs, "ns-a", "not permitted")
	})
}

// TestController_ACMEDomainPolicyOffByDefault proves the default (no policy) is unchanged:
// every watched ACME host stays eligible.
func TestController_ACMEDomainPolicyOffByDefault(t *testing.T) {
	ready := true
	cs := fake.NewSimpleClientset(
		ingTLS("ns-a", "evil", "evil.victim.com", "missing-b"),
		sliceFor("web", "ns-a", []epSpec{{ip: "10.0.0.1", ready: &ready}}, portSpec{name: "", num: 80}),
	)
	a := &tlsApplier{}
	runController(t, cs, a, Config{ACMEEmail: "ops@example.com"}) // no ACMEDomainPolicy
	eventually(t, "evil.victim.com ACME-eligible with no policy", func() bool { return a.hostIsACME("evil.victim.com") })
}

// TestController_SecretRotationHotSwap: re-issuing a BYO Secret hot-swaps the injected
// keypair without a restart (same controller).
func TestController_SecretRotationHotSwap(t *testing.T) {
	ready := true
	sec := tlsSecret(t, "prod", "web-cert", "example.com")
	cs := fake.NewSimpleClientset(
		ingTLS("prod", "site", "example.com", "web-cert"),
		sec,
		sliceFor("web", "prod", []epSpec{{ip: "10.0.0.1", ready: &ready}}, portSpec{name: "", num: 80}),
	)
	a := &tlsApplier{}
	runController(t, cs, a, Config{})

	var first []byte
	eventually(t, "initial BYO cert injected", func() bool {
		c, ok := a.dynamicCertFor("example.com")
		if ok {
			first = c.CertPEM
		}
		return ok
	})

	// Rotate the Secret (a fresh keypair) and update it in the cluster.
	newCert, newKey := certPEMFor(t, "example.com")
	rot := sec.DeepCopy()
	rot.Data["tls.crt"] = newCert
	rot.Data["tls.key"] = newKey
	if _, err := cs.CoreV1().Secrets("prod").Update(context.Background(), rot, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}

	eventually(t, "rotated BYO cert hot-swapped", func() bool {
		c, ok := a.dynamicCertFor("example.com")
		return ok && string(c.CertPEM) != string(first)
	})
}

// TestController_AddRemoveTLSHostLive: adding a second TLS Ingress injects a second
// cert live; deleting it removes it — no restart.
func TestController_AddRemoveTLSHostLive(t *testing.T) {
	ready := true
	cs := fake.NewSimpleClientset(
		ingTLS("prod", "a", "a.example.com", "a-cert"),
		tlsSecret(t, "prod", "a-cert", "a.example.com"),
		tlsSecret(t, "prod", "b-cert", "b.example.com"),
		sliceFor("web", "prod", []epSpec{{ip: "10.0.0.1", ready: &ready}}, portSpec{name: "", num: 80}),
	)
	a := &tlsApplier{}
	runController(t, cs, a, Config{})

	eventually(t, "a.example.com cert", func() bool { _, ok := a.dynamicCertFor("a.example.com"); return ok })

	// Add a second TLS Ingress.
	bIng := ingTLS("prod", "b", "b.example.com", "b-cert")
	if _, err := cs.NetworkingV1().Ingresses("prod").Create(context.Background(), bIng, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	eventually(t, "b.example.com cert added live", func() bool { _, ok := a.dynamicCertFor("b.example.com"); return ok })

	// Remove it.
	if err := cs.NetworkingV1().Ingresses("prod").Delete(context.Background(), "b", metav1.DeleteOptions{}); err != nil {
		t.Fatal(err)
	}
	eventually(t, "b.example.com cert removed live", func() bool { _, ok := a.dynamicCertFor("b.example.com"); return !ok })
	// a.example.com must keep serving throughout.
	if _, ok := a.dynamicCertFor("a.example.com"); !ok {
		t.Fatal("a.example.com cert must survive the add/remove of b")
	}
}

// hostIsACME reports whether the applied config marks host as ACME-mode TLS.
func (a *tlsApplier) hostIsACME(host string) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.lastCfg == nil {
		return false
	}
	for _, s := range a.lastCfg.TLS {
		for _, h := range s.Hosts {
			if h == host && s.TLS.Mode == tlsacme.ModeACME {
				return true
			}
		}
	}
	return false
}

// errInjectApplier always fails SetDynamicCerts (to exercise FIX 3) while applying
// routing normally.
type errInjectApplier struct{ tlsApplier }

func (a *errInjectApplier) SetDynamicCerts([]tlsacme.DynamicCert) error {
	return errInject
}

var errInject = errorString("inject boom")

type errorString string

func (e errorString) Error() string { return string(e) }

// TestController_CorruptSecretFallsToACME (FIX 2): a watched TLS host whose Secret is
// PRESENT but contains an unparseable keypair is treated as UNUSABLE, so the host falls
// back to ACME issuance (it appears ACME-mode in cfg.TLS) rather than being left dark.
// A de-duped warning Event names the corrupt Secret, and the host gets no BYO cert.
func TestController_CorruptSecretFallsToACME(t *testing.T) {
	ready := true
	corrupt := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "web-cert", Namespace: "prod"},
		Type:       corev1.SecretTypeTLS,
		Data: map[string][]byte{
			"tls.crt": []byte("-----BEGIN CERTIFICATE-----\nnope\n-----END CERTIFICATE-----\n"),
			"tls.key": []byte("garbage"),
		},
	}
	cs := fake.NewSimpleClientset(
		ingTLS("prod", "site", "example.com", "web-cert"),
		corrupt,
		sliceFor("web", "prod", []epSpec{{ip: "10.0.0.1", ready: &ready}}, portSpec{name: "", num: 80}),
	)
	a := &tlsApplier{}
	runController(t, cs, a, Config{ACMEEmail: "ops@example.com"})

	// Falls back to ACME (not dark).
	eventually(t, "example.com falls back to ACME", func() bool { return a.hostIsACME("example.com") })
	// Warning Event names the corrupt Secret.
	eventually(t, "BadTLSSecret warning event", func() bool {
		return warningEventContains(cs, "prod", "not a usable")
	})
	// And it is NOT served a BYO dynamic cert.
	if _, ok := a.dynamicCertFor("example.com"); ok {
		t.Fatal("a corrupt-Secret host must not receive a BYO cert")
	}
}

// TestController_InjectionErrorSurfaced (FIX 3): a dynamic-cert injection failure is
// surfaced in Stats.LastError even though the routing apply succeeds.
func TestController_InjectionErrorSurfaced(t *testing.T) {
	ready := true
	cs := fake.NewSimpleClientset(
		ingTLS("prod", "site", "example.com", "web-cert"),
		tlsSecret(t, "prod", "web-cert", "example.com"),
		sliceFor("web", "prod", []epSpec{{ip: "10.0.0.1", ready: &ready}}, portSpec{name: "", num: 80}),
	)
	a := &errInjectApplier{}
	ctrl := runController(t, cs, a, Config{})

	// Routing applies (the embedded tlsApplier.ApplyConfig succeeds) yet the injection
	// error must still appear in Stats.
	eventually(t, "injection error surfaced in Stats.LastError", func() bool {
		return strings.Contains(ctrl.Stats().LastError, "inject boom") && a.appliedText("example.com") != ""
	})
}

// TestController_MultiHostSecretSANMismatch (F10): a single spec.tls entry lists
// [a.example.com, b.example.com] for a Secret whose cert SAN covers ONLY a.example.com.
// a.example.com must get the BYO cert; b.example.com must NOT be served a.example.com's
// cert (no dynamic cert registered for it) — it falls back to ACME — and a warning Event
// names the SAN mismatch.
func TestController_MultiHostSecretSANMismatch(t *testing.T) {
	ready := true
	// One Ingress routing both hosts, with a single spec.tls entry covering [a, b].
	ing := ingress("prod", "site", "a.example.com", []pathRule{{path: "/", pathType: prefix, svc: "web", port: 80}})
	bRule := ingress("prod", "site-b", "b.example.com", []pathRule{{path: "/", pathType: prefix, svc: "web", port: 80}}).Spec.Rules[0]
	ing.Spec.Rules = append(ing.Spec.Rules, bRule)
	ing.Spec.TLS = []networkingv1.IngressTLS{{
		SecretName: "ab-cert",
		Hosts:      []string{"a.example.com", "b.example.com"},
	}}
	// Secret cert SAN covers ONLY a.example.com.
	cs := fake.NewSimpleClientset(
		ing,
		tlsSecret(t, "prod", "ab-cert", "a.example.com"),
		sliceFor("web", "prod", []epSpec{{ip: "10.0.0.1", ready: &ready}}, portSpec{name: "", num: 80}),
	)
	a := &tlsApplier{}
	runController(t, cs, a, Config{ACMEEmail: "ops@example.com"})

	// a.example.com gets the BYO cert.
	eventually(t, "a.example.com BYO cert injected", func() bool {
		_, ok := a.dynamicCertFor("a.example.com")
		return ok
	})
	// b.example.com must NOT be served the mismatched cert.
	if _, ok := a.dynamicCertFor("b.example.com"); ok {
		t.Fatal("b.example.com must NOT receive a.example.com's mismatched cert (SAN mismatch)")
	}
	// b.example.com falls back to ACME (never left dark).
	eventually(t, "b.example.com falls back to ACME", func() bool { return a.hostIsACME("b.example.com") })
	// And a is BYO, never ACME.
	if a.hostIsACME("a.example.com") {
		t.Fatal("a.example.com is covered by the BYO cert; must not be ACME-mode")
	}
	// A warning Event names the SAN mismatch for b.example.com.
	eventually(t, "SAN mismatch warning event", func() bool {
		return warningEventContains(cs, "prod", "b.example.com") &&
			warningEventContains(cs, "prod", "SANs")
	})
}

// TestHostPolicyUnion proves the ACME bound is the UNION of watched TLS+rule hosts and
// never open (an unrelated host is absent).
func TestHostPolicyUnion(t *testing.T) {
	a := ingTLS("prod", "a", "a.example.com", "a-cert")
	b := ingress("prod", "b", "b.example.com", []pathRule{{path: "/", pathType: prefix, svc: "web", port: 80}})
	union := HostPolicyUnion([]*networkingv1.Ingress{a, b})
	if !contains(union, "a.example.com") || !contains(union, "b.example.com") {
		t.Fatalf("union must include every watched host: %v", union)
	}
	if contains(union, "unwatched.example.com") {
		t.Fatalf("union must never include an unwatched host: %v", union)
	}
}
