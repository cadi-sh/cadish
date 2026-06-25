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
	"testing"
	"time"

	"github.com/cadi-sh/cadish/internal/config"
	"github.com/cadi-sh/cadish/internal/tlsacme"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

// managedLabelSelector is the canonical "cadish-managed" selector the tests opt into.
const managedLabelSelector = "cadi.sh/managed=true"

// selfSignedPEM returns a PEM-encoded self-signed keypair for host (a usable
// kubernetes.io/tls Secret payload). Mirrors the integration test's helper but lives in
// the default build so the selector unit tests run in the green gate.
func selfSignedPEM(t *testing.T, host string) (crt, key []byte) {
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

// labelSelectorCertApplier captures applied configs AND injected dynamic certs so the
// label-scoping tests can assert what the controller saw for BOTH ConfigMaps and Secrets.
type labelSelectorCertApplier struct {
	configs chan *config.Config
	certs   chan []tlsacme.DynamicCert
}

func (a *labelSelectorCertApplier) ApplyConfig(c *config.Config) error {
	select {
	case a.configs <- c:
	default:
	}
	return nil
}

func (a *labelSelectorCertApplier) SetDynamicCerts(d []tlsacme.DynamicCert) error {
	select {
	case a.certs <- d:
	default:
	}
	return nil
}

func newLabelSelectorApplier() *labelSelectorCertApplier {
	return &labelSelectorCertApplier{
		configs: make(chan *config.Config, 16),
		certs:   make(chan []tlsacme.DynamicCert, 16),
	}
}

// tlsSecretObj builds a usable kubernetes.io/tls Secret for host, optionally labelled.
func tlsSecretObj(t *testing.T, ns, name, host string, labeled bool) *corev1.Secret {
	t.Helper()
	crt, key := selfSignedPEM(t, host)
	s := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns},
		Type:       corev1.SecretTypeTLS,
		Data:       map[string][]byte{"tls.crt": crt, "tls.key": key},
	}
	if labeled {
		s.Labels = map[string]string{"cadi.sh/managed": "true"}
	}
	return s
}

// withTLS attaches a spec.tls entry (host → secretName) to ing.
func withTLS(ing *networkingv1.Ingress, host, secret string) *networkingv1.Ingress {
	ing.Spec.TLS = append(ing.Spec.TLS, networkingv1.IngressTLS{Hosts: []string{host}, SecretName: secret})
	return ing
}

// invalidPolicyCM builds a cadi.sh/policy ConfigMap with an INVALID fragment (an unknown
// directive) so that, IF the controller reads it, the translator emits a distinctive
// "invalid cadi.sh/policy fragment" reject — letting a test prove the ConfigMap WAS seen.
// A ConfigMap filtered out by the selector instead resolves to "not found".
func invalidPolicyCM(ns, name string, labeled bool) *corev1.ConfigMap {
	cm := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns},
		Data:       map[string]string{policyConfigMapKey: "this_is_not_a_real_directive foo bar"},
	}
	if labeled {
		cm.Labels = map[string]string{"cadi.sh/managed": "true"}
	}
	return cm
}

// waitCertInjected drains the cert channel until a DynamicCert for host appears.
func waitCertInjected(certs chan []tlsacme.DynamicCert, host string, d time.Duration) bool {
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		select {
		case set := <-certs:
			for _, dc := range set {
				for _, h := range dc.Hosts {
					if h == host {
						return true
					}
				}
			}
		case <-time.After(20 * time.Millisecond):
		}
	}
	return false
}

// waitReject polls Events in ns until a warning Event whose message contains substr
// appears (or the deadline elapses).
func waitReject(t *testing.T, cs *fake.Clientset, ns, substr string, d time.Duration) bool {
	t.Helper()
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		evs, _ := cs.CoreV1().Events(ns).List(context.Background(), metav1.ListOptions{})
		for _, e := range evs.Items {
			if e.Type == corev1.EventTypeWarning && strings.Contains(e.Message, substr) {
				return true
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	return false
}

// TestSecretLabelSelectorScopesReads proves that with a Secret label selector set, an
// UNLABELED kubernetes.io/tls Secret is NOT seen (its host falls through to ACME — no BYO
// cert is injected) while a LABELED one IS injected.
func TestSecretLabelSelectorScopesReads(t *testing.T) {
	const ns = "prod"
	const labeledHost = "labeled.example.com"
	const unlabeledHost = "unlabeled.example.com"
	ready := true

	labeledIng := withTLS(ingress(ns, "labeled", labeledHost,
		[]pathRule{{path: "/", pathType: prefix, svc: "web", port: 80}}), labeledHost, "labeled-tls")
	unlabeledIng := withTLS(ingress(ns, "unlabeled", unlabeledHost,
		[]pathRule{{path: "/", pathType: prefix, svc: "web", port: 80}}), unlabeledHost, "unlabeled-tls")

	cs := fake.NewSimpleClientset(
		labeledIng,
		unlabeledIng,
		tlsSecretObj(t, ns, "labeled-tls", labeledHost, true),
		tlsSecretObj(t, ns, "unlabeled-tls", unlabeledHost, false),
		sliceFor("web", ns, []epSpec{{ip: "10.0.0.1", ready: &ready}}, portSpec{name: "", num: 80}),
	)
	app := newLabelSelectorApplier()
	ctrl := New(cs, app, ``, Config{
		ClassName:           "cadish",
		ResyncDebounce:      10 * time.Millisecond,
		SecretLabelSelector: managedLabelSelector,
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = ctrl.Run(ctx) }()

	if !waitCertInjected(app.certs, labeledHost, 5*time.Second) {
		t.Fatalf("labeled Secret should be injected as a BYO cert")
	}
	// Give the controller ample time; the unlabeled host must never get a BYO cert.
	if waitCertInjected(app.certs, unlabeledHost, time.Second) {
		t.Fatalf("unlabeled Secret must NOT be seen with a Secret label selector set")
	}
}

// TestConfigMapLabelSelectorScopesReads proves that with a ConfigMap label selector set,
// an UNLABELED cadi.sh/policy ConfigMap is NOT seen (the lister reports it "not found")
// while a LABELED one IS read (its invalid fragment is surfaced as a distinct reject).
func TestConfigMapLabelSelectorScopesReads(t *testing.T) {
	const ns = "prod"
	ready := true

	labeledIng := ingressWithPolicy(ns, "labeled", "labeled.example.com", ns+"/labeled-pol",
		[]pathRule{{path: "/", pathType: prefix, svc: "web", port: 80}})
	unlabeledIng := ingressWithPolicy(ns, "unlabeled", "unlabeled.example.com", ns+"/unlabeled-pol",
		[]pathRule{{path: "/", pathType: prefix, svc: "web", port: 80}})

	cs := fake.NewSimpleClientset(
		labeledIng,
		unlabeledIng,
		invalidPolicyCM(ns, "labeled-pol", true),
		invalidPolicyCM(ns, "unlabeled-pol", false),
		sliceFor("web", ns, []epSpec{{ip: "10.0.0.1", ready: &ready}}, portSpec{name: "", num: 80}),
	)
	app := newLabelSelectorApplier()
	ctrl := New(cs, app, ``, Config{
		ClassName:              "cadish",
		ResyncDebounce:         10 * time.Millisecond,
		ConfigMapLabelSelector: managedLabelSelector,
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = ctrl.Run(ctx) }()

	// The LABELED ConfigMap is read → its invalid fragment is surfaced as a reject naming
	// THAT ConfigMap.
	if !waitReject(t, cs, ns, "invalid cadi.sh/policy fragment", 5*time.Second) {
		t.Fatalf("labeled ConfigMap should be read (invalid-fragment reject expected)")
	}
	// Both sites must still serve, and exactly ONE invalid-fragment reject must exist (the
	// labeled one). The UNLABELED ConfigMap is filtered out of the informer cache, so its
	// fragment resolves to empty (invisible) — it must NOT surface an invalid-fragment
	// reject. A standing reject de-dups, so counting the references in reject Events is the
	// reliable signal that only the labeled fragment was read.
	var got *config.Config
	deadline := time.Now().Add(5 * time.Second)
	for got == nil && time.Now().Before(deadline) {
		select {
		case c := <-app.configs:
			if hasSiteHost(c, "labeled.example.com") && hasSiteHost(c, "unlabeled.example.com") {
				got = c
			}
		case <-time.After(20 * time.Millisecond):
		}
	}
	if got == nil {
		t.Fatal("controller never applied a config with both sites")
	}
	// Count invalid-fragment rejects: exactly one (labeled-pol), never unlabeled-pol.
	if countInvalidFragmentRejects(t, cs, ns, ns+"/labeled-pol") == 0 {
		t.Errorf("labeled-pol should have an invalid-fragment reject")
	}
	if n := countInvalidFragmentRejects(t, cs, ns, ns+"/unlabeled-pol"); n != 0 {
		t.Errorf("unlabeled-pol must be invisible (filtered), got %d invalid-fragment rejects", n)
	}
}

// countInvalidFragmentRejects counts warning Events whose message reports an invalid
// cadi.sh/policy fragment AND names ref (the "ns/name" of the offending ConfigMap).
func countInvalidFragmentRejects(t *testing.T, cs *fake.Clientset, ns, ref string) int {
	t.Helper()
	evs, _ := cs.CoreV1().Events(ns).List(context.Background(), metav1.ListOptions{})
	n := 0
	for _, e := range evs.Items {
		if e.Type == corev1.EventTypeWarning &&
			strings.Contains(e.Message, "invalid cadi.sh/policy fragment") &&
			(e.InvolvedObject.Name == "unlabeled-pol" || e.InvolvedObject.Name == "labeled-pol") {
			// The reject's Ingress field is the policyRef "ns/name"; the Event name is built
			// from that ref's name. Match on the involved-object name.
			wantName := ref[strings.IndexByte(ref, '/')+1:]
			if e.InvolvedObject.Name == wantName {
				n++
			}
		}
	}
	return n
}

// TestNoSelectorSeesEverything proves the default (no selector) behaviour is unchanged:
// an UNLABELED Secret is injected and an UNLABELED ConfigMap is read.
func TestNoSelectorSeesEverything(t *testing.T) {
	const ns = "prod"
	const host = "plain.example.com"
	ready := true

	ing := withTLS(ingressWithPolicy(ns, "site", host, ns+"/pol",
		[]pathRule{{path: "/", pathType: prefix, svc: "web", port: 80}}), host, "plain-tls")

	cs := fake.NewSimpleClientset(
		ing,
		invalidPolicyCM(ns, "pol", false), // UNLABELED ConfigMap
		tlsSecretObj(t, ns, "plain-tls", host, false), // UNLABELED Secret
		sliceFor("web", ns, []epSpec{{ip: "10.0.0.1", ready: &ready}}, portSpec{name: "", num: 80}),
	)
	app := newLabelSelectorApplier()
	ctrl := New(cs, app, ``, Config{ClassName: "cadish", ResyncDebounce: 10 * time.Millisecond})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = ctrl.Run(ctx) }()

	if !waitCertInjected(app.certs, host, 5*time.Second) {
		t.Fatalf("with no selector the unlabeled Secret must still be injected")
	}
	// The unlabeled ConfigMap is read (its invalid fragment surfaces a reject) — proving
	// it was visible, not silently filtered.
	if !waitReject(t, cs, ns, "invalid cadi.sh/policy fragment", 5*time.Second) {
		t.Fatalf("with no selector the unlabeled ConfigMap must still be read")
	}
}
