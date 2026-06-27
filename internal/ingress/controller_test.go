package ingress

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cadi-sh/cadish/internal/config"
	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	networkingv1 "k8s.io/api/networking/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"
)

// --- fakes / helpers ---------------------------------------------------------

// applierFunc adapts a func to the Applier interface.
type applierFunc func(*config.Config) error

func (f applierFunc) ApplyConfig(c *config.Config) error { return f(c) }

// warmApplier is an Applier that ALSO implements Warmer, recording ApplyConfig + MarkWarm
// call counts so a test can assert the warm-readiness gate flips (only) after a successful
// reconcile. applyErr, when set, makes ApplyConfig fail (a first-reconcile failure must NOT
// mark warm).
type warmApplier struct {
	applyErr error
	applied  atomic.Int32
	warmed   atomic.Int32
}

func (w *warmApplier) ApplyConfig(*config.Config) error {
	w.applied.Add(1)
	return w.applyErr
}

func (w *warmApplier) MarkWarm() { w.warmed.Add(1) }

// hasSiteHost reports whether cfg has a site serving host.
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

type epSpec struct {
	ip    string
	ready *bool
}

type portSpec struct {
	name string
	num  int32
}

// sliceFor builds an EndpointSlice labelled for service in namespace (mirrors the
// Layer-1 test helper; the controller resolves k8s:// via Layer 1's resolver).
func sliceFor(service, namespace string, eps []epSpec, port portSpec) *discoveryv1.EndpointSlice {
	name := service
	endpoints := make([]discoveryv1.Endpoint, 0, len(eps))
	for _, e := range eps {
		name += "-" + e.ip
		ready := e.ready
		endpoints = append(endpoints, discoveryv1.Endpoint{
			Addresses:  []string{e.ip},
			Conditions: discoveryv1.EndpointConditions{Ready: ready},
		})
	}
	pname := port.name
	pnum := port.num
	return &discoveryv1.EndpointSlice{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
			Labels:    map[string]string{"kubernetes.io/service-name": service},
		},
		AddressType: discoveryv1.AddressTypeIPv4,
		Endpoints:   endpoints,
		Ports:       []discoveryv1.EndpointPort{{Name: &pname, Port: &pnum}},
	}
}

// ingressAt is ingress() with an explicit creationTimestamp (for oldest-wins tests).
func ingressAt(ns, name, host string, created time.Time, rules []pathRule) *networkingv1.Ingress {
	in := ingress(ns, name, host, rules)
	in.CreationTimestamp = metav1.NewTime(created)
	return in
}

// --- tests -------------------------------------------------------------------

func TestControllerReconcileApplies(t *testing.T) {
	ready := true
	cs := fake.NewSimpleClientset(
		ingress("prod", "site", "example.com", []pathRule{{path: "/", pathType: prefix, svc: "web", port: 80}}),
		sliceFor("web", "prod", []epSpec{{ip: "10.0.0.1", ready: &ready}}, portSpec{name: "", num: 80}),
	)
	applied := make(chan *config.Config, 4)
	applier := applierFunc(func(c *config.Config) error { applied <- c; return nil })
	base := ``
	ctrl := New(cs, applier, base, Config{ClassName: "cadish", ResyncDebounce: 10 * time.Millisecond})

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

	// Stats reflect a healthy reconcile (1 watched Ingress, no error, a non-empty hash).
	deadline := time.Now().Add(3 * time.Second)
	for {
		s := ctrl.Stats()
		if s.WatchedIngresses == 1 && s.LastError == "" && s.LastAppliedHash != "" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("unexpected stats: %+v", ctrl.Stats())
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// TestControllerSalvagesBadSite is the FIX-3 graceful-degradation guard: a policy
// fragment on site X passes isolated validation but COLLIDES in the combined compile (it
// redefines the generated @r0 matcher). The controller must drop ONLY site X and still
// apply sites Y and Z — one tenant's bad fragment must never freeze all cluster routing.
func TestControllerSalvagesBadSite(t *testing.T) {
	ready := true
	t0 := time.Unix(1000, 0)
	// X: a path rule (generates @r0) + a policy fragment that redefines @r0 → combined
	// compile failure, but passes isolated validateFragment.
	xIng := ingressAt("prod", "x", "x.test", t0, []pathRule{{path: "/api", pathType: prefix, svc: "web", port: 80}})
	xIng.Annotations = map[string]string{policyAnnotation: "prod/p"}
	badFrag := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{Name: "p", Namespace: "prod"},
		Data:       map[string]string{policyConfigMapKey: "@r0 path /foo\ncache_ttl @r0 ttl 1h"},
	}
	cs := fake.NewSimpleClientset(
		xIng,
		ingressAt("prod", "y", "y.test", t0, []pathRule{{path: "/", pathType: prefix, svc: "web", port: 80}}),
		ingressAt("prod", "z", "z.test", t0, []pathRule{{path: "/", pathType: prefix, svc: "web", port: 80}}),
		badFrag,
		sliceFor("web", "prod", []epSpec{{ip: "10.0.0.1", ready: &ready}}, portSpec{name: "", num: 80}),
	)
	applied := make(chan *config.Config, 16)
	applier := applierFunc(func(c *config.Config) error { applied <- c; return nil })
	ctrl := New(cs, applier, ``, Config{ClassName: "cadish", ResyncDebounce: 10 * time.Millisecond})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = ctrl.Run(ctx) }()

	select {
	case cfg := <-applied:
		if !hasSiteHost(cfg, "y.test") || !hasSiteHost(cfg, "z.test") {
			t.Fatalf("salvaged apply must still serve y.test and z.test")
		}
		if hasSiteHost(cfg, "x.test") {
			t.Fatalf("the offending site x.test must be dropped, not served")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("controller never applied a salvaged config")
	}

	// A warning Event names the dropped site / its Ingress.
	deadline := time.Now().Add(5 * time.Second)
	for {
		evs, _ := cs.CoreV1().Events("prod").List(ctx, metav1.ListOptions{})
		for _, e := range evs.Items {
			if e.Type == corev1.EventTypeWarning && strings.Contains(strings.ToLower(e.Message), "x.test") {
				return
			}
		}
		if time.Now().After(deadline) {
			t.Fatal("no warning Event emitted for the dropped site x.test")
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// TestControllerMarksWarmAfterFirstReconcile proves the warm-readiness gate flips once the
// first successful reconcile builds the routing table: the controller calls MarkWarm on the
// Warmer applier only AFTER ApplyConfig succeeds.
func TestControllerMarksWarmAfterFirstReconcile(t *testing.T) {
	ready := true
	cs := fake.NewSimpleClientset(
		ingress("prod", "site", "example.com", []pathRule{{path: "/", pathType: prefix, svc: "web", port: 80}}),
		sliceFor("web", "prod", []epSpec{{ip: "10.0.0.1", ready: &ready}}, portSpec{name: "", num: 80}),
	)
	applier := &warmApplier{}
	ctrl := New(cs, applier, ``, Config{ClassName: "cadish", ResyncDebounce: 10 * time.Millisecond})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = ctrl.Run(ctx) }()

	deadline := time.Now().Add(5 * time.Second)
	for {
		if applier.warmed.Load() > 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("controller never marked warm (applied=%d warmed=%d)", applier.applied.Load(), applier.warmed.Load())
		}
		time.Sleep(10 * time.Millisecond)
	}
	if applier.applied.Load() == 0 {
		t.Fatal("marked warm without ever applying a config")
	}
}

// TestControllerDoesNotMarkWarmOnFailedFirstReconcile is the fail-safe guard: when the very
// first ApplyConfig fails, the controller keeps the last good config AND must NOT mark warm
// — the pod stays NOT-ready (503) until a reconcile succeeds.
func TestControllerDoesNotMarkWarmOnFailedFirstReconcile(t *testing.T) {
	ready := true
	cs := fake.NewSimpleClientset(
		ingress("prod", "site", "example.com", []pathRule{{path: "/", pathType: prefix, svc: "web", port: 80}}),
		sliceFor("web", "prod", []epSpec{{ip: "10.0.0.1", ready: &ready}}, portSpec{name: "", num: 80}),
	)
	applier := &warmApplier{applyErr: errors.New("apply boom")}
	ctrl := New(cs, applier, ``, Config{ClassName: "cadish", ResyncDebounce: 10 * time.Millisecond})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = ctrl.Run(ctx) }()

	// Wait until the controller has attempted (and failed) at least one ApplyConfig.
	deadline := time.Now().Add(5 * time.Second)
	for {
		if applier.applied.Load() > 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("controller never attempted ApplyConfig")
		}
		time.Sleep(10 * time.Millisecond)
	}
	// Give the reconcile loop a few more cycles; a failing apply must NEVER mark warm.
	time.Sleep(200 * time.Millisecond)
	if w := applier.warmed.Load(); w != 0 {
		t.Fatalf("controller marked warm %d time(s) despite a failing first reconcile", w)
	}
}

// TestClusterEventDedup proves RenderFailed/ApplyFailed cluster Events are delta-deduped:
// an identical standing failure emits one Event, not one per reconcile.
func TestClusterEventDedup(t *testing.T) {
	cs := fake.NewSimpleClientset()
	ctrl := New(cs, applierFunc(func(*config.Config) error { return nil }), "", Config{ClassName: "cadish"})

	ctrl.emitClusterEventDeduped(corev1.EventTypeWarning, "RenderFailed", "boom")
	ctrl.emitClusterEventDeduped(corev1.EventTypeWarning, "RenderFailed", "boom") // identical → no new Event
	evs, _ := cs.CoreV1().Events(metav1.NamespaceDefault).List(context.Background(), metav1.ListOptions{})
	if len(evs.Items) != 1 {
		t.Fatalf("standing RenderFailed should emit one Event across two reconciles, got %d", len(evs.Items))
	}
	// A changed message emits a new Event.
	ctrl.emitClusterEventDeduped(corev1.EventTypeWarning, "RenderFailed", "different")
	evs, _ = cs.CoreV1().Events(metav1.NamespaceDefault).List(context.Background(), metav1.ListOptions{})
	if len(evs.Items) != 2 {
		t.Fatalf("changed RenderFailed message should emit a second Event, got %d", len(evs.Items))
	}
}

// TestRejectEventsDedup proves a standing reject is surfaced once, not re-emitted on a
// second identical reconcile (which would spam etcd), while a NEW reject still emits.
func TestRejectEventsDedup(t *testing.T) {
	cs := fake.NewSimpleClientset()
	ctrl := New(cs, applierFunc(func(*config.Config) error { return nil }), "", Config{ClassName: "cadish"})

	standing := []Reject{{Ingress: "prod/dup", Reason: `duplicate path Prefix "/" on host example.com (older Ingress wins)`}}
	ctrl.emitRejectEvents(standing)
	ctrl.emitRejectEvents(standing) // identical standing reject → no new Event

	evs, _ := cs.CoreV1().Events("prod").List(context.Background(), metav1.ListOptions{})
	if len(evs.Items) != 1 {
		t.Fatalf("standing reject should emit exactly one Event across two reconciles, got %d", len(evs.Items))
	}

	// A new reject (plus the still-standing one) emits exactly one more Event.
	ctrl.emitRejectEvents([]Reject{standing[0], {Ingress: "prod/other", Reason: "spec.defaultBackend has no service.name/port"}})
	evs, _ = cs.CoreV1().Events("prod").List(context.Background(), metav1.ListOptions{})
	if len(evs.Items) != 2 {
		t.Fatalf("only the new reject should emit a second Event, got %d", len(evs.Items))
	}
}

// TestEmitEventAlreadyExistsNoWarn (P4): when two controller replicas race to create
// the identically-named reject Event, the loser's create returns AlreadyExists. That
// is the Event already being present (not a failure), so it must be a silent no-op —
// no WARN. We simulate the loser by making the fake clientset reject the create with
// AlreadyExists and assert the controller logs nothing at warn level.
func TestEmitEventAlreadyExistsNoWarn(t *testing.T) {
	cs := fake.NewSimpleClientset()
	cs.PrependReactor("create", "events", func(k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, apierrors.NewAlreadyExists(schema.GroupResource{Resource: "events"}, "cadish-ingress-x.1")
	})
	ctrl := New(cs, applierFunc(func(*config.Config) error { return nil }), "", Config{ClassName: "cadish"})

	var buf bytes.Buffer
	ctrl.SetLogger(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn})))

	// Exercise all three Event-create paths.
	ctrl.emitEvent("prod", "ing", corev1.EventTypeWarning, "Rejected", "boom")
	ctrl.emitSecretEvent("prod", "tls", "BadTLSSecret", "boom")
	ctrl.emitClusterEvent(corev1.EventTypeWarning, "RenderFailed", "boom")

	if strings.Contains(buf.String(), "WARN") || strings.Contains(buf.String(), "already exists") {
		t.Fatalf("AlreadyExists must be a silent no-op, got log output:\n%s", buf.String())
	}
}

// TestEmitEventRealErrorWarns guards that a genuine (non-AlreadyExists) create failure
// still logs a WARN — the P4 fix must not swallow real errors.
func TestEmitEventRealErrorWarns(t *testing.T) {
	cs := fake.NewSimpleClientset()
	cs.PrependReactor("create", "events", func(k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, apierrors.NewInternalError(errors.New("etcd down"))
	})
	ctrl := New(cs, applierFunc(func(*config.Config) error { return nil }), "", Config{ClassName: "cadish"})

	var buf bytes.Buffer
	ctrl.SetLogger(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn})))

	ctrl.emitEvent("prod", "ing", corev1.EventTypeWarning, "Rejected", "boom")
	if !strings.Contains(buf.String(), "emit event") {
		t.Fatalf("a real create error must still WARN, got:\n%s", buf.String())
	}
}

// TestEventNamesAreContentAddressed (R39): Event names must be a deterministic function
// of the event's stable content (kind/ns/name/reason/message), not a per-process counter.
// Two independent controllers (simulating two replicas) emitting the SAME reject must
// produce the SAME Event name (so the second Create dedups via AlreadyExists), while a
// DIFFERENT reject must produce a DIFFERENT name (so no warning is suppressed).
func TestEventNamesAreContentAddressed(t *testing.T) {
	emit := func() string {
		cs := fake.NewSimpleClientset()
		ctrl := New(cs, applierFunc(func(*config.Config) error { return nil }), "", Config{ClassName: "cadish"})
		ctrl.emitEvent("prod", "ing", corev1.EventTypeWarning, "Rejected", "duplicate path")
		evs, _ := cs.CoreV1().Events("prod").List(context.Background(), metav1.ListOptions{})
		if len(evs.Items) != 1 {
			t.Fatalf("want exactly one Event, got %d", len(evs.Items))
		}
		return evs.Items[0].Name
	}
	a, b := emit(), emit()
	if a != b {
		t.Fatalf("same reject on two replicas must yield the same Event name: %q != %q", a, b)
	}
	// A different reject (different message) must NOT collide on the name.
	cs := fake.NewSimpleClientset()
	ctrl := New(cs, applierFunc(func(*config.Config) error { return nil }), "", Config{ClassName: "cadish"})
	ctrl.emitEvent("prod", "ing", corev1.EventTypeWarning, "Rejected", "a different reason entirely")
	evs, _ := cs.CoreV1().Events("prod").List(context.Background(), metav1.ListOptions{})
	if evs.Items[0].Name == a {
		t.Fatalf("a different reject must produce a different Event name; both were %q", a)
	}
}

// TestControllerBadIngressKeepsLastGood: a good Ingress applies; then a duplicate-path
// conflict Ingress arrives — the controller still applies a VALID config (serving never
// breaks) and emits a warning Event for the rejected duplicate.
func TestControllerBadIngressKeepsLastGood(t *testing.T) {
	ready := true
	t0 := time.Unix(1000, 0)
	cs := fake.NewSimpleClientset(
		ingressAt("prod", "good", "example.com", t0, []pathRule{{path: "/", pathType: prefix, svc: "web", port: 80}}),
		sliceFor("web", "prod", []epSpec{{ip: "10.0.0.1", ready: &ready}}, portSpec{name: "", num: 80}),
	)
	applied := make(chan *config.Config, 16)
	applier := applierFunc(func(c *config.Config) error { applied <- c; return nil })
	ctrl := New(cs, applier, ``, Config{ClassName: "cadish", ResyncDebounce: 10 * time.Millisecond})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = ctrl.Run(ctx) }()

	// First good apply.
	select {
	case cfg := <-applied:
		if !hasSiteHost(cfg, "example.com") {
			t.Fatalf("first apply missing example.com")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("no initial apply")
	}

	// A newer Ingress duplicates the same host+path → the older wins, the newer's path
	// is rejected (an Event), but serving stays valid.
	dup := ingressAt("prod", "dup", "example.com", t0.Add(time.Hour),
		[]pathRule{{path: "/", pathType: prefix, svc: "other", port: 80}})
	if _, err := cs.NetworkingV1().Ingresses("prod").Create(ctx, dup, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}

	// A warning Event is emitted for the rejected duplicate.
	deadline2 := time.Now().Add(5 * time.Second)
	for {
		evs, _ := cs.CoreV1().Events("prod").List(ctx, metav1.ListOptions{})
		found := false
		for _, e := range evs.Items {
			if e.Type == corev1.EventTypeWarning && strings.Contains(strings.ToLower(e.Message), "duplicate") {
				found = true
			}
		}
		if found {
			break
		}
		if time.Now().After(deadline2) {
			t.Fatal("no warning Event emitted for the duplicate-path conflict")
		}
		time.Sleep(20 * time.Millisecond)
	}

	// The conflict renders byte-identical text (older wins), so the last good config
	// keeps serving — no broken swap. Whatever WAS applied must still serve example.com.
	for {
		select {
		case cfg := <-applied:
			if !hasSiteHost(cfg, "example.com") {
				t.Fatalf("a config was applied without example.com (serving broke)")
			}
		default:
			return
		}
	}
}
