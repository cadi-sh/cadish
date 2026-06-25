package k8s

import (
	"reflect"
	"sort"
	"testing"

	discoveryv1 "k8s.io/api/discovery/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes/fake"

	"github.com/cadi-sh/cadish/internal/lb"
)

// epSpec is one endpoint address plus its readiness, for sliceFor.
type epSpec struct {
	ip    string
	ready *bool
}

// portSpec is one named/numbered port, for sliceFor.
type portSpec struct {
	name string
	num  int32
}

// sliceFor builds a *discoveryv1.EndpointSlice labelled for service in namespace,
// carrying the given endpoints (with readiness) and a single port. Its object name
// is derived from the endpoint IPs so distinct endpoint sets get distinct names.
func sliceFor(service, namespace string, eps []epSpec, port portSpec) *discoveryv1.EndpointSlice {
	name := service
	endpoints := make([]discoveryv1.Endpoint, 0, len(eps))
	for _, e := range eps {
		name += "-" + replaceDots(e.ip)
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
			Labels:    map[string]string{serviceNameLabel: service},
		},
		AddressType: discoveryv1.AddressTypeIPv4,
		Endpoints:   endpoints,
		Ports: []discoveryv1.EndpointPort{
			{Name: &pname, Port: &pnum},
		},
	}
}

func replaceDots(s string) string {
	b := []byte(s)
	for i := range b {
		if b[i] == '.' {
			b[i] = 'x'
		}
	}
	return string(b)
}

// newTestEndpointCache builds an EndpointCache backed by an EndpointSlice informer
// over a fake clientset seeded with slices, started and synced.
func newTestEndpointCache(t *testing.T, slices []*discoveryv1.EndpointSlice) *EndpointCache {
	t.Helper()
	var objs []runtime.Object
	for _, s := range slices {
		objs = append(objs, s)
	}
	cs := fake.NewSimpleClientset(objs...)
	f := informers.NewSharedInformerFactory(cs, 0)
	cache := &EndpointCache{
		slices: f.Discovery().V1().EndpointSlices().Lister(),
	}
	// Register the informer before Start so it is populated.
	f.Discovery().V1().EndpointSlices().Informer()
	stop := make(chan struct{})
	t.Cleanup(func() { close(stop) })
	f.Start(stop)
	f.WaitForCacheSync(stop)
	return cache
}

// normalize sorts endpoints by IP then Port so equality checks are order-stable.
func normalize(eps []lb.Endpoint) []lb.Endpoint {
	out := append([]lb.Endpoint(nil), eps...)
	sort.Slice(out, func(i, j int) bool {
		if out[i].IP != out[j].IP {
			return out[i].IP < out[j].IP
		}
		return out[i].Port < out[j].Port
	})
	return out
}

func TestEndpointCache(t *testing.T) {
	ready, notReady := true, false
	slices := []*discoveryv1.EndpointSlice{
		sliceFor("web", "prod", []epSpec{
			{ip: "10.0.0.1", ready: &ready},
			{ip: "10.0.0.2", ready: &notReady}, // excluded
		}, portSpec{name: "http", num: 8080}),
		sliceFor("web", "prod", []epSpec{
			{ip: "10.0.0.3", ready: &ready},
			{ip: "10.0.0.1", ready: &ready}, // dup across slices -> deduped
		}, portSpec{name: "http", num: 8080}),
	}
	cache := newTestEndpointCache(t, slices)

	t.Run("named port, ready-only, deduped", func(t *testing.T) {
		eps, err := cache.Endpoints("prod", "web", "http")
		if err != nil {
			t.Fatal(err)
		}
		got := normalize(eps) // sort by IP:Port
		want := []lb.Endpoint{{IP: "10.0.0.1", Port: 8080}, {IP: "10.0.0.3", Port: 8080}}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("got %+v want %+v", got, want)
		}
	})
	t.Run("numeric port passthrough", func(t *testing.T) {
		eps, _ := cache.Endpoints("prod", "web", "8080")
		if len(eps) != 2 {
			t.Fatalf("want 2 got %d", len(eps))
		}
	})
	t.Run("namespace scoping", func(t *testing.T) {
		eps, _ := cache.Endpoints("staging", "web", "http")
		if len(eps) != 0 {
			t.Fatalf("want 0 cross-namespace, got %d", len(eps))
		}
	})
	t.Run("unknown named port errors", func(t *testing.T) {
		if _, err := cache.Endpoints("prod", "web", "grpc"); err == nil {
			t.Fatal("expected error for unknown named port")
		}
	})
}

// TestEndpointCacheNumericTargetPort guards K8S-PORT: a single-port Service that maps
// its port number to a different container/target port (the standard `port: 80 ->
// targetPort: 8080`) must dial the real endpoint port (8080), not the requested Service
// port number (80). Referencing the backend by the numeric Service port previously dialed
// :80 and 502'd.
func TestEndpointCacheNumericTargetPort(t *testing.T) {
	ready := true
	slices := []*discoveryv1.EndpointSlice{
		// Service port 80 -> targetPort 8080: the slice carries only the endpoint port.
		sliceFor("web", "prod", []epSpec{{ip: "10.0.0.1", ready: &ready}}, portSpec{name: "http", num: 8080}),
	}
	cache := newTestEndpointCache(t, slices)
	eps, err := cache.Endpoints("prod", "web", "80") // referenced by the Service port number
	if err != nil {
		t.Fatal(err)
	}
	want := []lb.Endpoint{{IP: "10.0.0.1", Port: 8080}}
	if got := normalize(eps); !reflect.DeepEqual(got, want) {
		t.Fatalf("numeric Service port should map to the endpoint port: got %+v want %+v", got, want)
	}
}

// TestResolvePort exercises the port-mapping logic directly across the cases the
// EndpointSlice can and cannot disambiguate without a Service watch.
func TestResolvePort(t *testing.T) {
	str := func(s string) *string { return &s }
	i32 := func(n int32) *int32 { return &n }
	singlePort := &discoveryv1.EndpointSlice{Ports: []discoveryv1.EndpointPort{{Name: str("http"), Port: i32(8080)}}}
	multiPort := &discoveryv1.EndpointSlice{Ports: []discoveryv1.EndpointPort{
		{Name: str("http"), Port: i32(8080)},
		{Name: str("metrics"), Port: i32(9090)},
	}}

	cases := []struct {
		name    string
		slice   *discoveryv1.EndpointSlice
		port    string
		wantNum int
		wantOK  bool
	}{
		{"numeric single-port maps to endpoint port", singlePort, "80", 8080, true},
		{"numeric single-port equal to endpoint", singlePort, "8080", 8080, true},
		{"named single-port", singlePort, "http", 8080, true},
		{"named known multi-port", multiPort, "metrics", 9090, true},
		{"named unknown", singlePort, "grpc", 0, false},
		// Multi-port referenced by number cannot be disambiguated from the slice alone
		// (the slice keys ports by name, not by Service port number) — fall back to the
		// requested number rather than guess wrong. Documented limitation.
		{"numeric multi-port falls back to verbatim", multiPort, "80", 80, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			num, ok := resolvePort(c.slice, c.port)
			if num != c.wantNum || ok != c.wantOK {
				t.Fatalf("resolvePort(%q) = (%d,%v) want (%d,%v)", c.port, num, ok, c.wantNum, c.wantOK)
			}
		})
	}
}
