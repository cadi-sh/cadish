package config

import (
	"testing"

	"github.com/cadi-sh/cadish/internal/cadishfile"
)

func TestParseUpstreamURL(t *testing.T) {
	cases := []struct {
		in string
		ok bool
	}{
		{"http://127.0.0.1:8080", true},
		{"https://example.com", true},
		{"127.0.0.1:8080", true},         // bare host:port ⇒ http
		{"dns://backend.svc:8080", true}, // dynamic
		{"k8s://svc.prod:80", true},      // service.namespace
		{"k8s://svc:80", false},          // namespace mandatory
		{"ht!tp://[::bad", false},        // garbage
		{"", false},                      // empty
		{"ftp://example.com", false},     // unsupported scheme
		{"http://", false},               // no host
		{"dns://backend.svc", false},     // dynamic target needs a port
	}
	for _, c := range cases {
		err := ParseUpstreamURL(c.in, cadishfile.Pos{File: "Cadishfile", Line: 1, Col: 1})
		if c.ok && err != nil {
			t.Errorf("ParseUpstreamURL(%q) = %v, want ok", c.in, err)
		}
		if !c.ok && err == nil {
			t.Errorf("ParseUpstreamURL(%q) = nil, want error", c.in)
		}
	}
}
