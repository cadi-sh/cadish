package check

import "testing"

// A site that requests automatic TLS (`tls acme`) for an address a public ACME CA can
// never issue for — an IP literal, localhost, a dotless single-label name, or a reserved
// special-use TLD — checks clean today but silently never serves working TLS (the
// challenge fails only at the first handshake). check must warn (acme-host-unissuable).
func TestACMEHostUnissuableWarns(t *testing.T) {
	cases := map[string]string{
		"ip":             "192.168.1.10",
		"ipv6":           "[2001:db8::1]",
		"localhost":      "localhost",
		"dotless":        "intranet",
		"local-tld":      "printer.local",
		"test-tld":       "app.test",
		"internal-tld":   "svc.internal",
		"wildcard-local": "*.corp.local",
	}
	for name, addr := range cases {
		t.Run(name, func(t *testing.T) {
			src := []byte(addr + " {\n" +
				"  tls acme ops@example.com\n" +
				"  upstream app { to http://127.0.0.1:8080 }\n" +
				"}\n")
			r, err := CheckSource("Cadishfile", src)
			if err != nil {
				t.Fatalf("CheckSource: %v", err)
			}
			if n := codes(r)["acme-host-unissuable"]; n != 1 {
				t.Fatalf("addr %q: got %d acme-host-unissuable diagnostics, want 1; diags=%+v", addr, n, r.Diagnostics)
			}
		})
	}
}

// A public DNS site (apex and wildcard, which autocert issues per concrete subdomain on
// demand) with `tls acme` must NOT warn. Nor must a static-cert or `tls off` site on a
// non-public host (only ACME requires public issuance).
func TestACMEHostIssuableNoWarn(t *testing.T) {
	cases := map[string]string{
		"apex":         "api.example.com {\n  tls acme ops@example.com\n  upstream a { to http://127.0.0.1:8080 }\n}\n",
		"wildcard":     "api.example.com, *.example.com {\n  tls acme ops@example.com\n  upstream a { to http://127.0.0.1:8080 }\n}\n",
		"static-on-ip": "192.168.1.10 {\n  tls { cert /c.pem; key /k.pem }\n  upstream a { to http://127.0.0.1:8080 }\n}\n",
		"off-on-local": "printer.local {\n  tls off\n  upstream a { to http://127.0.0.1:8080 }\n}\n",
	}
	for name, src := range cases {
		t.Run(name, func(t *testing.T) {
			r, err := CheckSource("Cadishfile", []byte(src))
			if err != nil {
				t.Fatalf("CheckSource: %v", err)
			}
			if n := codes(r)["acme-host-unissuable"]; n != 0 {
				t.Fatalf("%s: got %d acme-host-unissuable diagnostics, want 0; diags=%+v", name, n, r.Diagnostics)
			}
		})
	}
}
