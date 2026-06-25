package config

import "testing"

func TestValidateListenAddr(t *testing.T) {
	cases := []struct {
		in string
		ok bool
	}{
		{":9090", true},             // wildcard bind
		{"127.0.0.1:9090", true},    // IPv4
		{"0.0.0.0:9090", true},      // IPv4 any
		{"localhost:9090", true},    // hostname
		{"db:9090", true},           // short all-hex-letters hostname (not an IP attempt)
		{"admin.local:80", true},    // dotted hostname (has letters)
		{"[::1]:9090", true},        // IPv6 loopback
		{"[2001:db8::1]:443", true}, // IPv6
		{"0.0.0.0.1:9090", false},   // malformed IPv4 (5 octets) — the reported bug
		{"256.1.1.1:80", false},     // out-of-range IPv4 octet
		{"1.2.3:80", false},         // too few octets, digits-and-dots => IP attempt
		{"127.0.0.1:99999", false},  // port out of range
		{"127.0.0.1:nope", false},   // non-numeric port
		{"noport", false},           // missing port
	}
	for _, c := range cases {
		err := ValidateListenAddr(c.in)
		if c.ok && err != nil {
			t.Errorf("ValidateListenAddr(%q) = %v, want ok", c.in, err)
		}
		if !c.ok && err == nil {
			t.Errorf("ValidateListenAddr(%q) = nil, want error", c.in)
		}
	}
}
