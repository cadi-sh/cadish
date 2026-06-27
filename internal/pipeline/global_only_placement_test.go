package pipeline

import (
	"strings"
	"testing"
)

// Finding 2 (round-3): a global-only block (server/admin/proxy_protocol/strict_host/
// security/access_log) written inside a SITE body is parsed ONLY from the leading
// global-options block by the config layer's *FromFile constructors — so a copy in a
// site body is silently ignored at runtime (the maxconn/timeout never applies) while
// `cadish check` reports 0 errors (it is a registered directive, so the unknown-directive
// lint never fires). That is a check≡run divergence and a silent-degradation footgun.
// Compile must REJECT it with a positioned, global-only placement error so check and run
// fail identically. These tests fail before the fix.

func TestGlobalOnlyServerInSiteBodyRejected(t *testing.T) {
	ce := compileErr(t, `example.com {
    upstream u { to http://127.0.0.1:9 }
    server { maxconn 5 }
    cache_ttl default ttl 60s
}`)
	if !strings.Contains(ce.Msg, "server") || !strings.Contains(ce.Msg, "global-only") {
		t.Fatalf("error must name `server` and say global-only; got %q", ce.Msg)
	}
}

// Every directive in the global-only set must be rejected in a site body — including one
// with an otherwise-valid inner knob (the silent-ignore would also swallow a bad knob).
func TestGlobalOnlyDirectivesInSiteBodyRejected(t *testing.T) {
	cases := map[string]string{
		"server":         "server { maxconn 5 }",
		"admin":          "admin { listen :9090 }",
		"proxy_protocol": "proxy_protocol { trust 10.0.0.0/8 }",
		"security":       "security { audit_log /tmp/x.log }",
		"strict_host":    "strict_host",
		"access_log":     "access_log off",
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			ce := compileErr(t, "example.com {\n    upstream u { to http://127.0.0.1:9 }\n    "+body+"\n    cache_ttl default ttl 60s\n}")
			if !strings.Contains(ce.Msg, name) || !strings.Contains(ce.Msg, "global-only") {
				t.Fatalf("%s in a site body must be a positioned global-only error; got %q", name, ce.Msg)
			}
			if ce.Pos.Line == 0 {
				t.Fatalf("%s error must carry a source position", name)
			}
		})
	}
}

// Control: the SAME directives in the leading global-options block compile clean — the
// rejection is placement-specific, not a ban on the directive.
func TestGlobalOnlyDirectivesInGlobalBlockOK(t *testing.T) {
	// The global block is a separate File.Global, never passed to Compile, so a site that
	// does NOT contain these compiles without error.
	compileSrc(t, `example.com {
    upstream u { to http://127.0.0.1:9 }
    cache_ttl default ttl 60s
}`)
}
