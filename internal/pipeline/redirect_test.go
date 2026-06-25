package pipeline

import (
	"net/http"
	"net/url"
	"testing"
)

func TestRedirectCaptureSubstitution(t *testing.T) {
	// example.com is a DECLARED address, so {host} legitimately reflects it (F12: the
	// safe reflection path — a request to a configured host redirects to that host).
	src := `example.com {
	upstream b { to http://x:80 }
	redirect (?i)^/(women|femmes)/?$ 301 https://{host}/mujeres
	redirect (?i)^/es(/.*)?$ 302 https://{host}/espanol$1
	cache_ttl default ttl 5m
}
`
	p := compileSrc(t, src)

	tests := []struct {
		name     string
		host     string
		path     string
		wantNil  bool
		wantCode int
		wantLoc  string
	}{
		{"women -> static target", "example.com", "/women", false, 301, "https://example.com/mujeres"},
		{"femmes alt -> static", "example.com", "/femmes/", false, 301, "https://example.com/mujeres"},
		{"es capture group", "example.com", "/es/registro", false, 302, "https://example.com/espanol/registro"},
		{"es bare prefix", "example.com", "/es", false, 302, "https://example.com/espanol"},
		{"no match", "example.com", "/about", true, 0, ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := &Request{Method: "GET", Host: tc.host, Path: tc.path, Query: url.Values{}}
			dec := p.EvalRequest(req)
			if tc.wantNil {
				if dec.Redirect != nil {
					t.Fatalf("expected no redirect, got %+v", dec.Redirect)
				}
				return
			}
			if dec.Redirect == nil {
				t.Fatalf("expected redirect, got nil")
			}
			if dec.Redirect.Status != tc.wantCode {
				t.Fatalf("status = %d, want %d", dec.Redirect.Status, tc.wantCode)
			}
			if dec.Redirect.Location != tc.wantLoc {
				t.Fatalf("location = %q, want %q", dec.Redirect.Location, tc.wantLoc)
			}
		})
	}
}

// SECURITY (F12): the {host} placeholder in a redirect TARGET must NOT reflect an
// arbitrary, attacker-controlled Host header (open redirect). When the inbound Host
// is not one of the site's configured addresses, {host} must resolve to the site's
// canonical (first configured) host instead of echoing the attacker value. A request
// carrying a DECLARED host still redirects to that same host.
func TestRedirectHostNotReflectedForUndeclaredHost(t *testing.T) {
	src := `www.example.com, example.com, *.cdn.example.com {
	upstream b { to http://x:80 }
	redirect ^/old 301 https://{host}/new
	cache_ttl default ttl 5m
}
`
	p := compileSrc(t, src)

	tests := []struct {
		name    string
		host    string
		wantLoc string
	}{
		// Attacker-supplied Host: must fall back to the canonical configured host, not
		// reflect "attacker.com".
		{"attacker host falls back to canonical", "attacker.com", "https://www.example.com/new"},
		// Declared hosts redirect to themselves (behavior unchanged).
		{"declared primary host preserved", "www.example.com", "https://www.example.com/new"},
		{"declared secondary host preserved", "example.com", "https://example.com/new"},
		// A host matching a declared wildcard is trusted and preserved.
		{"declared wildcard host preserved", "img.cdn.example.com", "https://img.cdn.example.com/new"},
		// Host with a port still matches the declared host (port-stripped).
		{"declared host with port preserved", "www.example.com:8443", "https://www.example.com/new"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := &Request{Method: "GET", Host: tc.host, Path: "/old", Query: url.Values{}}
			dec := p.EvalRequest(req)
			if dec.Redirect == nil {
				t.Fatalf("expected redirect, got nil")
			}
			if dec.Redirect.Location != tc.wantLoc {
				t.Fatalf("location = %q, want %q (host %q must not be reflected)", dec.Redirect.Location, tc.wantLoc, tc.host)
			}
		})
	}
}

func TestRedirectFirstMatchWins(t *testing.T) {
	src := `h.com {
	upstream b { to http://x:80 }
	redirect ^/a 301 https://{host}/first
	redirect ^/a 302 https://{host}/second
	cache_ttl default ttl 5m
}
`
	p := compileSrc(t, src)
	dec := p.EvalRequest(&Request{Host: "h.com", Path: "/abc"})
	if dec.Redirect == nil || dec.Redirect.Status != 301 || dec.Redirect.Location != "https://h.com/first" {
		t.Fatalf("first-match-wins broken: %+v", dec.Redirect)
	}
}

// A redirect must take precedence over (short-circuit) pass/route/cache_key, the
// same way respond does.
func TestRedirectShortCircuits(t *testing.T) {
	src := `site.example {
	upstream b { to http://x:80 }
	pass path /panel/*
	redirect ^/panel/old 301 https://{host}/panel/new
	cache_ttl default ttl 5m
}
`
	p := compileSrc(t, src)
	dec := p.EvalRequest(&Request{Host: "h.com", Path: "/panel/old"})
	if dec.Redirect == nil {
		t.Fatalf("redirect should short-circuit before pass")
	}
	if dec.Pass {
		t.Fatalf("redirect short-circuit should not also set Pass")
	}
}

func TestRedirectMapForm(t *testing.T) {
	src := `h.com {
	upstream b { to http://x:80 }
	redirect 301 map {
		/registro -> /register
		/mujeres  -> /women
	}
	cache_ttl default ttl 5m
}
`
	p := compileSrc(t, src)
	cases := []struct {
		path    string
		wantNil bool
		wantLoc string
	}{
		{"/registro", false, "https://h.com/register"},
		{"/mujeres", false, "https://h.com/women"},
		{"/registro/step2", false, "https://h.com/register/step2"},
		{"/other", true, ""},
	}
	for _, c := range cases {
		dec := p.EvalRequest(&Request{Host: "h.com", Path: c.path})
		if c.wantNil {
			if dec.Redirect != nil {
				t.Fatalf("%s: expected no redirect, got %+v", c.path, dec.Redirect)
			}
			continue
		}
		if dec.Redirect == nil || dec.Redirect.Status != 301 || dec.Redirect.Location != c.wantLoc {
			t.Fatalf("%s: got %+v, want loc %q", c.path, dec.Redirect, c.wantLoc)
		}
	}
}

// Scoped form: `redirect @scope CODE TARGET` fires when @scope matches (here a
// classify token matcher), and the TARGET may use {host}/{path}/{query} templates.
func TestRedirectScopedForm(t *testing.T) {
	src := `example.com {
	upstream b { to http://x:80 }
	@es classify {lang}==es
	classify {lang} {
		when header Accept-Language es -> es
		default                        -> en
	}
	redirect @es 302 https://{host}/es{path}
	cache_ttl default ttl 5m
}
`
	p := compileSrc(t, src)

	// Spanish Accept-Language -> classify {lang}==es -> @es fires.
	reqES := &Request{Method: "GET", Host: "example.com", Path: "/products", Query: url.Values{},
		Header: http.Header{"Accept-Language": []string{"es"}}}
	dec := p.EvalRequest(reqES)
	if dec.Redirect == nil {
		t.Fatalf("expected scoped redirect to fire on @es, got nil")
	}
	if dec.Redirect.Status != 302 || dec.Redirect.Location != "https://example.com/es/products" {
		t.Fatalf("scoped redirect = %+v, want 302 https://example.com/es/products", dec.Redirect)
	}

	// English -> @es does not fire, no redirect.
	reqEN := &Request{Method: "GET", Host: "example.com", Path: "/products", Query: url.Values{},
		Header: http.Header{"Accept-Language": []string{"en"}}}
	if d := p.EvalRequest(reqEN); d.Redirect != nil {
		t.Fatalf("expected no redirect for non-es, got %+v", d.Redirect)
	}
}

// The scoped form templates {host}/{path}/{query} in TARGET but has no path regex,
// so $N capture groups have nothing to expand to (they vanish).
func TestRedirectScopedTemplating(t *testing.T) {
	src := `h.com {
	upstream b { to http://x:80 }
	@gate header X-Region restricted
	redirect @gate 303 https://{host}/blocked?from={path}&q={query}
	cache_ttl default ttl 5m
}
`
	p := compileSrc(t, src)
	req := &Request{Method: "GET", Host: "h.com", Path: "/foo", Query: url.Values{"a": {"1"}},
		Header: http.Header{"X-Region": []string{"restricted"}}}
	dec := p.EvalRequest(req)
	if dec.Redirect == nil {
		t.Fatalf("expected scoped redirect to fire")
	}
	if dec.Redirect.Status != 303 || dec.Redirect.Location != "https://h.com/blocked?from=/foo&q=a=1" {
		t.Fatalf("got %+v, want 303 https://h.com/blocked?from=/foo&q=a=1", dec.Redirect)
	}
}

// A leading @matcher means the scoped form even when a status code follows: the old
// silent path-regex misread is gone.
func TestRedirectScopedNotPathRegex(t *testing.T) {
	src := `h.com {
	upstream b { to http://x:80 }
	@all method GET
	redirect @all 301 https://{host}/new
	cache_ttl default ttl 5m
}
`
	p := compileSrc(t, src)
	dec := p.EvalRequest(&Request{Method: "GET", Host: "h.com", Path: "/anything"})
	if dec.Redirect == nil || dec.Redirect.Location != "https://h.com/new" {
		t.Fatalf("scoped redirect via @all should fire: %+v", dec.Redirect)
	}
}

func TestCompileRedirectScopedErrors(t *testing.T) {
	bad := map[string]string{
		"undefined scope": "s {\n\tredirect @nope 301 https://x\n}\n",
		"scope non-3xx":   "s {\n\t@m method GET\n\tredirect @m 200 https://x\n}\n",
		"scope no target": "s {\n\t@m method GET\n\tredirect @m 301\n}\n",
		"scope bad code":  "s {\n\t@m method GET\n\tredirect @m abc https://x\n}\n",
		"scope empty tgt": "s {\n\t@m method GET\n\tredirect @m 301 \"\"\n}\n",
	}
	for name, src := range bad {
		t.Run(name, func(t *testing.T) {
			compileErr(t, src)
		})
	}
}

func TestCompileRedirectErrors(t *testing.T) {
	bad := map[string]string{
		"no args":            "s {\n\tredirect\n}\n",
		"non-3xx code":       "s {\n\tredirect ^/a 200 https://x\n}\n",
		"non-numeric code":   "s {\n\tredirect ^/a abc https://x\n}\n",
		"missing target":     "s {\n\tredirect ^/a 301\n}\n",
		"invalid regex":      "s {\n\tredirect ( 301 https://x\n}\n",
		"map entry no arrow": "s {\n\tredirect 301 map {\n\t\t/a\n\t}\n}\n",
	}
	for name, src := range bad {
		t.Run(name, func(t *testing.T) {
			compileErr(t, src)
		})
	}
}
