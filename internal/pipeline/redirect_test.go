package pipeline

import (
	"net/http"
	"net/url"
	"strings"
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

// REDIRECT-TOKEN Part A: a derived {classify.NAME} token resolves in a redirect
// Location. With the zero resolver it expanded to "", producing a broken target. The
// token sits in the PATH here: Fix B forbids a {classify.*} token in the AUTHORITY
// (an open redirect — only the validated {host} family may sit in host position), so
// language selection by subdomain must use {host.sub}/{host.base}, not {classify}.
func TestRedirectClassifyTokenResolves(t *testing.T) {
	src := `example.com {
	upstream b { to http://x:80 }
	classify {langredir} {
		when header Accept-Language es -> es
		default                        -> www
	}
	redirect ^/go(/.*)?$ 302 https://{host}/{classify.langredir}/go$1
	cache_ttl default ttl 5m
}
`
	p := compileSrc(t, src)

	reqES := &Request{Method: "GET", Host: "example.com", Path: "/go/x", Query: url.Values{},
		Header: http.Header{"Accept-Language": []string{"es"}}}
	dec := p.EvalRequest(reqES)
	if dec.Redirect == nil {
		t.Fatalf("expected redirect, got nil")
	}
	if dec.Redirect.Location != "https://example.com/es/go/x" {
		t.Fatalf("classify token not resolved in Location: got %q, want %q", dec.Redirect.Location, "https://example.com/es/go/x")
	}

	reqEN := &Request{Method: "GET", Host: "example.com", Path: "/go", Query: url.Values{},
		Header: http.Header{"Accept-Language": []string{"en"}}}
	if d := p.EvalRequest(reqEN); d.Redirect == nil || d.Redirect.Location != "https://example.com/www/go" {
		t.Fatalf("default classify token: got %+v, want https://example.com/www/go", d.Redirect)
	}
}

// REDIRECT-TOKEN Part A: the request-scoped {geo}, {client_ip} and {http.NAME}
// tokens resolve in a redirect Location. They were left empty by the zero resolver
// + unpopulated env on the redirect path.
func TestRedirectDerivedTokensResolve(t *testing.T) {
	src := `example.com {
	upstream b { to http://x:80 }
	redirect ^/t 302 https://{host}/g?geo={geo}&ip={client_ip}&h={http.X-Foo}
	cache_ttl default ttl 5m
}
`
	p := compileSrc(t, src)
	req := &Request{Method: "GET", Host: "example.com", Path: "/t", Query: url.Values{},
		ClientIP: "1.2.3.4", Geo: "ES",
		Header: http.Header{"X-Foo": []string{"bar"}}}
	dec := p.EvalRequest(req)
	if dec.Redirect == nil {
		t.Fatalf("expected redirect, got nil")
	}
	want := "https://example.com/g?geo=ES&ip=1.2.3.4&h=bar"
	if dec.Redirect.Location != want {
		t.Fatalf("derived tokens not resolved: got %q, want %q", dec.Redirect.Location, want)
	}
}

// SECURITY REGRESSION (F12): even now that the redirect env is populated with the
// live resolver + Header/ClientIP/Geo, {host} must STILL resolve through
// p.redirectHost — the VALIDATED host — and must NOT be overridden to the raw
// request Host (normHost). An attacker-supplied Host must not be reflected into the
// Location. This guards against accidentally calling fillHeaderTemplateEnv (which
// sets Host = normHost) on the redirect path.
func TestRedirectHostStaysValidatedWithLiveResolver(t *testing.T) {
	src := `www.example.com, example.com {
	upstream b { to http://x:80 }
	redirect ^/old 301 https://{host}/new?h={http.X-Trace}
	cache_ttl default ttl 5m
}
`
	p := compileSrc(t, src)
	// Attacker-controlled Host + a reflected header: {host} must fall back to the
	// canonical configured host, NOT echo "attacker.example.net".
	req := &Request{Method: "GET", Host: "attacker.example.net", Path: "/old", Query: url.Values{},
		Header: http.Header{"X-Trace": []string{"t1"}}}
	dec := p.EvalRequest(req)
	if dec.Redirect == nil {
		t.Fatalf("expected redirect, got nil")
	}
	want := "https://www.example.com/new?h=t1"
	if dec.Redirect.Location != want {
		t.Fatalf("host must stay validated: got %q, want %q (attacker host must not be reflected)", dec.Redirect.Location, want)
	}
}

// TestRedirectProtoTokenFromTLS is the Finding 3 regression: on a TLS-terminated
// listener (req.TLS set), a `redirect … {proto}://{host}{path}` Location must resolve
// {proto}/{scheme} to "https", not the bare default "http" — otherwise the redirect
// downgrades the scheme (and on a force-https rule, loops). The redirect path previously
// omitted Scheme from its TemplateEnv, so {proto} always defaulted to http even under TLS.
func TestRedirectProtoTokenFromTLS(t *testing.T) {
	src := `example.com {
	upstream b { to http://x:80 }
	redirect ^/r 302 {proto}://{host}{path}
	cache_ttl default ttl 5m
}
`
	p := compileSrc(t, src)
	reqTLS := &Request{Method: "GET", Host: "example.com", Path: "/r", Query: url.Values{}, TLS: true}
	dec := p.EvalRequest(reqTLS)
	if dec.Redirect == nil {
		t.Fatalf("expected redirect, got nil")
	}
	if want := "https://example.com/r"; dec.Redirect.Location != want {
		t.Fatalf("{proto} under TLS: got %q, want %q", dec.Redirect.Location, want)
	}
	// Without TLS it stays http (unchanged behavior).
	reqPlain := &Request{Method: "GET", Host: "example.com", Path: "/r", Query: url.Values{}}
	d2 := p.EvalRequest(reqPlain)
	if d2.Redirect == nil || d2.Redirect.Location != "http://example.com/r" {
		t.Fatalf("{proto} without TLS: got %+v, want http://example.com/r", d2.Redirect)
	}
}

// {host.base}/{host.sub}: ONE brand-agnostic rule rewrites the subdomain of any
// configured brand to www.<base>, replacing the per-brand literal targets. The base
// is public-suffix aware (brand-a.example, brand-b.example, and the multi-label tech555.io), and
// it derives from the VALIDATED redirect host so the open-redirect defense (F12) still
// applies to the COMPUTED host.
func TestRedirectHostBaseSubdomainRewrite(t *testing.T) {
	src := `es.brand-a.example, www.brand-b.example, brand-a.example, cam4you.tech555.io {
	upstream b { to http://x:80 }
	redirect ^/(.*)$ 302 https://www.{host.base}/$1
	cache_ttl default ttl 5m
}
`
	p := compileSrc(t, src)
	tests := []struct {
		name    string
		host    string
		wantLoc string
	}{
		// Single brand-agnostic rule collapses the per-brand literal targets:
		{"es.brand-a.example -> www.brand-a.example", "es.brand-a.example", "https://www.brand-a.example/page"},
		{"www.brand-b.example -> www.brand-b.example", "www.brand-b.example", "https://www.brand-b.example/page"},
		{"bare brand-a.example -> www.brand-a.example", "brand-a.example", "https://www.brand-a.example/page"},
		// Multi-label public suffix: the whole host is the base (sub empty), NOT tech555.io.
		{"multi-label suffix base", "cam4you.tech555.io", "https://www.cam4you.tech555.io/page"},
		// SECURITY (F12): an attacker Host is NOT trusted, so {host.base} derives from the
		// canonical configured host (es.brand-a.example -> base brand-a.example), never the attacker's.
		{"attacker host falls back to canonical base", "evil.attacker.test", "https://www.brand-a.example/page"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := &Request{Method: "GET", Host: tc.host, Path: "/page", Query: url.Values{}}
			dec := p.EvalRequest(req)
			if dec.Redirect == nil {
				t.Fatalf("expected redirect, got nil")
			}
			if dec.Redirect.Location != tc.wantLoc {
				t.Fatalf("location = %q, want %q", dec.Redirect.Location, tc.wantLoc)
			}
		})
	}
}

// A redirect whose computed {host.base} target equals the request's own host must NOT
// loop: a request already on www.<base> selects no earlier rule and the www-targeting
// rule self-targets, so a force-www family is written to fire ONLY off the bare/sub
// host. Here a request to the www host falls through (no rule matches the www host),
// proving the family does not redirect a host to itself.
func TestRedirectHostBaseNoSelfLoop(t *testing.T) {
	src := `brand-a.example, www.brand-a.example {
	upstream b { to http://x:80 }
	@bare host brand-a.example
	redirect @bare ^/(.*)$ 302 https://www.{host.base}/$1
	cache_ttl default ttl 5m
}
`
	p := compileSrc(t, src)
	// Bare host: the @bare scope fires, rewrite to the www host.
	if d := p.EvalRequest(&Request{Method: "GET", Host: "brand-a.example", Path: "/x", Query: url.Values{}}); d.Redirect == nil || d.Redirect.Location != "https://www.brand-a.example/x" {
		t.Fatalf("bare host should redirect to www: %+v", d.Redirect)
	}
	// Already on www: @bare does not match, so no redirect — no self-loop.
	if d := p.EvalRequest(&Request{Method: "GET", Host: "www.brand-a.example", Path: "/x", Query: url.Values{}}); d.Redirect != nil {
		t.Fatalf("www host must not redirect to itself (loop), got %+v", d.Redirect)
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

// REDIRECT-TOKEN Part B: the combined `redirect @scope PATH_REGEX CODE TARGET`
// form rewrites a path segment ONLY when a matcher scope (here a classified
// language token) also matches. It fires only when BOTH the scope AND the path
// regex match; the regex submatches feed $N in the Location AND the Part-A derived
// tokens ({host}) still resolve. First-match-wins across the two directional rules.
func TestRedirectScopedRegexCombined(t *testing.T) {
	src := `example.com {
	upstream b { to http://x:80 }
	classify {langredir} {
		when header Accept-Language es -> es
		when header Accept-Language en -> en
		default                        -> none
	}
	@es_target classify {langredir}==es
	@en_target classify {langredir}==en
	redirect @es_target (?i)^(.*)/(couples|parejas)/?$ 301 https://{host}$1/parejas
	redirect @en_target (?i)^(.*)/(couples|parejas)/?$ 301 https://{host}$1/couples
	cache_ttl default ttl 5m
}
`
	p := compileSrc(t, src)

	tests := []struct {
		name     string
		lang     string
		path     string
		wantNil  bool
		wantCode int
		wantLoc  string
	}{
		// es scope + regex both match → couples rewritten to parejas, $1 = /section.
		{"es couples -> parejas", "es", "/section/couples", false, 301, "https://example.com/section/parejas"},
		// en scope: the @es_target rule's scope fails, the @en_target rule fires.
		{"en parejas -> couples", "en", "/section/parejas", false, 301, "https://example.com/section/couples"},
		// deeper capture: $1 carries the whole leading path.
		{"es deep capture", "es", "/a/b/couples", false, 301, "https://example.com/a/b/parejas"},
		// scope matches (es) but the regex does NOT → fall through, no redirect.
		{"es but regex no match", "es", "/about", true, 0, ""},
		// regex matches but the scope does NOT (no language) → no redirect.
		{"regex match but scope no match", "none", "/section/couples", true, 0, ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			h := http.Header{}
			if tc.lang != "none" {
				h.Set("Accept-Language", tc.lang)
			}
			req := &Request{Method: "GET", Host: "example.com", Path: tc.path, Query: url.Values{}, Header: h}
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
			if dec.Redirect.Status != tc.wantCode || dec.Redirect.Location != tc.wantLoc {
				t.Fatalf("got %+v, want %d %q", dec.Redirect, tc.wantCode, tc.wantLoc)
			}
		})
	}
}

// REDIRECT-TOKEN Part B: in the combined form a derived {classify.NAME} token AND a
// $N capture resolve together in the Location (Part A still works under a scope),
// and {host} stays the VALIDATED redirect host (F12), never the raw request Host. The
// {classify.*} token sits in the PATH (Fix B forbids it in the AUTHORITY), while the
// validated {host} family carries the authority.
func TestRedirectScopedRegexTokenAndCapture(t *testing.T) {
	src := `www.example.com, example.com {
	upstream b { to http://x:80 }
	classify {langredir} {
		when header Accept-Language es -> es
		default                        -> www
	}
	@active classify {langredir}==es
	redirect @active (?i)^/go(/.*)?$ 302 https://{host}/{classify.langredir}$1
	cache_ttl default ttl 5m
}
`
	p := compileSrc(t, src)
	// Attacker-supplied Host: {host} must fall back to the canonical configured host
	// (www.example.com), the classify token resolves to "es", and $1 = "/x".
	req := &Request{Method: "GET", Host: "attacker.test", Path: "/go/x", Query: url.Values{},
		Header: http.Header{"Accept-Language": []string{"es"}}}
	dec := p.EvalRequest(req)
	if dec.Redirect == nil {
		t.Fatalf("expected combined redirect to fire, got nil")
	}
	want := "https://www.example.com/es/x"
	if dec.Redirect.Location != want {
		t.Fatalf("combined token+capture = %q, want %q", dec.Redirect.Location, want)
	}
}

// REGRESSION: all four redirect forms (regex, scope-only, map, and the NEW
// scope+regex combined) parse together in one site without error — the
// disambiguation tells them apart cleanly.
func TestRedirectAllFourFormsParse(t *testing.T) {
	src := `example.com {
	upstream b { to http://x:80 }
	@m method GET
	redirect ^/regex 301 https://{host}/r
	redirect @m ^/combined/(.*)$ 303 https://{host}/c/$1
	redirect 301 map {
		/registro -> /register
	}
	redirect @m 302 https://{host}/scoped
	cache_ttl default ttl 5m
}
`
	p := compileSrc(t, src)
	// scope-only @m fires on a non-/regex, non-/combined path.
	if d := p.EvalRequest(&Request{Method: "GET", Host: "example.com", Path: "/anything", Query: url.Values{}}); d.Redirect == nil || d.Redirect.Location != "https://example.com/scoped" {
		t.Fatalf("scope-only form broke: %+v", d.Redirect)
	}
	// combined form fires only with scope (GET) AND regex (/combined/...).
	if d := p.EvalRequest(&Request{Method: "GET", Host: "example.com", Path: "/combined/xyz", Query: url.Values{}}); d.Redirect == nil || d.Redirect.Status != 303 || d.Redirect.Location != "https://example.com/c/xyz" {
		t.Fatalf("combined form broke: %+v", d.Redirect)
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

// TestRedirectOpenRedirectHostToken (R26): a raw {http.*} request-header token in the
// AUTHORITY of a redirect Location is an open redirect (the header is attacker-supplied
// and host-unvalidated, unlike the {host} family). Such targets must be rejected at
// compile time, while {http.*} in the path/query and the validated {host} tokens stay
// allowed.
func TestRedirectOpenRedirectHostToken(t *testing.T) {
	reject := []string{
		// {http.x-forwarded-host} as the whole authority of an absolute Location.
		"example.com {\n\tupstream b { to http://x:80 }\n\tredirect ^/.*$ 302 https://{http.x-forwarded-host}/login\n}\n",
		// Scoped form, host position.
		"example.com {\n\t@all path /*\n\tupstream b { to http://x:80 }\n\tredirect @all 302 https://{http.host}/\n}\n",
		// Protocol-relative authority.
		"example.com {\n\tupstream b { to http://x:80 }\n\tredirect ^/.*$ 301 //{http.x-original-host}/x\n}\n",
		// Token embedded in (not equal to) the authority.
		"example.com {\n\tupstream b { to http://x:80 }\n\tredirect ^/.*$ 302 https://pre-{http.host}.evil/x\n}\n",
	}
	for i, src := range reject {
		t.Run("reject", func(t *testing.T) {
			ce := compileErr(t, src)
			if ce == nil {
				t.Fatalf("case %d: want compile error for open-redirect target", i)
			}
		})
	}

	// R26 bypass battery: browsers treat SPECIAL schemes (http/https) as introducing an
	// authority after the ':' regardless of the slash count/direction, so these classic
	// filter-bypass forms reflect a host-bearing {http.*} token into the navigation origin
	// just like the naive https://{http.host} — they must all be rejected at compile.
	bypass := []string{
		"example.com {\n\tupstream b { to http://x:80 }\n\tredirect ^/.*$ 302 https:/{http.x-forwarded-host}/login\n}\n",
		"example.com {\n\tupstream b { to http://x:80 }\n\tredirect ^/.*$ 302 https:{http.host}/login\n}\n",
		"example.com {\n\tupstream b { to http://x:80 }\n\tredirect ^/.*$ 302 https:\\\\{http.host}\n}\n",
		"example.com {\n\tupstream b { to http://x:80 }\n\tredirect ^/.*$ 302 https:/\\{http.host}\n}\n",
	}
	for i, src := range bypass {
		t.Run("bypass-reject", func(t *testing.T) {
			ce := compileErr(t, src)
			if ce == nil {
				t.Fatalf("bypass case %d (%q): want compile error for open-redirect target", i, src)
			}
		})
	}

	allow := []string{
		// {host} is validated (F12) — still allowed in the authority.
		"example.com {\n\tupstream b { to http://x:80 }\n\tredirect ^/.*$ 302 https://{host}/login\n}\n",
		// {host.base} followed by {uri} (the path/query expands at runtime) — the host is
		// still the validated {host.base}, so it stays allowed.
		"example.com {\n\tupstream b { to http://x:80 }\n\tredirect ^/.*$ 302 https://{host.base}{uri}\n}\n",
		// {host.base}/{host.sub} (validated, derived from {host}) — allowed in authority.
		"example.com {\n\tupstream b { to http://x:80 }\n\tredirect ^/.*$ 302 https://{host.sub}.{host.base}/x\n}\n",
		// {http.*} in the QUERY (not the host) — harmless, allowed.
		"example.com {\n\tupstream b { to http://x:80 }\n\tredirect ^/.*$ 302 https://{host}/login?ref={http.referer}\n}\n",
		// {http.*} in the PATH (not the host) — harmless, allowed.
		"example.com {\n\tupstream b { to http://x:80 }\n\tredirect ^/.*$ 302 https://{host}/u/{http.x-user}\n}\n",
		// A static literal authority (operator's deliberate external redirect) — allowed.
		"example.com {\n\tupstream b { to http://x:80 }\n\tredirect ^/.*$ 302 https://partner.example.net/\n}\n",
	}
	for _, src := range allow {
		t.Run("allow", func(t *testing.T) {
			_ = compileSrc(t, src) // Fatals if the safe target is wrongly rejected
		})
	}
}

// TestRedirectOpenRedirectAuthorityWhitelist (Fix B / R26 follow-up): the redirect
// Location AUTHORITY (scheme://AUTHORITY/…) may carry ONLY the validated host family
// ({host}/{host.base}/{host.sub}) plus literal text and $N backrefs. ANY other
// request-sourced template token in host position — {query.*}, {http.*}, {client_ip},
// {geo*}, {classify.*}, {device}, {currency}, … — is an open redirect and must hard-fail
// at COMPILE (the same gate that protects both `cadish run` AND `cadish edge build`,
// since edge build compiles the same Cadishfile before projecting the IR). Tokens in the
// PATH/query portion (after the authority) stay unrestricted — path reflection is not an
// open redirect.
func TestRedirectOpenRedirectAuthorityWhitelist(t *testing.T) {
	// Each of these places a request-sourced token in the Location AUTHORITY → reject.
	reject := []string{
		// The reviewer's confirmed probe: {query.NAME} as the whole authority.
		"example.com {\n\tupstream b { to http://x:80 }\n\tredirect ^/go$ 302 https://{query.next}/login\n}\n",
		// {client_ip} as the authority.
		"example.com {\n\tupstream b { to http://x:80 }\n\tredirect ^/.*$ 302 https://{client_ip}/x\n}\n",
		// {geo} as the authority.
		"example.com {\n\tupstream b { to http://x:80 }\n\tredirect ^/.*$ 302 https://{geo}.evil.test/x\n}\n",
		// {classify.NAME} in the authority (subdomain selection) — no longer allowed.
		"example.com {\n\tupstream b { to http://x:80 }\n\tclassify {lr} {\n\t\twhen header Accept-Language es -> es\n\t\tdefault -> www\n\t}\n\tredirect ^/.*$ 302 https://{classify.lr}.example.com/x\n}\n",
		// {device} in the authority.
		"example.com {\n\tupstream b { to http://x:80 }\n\tredirect ^/.*$ 302 https://{device}.evil.test/x\n}\n",
		// Embedded (not equal to) the authority — still attacker-influenced host.
		"example.com {\n\tupstream b { to http://x:80 }\n\tredirect ^/.*$ 302 https://pre-{query.next}.evil/x\n}\n",
		// Scoped form, authority position.
		"example.com {\n\t@all path /*\n\tupstream b { to http://x:80 }\n\tredirect @all 302 https://{query.next}/\n}\n",
		// Protocol-relative authority.
		"example.com {\n\tupstream b { to http://x:80 }\n\tredirect ^/.*$ 301 //{query.next}/x\n}\n",
		// Scheme-relative bypass variants (browsers fold to an authority after the ':').
		"example.com {\n\tupstream b { to http://x:80 }\n\tredirect ^/.*$ 302 https:/{query.next}/x\n}\n",
		"example.com {\n\tupstream b { to http://x:80 }\n\tredirect ^/.*$ 302 https:{query.next}/x\n}\n",
		// userinfo: an attacker token as the host AFTER the '@' (the real authority).
		"example.com {\n\tupstream b { to http://x:80 }\n\tredirect ^/.*$ 302 https://static.example.net@{query.next}/x\n}\n",
		// F-D2: an UNANCHORED $N capture forming the host — compiles today but the runtime
		// guard suppresses it on every request (permanently dead). Reject loudly instead.
		"example.com {\n\tupstream b { to http://x:80 }\n\tredirect ^/(\\w+)\\.cdn$ 301 https://$1.example.com/\n}\n",
		// Protocol-relative unanchored capture host.
		"example.com {\n\tupstream b { to http://x:80 }\n\tredirect ^/(\\w+)$ 302 //$1.evil.test/x\n}\n",
	}
	for i, src := range reject {
		t.Run("reject", func(t *testing.T) {
			if ce := compileErr(t, src); ce == nil {
				t.Fatalf("case %d: want open-redirect compile error, got nil", i)
			}
		})
	}

	// Safe targets must STILL compile: the validated host family in the authority, and
	// any request-sourced token in the PATH/query portion.
	allow := []string{
		// Validated host tokens in the authority.
		"example.com {\n\tupstream b { to http://x:80 }\n\tredirect ^/.*$ 302 https://{host}/x\n}\n",
		"example.com {\n\tupstream b { to http://x:80 }\n\tredirect ^/.*$ 302 https://{host.base}/x\n}\n",
		"example.com {\n\tupstream b { to http://x:80 }\n\tredirect ^/.*$ 302 https://{host.sub}.{host.base}/x\n}\n",
		// {uri} immediately after the host terminates the authority (it expands rooted at '/').
		"example.com {\n\tupstream b { to http://x:80 }\n\tredirect ^/.*$ 302 https://es.{host.base}{uri}\n}\n",
		// {query.NAME} in the PATH — harmless, allowed.
		"example.com {\n\tupstream b { to http://x:80 }\n\tredirect ^/.*$ 302 https://{host}/go/{query.next}\n}\n",
		// {classify.NAME} in the PATH — allowed.
		"example.com {\n\tupstream b { to http://x:80 }\n\tclassify {lr} {\n\t\twhen header Accept-Language es -> es\n\t\tdefault -> www\n\t}\n\tredirect ^/.*$ 302 https://{host}/{classify.lr}/x\n}\n",
		// Static literal external authority (operator's deliberate choice) — allowed.
		"example.com {\n\tupstream b { to http://x:80 }\n\tredirect ^/.*$ 302 https://partner.example.net/\n}\n",
		// F-D2: a $N capture ANCHORED by a preceding validated {host} token (rebuilding a
		// path from captures, e.g. the index.php strip) is allowed — the runtime guard
		// fires it when the capture is a rooted path and suppresses an escape.
		"example.com {\n\tupstream b { to http://x:80 }\n\tredirect (?i)^(/.*?)?/index\\.php(/.*)?$ 301 https://{host}$1$2\n}\n",
	}
	for _, src := range allow {
		t.Run("allow", func(t *testing.T) {
			_ = compileSrc(t, src) // Fatals if a safe target is wrongly rejected.
		})
	}
}

// TestRedirectOpenRedirectProbe (Fix B): the reviewer's runtime probe. A redirect that
// reflects {query.next} in the PATH compiles and, at runtime, the Location AUTHORITY
// stays the VALIDATED host — never the attacker's. (The unsafe authority variant cannot
// even compile, proved above; here we prove the safe path-reflection cannot be coerced
// into an attacker host.)
func TestRedirectOpenRedirectProbe(t *testing.T) {
	src := `example.com {
	upstream b { to http://x:80 }
	redirect ^/go$ 302 https://{host}/next/{query.next}
	cache_ttl default ttl 5m
}
`
	p := compileSrc(t, src)
	req := &Request{Method: "GET", Host: "example.com", Path: "/go", Query: url.Values{"next": {"evil.attacker.example"}}}
	dec := p.EvalRequest(req)
	if dec.Redirect == nil {
		t.Fatalf("expected redirect, got nil")
	}
	// The authority must be example.com, NOT the attacker value reflected from ?next=.
	if got := dec.Redirect.Location; !strings.HasPrefix(got, "https://example.com/") {
		t.Fatalf("open redirect: Location %q must keep the validated host authority", got)
	}
}

// TestRedirectRuntimeAuthorityInjection is the open-redirect RUNTIME backstop: a target
// whose authority is built from a regex capture ($N) or a request-sourced token passes the
// compile-time guard (the authority span holds only literal text + $N backrefs + {host}),
// yet at RUNTIME the expansion can inject an off-origin authority — the classic index.php
// userinfo trick `/index.php@evil.example.com/` makes the validated host the USERINFO and
// the attacker host the real navigation origin. The runtime post-expansion authority
// assertion must SUPPRESS such redirects (fall through, Redirect==nil) while leaving every
// legitimate redirect — including capture-bearing path rewrites, the language-redirect
// {host.base} family, and operator-declared literal external targets — firing as before.
func TestRedirectRuntimeAuthorityInjection(t *testing.T) {
	// The live exploit config: a capture lands immediately in the authority position.
	src := `brand-a.example {
	upstream b { to http://x:80 }
	redirect (?i)^(/.*?)?/index\.php(.*)$ 301 https://{host}$1$2?{query}
	cache_ttl default ttl 5m
}
`
	p := compileSrc(t, src)

	t.Run("exploit suppressed", func(t *testing.T) {
		// $1="", $2="@evil.example.com/" → https://brand-a.example@evil.example.com/?
		// brand-a.example becomes userinfo, evil.example.com the real host → SUPPRESS.
		req := &Request{Method: "GET", Host: "brand-a.example", Path: "/index.php@evil.example.com/", Query: url.Values{}}
		dec := p.EvalRequest(req)
		if dec.Redirect != nil {
			t.Fatalf("open-redirect must be suppressed, got Location %q", dec.Redirect.Location)
		}
	})

	t.Run("legit index.php strip still redirects", func(t *testing.T) {
		// $1="/foo", $2="/bar" → https://brand-a.example/foo/bar?x=1 (authority unchanged) → ALLOW.
		req := &Request{Method: "GET", Host: "brand-a.example", Path: "/foo/index.php/bar", Query: url.Values{"x": {"1"}}}
		dec := p.EvalRequest(req)
		if dec.Redirect == nil {
			t.Fatalf("legit index.php strip must still redirect, got nil")
		}
		if want := "https://brand-a.example/foo/bar?x=1"; dec.Redirect.Location != want {
			t.Fatalf("location = %q, want %q", dec.Redirect.Location, want)
		}
	})

	// The language-redirect {host.base} family resolves the host identically with the
	// request inputs neutralized (host kept), so it must STILL fire.
	t.Run("language redirect allowed", func(t *testing.T) {
		src := `es.brand-a.example, brand-a.example {
	upstream b { to http://x:80 }
	redirect ^/(.*)$ 302 https://es.{host.base}{uri}
	cache_ttl default ttl 5m
}
`
		p := compileSrc(t, src)
		req := &Request{Method: "GET", Host: "brand-a.example", Path: "/page", Query: url.Values{"q": {"1"}}}
		dec := p.EvalRequest(req)
		if dec.Redirect == nil {
			t.Fatalf("language redirect must still fire, got nil")
		}
		if want := "https://es.brand-a.example/page?q=1"; dec.Redirect.Location != want {
			t.Fatalf("location = %q, want %q", dec.Redirect.Location, want)
		}
	})

	// An operator-declared literal external authority (no request input in the host) must
	// STILL fire: ref and got authorities are the same literal, so it is allowed.
	t.Run("literal off-site redirect allowed", func(t *testing.T) {
		src := `brand-a.example {
	upstream b { to http://x:80 }
	redirect ^/partner(/.*)?$ 302 https://provider.example.net/landing$1
	cache_ttl default ttl 5m
}
`
		p := compileSrc(t, src)
		req := &Request{Method: "GET", Host: "brand-a.example", Path: "/partner/x", Query: url.Values{}}
		dec := p.EvalRequest(req)
		if dec.Redirect == nil {
			t.Fatalf("literal off-site redirect must still fire, got nil")
		}
		if want := "https://provider.example.net/landing/x"; dec.Redirect.Location != want {
			t.Fatalf("location = %q, want %q", dec.Redirect.Location, want)
		}
	})

	// Latent variant #2: a RELATIVE target whose leading token is request-sourced expands to
	// an ABSOLUTE off-origin Location. The compile-time guard sees a relative target (no
	// authority) and allows it; the runtime check sees a got-authority where ref has none →
	// SUPPRESS.
	t.Run("relative query-token target suppressed", func(t *testing.T) {
		src := `brand-a.example {
	upstream b { to http://x:80 }
	redirect ^/r$ 302 {query.next}
	cache_ttl default ttl 5m
}
`
		p := compileSrc(t, src)
		req := &Request{Method: "GET", Host: "brand-a.example", Path: "/r", Query: url.Values{"next": {"https://evil.com/x"}}}
		dec := p.EvalRequest(req)
		if dec.Redirect != nil {
			t.Fatalf("relative request-sourced absolute redirect must be suppressed, got Location %q", dec.Redirect.Location)
		}
		// A SAFE relative next (still relative after expansion) must STILL redirect.
		req2 := &Request{Method: "GET", Host: "brand-a.example", Path: "/r", Query: url.Values{"next": {"/account"}}}
		dec2 := p.EvalRequest(req2)
		if dec2.Redirect == nil || dec2.Redirect.Location != "/account" {
			t.Fatalf("safe relative next must redirect to /account, got %+v", dec2.Redirect)
		}
	})
}

// TestLocationAuthority unit-tests the concrete-string authority extractor that backs the
// runtime open-redirect defense.
func TestLocationAuthority(t *testing.T) {
	tests := []struct {
		in      string
		wantA   string
		wantHas bool
	}{
		{"https://brand-a.example@evil.example.com/?", "brand-a.example@evil.example.com", true},
		{"https://brand-a.example/foo/bar?x=1", "brand-a.example", true},
		{"https://brand-a.example?", "brand-a.example", true},
		{"https://es.brand-a.example/page", "es.brand-a.example", true},
		{"//evil.com/x", "evil.com", true},
		{"https://evil.com/x", "evil.com", true},
		{"https:/evil.com/x", "evil.com", true},  // scheme-relative bypass folds to authority
		{`https:\\evil.com/x`, "evil.com", true}, // backslash fold
		{"/account", "", false},                  // path-absolute relative: no authority
		{"relative/path", "", false},             // path-relative: no authority
		{"", "", false},                          // empty: no authority
	}
	for _, tc := range tests {
		gotA, gotHas := locationAuthority(tc.in)
		if gotA != tc.wantA || gotHas != tc.wantHas {
			t.Errorf("locationAuthority(%q) = (%q, %v), want (%q, %v)", tc.in, gotA, gotHas, tc.wantA, tc.wantHas)
		}
	}
}

// TestRedirectWhitespaceAuthorityBypass is the open-redirect RUNTIME backstop's
// whitespace/control-char hardening: a Location whose expansion begins with leading OWS
// (e.g. "  //evil/") or carries an embedded TAB/CR/LF reports NO authority to a naive
// inspector, yet net/http's Header.Set strips leading/trailing OWS (and a UA ignores
// embedded control bytes) before the value hits the wire — restoring a live off-origin
// authority. normalizeRedirectLocation collapses the Location to the on-the-wire bytes
// BEFORE the authority check, so these all SUPPRESS while legit redirects are untouched.
func TestRedirectWhitespaceAuthorityBypass(t *testing.T) {
	// A bare `{query.next}` target (relative at compile time) and a `https://{host}{query.next}`
	// style guard are both exercised; here a `{query.next}`-only rule is the cleanest probe.
	bypasses := []struct {
		name string
		next string
	}{
		{"leading double-space protocol-relative", "  //evil.example.com/"},
		{"leading tab protocol-relative", "\t//evil.example.com/"},
		{"leading space then https", " https://evil.example.com/"},
		{"leading double-space then https", "  https://evil.example.com/"},
		{"embedded CRLF in protocol-relative", "//evil.example\r\n.com/"},
		{"embedded tab hides authority", "//evil.\texample.com/"},
		// Leading C0 control bytes (0x01-0x08, 0x0B, 0x0E-0x1F): a UA strips ALL
		// leading C0-control-or-space before parsing, so these resolve off-origin even
		// though only space+tab were trimmed before. normalizeRedirectLocation now trims
		// every leading byte <= 0x20, so they must SUPPRESS too.
		{"leading vertical-tab protocol-relative", "\v//evil.example.com/"},
		{"leading 0x01 protocol-relative", "\x01//evil.example.com/"},
		{"leading vertical-tab then https", "\vhttps://evil.example.com/"},
		{"trailing-only ows safe path stays", "  /clean/path  "}, // normalizes to "/clean/path" (relative → fires)
	}
	srcNext := `brand-a.example {
	upstream b { to http://x:80 }
	redirect ^/n$ 302 {query.next}
	cache_ttl default ttl 5m
}
`
	pNext := compileSrc(t, srcNext)
	for _, tc := range bypasses {
		t.Run("query.next/"+tc.name, func(t *testing.T) {
			req := &Request{Method: "GET", Host: "brand-a.example", Path: "/n", Query: url.Values{"next": {tc.next}}}
			dec := pNext.EvalRequest(req)
			if tc.name == "trailing-only ows safe path stays" {
				// "  /clean/path  " → "/clean/path": relative, no authority → ALLOW.
				if dec.Redirect == nil || dec.Redirect.Location != "/clean/path" {
					t.Fatalf("safe relative path must redirect to /clean/path, got %+v", dec.Redirect)
				}
				return
			}
			if dec.Redirect != nil {
				t.Fatalf("whitespace/control bypass must be suppressed, got Location %q", dec.Redirect.Location)
			}
		})
	}

	// A `{http.NAME}`-only target: same bypass surface via an attacker-influenced header.
	srcHdr := `brand-a.example {
	upstream b { to http://x:80 }
	redirect ^/h$ 302 {http.X-Next}
	cache_ttl default ttl 5m
}
`
	pHdr := compileSrc(t, srcHdr)
	for _, tc := range bypasses {
		if tc.name == "trailing-only ows safe path stays" {
			continue
		}
		t.Run("http.X-Next/"+tc.name, func(t *testing.T) {
			req := &Request{Method: "GET", Host: "brand-a.example", Path: "/h", Query: url.Values{}, Header: http.Header{"X-Next": {tc.next}}}
			dec := pHdr.EvalRequest(req)
			if dec.Redirect != nil {
				t.Fatalf("whitespace/control bypass via header must be suppressed, got Location %q", dec.Redirect.Location)
			}
		})
	}

	// Regression: the live index.php-strip pattern, the language redirect, a literal off-site
	// target, and a plain relative target must all STILL fire after normalization.
	t.Run("legit index.php strip still fires", func(t *testing.T) {
		src := `brand-a.example {
	upstream b { to http://x:80 }
	redirect (?i)^(/.*?)?/index\.php(/.*)?$ 301 https://{host}$1$2?{query}
	cache_ttl default ttl 5m
}
`
		p := compileSrc(t, src)
		req := &Request{Method: "GET", Host: "brand-a.example", Path: "/foo/index.php/bar", Query: url.Values{"x": {"1"}}}
		dec := p.EvalRequest(req)
		if dec.Redirect == nil || dec.Redirect.Location != "https://brand-a.example/foo/bar?x=1" {
			t.Fatalf("legit index.php strip must redirect to https://brand-a.example/foo/bar?x=1, got %+v", dec.Redirect)
		}
	})
	t.Run("language redirect still fires", func(t *testing.T) {
		src := `es.brand-a.example, brand-a.example {
	upstream b { to http://x:80 }
	redirect ^/(.*)$ 302 https://es.{host.base}{uri}
	cache_ttl default ttl 5m
}
`
		p := compileSrc(t, src)
		req := &Request{Method: "GET", Host: "brand-a.example", Path: "/page", Query: url.Values{"q": {"1"}}}
		dec := p.EvalRequest(req)
		if dec.Redirect == nil || dec.Redirect.Location != "https://es.brand-a.example/page?q=1" {
			t.Fatalf("language redirect must fire to https://es.brand-a.example/page?q=1, got %+v", dec.Redirect)
		}
	})
	t.Run("literal off-site redirect still fires", func(t *testing.T) {
		src := `brand-a.example {
	upstream b { to http://x:80 }
	redirect ^/go$ 302 https://provider.example.com/x
	cache_ttl default ttl 5m
}
`
		p := compileSrc(t, src)
		req := &Request{Method: "GET", Host: "brand-a.example", Path: "/go", Query: url.Values{}}
		dec := p.EvalRequest(req)
		if dec.Redirect == nil || dec.Redirect.Location != "https://provider.example.com/x" {
			t.Fatalf("literal off-site redirect must fire, got %+v", dec.Redirect)
		}
	})
	t.Run("plain relative redirect still fires", func(t *testing.T) {
		src := `brand-a.example {
	upstream b { to http://x:80 }
	redirect ^/old$ 302 /clean/path
	cache_ttl default ttl 5m
}
`
		p := compileSrc(t, src)
		req := &Request{Method: "GET", Host: "brand-a.example", Path: "/old", Query: url.Values{}}
		dec := p.EvalRequest(req)
		if dec.Redirect == nil || dec.Redirect.Location != "/clean/path" {
			t.Fatalf("relative redirect must fire to /clean/path, got %+v", dec.Redirect)
		}
	})
}

// TestNormalizeRedirectLocation unit-tests the on-the-wire normalization (control-char strip
// + leading/trailing OWS trim) that the runtime open-redirect defense relies on.
func TestNormalizeRedirectLocation(t *testing.T) {
	tests := []struct {
		in, want string
	}{
		{"//evil.example.com/", "//evil.example.com/"},
		{"  //evil.example.com/", "//evil.example.com/"},
		{"\t//evil.example.com/", "//evil.example.com/"},
		{" https://evil.example.com/ ", "https://evil.example.com/"},
		{"//evil.example\r\n.com/", "//evil.example.com/"},
		{"//evil.\texample.com/", "//evil.example.com/"},
		{"https://a\fb\x00c/", "https://abc/"},
		{"\v//evil.example.com/", "//evil.example.com/"},   // leading C0 vertical tab trimmed
		{"\x01//evil.example.com/", "//evil.example.com/"}, // leading C0 0x01 trimmed
		{"//evil.example.com/\x1f", "//evil.example.com/"}, // trailing C0 trimmed
		{"  /clean/path  ", "/clean/path"},
		{"/already/clean", "/already/clean"},
		{"", ""},
		{"   ", ""},
	}
	for _, tc := range tests {
		if got := normalizeRedirectLocation(tc.in); got != tc.want {
			t.Errorf("normalizeRedirectLocation(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// TestRedirectScopedCombinedAllDigitRegex (Fix D): the scoped combined form
// (`@scope REGEX CODE TARGET`) whose PATH_REGEX first token is all-digits must parse as
// the COMBINED form (regex applied to the path), not be misread as the scope-only
// `@scope CODE TARGET` form. Disambiguation is on a VALID 3xx redirect code, not
// "all digits".
func TestRedirectScopedCombinedAllDigitRegex(t *testing.T) {
	// `12` is an all-digit PATH_REGEX (matches a path containing "12"), NOT a redirect code.
	src := `example.com {
	upstream b { to http://x:80 }
	@m method GET
	redirect @m 12 301 https://{host}/hit
	cache_ttl default ttl 5m
}
`
	p := compileSrc(t, src)
	// A path containing "12" matches the regex -> redirect fires.
	if d := p.EvalRequest(&Request{Method: "GET", Host: "example.com", Path: "/a12b", Query: url.Values{}}); d.Redirect == nil || d.Redirect.Status != 301 || d.Redirect.Location != "https://example.com/hit" {
		t.Fatalf("all-digit regex combined form should fire on a matching path: %+v", d.Redirect)
	}
	// A path NOT containing "12" must NOT match -> proves "12" is a REGEX, not a no-op.
	if d := p.EvalRequest(&Request{Method: "GET", Host: "example.com", Path: "/abc", Query: url.Values{}}); d.Redirect != nil {
		t.Fatalf("all-digit regex must not match a non-matching path: %+v", d.Redirect)
	}

	// Anchored all-digit regex variant: `^/0+$`.
	src2 := `example.com {
	upstream b { to http://x:80 }
	@m method GET
	redirect @m ^/0+$ 302 https://{host}/zeros
	cache_ttl default ttl 5m
}
`
	p2 := compileSrc(t, src2)
	if d := p2.EvalRequest(&Request{Method: "GET", Host: "example.com", Path: "/000", Query: url.Values{}}); d.Redirect == nil || d.Redirect.Location != "https://example.com/zeros" {
		t.Fatalf("anchored all-digit regex combined form should fire: %+v", d.Redirect)
	}

	// Sentinel: the scope-only form with a trailing no_store (`@scope CODE TARGET no_store`)
	// must STILL parse as scope-only (CODE=302), not misread the code as a regex.
	src3 := `example.com {
	upstream b { to http://x:80 }
	@m method GET
	redirect @m 302 https://{host}/scoped no_store
	cache_ttl default ttl 5m
}
`
	p3 := compileSrc(t, src3)
	if d := p3.EvalRequest(&Request{Method: "GET", Host: "example.com", Path: "/anything", Query: url.Values{}}); d.Redirect == nil || d.Redirect.Status != 302 || d.Redirect.Location != "https://example.com/scoped" || !d.Redirect.NoStore {
		t.Fatalf("scope-only CODE TARGET no_store must stay scope-only: %+v", d.Redirect)
	}
}

// TestRedirectNoStore verifies that the `no_store` trailing modifier is accepted on
// all three non-map redirect forms (regex, scoped-only, combined scope+regex), sets
// NoStore on the resulting decision, and that a plain redirect without no_store does
// NOT set NoStore (so a redirect without no_store is unchanged — no regression).
func TestRedirectNoStore(t *testing.T) {
	src := `example.com {
	upstream b { to http://x:80 }
	@lang cookie lang es
	redirect @lang 302 https://es.example.com{uri} no_store
	redirect ^/about 301 https://example.com/about-us
	cache_ttl default ttl 5m
}
`
	p := compileSrc(t, src)

	// Scoped form with no_store — should set NoStore true.
	decNoStore := p.EvalRequest(&Request{
		Method: "GET", Host: "example.com", Path: "/news",
		Query:  url.Values{},
		Header: http.Header{"Cookie": []string{"lang=es"}},
	})
	if decNoStore.Redirect == nil {
		t.Fatal("expected redirect for lang=es request, got nil")
	}
	if !decNoStore.Redirect.NoStore {
		t.Errorf("redirect with no_store modifier: NoStore = false, want true")
	}

	// Plain regex redirect without no_store — should NOT set NoStore.
	decPlain := p.EvalRequest(&Request{
		Method: "GET", Host: "example.com", Path: "/about",
		Query: url.Values{},
	})
	if decPlain.Redirect == nil {
		t.Fatal("expected redirect for /about request, got nil")
	}
	if decPlain.Redirect.NoStore {
		t.Errorf("redirect without no_store modifier: NoStore = true, want false")
	}
}

// TestRedirectNoStoreRegexForm verifies the regex form (`redirect PATH_REGEX CODE TARGET no_store`).
func TestRedirectNoStoreRegexForm(t *testing.T) {
	src := `example.com {
	upstream b { to http://x:80 }
	redirect ^/promo(/.*)?$ 302 https://example.com/sale$1 no_store
	redirect ^/old(/.*)?$ 301 https://example.com/new$1
	cache_ttl default ttl 5m
}
`
	p := compileSrc(t, src)
	dec := p.EvalRequest(&Request{
		Method: "GET", Host: "example.com", Path: "/promo/deal",
		Query: url.Values{},
	})
	if dec.Redirect == nil {
		t.Fatal("expected redirect, got nil")
	}
	if !dec.Redirect.NoStore {
		t.Errorf("regex redirect with no_store: NoStore = false, want true")
	}
	// Sentinel: a PLAIN regex redirect (no no_store) in the same pipeline must NOT set NoStore.
	decPlain := p.EvalRequest(&Request{
		Method: "GET", Host: "example.com", Path: "/old/page",
		Query: url.Values{},
	})
	if decPlain.Redirect == nil {
		t.Fatal("expected redirect for /old/page, got nil")
	}
	if decPlain.Redirect.NoStore {
		t.Errorf("plain regex redirect: NoStore = true, want false")
	}
}

// TestRedirectNoStoreCombinedForm verifies the combined form
// (`redirect @scope PATH_REGEX CODE TARGET no_store`).
func TestRedirectNoStoreCombinedForm(t *testing.T) {
	src := `example.com {
	upstream b { to http://x:80 }
	@mobile method GET
	redirect @mobile ^/shop(/.*)?$ 302 https://m.example.com/shop$1 no_store
	redirect @mobile ^/legacy(/.*)?$ 301 https://m.example.com/v2$1
	cache_ttl default ttl 5m
}
`
	p := compileSrc(t, src)
	dec := p.EvalRequest(&Request{
		Method: "GET", Host: "example.com", Path: "/shop/deals",
		Query: url.Values{},
	})
	if dec.Redirect == nil {
		t.Fatal("expected redirect, got nil")
	}
	if !dec.Redirect.NoStore {
		t.Errorf("combined redirect with no_store: NoStore = false, want true")
	}
	// Sentinel: a PLAIN combined redirect (no no_store) in the same pipeline must NOT set NoStore.
	decPlain := p.EvalRequest(&Request{
		Method: "GET", Host: "example.com", Path: "/legacy/x",
		Query: url.Values{},
	})
	if decPlain.Redirect == nil {
		t.Fatal("expected redirect for /legacy/x, got nil")
	}
	if decPlain.Redirect.NoStore {
		t.Errorf("plain combined redirect: NoStore = true, want false")
	}
}
