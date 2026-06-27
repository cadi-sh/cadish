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

// REDIRECT-TOKEN Part A: a derived {classify.NAME} token resolves in a redirect
// Location (here a language table picks the target subdomain). With the zero
// resolver it expanded to "", producing a broken "https://.example.com/...".
func TestRedirectClassifyTokenResolves(t *testing.T) {
	src := `example.com {
	upstream b { to http://x:80 }
	classify {langredir} {
		when header Accept-Language es -> es
		default                        -> www
	}
	redirect ^/go(/.*)?$ 302 https://{classify.langredir}.example.com/go$1
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
	if dec.Redirect.Location != "https://es.example.com/go/x" {
		t.Fatalf("classify token not resolved in Location: got %q, want %q", dec.Redirect.Location, "https://es.example.com/go/x")
	}

	reqEN := &Request{Method: "GET", Host: "example.com", Path: "/go", Query: url.Values{},
		Header: http.Header{"Accept-Language": []string{"en"}}}
	if d := p.EvalRequest(reqEN); d.Redirect == nil || d.Redirect.Location != "https://www.example.com/go" {
		t.Fatalf("default classify token: got %+v, want https://www.example.com/go", d.Redirect)
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
// is public-suffix aware (nudity.tv, amateur.tv, and the multi-label tech555.io), and
// it derives from the VALIDATED redirect host so the open-redirect defense (F12) still
// applies to the COMPUTED host.
func TestRedirectHostBaseSubdomainRewrite(t *testing.T) {
	src := `es.nudity.tv, www.amateur.tv, nudity.tv, cam4you.tech555.io {
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
		{"es.nudity.tv -> www.nudity.tv", "es.nudity.tv", "https://www.nudity.tv/page"},
		{"www.amateur.tv -> www.amateur.tv", "www.amateur.tv", "https://www.amateur.tv/page"},
		{"bare nudity.tv -> www.nudity.tv", "nudity.tv", "https://www.nudity.tv/page"},
		// Multi-label public suffix: the whole host is the base (sub empty), NOT tech555.io.
		{"multi-label suffix base", "cam4you.tech555.io", "https://www.cam4you.tech555.io/page"},
		// SECURITY (F12): an attacker Host is NOT trusted, so {host.base} derives from the
		// canonical configured host (es.nudity.tv -> base nudity.tv), never the attacker's.
		{"attacker host falls back to canonical base", "evil.attacker.test", "https://www.nudity.tv/page"},
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
	src := `nudity.tv, www.nudity.tv {
	upstream b { to http://x:80 }
	@bare host nudity.tv
	redirect @bare ^/(.*)$ 302 https://www.{host.base}/$1
	cache_ttl default ttl 5m
}
`
	p := compileSrc(t, src)
	// Bare host: the @bare scope fires, rewrite to the www host.
	if d := p.EvalRequest(&Request{Method: "GET", Host: "nudity.tv", Path: "/x", Query: url.Values{}}); d.Redirect == nil || d.Redirect.Location != "https://www.nudity.tv/x" {
		t.Fatalf("bare host should redirect to www: %+v", d.Redirect)
	}
	// Already on www: @bare does not match, so no redirect — no self-loop.
	if d := p.EvalRequest(&Request{Method: "GET", Host: "www.nudity.tv", Path: "/x", Query: url.Values{}}); d.Redirect != nil {
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
// and {host} stays the VALIDATED redirect host (F12), never the raw request Host.
func TestRedirectScopedRegexTokenAndCapture(t *testing.T) {
	src := `www.example.com, example.com {
	upstream b { to http://x:80 }
	classify {langredir} {
		when header Accept-Language es -> es
		default                        -> www
	}
	@active classify {langredir}==es
	redirect @active (?i)^/go(/.*)?$ 302 https://{classify.langredir}.example.com{host}$1
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
	want := "https://es.example.comwww.example.com/x"
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
