package edgeir

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/cadi-sh/cadish/internal/cadishfile"
	"github.com/cadi-sh/cadish/internal/pipeline"
)

// compile parses a single-site Cadishfile source and compiles it to a Pipeline.
func compile(t *testing.T, src string) *pipeline.Pipeline {
	t.Helper()
	f, err := cadishfile.Parse("test.cadish", []byte(src))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(f.Sites) != 1 {
		t.Fatalf("want 1 site, got %d", len(f.Sites))
	}
	p, err := pipeline.Compile(f.Sites[0])
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	return p
}

const storefrontSrc = `example.com, *.example.com {
    @ajax     header X-Requested-With XMLHttpRequest
    @nocache  path /panel/*
    @listings path_regex ^/catalog/

    respond /health-check 200 "OK"
    purge   when header X-Purge-Token secret   regex {http.X-Purge-Regex}

    pass   @ajax
    pass   method POST
    pass   @nocache

    cache_key   url host

    cache_ttl   status 404 410   ttl 60s grace 1h
    cache_ttl   status not 200   hit_for_miss 5s
    cache_ttl   @listings        ttl 2s  grace 24h
    cache_ttl   default          ttl 2s  grace 24h

    storage   @listings -> disk
    storage   default -> ram

    strip_cookies   path_regex \.(css|js|png)$

    header  -Server
    header  +cache_status   X-Cache
}`

func TestProjectStorefront(t *testing.T) {
	p := compile(t, storefrontSrc)
	ir, rep, err := Project(p)
	if err != nil {
		t.Fatalf("Project: %v", err)
	}
	if ir.IRVersion != IRVersion {
		t.Errorf("IRVersion = %d, want %d", ir.IRVersion, IRVersion)
	}

	// Site hosts.
	if got := strings.Join(ir.Site.Hosts, ","); got != "example.com,*.example.com" {
		t.Errorf("hosts = %q", got)
	}
	// Redirect trusted-host allowlist + canonical host (open-redirect defense, D74):
	// the normalized projection of the server's trustedHosts/canonicalHost. The worker
	// resolves a `redirect` {host} against these instead of reflecting the inbound Host.
	if got := strings.Join(ir.Site.RedirectHosts, ","); got != "*.example.com,example.com" {
		t.Errorf("redirectHosts = %q", got)
	}
	if ir.Site.CanonicalHost != "example.com" {
		t.Errorf("canonicalHost = %q, want example.com", ir.Site.CanonicalHost)
	}

	// Matchers projected by id with kind + fields.
	if m, ok := ir.Matchers["ajax"]; !ok {
		t.Error("missing @ajax matcher")
	} else if m.Kind != "header" || m.Name != "X-Requested-With" {
		t.Errorf("@ajax = %+v, want header X-Requested-With", m)
	}
	if m, ok := ir.Matchers["nocache"]; !ok {
		t.Error("missing @nocache matcher")
	} else if m.Kind != "path" || len(m.Patterns) != 1 || m.Patterns[0] != "/panel/*" {
		t.Errorf("@nocache = %+v, want path /panel/*", m)
	}
	if m, ok := ir.Matchers["listings"]; !ok {
		t.Error("missing @listings matcher")
	} else if m.Kind != "path_regex" || m.Regex != "^/catalog/" {
		t.Errorf("@listings = %+v, want path_regex ^/catalog/", m)
	}

	// pass references matchers by id (OR), in order.
	if len(ir.Recv.Pass) != 3 {
		t.Fatalf("want 3 pass rules, got %d", len(ir.Recv.Pass))
	}
	if ir.Recv.Pass[0].Names[0] != "ajax" {
		t.Errorf("pass[0] = %+v", ir.Recv.Pass[0])
	}
	// pass method POST is an inline matcher.
	if len(ir.Recv.Pass[1].Inline) != 1 || ir.Recv.Pass[1].Inline[0].Kind != "method" {
		t.Errorf("pass[1] = %+v, want inline method", ir.Recv.Pass[1])
	}

	// respond.
	if len(ir.Recv.Respond) != 1 || ir.Recv.Respond[0].Path != "/health-check" || ir.Recv.Respond[0].Status != 200 {
		t.Errorf("respond = %+v", ir.Recv.Respond)
	}

	// cache key tokens.
	gotKey := make([]string, 0, len(ir.Key.Tokens))
	for _, tk := range ir.Key.Tokens {
		gotKey = append(gotKey, tk.Kind)
	}
	if strings.Join(gotKey, ",") != "url,host" {
		t.Errorf("key tokens = %v, want url,host", gotKey)
	}

	// ttl rules: status selector + scope selector + default, in order.
	if len(ir.Response.TTL) != 4 {
		t.Fatalf("want 4 ttl rules, got %d", len(ir.Response.TTL))
	}
	if ir.Response.TTL[0].SelKind != "status_in" || ir.Response.TTL[0].TTL != "1m0s" {
		t.Errorf("ttl[0] = %+v", ir.Response.TTL[0])
	}
	if ir.Response.TTL[1].SelKind != "status_not_in" || !ir.Response.TTL[1].IsHFM {
		t.Errorf("ttl[1] = %+v, want hit_for_miss", ir.Response.TTL[1])
	}
	if ir.Response.TTL[3].SelKind != "default" {
		t.Errorf("ttl[3] = %+v, want default", ir.Response.TTL[3])
	}

	// deliver: cache-status header.
	if ir.Deliver.CacheStatusHeader != "X-Cache" {
		t.Errorf("cacheStatusHeader = %q, want X-Cache", ir.Deliver.CacheStatusHeader)
	}

	// purge with a request-sourced regex BAN is DELEGATED (not in the edge purge set).
	if !containsReason(rep.DelegatedItems, "purge") {
		t.Errorf("expected a delegated purge regex, report = %+v", rep.DelegatedItems)
	}

	// Coverage report counts something edge-native.
	if rep.EdgeNative == 0 {
		t.Error("expected some edge-native directives")
	}

	// IR must round-trip through JSON (the contract is serializable).
	b, err := json.Marshal(ir)
	if err != nil {
		t.Fatalf("marshal IR: %v", err)
	}
	if !strings.Contains(string(b), fmt.Sprintf(`"irVersion":%d`, IRVersion)) {
		t.Errorf("serialized IR missing irVersion: %s", b)
	}
}

// TestProjectReplaceIsEdgeNative (D75): a `replace` body transform is now EDGE-NATIVE
// within the worker's body-size cap. It is projected into Response.Transforms (with the
// scope + old/new) and the size cap into Response.TransformMaxBytes — NOT delegated.
// The over-cap/streaming case is a runtime pass-through (the worker streams a large body
// untransformed), not a delegate entry.
func TestProjectReplaceIsEdgeNative(t *testing.T) {
	src := `example.com {
    @html content_type text/html
    replace @html OLD NEW
    cache_ttl default ttl 1m
}`
	p := compile(t, src)
	ir, _, err := Project(p)
	if err != nil {
		t.Fatalf("Project: %v", err)
	}
	for _, d := range ir.Delegate {
		if d.Directive == "replace" {
			t.Errorf("replace should be edge-native, not delegated; delegate = %+v", ir.Delegate)
		}
	}
	if len(ir.Response.Transforms) != 1 {
		t.Fatalf("want 1 projected transform, got %d (%+v)", len(ir.Response.Transforms), ir.Response.Transforms)
	}
	tr := ir.Response.Transforms[0]
	if tr.Old != "OLD" || tr.New != "NEW" {
		t.Errorf("transform old/new = %q/%q, want OLD/NEW", tr.Old, tr.New)
	}
	if ir.Response.TransformMaxBytes != 1<<20 {
		t.Errorf("transformMaxBytes = %d, want %d", ir.Response.TransformMaxBytes, 1<<20)
	}
}

// TestProjectOnErrorIsEdgeNative (D76): a `respond on_error` synthetic is now
// EDGE-NATIVE for the outage path. It is projected into Response.OnError (scope +
// status + body + content_type) — NOT delegated.
func TestProjectOnErrorIsEdgeNative(t *testing.T) {
	src := `example.com {
    respond on_error 503 "down for maintenance"
    cache_ttl default ttl 1m
}`
	p := compile(t, src)
	ir, _, err := Project(p)
	if err != nil {
		t.Fatalf("Project: %v", err)
	}
	for _, d := range ir.Delegate {
		if d.Directive == "respond on_error" {
			t.Errorf("respond on_error should be edge-native, not delegated; delegate = %+v", ir.Delegate)
		}
	}
	if len(ir.Response.OnError) != 1 {
		t.Fatalf("want 1 projected on_error rule, got %d (%+v)", len(ir.Response.OnError), ir.Response.OnError)
	}
	oe := ir.Response.OnError[0]
	if oe.Status != 503 || oe.Body != "down for maintenance" {
		t.Errorf("on_error = %d/%q, want 503/down for maintenance", oe.Status, oe.Body)
	}
	if oe.ContentType == "" {
		t.Error("on_error content type should default to text/html; charset=utf-8")
	}
}

// TestProjectRewriteIsDelegated (P0): a `rewrite` directive is compiled in the
// pipeline but NOT projected into the worker IR — it must land in delegate[] with a
// reason (never silently dropped), exactly like `replace`, so the coverage report
// records it and -strict fails.
func TestProjectRewriteIsDelegated(t *testing.T) {
	src := `example.com {
    rewrite strip_query utm_*
    cache_ttl default ttl 1m
}`
	p := compile(t, src)
	ir, rep, err := Project(p)
	if err != nil {
		t.Fatalf("Project: %v", err)
	}
	found := false
	for _, d := range ir.Delegate {
		if d.Directive == "rewrite" {
			found = true
			if d.Reason == "" {
				t.Error("delegate rewrite has empty reason")
			}
		}
	}
	if !found {
		t.Errorf("rewrite not delegated; delegate = %+v", ir.Delegate)
	}
	if !containsReason(rep.DelegatedItems, "rewrite") {
		t.Errorf("rewrite not in coverage report; report = %+v", rep.DelegatedItems)
	}
}

// TestProjectEncodeIsDelegated (P0): an `encode` directive is compiled in the
// pipeline but NOT projected into the worker IR — it must land in delegate[] with a
// reason (never silently dropped), like `replace`, so the report records it and
// -strict fails.
func TestProjectEncodeIsDelegated(t *testing.T) {
	src := `example.com {
    encode zstd br gzip
    cache_ttl default ttl 1m
}`
	p := compile(t, src)
	ir, rep, err := Project(p)
	if err != nil {
		t.Fatalf("Project: %v", err)
	}
	found := false
	for _, d := range ir.Delegate {
		if d.Directive == "encode" {
			found = true
			if d.Reason == "" {
				t.Error("delegate encode has empty reason")
			}
		}
	}
	if !found {
		t.Errorf("encode not delegated; delegate = %+v", ir.Delegate)
	}
	if !containsReason(rep.DelegatedItems, "encode") {
		t.Errorf("encode not in coverage report; report = %+v", rep.DelegatedItems)
	}
}

func TestProjectClassify(t *testing.T) {
	src := `example.com {
    @verified  cookie verified_prod
    @adult     host adult.example.com
    classify {age} {
        when @verified -> ok
        when @adult    -> gate
        default        -> open
    }
    cache_key method host path {age}
}`
	p := compile(t, src)
	ir, _, err := Project(p)
	if err != nil {
		t.Fatalf("Project: %v", err)
	}
	cl, ok := ir.Classifiers["age"]
	if !ok {
		t.Fatalf("missing classifier age; got %+v", ir.Classifiers)
	}
	if cl.Default != "open" {
		t.Errorf("default = %q, want open", cl.Default)
	}
	if len(cl.Rows) != 2 {
		t.Fatalf("want 2 rows, got %d", len(cl.Rows))
	}
	if cl.Rows[0].Value != "ok" || len(cl.Rows[0].Conj) != 1 || cl.Rows[0].Conj[0] != "verified" {
		t.Errorf("row0 = %+v", cl.Rows[0])
	}
	// the {age} classify token is in the cache key.
	last := ir.Key.Tokens[len(ir.Key.Tokens)-1]
	if last.Kind != "classify" || last.Ref != "age" {
		t.Errorf("key tail = %+v, want classify age", last)
	}
}

// TestPurgeTokenNeverShipsToEdge is the security regression for D34: the purge-token
// guard secret must NEVER appear anywhere in the IR JSON that ships to the public
// edge worker. Covers both the inline form (`purge when header X-Purge-Token TOK`)
// and the named form (`purge when @tok`), single-key and regex BAN.
func TestPurgeTokenNeverShipsToEdge(t *testing.T) {
	const token = "s3cr3t-purge-token-DO-NOT-LEAK"
	cases := []struct {
		name string
		src  string
	}{
		{"inline single-key", `example.com {
    purge when header X-Purge-Token ` + token + `
}`},
		{"inline regex ban", `example.com {
    purge when header X-Purge-Token ` + token + ` regex ^/assets/.*
}`},
		{"named guard", `example.com {
    @tok header X-Purge-Token ` + token + `
    purge when @tok
}`},
		{"cookie guard", `example.com {
    purge when cookie purge_auth ` + token + `
}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := compile(t, tc.src)
			ir, rep, err := Project(p)
			if err != nil {
				t.Fatalf("Project: %v", err)
			}
			b, err := json.Marshal(ir)
			if err != nil {
				t.Fatalf("marshal: %v", err)
			}
			if strings.Contains(string(b), token) {
				t.Fatalf("SECRET LEAK: purge token present in IR JSON:\n%s", b)
			}
			// Every purge must be delegated (never edge-native).
			if len(ir.Recv.Purge) != 0 {
				t.Errorf("purge should be delegated, got %d edge-native purge(s)", len(ir.Recv.Purge))
			}
			if !containsReason(rep.DelegatedItems, "purge") {
				t.Errorf("purge not delegated; report = %+v", rep.DelegatedItems)
			}
		})
	}
}

// TestNamedPurgeGuardMatcherRedacted verifies a named purge-guard matcher keeps its
// kind/name (for the report) but is marked Redacted with no values.
func TestNamedPurgeGuardMatcherRedacted(t *testing.T) {
	src := `example.com {
    @tok header X-Purge-Token topsecret
    purge when @tok
}`
	p := compile(t, src)
	ir, _, err := Project(p)
	if err != nil {
		t.Fatalf("Project: %v", err)
	}
	m, ok := ir.Matchers["tok"]
	if !ok {
		t.Fatal("missing @tok matcher")
	}
	if !m.Redacted {
		t.Error("@tok should be marked Redacted")
	}
	if len(m.Values) != 0 {
		t.Errorf("@tok values not redacted: %v", m.Values)
	}
	if m.Kind != "header" || m.Name != "X-Purge-Token" {
		t.Errorf("@tok kind/name should survive redaction: %+v", m)
	}
}

// TestNonSecretHeaderMatcherPreservedWithWarning verifies a legitimate (non-purge)
// header value matcher is NOT redacted (the conformance suite needs the value to
// match) but does raise a visibility warning.
func TestNonSecretHeaderMatcherPreservedWithWarning(t *testing.T) {
	src := `example.com {
    @ajax header X-Requested-With XMLHttpRequest
    pass @ajax
}`
	p := compile(t, src)
	ir, rep, err := Project(p)
	if err != nil {
		t.Fatalf("Project: %v", err)
	}
	m := ir.Matchers["ajax"]
	if m.Redacted {
		t.Error("a non-purge header matcher must not be redacted")
	}
	if len(m.Values) != 1 || m.Values[0] != "XMLHttpRequest" {
		t.Errorf("@ajax value should survive: %+v", m)
	}
	if len(rep.Warnings) == 0 {
		t.Error("expected a value-exposure warning for the shipped header value")
	}
}

// TestJSONMatcherValueExposureWarning verifies the secret-exposure advisory (Finding
// D) also covers cookie_json / header_json: these project their literal match values
// into the public IR exactly like `cookie` / `header`, so a literal secret in one
// must raise the same heads-up.
func TestJSONMatcherValueExposureWarning(t *testing.T) {
	src := `example.com {
    @sess cookie_json sessionCookie auth.token s3cr3t-token
    @plan header_json X-Session plan.tier pro
    pass @sess @plan
}`
	p := compile(t, src)
	ir, rep, err := Project(p)
	if err != nil {
		t.Fatalf("Project: %v", err)
	}
	// The literal value still ships (the JS side needs it to match) — it is advisory.
	if m := ir.Matchers["sess"]; len(m.Values) != 1 || m.Values[0] != "s3cr3t-token" {
		t.Errorf("@sess value should survive (advisory, not redacted): %+v", m)
	}
	hasWarn := func(sub string) bool {
		for _, w := range rep.Warnings {
			if strings.Contains(w, sub) {
				return true
			}
		}
		return false
	}
	if !hasWarn("cookie_json matcher @sess") {
		t.Errorf("expected a cookie_json value-exposure warning; got %v", rep.Warnings)
	}
	if !hasWarn("header_json matcher @plan") {
		t.Errorf("expected a header_json value-exposure warning; got %v", rep.Warnings)
	}
}

// compileWithEnv mirrors the real edge load: parse → SubstituteEnv → compile. An
// unquoted `{$VAR}` placeholder is env-expanded to its literal value before compile
// (so a secret lands in the IR); a quoted `"{$VAR}"` stays the literal text `{$VAR}`
// (never expanded — classifyArg treats a quoted token as a literal).
func compileWithEnv(t *testing.T, src string, env map[string]string) *pipeline.Pipeline {
	t.Helper()
	f, err := cadishfile.Parse("test.cadish", []byte(src))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	cadishfile.SubstituteEnv(f, func(name string) (string, bool) {
		v, ok := env[name]
		return v, ok
	})
	if len(f.Sites) != 1 {
		t.Fatalf("want 1 site, got %d", len(f.Sites))
	}
	p, err := pipeline.Compile(f.Sites[0])
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	return p
}

// withEnvValues sets the package env-value provider for the duration of a test so the
// value-exposure scan can recognise an env-expanded secret without reading the real
// process environment (keeps the test hermetic).
func withEnvValues(t *testing.T, env map[string]string) {
	t.Helper()
	prev := envValues
	envValues = func() map[string]struct{} {
		set := make(map[string]struct{}, len(env))
		for _, v := range env {
			if v != "" {
				set[v] = struct{}{}
			}
		}
		return set
	}
	t.Cleanup(func() { envValues = prev })
}

// TestValueExposureScansAllStringFields (Fix 1) pins that the secret-exposure gate
// covers EVERY IR string field whose source could be an unquoted `{$VAR}` env
// placeholder — not just matcher values. An env-expanded secret in a request/response
// header value, a `replace` transform, a `respond on_error` body, a `redirect` target,
// or a cache_key `literal:` token must be flagged for value exposure (so `cadish edge
// build -strict` trips), while a quoted `"{$VAR}"` (which stays the literal text and
// never ships the secret) must NOT warn.
func TestValueExposureScansAllStringFields(t *testing.T) {
	env := map[string]string{"HDR_SECRET": "topsecret-aabbccdd"}
	withEnvValues(t, env)

	cases := []struct {
		name string
		src  string
	}{
		{"req header value", `example.com {
    header X-Internal-Auth {$HDR_SECRET}
    cache_ttl default ttl 1m
}`},
		{"resp header value", `example.com {
    cache_key host
    header X-Origin-Auth {$HDR_SECRET}
    cache_ttl default ttl 1m
}`},
		{"transform new", `example.com {
    replace OLDTOKEN {$HDR_SECRET}
    cache_ttl default ttl 1m
}`},
		{"transform old", `example.com {
    replace {$HDR_SECRET} REDACTED
    cache_ttl default ttl 1m
}`},
		{"on_error body", `example.com {
    respond on_error 503 {$HDR_SECRET}
    cache_ttl default ttl 1m
}`},
		{"respond body", `example.com {
    respond /maint 503 down-{$HDR_SECRET}
    cache_ttl default ttl 1m
}`},
		{"on_error content_type", `example.com {
    respond on_error 503 down content_type text/html-{$HDR_SECRET}
    cache_ttl default ttl 1m
}`},
		{"redirect target", `example.com {
    redirect /go 302 https://example.com/{$HDR_SECRET}
    cache_ttl default ttl 1m
}`},
		{"cache_key literal", `example.com {
    cache_key host literal:{$HDR_SECRET}
    cache_ttl default ttl 1m
}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := compileWithEnv(t, tc.src, env)
			_, rep, err := Project(p)
			if err != nil {
				t.Fatalf("Project: %v", err)
			}
			if rep.ValueExposed == 0 {
				t.Errorf("ValueExposed = 0, want > 0 (env secret leaked into IR); warnings = %v", rep.Warnings)
			}
		})
	}
}

// TestValueExposureQuotedPlaceholderClean (Fix 1): a QUOTED "{$VAR}" is never
// env-expanded — it stays the literal text `{$VAR}` and ships no secret — so it must
// NOT be flagged. And a plain non-env literal must not be flagged either (the scan is
// env-value-scoped, not flag-everything, for these fields).
func TestValueExposureQuotedPlaceholderClean(t *testing.T) {
	env := map[string]string{"HDR_SECRET": "topsecret-aabbccdd"}
	withEnvValues(t, env)

	cases := []struct {
		name string
		src  string
	}{
		{"quoted placeholder header", `example.com {
    header X-Internal-Auth "{$HDR_SECRET}"
    cache_ttl default ttl 1m
}`},
		{"plain literal header", `example.com {
    header X-Frame-Options DENY
    cache_ttl default ttl 1m
}`},
		{"quoted placeholder on_error", `example.com {
    respond on_error 503 "{$HDR_SECRET}"
    cache_ttl default ttl 1m
}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := compileWithEnv(t, tc.src, env)
			_, rep, err := Project(p)
			if err != nil {
				t.Fatalf("Project: %v", err)
			}
			if rep.ValueExposed != 0 {
				t.Errorf("ValueExposed = %d, want 0 (quoted/non-env value ships no secret); warnings = %v", rep.ValueExposed, rep.Warnings)
			}
		})
	}
}

// TestStickyTokenCarriesCookieName verifies the {sticky} cache-key token ships the
// site-level sticky cookie NAME in the IR — without it the JS interpreter cannot
// read the cookie and the edge cache key silently diverges from the server's.
func TestStickyTokenCarriesCookieName(t *testing.T) {
	src := `example.com {
    upstream web {
        to http://backend
        sticky by cookie PHPSESSID else client_ip
    }
    cache_key host path {sticky}
}`
	p := compile(t, src)
	ir, _, err := Project(p)
	if err != nil {
		t.Fatalf("Project: %v", err)
	}
	var sticky *KeyToken
	for i := range ir.Key.Tokens {
		if ir.Key.Tokens[i].Kind == "sticky" {
			sticky = &ir.Key.Tokens[i]
		}
	}
	if sticky == nil {
		t.Fatalf("no sticky token in key: %+v", ir.Key.Tokens)
	}
	if sticky.Arg != "PHPSESSID" {
		t.Errorf("sticky token Arg = %q, want PHPSESSID (the cookie name)", sticky.Arg)
	}
}

// TestProjectEdgeBlock verifies the `edge {}` cache-tier policies (default + per-
// scope local/distribute/skip) project into EdgeIR.Edge, and — critically — that
// the deploy identity (account/zone/worker/routes/kv) NEVER ships in the worker IR
// (it is management-plane metadata read separately via pipeline.EdgeDeployConfig).
func TestProjectEdgeBlock(t *testing.T) {
	src := `example.com {
    @html   content_type text/html
    @assets path /assets/*
    edge {
        account super-secret-account-id
        zone    example.com
        worker  cadish-edge-example
        route   example.com/*
        kv      EDGE_CACHE
        default local
        distribute @html
        skip @assets
    }
    cache_ttl default ttl 1m
}`
	p := compile(t, src)
	ir, _, err := Project(p)
	if err != nil {
		t.Fatalf("Project: %v", err)
	}
	if ir.Edge.Default != "local" {
		t.Errorf("edge default = %q, want local", ir.Edge.Default)
	}
	if len(ir.Edge.Policies) != 2 {
		t.Fatalf("want 2 edge policies, got %d", len(ir.Edge.Policies))
	}
	if ir.Edge.Policies[0].Tier != "distribute" || ir.Edge.Policies[0].Scope.Names[0] != "html" {
		t.Errorf("policy[0] = %+v", ir.Edge.Policies[0])
	}
	if ir.Edge.Policies[1].Tier != "skip" || ir.Edge.Policies[1].Scope.Names[0] != "assets" {
		t.Errorf("policy[1] = %+v", ir.Edge.Policies[1])
	}
	// No kv_ttl declared => omitted (0); kv_max_bytes defaults to 1 MiB.
	if ir.Edge.KVTTLSeconds != 0 {
		t.Errorf("kvTtlSeconds = %d, want 0 (unset)", ir.Edge.KVTTLSeconds)
	}
	if ir.Edge.KVMaxBytes != 1<<20 {
		t.Errorf("kvMaxBytes = %d, want 1 MiB", ir.Edge.KVMaxBytes)
	}

	// Deploy identity must NOT appear in the public worker IR.
	b, err := json.Marshal(ir)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	for _, secret := range []string{"super-secret-account-id", "cadish-edge-example", "EDGE_CACHE"} {
		if strings.Contains(string(b), secret) {
			t.Errorf("deploy identity %q leaked into the worker IR:\n%s", secret, b)
		}
	}
}

// TestProjectEdgeKVGuardrails verifies kv_ttl/kv_max_bytes project into the IR's
// Edge fields (kvTtlSeconds rounded up to whole seconds; kvMaxBytes in bytes).
func TestProjectEdgeKVGuardrails(t *testing.T) {
	src := `example.com {
    @html content_type text/html
    edge {
        worker w
        kv     EDGE_CACHE
        distribute @html
        kv_ttl       5m
        kv_max_bytes 256KiB
    }
    cache_ttl default ttl 1m
}`
	p := compile(t, src)
	ir, _, err := Project(p)
	if err != nil {
		t.Fatalf("Project: %v", err)
	}
	if ir.Edge.KVTTLSeconds != 300 {
		t.Errorf("kvTtlSeconds = %d, want 300", ir.Edge.KVTTLSeconds)
	}
	if ir.Edge.KVMaxBytes != 256*1024 {
		t.Errorf("kvMaxBytes = %d, want %d", ir.Edge.KVMaxBytes, 256*1024)
	}
}

// TestProjectEdgeKVMaxBytesOversizeWarns verifies a kv_max_bytes above the 25 MB
// Workers KV hard cap produces a build warning (advisory, not an error).
func TestProjectEdgeKVMaxBytesOversizeWarns(t *testing.T) {
	src := `example.com {
    @html content_type text/html
    edge {
        worker w
        kv     EDGE_CACHE
        distribute @html
        kv_max_bytes 30MB
    }
    cache_ttl default ttl 1m
}`
	p := compile(t, src)
	ir, rep, err := Project(p)
	if err != nil {
		t.Fatalf("Project: %v", err)
	}
	if ir.Edge.KVMaxBytes != 30*1e6 {
		t.Errorf("kvMaxBytes = %d, want %d", ir.Edge.KVMaxBytes, int64(30*1e6))
	}
	found := false
	for _, w := range rep.Warnings {
		if strings.Contains(w, "kv_max_bytes") && strings.Contains(w, "25 MB") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected a 25 MB hard-cap warning, got warnings: %v", rep.Warnings)
	}
}

func containsReason(items []DelegatedItem, directive string) bool {
	for _, d := range items {
		if strings.Contains(d.Directive, directive) {
			return true
		}
	}
	return false
}

// TestProjectCacheKeyHeader covers the `header +cache_key` projection: the deliver
// block surfaces the target name + raw flag, and the cache_key op is NOT delegated
// (the worker emits the hash natively). The hash VALUE is never baked into the IR
// (AST/IR semantics-free) — only the directive marker.
func TestProjectCacheKeyHeader(t *testing.T) {
	src := `ck.example.com {
    @debug header X-Debug 1
    cache_key method host path
    header +cache_key X-Cache-Key
    header @debug +cache_key X-Cache-Key-Raw raw
}`
	p := compile(t, src)
	ir, _, err := Project(p)
	if err != nil {
		t.Fatalf("Project: %v", err)
	}
	// Last matching cache_key op wins (mirrors CacheStatusHeader); here the scoped raw
	// rule is declared last, so the projected marker is the raw one.
	if ir.Deliver.CacheKeyHeader != "X-Cache-Key-Raw" {
		t.Errorf("cacheKeyHeader = %q, want X-Cache-Key-Raw", ir.Deliver.CacheKeyHeader)
	}
	if !ir.Deliver.CacheKeyRaw {
		t.Error("cacheKeyRaw = false, want true (last op is the raw form)")
	}
	// No hash value is baked into the IR — only the directive markers.
	b, err := json.Marshal(ir)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if strings.Contains(string(b), "method\\u001fck.example.com") {
		t.Errorf("a rendered cache key leaked into the IR:\n%s", b)
	}
}

// TestProjectCacheKeyHeaderHashOnly covers the common single-directive (hash) form.
func TestProjectCacheKeyHeaderHashOnly(t *testing.T) {
	p := compile(t, `ck.example.com {
    cache_key path
    header +cache_key X-Cache-Key
}`)
	ir, _, err := Project(p)
	if err != nil {
		t.Fatalf("Project: %v", err)
	}
	if ir.Deliver.CacheKeyHeader != "X-Cache-Key" || ir.Deliver.CacheKeyRaw {
		t.Errorf("cacheKeyHeader=%q raw=%v, want X-Cache-Key false", ir.Deliver.CacheKeyHeader, ir.Deliver.CacheKeyRaw)
	}
}

// TestProjectSecurityGateIsDelegated (Fix A): a site that configures a security
// gate (allow/deny/block/rate_limit) must NOT silently lose its ACL at the edge.
// The projector records the gate as a delegated `security` directive (so -strict
// trips) AND emits a loud warning naming the rules as unenforced at the edge.
func TestProjectSecurityGateIsDelegated(t *testing.T) {
	src := `example.com {
    @admin path /admin/*
    deny @admin
    cache_ttl default ttl 1m
}`
	p := compile(t, src)
	ir, rep, err := Project(p)
	if err != nil {
		t.Fatalf("Project: %v", err)
	}
	if !containsReason(rep.DelegatedItems, "security") {
		t.Errorf("security gate not delegated; report = %+v", rep.DelegatedItems)
	}
	found := false
	for _, d := range ir.Delegate {
		if d.Directive == "security" {
			found = true
		}
	}
	if !found {
		t.Errorf("security gate not in delegate[]; delegate = %+v", ir.Delegate)
	}
	if rep.SecurityGate == 0 {
		t.Error("rep.SecurityGate should be > 0 when a security gate is present")
	}
	// A loud warning must name allow/deny/block/rate_limit as unenforced.
	warned := false
	for _, w := range rep.Warnings {
		if strings.Contains(w, "NOT enforced at the edge") {
			warned = true
		}
	}
	if !warned {
		t.Errorf("expected a loud security-gate warning, got: %v", rep.Warnings)
	}
}

// TestProjectNoSecurityGateClean (Fix A): a site with no security gate is
// unaffected — no `security` delegate, no SecurityGate count.
func TestProjectNoSecurityGateClean(t *testing.T) {
	src := `example.com {
    cache_key url host
    cache_ttl default ttl 1m
}`
	p := compile(t, src)
	_, rep, err := Project(p)
	if err != nil {
		t.Fatalf("Project: %v", err)
	}
	if rep.SecurityGate != 0 {
		t.Errorf("SecurityGate = %d, want 0 for a non-security site", rep.SecurityGate)
	}
	if containsReason(rep.DelegatedItems, "security") {
		t.Errorf("non-security site has a security delegate; report = %+v", rep.DelegatedItems)
	}
}

// TestProjectValueExposureCount (Fix B): a header matcher carrying a literal value
// is flagged for value exposure AND counted in rep.ValueExposed (so -strict can
// fail). An env-ref or non-value matcher does not inflate the count.
func TestProjectValueExposureCount(t *testing.T) {
	src := `example.com {
    @auth header X-Internal-Auth s3cr3t
    pass @auth
    cache_ttl default ttl 1m
}`
	p := compile(t, src)
	_, rep, err := Project(p)
	if err != nil {
		t.Fatalf("Project: %v", err)
	}
	if rep.ValueExposed == 0 {
		t.Errorf("ValueExposed = 0, want > 0 for a literal header value; warnings = %v", rep.Warnings)
	}
}

// TestProjectNoValueExposure (Fix B): a matcher with no literal value (e.g. a path
// matcher) does not falsely inflate the value-exposure count.
func TestProjectNoValueExposure(t *testing.T) {
	src := `example.com {
    @api path /api/*
    pass @api
    cache_ttl default ttl 1m
}`
	p := compile(t, src)
	_, rep, err := Project(p)
	if err != nil {
		t.Fatalf("Project: %v", err)
	}
	if rep.ValueExposed != 0 {
		t.Errorf("ValueExposed = %d, want 0 for a path matcher", rep.ValueExposed)
	}
}

// TestProjectRegexFlagsLifted (BUG-1) asserts a path_regex/host_regex and a redirect
// carrying an RE2 inline flag group `(?i)`/`(?is)` project to a JS-compilable
// {regex, regexFlags} pair — the inline flag is stripped from the source and emitted
// as a JS RegExp flag string, so the worker compiles `new RegExp(regex, flags)`
// instead of crashing on `(?i)`.
func TestProjectRegexFlagsLifted(t *testing.T) {
	src := `example.com {
    @bypass path_regex (?i)^/(atvpanel|admin)
    @assets path_regex (?is)\.(css|js)$
    redirect (?i)^/cams/?$ 301 https://example.com/broadcast
    pass @bypass
    pass @assets
    cache_key host path
}`
	p := compile(t, src)
	ir, _, err := Project(p)
	if err != nil {
		t.Fatalf("Project: %v", err)
	}
	if m := ir.Matchers["bypass"]; m.Regex != "^/(atvpanel|admin)" || m.RegexFlags != "i" || m.RegexUntranslatable {
		t.Errorf("bypass = %+v, want regex=^/(atvpanel|admin) flags=i", m)
	}
	if m := ir.Matchers["assets"]; m.Regex != `\.(css|js)$` || m.RegexFlags != "is" || m.RegexUntranslatable {
		t.Errorf("assets = %+v, want regex stripped flags=is", m)
	}
	if len(ir.Recv.Redirect) != 1 {
		t.Fatalf("want 1 redirect, got %d", len(ir.Recv.Redirect))
	}
	if r := ir.Recv.Redirect[0]; r.Regex != "^/cams/?$" || r.RegexFlags != "i" {
		t.Errorf("redirect = %+v, want regex=^/cams/?$ flags=i", r)
	}
	// No inline `(?` flag group may survive in any shipped regex source (JS would throw).
	b, _ := json.Marshal(ir)
	if strings.Contains(string(b), "(?i)") || strings.Contains(string(b), "(?is)") {
		t.Errorf("IR still ships an inline RE2 flag group: %s", b)
	}
}

// TestProjectUntranslatableRegexDelegated (BUG-1 negative) asserts that an RE2
// construct with no faithful JS equivalent (ungreedy `(?U)`) is NEVER shipped: the
// matcher source is stripped + marked untranslatable, and the directive is delegated
// (loud) rather than shipping a crashing/divergent pattern.
func TestProjectUntranslatableRegexDelegated(t *testing.T) {
	// Matcher form.
	{
		src := `x {
    @bad path_regex (?U)a+b
    pass @bad
    cache_key host path
}`
		p := compile(t, src)
		ir, rep, err := Project(p)
		if err != nil {
			t.Fatalf("Project: %v", err)
		}
		m := ir.Matchers["bad"]
		if !m.RegexUntranslatable || m.Regex != "" || m.RegexFlags != "" {
			t.Errorf("bad matcher = %+v, want untranslatable + empty regex", m)
		}
		if !hasDelegate(rep, "path_regex") {
			t.Errorf("untranslatable path_regex matcher not delegated; report = %+v", rep)
		}
		// The crashing source must not ship as a compilable regex. (The delegate REASON
		// text legitimately names `(?U)` as documentation — only the matcher's own
		// regex/regexFlags fields are checked here.)
		if m.Regex != "" || m.RegexFlags != "" {
			t.Errorf("untranslatable matcher still carries a compilable pattern: %+v", m)
		}
	}
	// Redirect form.
	{
		src := `x {
    redirect (?U)^/a+$ 301 https://e/x
    cache_key host path
}`
		p := compile(t, src)
		ir, rep, err := Project(p)
		if err != nil {
			t.Fatalf("Project: %v", err)
		}
		if len(ir.Recv.Redirect) != 0 {
			t.Errorf("want 0 shipped redirects (delegated), got %d: %+v", len(ir.Recv.Redirect), ir.Recv.Redirect)
		}
		if !hasDelegate(rep, "redirect") {
			t.Errorf("untranslatable redirect not delegated; report = %+v", rep)
		}
	}
}

// TestProjectInlineClassifyMatcherEmitted (BUG-2) asserts that an inline (unnamed)
// matcher in a classify `when` row projects to a synthesized NAMED matcher the
// runtime can resolve — never an empty conj entry (which would silently no-op).
func TestProjectInlineClassifyMatcherEmitted(t *testing.T) {
	src := `example.com {
    classify {lang} {
        when cookie selectedLanguage es -> es
        default                         -> en
    }
    cache_key host path {lang}
}`
	p := compile(t, src)
	ir, _, err := Project(p)
	if err != nil {
		t.Fatalf("Project: %v", err)
	}
	cl := ir.Classifiers["lang"]
	if len(cl.Rows) != 1 || len(cl.Rows[0].Conj) != 1 {
		t.Fatalf("rows = %+v", cl.Rows)
	}
	sn := cl.Rows[0].Conj[0]
	if sn == "" {
		t.Fatalf("inline classify matcher projected to an EMPTY conj name (BUG-2): %+v", cl.Rows[0])
	}
	m, ok := ir.Matchers[sn]
	if !ok {
		t.Fatalf("synthesized matcher %q not emitted into ir.Matchers", sn)
	}
	if m.Kind != "cookie" || m.Name != "selectedLanguage" || len(m.Values) != 1 || m.Values[0] != "es" {
		t.Errorf("synthesized matcher = %+v, want cookie selectedLanguage es", m)
	}
}

func hasDelegate(rep CoverageReport, directive string) bool {
	for _, it := range rep.DelegatedItems {
		if it.Directive == directive {
			return true
		}
	}
	return false
}

// TestProjectScopedCacheKey verifies the D70 scoped cache_key v2 projection: the FULL
// ordered recipe list ships with each recipe's selector, the catch-all is Always, and
// the scoped recipe is NO LONGER delegated (it is edge-native now).
func TestProjectScopedCacheKey(t *testing.T) {
	const src = `example.com {
    @ssr header X-IS-SSR-URL true
    cache_key @ssr     host path
    cache_key default  host url
    cache_ttl default ttl 1m
}`
	p := compile(t, src)
	ir, rep, err := Project(p)
	if err != nil {
		t.Fatalf("Project: %v", err)
	}
	if len(ir.Key.Recipes) != 2 {
		t.Fatalf("want 2 recipes, got %d: %+v", len(ir.Key.Recipes), ir.Key.Recipes)
	}
	// recipe 0: scoped on @ssr -> host path (selector not Always).
	r0 := ir.Key.Recipes[0]
	if r0.Selector.Always {
		t.Errorf("recipe[0] selector should be scoped, got Always")
	}
	if len(r0.Selector.Names) != 1 || r0.Selector.Names[0] != "ssr" {
		t.Errorf("recipe[0] selector names = %v, want [ssr]", r0.Selector.Names)
	}
	if len(r0.Tokens) != 2 || r0.Tokens[0].Kind != "host" || r0.Tokens[1].Kind != "path" {
		t.Errorf("recipe[0] tokens = %+v, want host path", r0.Tokens)
	}
	// recipe 1: default catch-all -> host url (Always).
	r1 := ir.Key.Recipes[1]
	if !r1.Selector.Always {
		t.Errorf("recipe[1] (default) selector should be Always")
	}
	if len(r1.Tokens) != 2 || r1.Tokens[0].Kind != "host" || r1.Tokens[1].Kind != "url" {
		t.Errorf("recipe[1] tokens = %+v, want host url", r1.Tokens)
	}
	// The flat Tokens still carries the default recipe (backward compat / fallback).
	if len(ir.Key.Tokens) != 2 || ir.Key.Tokens[1].Kind != "url" {
		t.Errorf("flat Key.Tokens = %+v, want the default recipe host url", ir.Key.Tokens)
	}
	// scoped cache_key is NO LONGER delegated (D70 made it edge-native).
	if containsReason(rep.DelegatedItems, "cache_key") {
		t.Errorf("scoped cache_key must not be delegated anymore: %+v", rep.DelegatedItems)
	}
}

// TestProjectDeviceClassifier verifies the {device} UA ruleset is projected only when
// the cache key uses {device}, and that a custom device_detect block round-trips.
func TestProjectDeviceClassifier(t *testing.T) {
	// No {device} token -> no device block (zero-cost-when-unused).
	noDev := compile(t, "a.example.com {\n cache_key host path\n cache_ttl default ttl 1m\n}")
	if ir, _, _ := Project(noDev); ir.Device != nil {
		t.Errorf("site without {device} should not project a device ruleset, got %+v", ir.Device)
	}
	// Default ruleset projected when {device} is used.
	def := compile(t, "b.example.com {\n cache_key host path {device}\n cache_ttl default ttl 1m\n}")
	dir, _, _ := Project(def)
	if dir.Device == nil || len(dir.Device.Rules) == 0 {
		t.Fatalf("site with {device} should project the default device ruleset")
	}
	if dir.Device.Default != "desktop" {
		t.Errorf("default device class = %q, want desktop", dir.Device.Default)
	}
	// Custom block with folds round-trips.
	cust := compile(t, "c.example.com {\n device_detect {\n  fold tablet desktop\n }\n cache_key host {device}\n cache_ttl default ttl 1m\n}")
	cir, _, _ := Project(cust)
	if cir.Device == nil {
		t.Fatal("custom device_detect should project a ruleset")
	}
	foundFold := false
	for _, f := range cir.Device.Folds {
		if f.From == "tablet" && f.Into == "desktop" {
			foundFold = true
		}
	}
	if !foundFold {
		t.Errorf("expected a tablet->desktop fold, got %+v", cir.Device.Folds)
	}
}

// TestProjectMaxStale verifies max_stale (D60) is projected into the TTL IR (D70).
func TestProjectMaxStale(t *testing.T) {
	const src = `s.example.com {
    cache_key host path
    cache_ttl default ttl 1m grace 5m max_stale 24h
}`
	ir, _, err := Project(compile(t, src))
	if err != nil {
		t.Fatalf("Project: %v", err)
	}
	var found bool
	for _, r := range ir.Response.TTL {
		if r.SelKind == "default" && r.MaxStale == "24h0m0s" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected a default TTL rule with maxStale 24h0m0s, got %+v", ir.Response.TTL)
	}
}

// TestEnvExposureShortValuesNoFalsePositive (E1) pins that the env-secret exposure
// scan does NOT false-positive on a short env value (e.g. `SHORTV=1`) that happens to
// appear as a substring of a legitimate numeric header value like
// `Cache-Control: public, max-age=31536000, immutable`. A 1-char env value is below the
// secret-length threshold and must be skipped before the substring scan, so a dev/CI
// box with common short env vars (CLAUDECODE=1, MallocNanoZone=0) does not break
// `cadish edge build -strict` on ordinary IR strings.
func TestEnvExposureShortValuesNoFalsePositive(t *testing.T) {
	withEnvValues(t, map[string]string{"SHORTV": "1", "MALLOC": "0"})
	ir := EdgeIR{}
	ir.Response.HeaderResp = []Header{{
		Ops: []HeaderOp{{Op: "set", Name: "Cache-Control", Value: "public, max-age=31536000, immutable"}},
	}}
	if w := envValueExposureWarnings(ir); len(w) != 0 {
		t.Errorf("short env value false-positived on a numeric header value: %v", w)
	}
}

// TestEnvExposureLongValueStillFlagged (E1) pins that a real (long enough) env-expanded
// secret embedded in a header value is STILL flagged after the short-value guard — the
// guard skips only trivially-short values, never a plausible secret.
func TestEnvExposureLongValueStillFlagged(t *testing.T) {
	withEnvValues(t, map[string]string{"SECRET": "topsecret-aabbccdd"})
	ir := EdgeIR{}
	ir.Response.HeaderResp = []Header{{
		Ops: []HeaderOp{{Op: "set", Name: "X-Auth", Value: "topsecret-aabbccdd"}},
	}}
	if w := envValueExposureWarnings(ir); len(w) != 1 {
		t.Errorf("long env secret not flagged: %v", w)
	}
}

// TestScopedRespondDelegated (E2) pins that the scoped `respond @scope STATUS BODY`
// form is NOT silently dropped from the edge projection: it cannot be projected as an
// exact-path edge respond, so it must be recorded as a Delegate so the coverage report
// counts it and `cadish edge build -strict` fails (the "never silently dropped"
// contract). Previously EdgeRespondRules skipped it with no Delegate ⇒ -strict exit 0
// with the rule absent from both the IR and the worker bundle.
func TestScopedRespondDelegated(t *testing.T) {
	src := `example.com {
    @down path /status /health
    respond @down 200 "OK"
    cache_ttl default ttl 1m
}`
	p := compile(t, src)
	ir, rep, err := Project(p)
	if err != nil {
		t.Fatalf("Project: %v", err)
	}
	// The scoped respond is NOT an exact-path edge respond.
	for _, r := range ir.Recv.Respond {
		if r.Status == 200 && r.Body == "OK" {
			t.Fatalf("scoped respond was projected as an exact-path respond: %+v", r)
		}
	}
	// It must be delegated (counted, not dropped).
	found := false
	for _, d := range ir.Delegate {
		if d.Directive == "respond" {
			found = true
		}
	}
	if !found {
		t.Errorf("scoped respond not recorded as a Delegate; delegate list = %+v", ir.Delegate)
	}
	if rep.Delegated == 0 {
		t.Errorf("rep.Delegated = 0, want > 0 so -strict fails (scoped respond must not be silently dropped)")
	}
}
