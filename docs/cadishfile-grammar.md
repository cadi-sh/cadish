# The Cadishfile grammar (form A)

The **Cadishfile** is cadish's configuration format: a flat, declarative list of
**matchers** and **directives** per site. This document specifies the grammar
implemented by `internal/cadishfile` (the lexer, parser, AST, and formatter) and
catalogs the matcher and directive keywords recognized for v1.

> **Scope.** The parser is *structural only*. It faithfully represents a
> Cadishfile as an AST but does **not** interpret the meaning of any directive or
> matcher — that validation (and the complexity report) belongs to `cadish check`
> and the pipeline compiler. The parser will happily accept an unknown directive
> or a misused matcher; whether it *means* anything is decided later.

## 1. Lexical structure

The lexer turns source bytes into a stream of tokens.

| Token | Description |
|---|---|
| **word** | A bare word, a double-quoted string, a placeholder, or a matcher reference — any single argument-like unit. |
| **`{`** / **`}`** | Block open / close. |
| **`;`** | Explicit statement separator. |
| **newline** | End of a logical line (a statement separator). Consecutive blank lines are recorded for the formatter. |
| **comment** | `# ...` to end of line. |
| **EOF** | End of input. |

### Words and quoting

- A **bare word** runs until whitespace, a structural character (`{`, `}`, `;`),
  or end of line.
- **Backslashes are literal** inside bare words. This is deliberate: the
  Cadishfile is full of regexes such as `\.(css|js)$`, and the lexer must not
  eat the backslashes. The *only* special backslash is one immediately followed
  by a newline — a line continuation (see below).
- A **double-quoted string** `"..."` preserves interior spaces. Inside it, `\"`
  is an escaped quote and `\\` an escaped backslash; any other `\x` keeps both
  characters literally. A quoted string may span lines.

### Placeholders

A token may contain a **placeholder**: a brace-balanced span with no interior
whitespace.

- **Environment placeholder** `{$VAR}` — substituted from the environment by an
  explicit, opt-in pass (`SubstituteEnv`), never at parse time. A **default** may
  follow a colon: `{$VAR:fallback}` expands to `$VAR` when it is set (even to an empty
  string) and to `fallback` otherwise; the default itself may contain colons (e.g.
  `to http://localhost:{$PORT:8080}`). `{$VAR:}` is an explicit empty default; a bare
  `{$VAR}` for an unset variable still expands to empty.
- **Generic placeholder** `{device}`, `{geo}`, `{http.X-Foo}` — a runtime value
  resolved by the pipeline; left untouched by env substitution.

A `{` that begins such a span is part of the word; a standalone `{` (followed by
whitespace or a newline) opens a block. The lexer disambiguates by lookahead.

### Comments

`#` begins a comment that runs to end of line. A comment may stand on its own
line or trail a statement (`directive args  # note`). Comments carry no AST
meaning but are preserved by the formatter.

### Line continuation

A backslash immediately followed by a newline (`\`⏎) is a **line continuation**:
the newline is suppressed and the next physical line's tokens continue the
current logical line. The canonical example uses this to spread long matcher
argument lists across lines.

## 2. Syntactic grammar (EBNF-ish)

```ebnf
File        = [ GlobalOptions ] { Site | Statement } ;

GlobalOptions = "{" Body "}" ;          (* only at the very top of the file *)

Site        = Address { [ "," ] Address } "{" Body "}" ;
Address     = word ;                     (* not validated or normalized *)

Body        = { Separator } { Statement { Separator } } ;
Separator   = newline | ";" ;

Statement   = MatcherDef | Directive ;

MatcherDef  = "@" name type { Arg } ;    (* first token begins with "@" *)
Directive   = name { Arg } [ "{" Body "}" ] ;

Arg         = word ;                     (* literal | matcher-ref | placeholder *)
```

Notes:

- **Sites vs. fragments.** A complete config is a sequence of site blocks. An
  importable sub-config (e.g. `nocache.cadish`, pulled in via `import`) is a bare
  list of statements with *no* site wrapper; those statements parse into the
  file's top-level `Body`. The parser decides per top-level construct: a leading
  run of words closed by `{` is a site; otherwise it is a top-level statement.
- **Matcher vs. directive.** A statement is a *matcher definition* when its first
  (unquoted) token begins with `@`; otherwise it is a *directive*. Only
  directives may carry a nested block.
- **Empty block vs. no block.** `name { }` yields a directive with a present but
  empty block; `name` yields a directive with no block. The AST distinguishes
  these (`Directive.HasBlock`).
- **Addresses** may be comma-separated; a trailing comma fused to an address word
  (`a.com,`) is split. Addresses are kept as raw strings and never validated.

### Argument kinds

Each argument is classified syntactically (this says nothing about whether it
resolves to anything):

| Kind | Shape | Example |
|---|---|---|
| `literal` | bare word or quoted string | `url`, `"GET, POST"` |
| `matcher-ref` | unquoted token starting with `@` | `@ajax` |
| `placeholder` | unquoted token containing a `{...}` span | `{$PURGE_TOKEN}`, `{device}` |

A *quoted* `"@x"` is a literal, not a matcher reference.

## 3. Matcher catalog (v1)

Matchers are defined with `@name type arg...` and referenced elsewhere as
`@name`. The parser accepts any `type`; the recognized v1 types are:

| Matcher type | Meaning (interpreted later) | Example |
|---|---|---|
| `path` | exact / glob path set | `@nocache path /a/* /b/*` |
| `path_regex` | regex over the path | `@listings path_regex /(catalog|deals)/` |
| `host` | host set | `@api host api.example.com` |
| `host_regex` | regex over the host | `@static host_regex ^static` |
| `header` | header name + value | `@ajax header X-Requested-With XMLHttpRequest` |
| `header_present` | a request header is present (any value) | `@cors header_present Origin` |
| `header_regex` | regex (RE2) over a request header's value | `@beta header_regex User-Agent (?i)\bbeta\b` |
| `cookie` | a named cookie present or equal to a value | `@authed cookie sessionid` |
| `method` | HTTP method set | `@writes method POST PUT` |
| `upstream` | request bound to a named upstream | `@images upstream images` |
| `content_type` | response Content-Type (substring; resolves in the response phases — ORIGIN/DELIVER) | `@longcache content_type text/css image/svg+xml` |
| `cookie_json` | a bounded dotted-field test inside a JSON **cookie** value | `@beta cookie_json prefs flags.beta true` |
| `header_json` | a bounded dotted-field test inside a JSON **header** value | `@beta header_json X-Ctx user.tier premium` |
| `set_cookie` | response `Set-Cookie` present, or a named cookie set | `@sets set_cookie sessionid` |
| `classify` | a server-resolved `classify {TOKEN}` class | `@bot classify {ua_class} bot` |
| `geo` | a server-resolved geo class (country / continent / region) | `@eu geo continent EU` |
| `query_present` | presence of a query parameter (name, `*` glob) | `@search query_present q` |
| `query` | a named query param's value is in an OR set (no value = presence of that one param) | `@prod query env prod staging` |
| `ip` | client IP / CIDR ACL (resolved real client IP) | `@office ip 10.0.0.0/8` |
| `all` | AND-composite: every referenced (optionally `!`-negated) sub-matcher matches | `@m all @path @method !@bot` |

These names are available programmatically as `cadishfile.DefaultMatcherTypes`.
(`content_type` / `set_cookie` are **response-phase** matchers; the rest are
request-phase.)

## 4. Directive catalog (v1)

The parser accepts any directive name. The recognized v1 directives (from the
cadish design §4 and the canonical configs) are exposed as
`cadishfile.DefaultDirectives` and seeded into a `DirectiveRegistry` so later
milestones can warn on unknown directives:

| Directive | Purpose | Block? |
|---|---|---|
| `tls` | TLS / ACME settings | yes |
| `cache` | two-tier cache sizing (`ram`, `disk`) | yes |
| `device_detect` | customize the `{device}` UA classifier (ordered `CLASS ua_contains …` rules) | yes |
| `upstream` | backend definition (`to`, `sticky`, `health`, …) | yes |
| `cluster` | sharded peer cache (`shard_by`, `health`) | yes |
| `origin` | composed origin chains (`origin chain a -> b`) | no |
| `pass` | bypass cache for matched requests | no |
| `cache_key` | cache key composition | no |
| `cache_ttl` | TTL / grace policy by status or matcher | no |
| `cache_unsafe` | opt out of safe-by-default caching (cache Set-Cookie/private/uncovered-Vary) | no |
| `storage` | storage tier routing (`-> ram` / `-> disk`) | no |
| `lb` / `sticky` | load-balancing / stickiness | no |
| `header` | response header manipulation | no |
| `strip_cookies` | cookie hygiene by path / matcher | no |
| `route` | route matched requests to an upstream | no |
| `respond` | synthetic responses | no |
| `purge` | purge / ban (token-protected) | no |
| `cors` | CORS policy | no |
| `import` | include a sub-config (`import nocache.cadish`) | no |
| `host_header` | which Host the origin sees | no |
| `sni` | per-upstream TLS ClientHello server name | no |
| `http_reuse` | per-upstream connection-reuse knob (`http_reuse never`) | no |
| `rewrite` | edit the origin-bound path/query in RECV | no |
| `redirect` | computed 3xx redirect (status + target / `map`) | no |
| `geo` | geo source + trusted-proxy block for `{geo}` tokens / `geo` matcher | yes |
| `trust_proxy` | site-level trusted-proxy CIDRs (real-client-IP resolution) | no |
| `normalize` | request normalization (query sort, etc.) | yes |
| `tenant` | multi-tenant key/scoping setup | yes |
| `replace` | deliver-phase response-body literal rewrite | no |
| `encode` | response compression on delivery (`zstd br gzip`) | no |
| `classify` | define a `{TOKEN}` request classifier (ordered `when` rules) | yes |
| `edge` | Cadish Edge (Cloudflare Workers) deploy + cache-tier policy | yes |
| `access_log` | global access-log toggle (`access_log off`) | no |
| `admin` | global dashboard/metrics listener | yes |
| `proxy_protocol` | global opt-in PROXY-protocol listener (`trust …`) | yes |
| `security` | global security observability (`audit_log …`) | yes |
| `allow` / `deny` / `block` | security gate (native primitives, server-only) | no |
| `monitor` | global toggle: run the security gate in monitor (non-enforcing) mode | no |
| `rate_limit` | stateful rate limiter (token bucket, server-only) | no |

(The "Block?" column reflects typical usage; the parser does not enforce it.)

## 5. Worked example

```cadish
example.com, *.example.com {
    tls {
        acme ops@example.com
    }

    upstream web {
        to        k8s://web-ingress:8080
        sticky    by cookie PHPSESSID else client_ip
        health    GET / expect 301 interval 5s window 6 threshold 3
    }

    cache {
        ram   10GiB
        disk  /var/cache/cadish 2TiB
    }

    @ajax   header X-Requested-With XMLHttpRequest
    @static host_regex ^static
    import  nocache.cadish

    pass        @ajax
    cache_key   url host
    cache_ttl   status 404 410 ttl 60s grace 1h
    purge       when header X-Purge-Token {$PURGE_TOKEN}
    header      Access-Control-Allow-Methods "GET, OPTIONS, POST"
}
```

This parses to one `Site` with two addresses and a body mixing `Directive` nodes
(`tls`, `upstream`, `cache`, `pass`, `cache_key`, `cache_ttl`, `purge`, `header`,
`import`) and `MatcherDef` nodes (`@ajax`, `@static`). The `tls`, `upstream`, and
`cache` directives carry nested blocks; `{$PURGE_TOKEN}` is a placeholder
argument.

## 6. Formatting

`cadish fmt` (and `cadishfile.Format`) rewrite a Cadishfile into a canonical
form:

- 4-space indentation, one level per nested block;
- exactly one statement per line (`;`-separated statements are split onto their
  own lines);
- opening braces stay on the statement line (`name {`), closing braces on their
  own line;
- line continuations are removed (continued arguments are joined);
- runs of blank lines collapse to at most one; a block never starts with a blank
  line;
- comments are preserved (full-line comments on their own line, trailing comments
  at the end of their statement line);
- output ends with exactly one trailing newline.

Formatting is **idempotent**: `Format(Format(x)) == Format(x)`.
```
