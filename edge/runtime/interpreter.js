// interpreter.js — the Cadish Edge IR interpreter.
//
// A faithful, PURE port of the Go matcher switch (internal/pipeline/matcher.go)
// and the EvalRequest / EvalResponse / EvalDeliver phase walk
// (internal/pipeline/pipeline.go) over the EdgeIR contract (internal/edgeir).
//
// All "logic" lives here, driven entirely by the IR the Go `cadish` binary emits
// — the worker never sees the Cadishfile. This module does NO I/O: it turns an IR
// + a plain request object (+ optional origin status/headers + cache status) into
// the same DECISIONS the Go pipeline produces. The cross-runtime conformance suite
// (test/conformance) proves Go and JS decide identically for the same (IR, request).
//
// Keep this in lockstep with the Go pipeline: a change to the Go matcher/eval
// semantics must be mirrored here, and the conformance suite must stay green.

export const IR_VERSION = 4;

// ---------------------------------------------------------------------------
// Header / cookie / host helpers (port of net/http + request.go semantics).
// ---------------------------------------------------------------------------

// canonicalHeaderKey mirrors textproto.CanonicalMIMEHeaderKey: upper-case the
// first letter and any letter after '-', lower-case the rest. Non-token bytes
// leave the key unchanged (returned as-is), matching Go's fast bail-out.
export function canonicalHeaderKey(name) {
  if (name === "") return name;
  let out = "";
  let upper = true;
  for (let i = 0; i < name.length; i++) {
    let c = name[i];
    const code = name.charCodeAt(i);
    // Only ASCII letters are case-folded; a non-token byte makes Go return the
    // header verbatim. We keep it simple: fold ASCII letters, pass the rest.
    if (upper && c >= "a" && c <= "z") c = c.toUpperCase();
    else if (!upper && c >= "A" && c <= "Z") c = c.toLowerCase();
    out += c;
    upper = code === 0x2d; // next char is upper-cased iff this one is '-'
  }
  return out;
}

// newRequest normalizes a plain request object into the interpreter's internal
// shape: a canonicalized header map (name -> [values]), a query map (name ->
// [values]), and the scalar fields. Geo/device are INPUTS (the server pre-pass /
// the edge geo injection resolved them); the interpreter only reads them.
export function newRequest(input) {
  const header = new Map();
  const rawHeader = input.header || {};
  for (const k of Object.keys(rawHeader)) {
    const ck = canonicalHeaderKey(k);
    const v = rawHeader[k];
    const arr = Array.isArray(v) ? v.slice() : [v];
    if (header.has(ck)) header.set(ck, header.get(ck).concat(arr));
    else header.set(ck, arr);
  }
  const query = new Map();
  const rawQuery = input.query || {};
  for (const k of Object.keys(rawQuery)) {
    const v = rawQuery[k];
    query.set(k, Array.isArray(v) ? v.slice() : [v]);
  }
  return {
    method: input.method || "",
    host: input.host || "",
    path: input.path || "",
    query,
    header,
    clientIP: input.clientIP || "",
    device: input.device || "",
    geo: input.geo || "",
    geoContinent: input.geoContinent || "",
    geoRegion: input.geoRegion || "",
  };
}

function reqMethod(req) {
  return (req.method || "GET").toUpperCase();
}

function headerGet(req, name) {
  const v = req.header.get(canonicalHeaderKey(name));
  return v && v.length ? v[0] : "";
}

// headerCombined returns ALL values of a header joined as one RFC 9110 §5.3 field-value
// (comma+space) — what a compliant origin sees for a multi-line header. Every CACHE-KEY-
// influencing reader (the header:NAME key token, normalize/tenant from a header) MUST use it,
// NOT headerGet's first value, or two distinct requests collapse onto one key while the origin
// uses the combined value (cross-tenant poison). Mirrors Go Request.headerCombined.
function headerCombined(req, name) {
  const v = req.header.get(canonicalHeaderKey(name));
  if (!v || v.length === 0) return "";
  return v.length === 1 ? v[0] : v.join(", ");
}

// headerValues returns ALL values of a header (the canonicalized array), or [] when
// absent. The header_regex matcher OR-matches its RegExp across every value, mirroring
// the Go matcher's headerValues helper.
function headerValues(req, name) {
  const v = req.header.get(canonicalHeaderKey(name));
  return v && v.length ? v : [];
}

function headerPresent(req, name) {
  return req.header.has(canonicalHeaderKey(name));
}

function queryGet(req, name) {
  const v = req.query.get(name);
  return v && v.length ? v[0] : "";
}

// parseCookies parses the request "Cookie" header into [{name, value}], mirroring
// net/http's readCookies closely enough for matching: split on ';', trim, split
// on the first '=', strip surrounding quotes from the value.
function parseCookies(req) {
  const raw = headerGet(req, "Cookie");
  if (!raw) return [];
  const out = [];
  for (let part of raw.split(";")) {
    part = part.trim();
    if (part === "") continue;
    const eq = part.indexOf("=");
    let name, value;
    if (eq < 0) {
      name = part;
      value = "";
    } else {
      name = part.slice(0, eq).trim();
      value = part.slice(eq + 1).trim();
    }
    if (name === "") continue;
    if (value.length >= 2 && value.startsWith('"') && value.endsWith('"')) {
      value = value.slice(1, -1);
    }
    out.push({ name, value });
  }
  return out;
}

function cookieValue(req, name) {
  for (const c of parseCookies(req)) if (c.name === name) return c.value;
  return "";
}

function cookiePresent(req, name) {
  for (const c of parseCookies(req)) if (c.name === name) return true;
  return false;
}

function cookieNamePrefixPresent(req, prefix) {
  for (const c of parseCookies(req)) if (c.name.startsWith(prefix)) return true;
  return false;
}

// cookieRawJSON returns {present, value} for a named cookie, distinguishing absent
// from present-with-empty-value (mirrors pipeline.cookieRaw): the JSON matcher
// fails closed on an empty value at the parse, not at the presence check.
function cookieRawJSON(req, name) {
  for (const c of parseCookies(req)) if (c.name === name) return { present: true, value: c.value };
  return { present: false, value: "" };
}

// --- cookie_json / header_json field engine (port of cookie_json.go, D54) -------

const JSON_VALUE_SIZE_CAP = 8 * 1024; // raw value byte cap; over => false, no parse
const JSON_DEPTH_CAP = 32; // nesting depth cap

// jsonDecodeCookieValue percent-decodes a raw value ONCE before parsing (JSON
// cookies are commonly %7B…-encoded). A value with no '%' is returned as-is; an
// invalid escape falls back to the raw value (fail-open to the parser, which then
// fails closed on malformed JSON).
function jsonDecodeCookieValue(raw) {
  if (raw.indexOf("%") < 0) return raw;
  try {
    return decodeURIComponent(raw);
  } catch (_e) {
    return raw;
  }
}

// jsonDepthOK rejects a parsed value that nests deeper than JSON_DEPTH_CAP anywhere,
// mirroring the Go decoder's depth guard (the Go side bounds the streaming decode;
// here we bound the already-parsed tree, which is equivalent for the bounded inputs
// the size cap admits).
function jsonDepthOK(v, depth) {
  if (depth > JSON_DEPTH_CAP) return false;
  if (v === null || typeof v !== "object") return true;
  if (Array.isArray(v)) {
    for (const e of v) if (!jsonDepthOK(e, depth + 1)) return false;
    return true;
  }
  for (const k of Object.keys(v)) if (!jsonDepthOK(v[k], depth + 1)) return false;
  return true;
}

// jsonResolveField parses raw (already percent-decoded) and walks the dotted path,
// returning {found, value} for an existing, non-null SCALAR leaf coerced to its
// JSON string form (true->"true", numbers->source digits, strings->themselves).
// ANY anomaly (over-size, malformed JSON, too-deep, missing/extra structure, a
// non-scalar or null leaf) yields found=false.
function jsonResolveField(raw, segs) {
  if (raw.length > JSON_VALUE_SIZE_CAP) return { found: false, value: "" };
  if (segs.length === 0) return { found: false, value: "" };
  let doc;
  try {
    doc = JSON.parse(raw);
  } catch (_e) {
    return { found: false, value: "" };
  }
  if (!jsonDepthOK(doc, 0)) return { found: false, value: "" };
  let cur = doc;
  for (const seg of segs) {
    if (cur === null || typeof cur !== "object") return { found: false, value: "" };
    if (seg.isIndex) {
      if (!Array.isArray(cur)) return { found: false, value: "" };
      if (seg.index < 0 || seg.index >= cur.length) return { found: false, value: "" };
      cur = cur[seg.index];
    } else {
      if (Array.isArray(cur)) return { found: false, value: "" };
      if (!Object.prototype.hasOwnProperty.call(cur, seg.key)) return { found: false, value: "" };
      cur = cur[seg.key];
    }
  }
  // Coerce the scalar leaf. Objects/arrays/null are "no usable value".
  if (cur === null) return { found: false, value: "" };
  switch (typeof cur) {
    case "boolean":
      return { found: true, value: cur ? "true" : "false" };
    case "number": {
      // PARITY (Finding C #1): Go coerces a numeric leaf to its EXACT JSON source
      // digits (json.Number.String()), e.g. 1e3 -> "1e3", 1.0 -> "1.0",
      // 1.50 -> "1.50". JS String(n) would re-render the parsed double (1e3 -> "1000",
      // 1.0 -> "1", 1.50 -> "1.5") and diverge. We instead extract the leaf number's
      // RAW source substring from `raw` so both runtimes carry the identical digits.
      // JSON.parse above already validated structure/depth/path and confirmed the leaf
      // is a number, so the source scan navigates the same path and cannot fail; if it
      // ever did, fail closed (found=false) rather than emit a divergent double.
      const src = jsonRawNumberSource(raw, segs);
      if (src === null) return { found: false, value: "" };
      return { found: true, value: src };
    }
    case "string":
      return { found: true, value: cur };
    default: // object/array
      return { found: false, value: "" };
  }
}

// jsonRawNumberSource scans the raw (already percent-decoded) JSON text, navigates
// the dotted path, and returns the EXACT source substring of the leaf number (so it
// matches Go's json.Number — see Finding C #1). On a duplicate object key it keeps
// the LAST occurrence, matching JSON.parse (Finding C #3). Returns null if the path
// does not resolve to a number (the caller has already confirmed via JSON.parse that
// it does, so null is a defensive fail-closed). It is a minimal recursive-descent
// JSON reader: it understands strings (with escapes), numbers, literals, objects and
// arrays well enough to locate the leaf; full validation lives in JSON.parse.
function jsonRawNumberSource(raw, segs) {
  const s = raw;
  let i = 0;
  const n = s.length;

  function skipWs() {
    while (i < n) {
      const c = s[i];
      if (c === " " || c === "\t" || c === "\n" || c === "\r") i++;
      else break;
    }
  }
  // readString consumes a JSON string starting at s[i] === '"', returning its decoded
  // value (used to compare object keys); leaves i past the closing quote.
  function readString() {
    i++; // opening quote
    let out = "";
    while (i < n) {
      const c = s[i++];
      if (c === '"') return out;
      if (c === "\\") {
        const e = s[i++];
        switch (e) {
          case '"': out += '"'; break;
          case "\\": out += "\\"; break;
          case "/": out += "/"; break;
          case "b": out += "\b"; break;
          case "f": out += "\f"; break;
          case "n": out += "\n"; break;
          case "r": out += "\r"; break;
          case "t": out += "\t"; break;
          case "u": {
            const hex = s.slice(i, i + 4);
            i += 4;
            out += String.fromCharCode(parseInt(hex, 16));
            break;
          }
          default: out += e; break;
        }
      } else {
        out += c;
      }
    }
    return out; // unterminated — JSON.parse already rejected this case
  }
  // skipValue advances i past one complete JSON value (string, number, literal,
  // object, or array). Used to step over non-target siblings.
  function skipValue() {
    skipWs();
    const c = s[i];
    if (c === '"') {
      readString();
      return;
    }
    if (c === "{" || c === "[") {
      const close = c === "{" ? "}" : "]";
      i++;
      while (i < n) {
        skipWs();
        if (s[i] === close) {
          i++;
          return;
        }
        if (s[i] === ",") {
          i++;
          continue;
        }
        if (c === "{") {
          skipWs();
          readString(); // key
          skipWs();
          i++; // ':'
        }
        skipValue();
      }
      return;
    }
    // number / true / false / null: run to a structural delimiter.
    while (i < n && !",}]: \t\n\r".includes(s[i])) i++;
  }
  // numberSource captures the raw substring of a number at s[i].
  function numberSource() {
    const start = i;
    while (i < n && !",}]: \t\n\r".includes(s[i])) i++;
    return s.slice(start, i);
  }

  // resolve walks segs[depth:] against the value at s[i], returning the leaf number
  // source or null. On a duplicate object key it keeps the LAST match.
  function resolve(depth) {
    skipWs();
    if (depth >= segs.length) {
      // Leaf position: must be a number for our purposes.
      skipWs();
      const c = s[i];
      if (c === "-" || (c >= "0" && c <= "9")) return numberSource();
      skipValue();
      return null;
    }
    const seg = segs[depth];
    const c = s[i];
    if (seg.isIndex) {
      if (c !== "[") {
        skipValue();
        return null;
      }
      i++;
      let idx = 0;
      let found = null;
      while (i < n) {
        skipWs();
        if (s[i] === "]") {
          i++;
          break;
        }
        if (s[i] === ",") {
          i++;
          continue;
        }
        if (idx === seg.index) {
          found = resolve(depth + 1);
        } else {
          skipValue();
        }
        idx++;
      }
      return found;
    }
    if (c !== "{") {
      skipValue();
      return null;
    }
    i++;
    let found = null;
    while (i < n) {
      skipWs();
      if (s[i] === "}") {
        i++;
        break;
      }
      if (s[i] === ",") {
        i++;
        continue;
      }
      skipWs();
      const key = readString();
      skipWs();
      i++; // ':'
      if (key === seg.key) {
        found = resolve(depth + 1); // LAST occurrence wins
      } else {
        skipValue();
      }
    }
    return found;
  }

  try {
    return resolve(0);
  } catch (_e) {
    return null; // defensive: JSON.parse already validated, so this is unreachable
  }
}

// splitJSONPath splits a dotted PATH into segments; an all-digit segment is an
// array index. Mirrors pipeline.compileJSONPath (the IR already validated the path,
// so this is a faithful re-split, not a re-validation).
function splitJSONPath(path) {
  const out = [];
  for (const p of path.split(".")) {
    if (p.length > 0 && /^[0-9]+$/.test(p)) {
      out.push({ isIndex: true, index: Number(p) });
    } else {
      out.push({ isIndex: false, key: p });
    }
  }
  return out;
}

// jsonFieldMatch applies the cookie-matcher semantics over a resolved field:
// missing source => false; no values => presence (non-null scalar); else OR-equals.
function jsonFieldMatch(raw, present, segs, values) {
  if (!present) return false;
  const res = jsonResolveField(jsonDecodeCookieValue(raw), segs);
  if (!res.found) return false;
  if (!values || values.length === 0) return true;
  return values.includes(res.value);
}

// responseCookieNames parses Set-Cookie headers from a response header map (an
// object name -> string|[string]) into the set of cookie names they set.
function responseCookieNames(respHeader) {
  if (!respHeader) return [];
  let vals = null;
  for (const k of Object.keys(respHeader)) {
    if (canonicalHeaderKey(k) === "Set-Cookie") {
      const v = respHeader[k];
      vals = Array.isArray(v) ? v : [v];
      break;
    }
  }
  if (!vals) return [];
  const names = [];
  for (const sc of vals) {
    if (!sc) continue;
    const eq = sc.indexOf("=");
    const semi = sc.indexOf(";");
    let end = eq;
    if (semi >= 0 && semi < eq) end = semi; // malformed, no name=value
    if (eq < 0) continue;
    const name = sc.slice(0, eq).trim();
    if (name !== "") names.push(name);
  }
  return names;
}

function respHeaderGet(respHeader, name) {
  if (!respHeader) return "";
  for (const k of Object.keys(respHeader)) {
    if (canonicalHeaderKey(k) === canonicalHeaderKey(name)) {
      const v = respHeader[k];
      return Array.isArray(v) ? (v.length ? v[0] : "") : v;
    }
  }
  return "";
}

// normalizeHost lower-cases a host, strips any trailing :port (port-after-] for
// IPv6), and strips an FQDN trailing dot (WB1), mirroring request.go normalizeHost.
export function normalizeHost(host) {
  host = (host || "").trim().toLowerCase();
  if (host === "") return "";
  let h = host;
  if (host.startsWith("[")) {
    const i = host.lastIndexOf("]");
    if (i >= 0 && host.slice(i + 1).startsWith(":")) h = host.slice(0, i + 1);
  } else {
    const i = host.lastIndexOf(":");
    if (i >= 0) {
      const colons = (host.match(/:/g) || []).length;
      // A hostname/IPv4 cannot contain a colon, so a SINGLE colon is always a host:port
      // delimiter — strip it whatever the "port" is, matching Go's normalizeHost /
      // net.SplitHostPort so a `host:zzz` cannot fork the cache key. A bare IPv6 (multiple
      // colons) is left intact; bracketed [::1]:port is handled above.
      if (colons === 1) h = host.slice(0, i);
    }
  }
  // FQDN trailing dot: `example.com.` is the same host as `example.com`.
  return h.endsWith(".") ? h.slice(0, -1) : h;
}

// ---------------------------------------------------------------------------
// Glob / pattern matching (port of glob.go).
// ---------------------------------------------------------------------------

// matchGlob implements the part-list glob: '*' matches any run of characters.
function matchGlob(pattern, s) {
  const leadingStar = pattern.startsWith("*");
  const trailingStar = pattern.endsWith("*");
  let parts = pattern.split("*").filter((p) => p !== "");
  if (parts.length === 0) return true; // all stars
  if (!leadingStar) {
    if (!s.startsWith(parts[0])) return false;
    s = s.slice(parts[0].length);
    parts = parts.slice(1);
  }
  let suffix = "";
  if (!trailingStar && parts.length > 0) {
    suffix = parts[parts.length - 1];
    parts = parts.slice(0, -1);
  }
  for (const p of parts) {
    const i = s.indexOf(p);
    if (i < 0) return false;
    s = s.slice(i + p.length);
  }
  if (suffix !== "") return s.endsWith(suffix);
  return true;
}

// matchPathPattern matches one path pattern (exact, "*", or a glob — the prefix
// case "/a/*" is just a trailing-star glob). OR semantics live in the caller.
function matchPathPattern(pattern, path) {
  if (pattern === "*") return true;
  if (!pattern.includes("*")) return path === pattern;
  return matchGlob(pattern, path);
}

// matchHostPattern matches one host pattern: an exact host or a "*.suffix"
// wildcard, against a normalized host. The "*." wildcard is SUFFIX-ONLY and does
// NOT match the bare apex — mirroring the Go `host` matcher (pipeline.hostSet.Match,
// which stores ".example.com" and tests HasSuffix only). So `*.example.com` matches
// `a.example.com` but NOT `example.com`. (This is the scope `host` matcher; the
// redirect-trust path has its own trustedHostMatch and is intentionally different.)
function matchHostPattern(pattern, host) {
  pattern = pattern.toLowerCase();
  if (pattern.startsWith("*.")) {
    return host.endsWith(pattern.slice(1)); // ".example.com" — suffix only, no apex
  }
  return host === pattern;
}

// nameGlobMatch matches a param/name against a set of patterns (exact, "*"
// matchAll, and globs) — port of nameGlobSet.match.
function nameGlobMatch(patterns, name) {
  for (const p of patterns || []) {
    if (p === "*") return true;
    if (!p.includes("*")) {
      if (name === p) return true;
    } else if (matchGlob(p, name)) return true;
  }
  return false;
}

// ---------------------------------------------------------------------------
// Matcher evaluation (port of matcher.go match()).
// ---------------------------------------------------------------------------

// compiledRegExp caches (source, flags) → RegExp so a path_regex/host_regex matcher
// or a redirect rule compiles its pattern ONCE, not on every request (the worker
// evaluates these on the per-request hot path). Bounded by the number of distinct
// regex sources in the IR (small and fixed per deploy).
//
// `flags` is the JS RegExp flag string the Go projector lifted off any RE2 inline
// flag group (`(?i)`, `(?is)`, …) — JavaScript cannot compile inline `(?flags)`
// groups, so the projector emits `{regex, regexFlags}` and we compile
// `new RegExp(regex, flags)` (BUG-1). A pattern the projector could NOT faithfully
// translate is never sent here (it is marked regexUntranslatable + delegated).
const _reCache = new Map();
function compiledRegExp(src, flags) {
  const key = (flags || "") + " " + src;
  let re = _reCache.get(key);
  if (re === undefined) {
    re = new RegExp(src, flags || "");
    _reCache.set(key, re);
  }
  return re;
}

// matchOne evaluates a single IR matcher against the context.
function matchOne(ir, m, ctx) {
  const req = ctx.req;
  // A server-only matcher kind (`all`/`query` — slice-2 Gateway matchers with no edge
  // runtime) is marked serverOnly + delegated by the Go projector; fail it CLOSED here
  // so it never silently matches if one slipped into the IR (Fix #4), mirroring
  // regexUntranslatable.
  if (m.serverOnly) return false;
  switch (m.kind) {
    case "path":
      return (m.patterns || []).some((p) => matchPathPattern(p, req.path));
    case "path_regex":
      // A regex the Go projector could not faithfully translate to a JS RegExp is
      // marked untranslatable + delegated: fail it CLOSED here (never compile a
      // crashing/divergent pattern). BUG-1.
      if (m.regexUntranslatable) return false;
      return compiledRegExp(m.regex, m.regexFlags).test(req.path);
    case "host":
      return (m.patterns || []).some((p) => matchHostPattern(p, normalizeHost(req.host)));
    case "host_regex":
      if (m.regexUntranslatable) return false;
      return compiledRegExp(m.regex, m.regexFlags).test(normalizeHost(req.host));
    case "header": {
      if (!m.values || m.values.length === 0) return headerPresent(req, m.name);
      // OR across ALL header values (WAF1, mirrors the Go matcher): a benign first line
      // must not HIDE a blocked second line and bypass a deny/block access-control rule.
      return headerValues(req, m.name).some((v) => m.values.includes(v));
    }
    case "header_regex": {
      // RE2 regex on a request header value (the Accept-Language language gate). A
      // regex the Go projector could not faithfully translate is failed CLOSED (BUG-1),
      // identical to path_regex/host_regex. Multi-valued header → match if ANY value
      // matches, mirroring the Go matcher's headerValues OR.
      if (m.regexUntranslatable) return false;
      const re = compiledRegExp(m.regex, m.regexFlags);
      return headerValues(req, m.name).some((v) => re.test(v));
    }
    case "method":
      return (m.methods || []).includes(reqMethod(req));
    case "upstream":
      return (m.upstreams || []).includes(ctx.upstream);
    case "content_type": {
      if (!ctx.respHeader) return false;
      const ct = respHeaderGet(ctx.respHeader, "Content-Type").toLowerCase();
      if (ct === "") return false;
      return (m.contentTypes || []).some((want) => ct.includes(want));
    }
    case "cookie": {
      if (m.glob) return cookieNamePrefixPresent(req, m.name);
      if (!m.values || m.values.length === 0) return cookiePresent(req, m.name);
      const v = cookieValue(req, m.name);
      return m.values.includes(v);
    }
    case "cookie_json": {
      const c = cookieRawJSON(req, m.name);
      return jsonFieldMatch(c.value, c.present, splitJSONPath(m.jsonPath), m.values);
    }
    case "header_json": {
      return jsonFieldMatch(headerGet(req, m.name), headerPresent(req, m.name), splitJSONPath(m.jsonPath), m.values);
    }
    case "set_cookie": {
      if (!ctx.respHeader) return false;
      const names = responseCookieNames(ctx.respHeader);
      if (names.length === 0) return false;
      if (!m.cookieNames || m.cookieNames.length === 0) return true;
      return names.some((n) => m.cookieNames.includes(n));
    }
    case "classify": {
      const got = classifyResolve(ir, m.classifyToken, ctx);
      const eq = got === m.classifyValue;
      return m.classifyNegate ? !eq : eq;
    }
    case "geo": {
      let got = "";
      if (m.geoGranularity === "continent") got = req.geoContinent;
      else if (m.geoGranularity === "region") got = req.geoRegion;
      else got = req.geo;
      if (got === "") return false;
      return (m.geoValues || []).includes(got);
    }
    case "query_present": {
      if (req.query.size === 0) return false;
      for (const name of req.query.keys()) if (nameGlobMatch(m.queryNames, name)) return true;
      return false;
    }
  }
  return false;
}

// scopeMatches reports whether a scope matches: a nil/Always scope is
// unconditional; otherwise OR over the named + inline matchers.
function scopeMatches(ir, scope, ctx) {
  if (!scope) return true;
  if (scope.always) return true;
  for (const name of scope.names || []) {
    const m = ir.matchers[name];
    if (m && matchOne(ir, m, ctx)) return true;
  }
  for (const m of scope.inline || []) {
    if (matchOne(ir, m, ctx)) return true;
  }
  return false;
}

// ---------------------------------------------------------------------------
// Derived-token resolvers (classify / normalize / tenant) — port of
// classify.go, normalize.go, tenant.go.
// ---------------------------------------------------------------------------

function classifyResolve(ir, name, ctx) {
  const cl = ir.classifiers && ir.classifiers[name];
  if (!cl) return "";
  for (const row of cl.rows || []) {
    let all = true;
    for (const mn of row.conj || []) {
      const m = ir.matchers[mn];
      if (!m || !matchOne(ir, m, ctx)) {
        all = false;
        break;
      }
    }
    if (all) return row.value;
  }
  return cl.default || "";
}

function normalizeResolve(ir, name, req) {
  const n = ir.normalizers && ir.normalizers[name];
  if (!n) return "";
  let v = "";
  if (n.source === "header") v = headerCombined(req, n.sourceName);
  else if (n.source === "cookie") v = cookieValue(req, n.sourceName);
  else if (n.source === "query") v = queryGet(req, n.sourceName);
  const map = n.map || {};
  if (Object.prototype.hasOwnProperty.call(map, v)) return map[v];
  return n.default || "";
}

function tenantMatch(pattern, v) {
  if (pattern.startsWith("*.")) {
    const suffix = pattern.slice(1); // ".example.com"
    return v === pattern.slice(2) || v.endsWith(suffix);
  }
  return v === pattern;
}

function tenantResolve(ir, req) {
  const tr = ir.tenant;
  if (!tr) return "";
  let v;
  if (tr.fromHeader) v = headerCombined(req, tr.fromHeader).toLowerCase();
  else v = normalizeHost(req.host);
  for (const r of tr.rules || []) if (tenantMatch(r.pattern, v)) return r.name;
  return tr.default || "";
}

// ---------------------------------------------------------------------------
// {device} User-Agent classifier (port of internal/classify Classify, D70).
//
// A faithful port of classify.Classifier.Classify: an ordered first-match-wins
// substring ruleset over the lower-cased User-Agent, then folds. The IR carries the
// ruleset (ir.device); the worker classifies natively from the User-Agent header —
// no X-Cadish-Device crutch. The same UA yields the same {device} bucket as the Go
// server's pre-pass (conformance-proven).
// ---------------------------------------------------------------------------

const DEVICE_BUILTIN_DEFAULT = "desktop";

// ruleMatches mirrors classify.Rule.matches: ANY substring present (OR) AND NONE of
// the excludes present. The UA is already lower-cased; substrings/excludes are
// lower-cased by the Go projector.
function deviceRuleMatches(rule, lua) {
  let hit = false;
  for (const s of rule.substrings || []) {
    if (lua.includes(s)) {
      hit = true;
      break;
    }
  }
  if (!hit) return false;
  for (const x of rule.exclude || []) {
    if (lua.includes(x)) return false;
  }
  return true;
}

// applyDeviceFold follows the fold chain, bounded by the fold count so a configured
// cycle terminates (mirrors classify.applyFold).
function applyDeviceFold(folds, cls) {
  if (!folds || folds.length === 0) return cls;
  const map = new Map();
  for (const f of folds) map.set(f.from, f.into);
  for (let i = 0; i <= folds.length; i++) {
    const next = map.get(cls);
    if (next === undefined) break;
    cls = next;
  }
  return cls;
}

// classifyDevice resolves the {device} bucket for a request from the IR's device
// ruleset and the request's User-Agent. With no ruleset (the IR omits it because the
// site does not key on {device}) it returns "" — the token is then a constant empty
// string, exactly as the Go side renders req.Device when the pre-pass did not run.
function classifyDevice(ir, req) {
  const dc = ir.device;
  if (!dc) return "";
  const ua = headerGet(req, "User-Agent");
  let cls = dc.default || DEVICE_BUILTIN_DEFAULT;
  if (ua !== "") {
    const lua = ua.toLowerCase();
    for (const r of dc.rules || []) {
      if (deviceRuleMatches(r, lua)) {
        cls = r.class;
        break;
      }
    }
  }
  return applyDeviceFold(dc.folds, cls);
}

// ---------------------------------------------------------------------------
// Canonical query rendering (port of cachekey.go writeCanonicalQuery) +
// Go url.QueryEscape.
// ---------------------------------------------------------------------------

const utf8 = new TextEncoder();

// goQueryEscape mirrors Go's url.QueryEscape (encodeQueryComponent): unreserved
// bytes [A-Za-z0-9-_.~] pass through, space becomes '+', everything else is %XX
// (upper-case hex), byte-wise over the UTF-8 encoding.
function goQueryEscape(s) {
  let out = "";
  for (const b of utf8.encode(s)) {
    if (
      (b >= 0x41 && b <= 0x5a) || // A-Z
      (b >= 0x61 && b <= 0x7a) || // a-z
      (b >= 0x30 && b <= 0x39) || // 0-9
      b === 0x2d || // -
      b === 0x2e || // .
      b === 0x5f || // _
      b === 0x7e // ~
    ) {
      out += String.fromCharCode(b);
    } else if (b === 0x20) {
      out += "+";
    } else {
      out += "%" + b.toString(16).toUpperCase().padStart(2, "0");
    }
  }
  return out;
}

// canonicalQuery renders the query with keys+values sorted, each escaped, exactly
// like the Go {query}/{url}/{query_allow} tokens. allow (an array of name
// patterns) keeps only matching params; a null allow keeps every param. prefix
// emits a leading '?' iff at least one pair is written.
function canonicalQuery(req, prefix, allow) {
  if (req.query.size === 0) return "";
  const keys = [];
  for (const k of req.query.keys()) {
    if (allow && !nameGlobMatch(allow, k)) continue;
    keys.push(k);
  }
  keys.sort();
  let out = "";
  let first = true;
  for (const k of keys) {
    const vals = (req.query.get(k) || []).slice().sort();
    const ek = goQueryEscape(k);
    for (const v of vals) {
      if (first && prefix) out += "?";
      if (!first) out += "&";
      first = false;
      out += ek + "=" + goQueryEscape(v);
    }
  }
  return out;
}

// ---------------------------------------------------------------------------
// Cache key (port of cachekey.go buildKey/writeToken).
// ---------------------------------------------------------------------------

const KEY_SEP = "\x1f";
const DEFAULT_KEY_TOKENS = [{ kind: "method" }, { kind: "host" }, { kind: "path" }];

// selectKeyTokens picks the cache-key recipe for a request: the first recipe whose
// selector matches (first-match-wins, source order), mirroring pipeline.selectKeyTokens.
// With no recipes (a single-recipe v1-shaped IR) it returns ir.key.tokens. Falls back
// to the built-in default tokens when nothing applies, exactly like the Go buildKey.
function selectKeyTokens(ir, ctx) {
  const recipes = (ir.key && ir.key.recipes) || [];
  for (const rc of recipes) {
    if (scopeMatches(ir, rc.selector, ctx)) return rc.tokens || [];
  }
  // No scoped recipes (or none matched — selectKeyTokens returns nil in Go, and
  // buildKey then uses the built-in default). The catch-all is always present as a
  // recipe when recipes are projected, so reaching here means recipes is empty: use
  // the flat tokens (the v1 shape / a site with no cache_key → default tokens).
  return (ir.key && ir.key.tokens) || [];
}

// keyHeaderNamesForTokens returns the lower-cased request header names a token list keys on
// (only `header:NAME` tokens). Mirrors Go's keyHeaderNamesForTokens. Used to judge Vary
// coverage against the SELECTED recipe — not the global union of every recipe's headers.
function keyHeaderNamesForTokens(tokens) {
  const names = [];
  for (const t of tokens || []) {
    if (t.kind === "header" && t.arg) names.push(String(t.arg).toLowerCase());
  }
  return names;
}

// keyCoversAllCookies reports whether a token list isolates EVERY cookie name a request
// carries: either a whole-`header:Cookie` token, or a `cookie:NAME` token for each name.
// Mirrors Go's keyCoversAllCookies — the name-aware coverage that the credential bypass uses.
function keyCoversAllCookies(tokens, cookieNames) {
  const keyed = new Set();
  for (const t of tokens || []) {
    if (t.kind === "header" && String(t.arg).toLowerCase() === "cookie") return true;
    if (t.kind === "cookie") keyed.add(t.arg);
  }
  if (!cookieNames || cookieNames.length === 0) return false;
  // A cookie:NAME token keys on the FIRST occurrence's value while the origin sees all
  // of them, so a keyed cookie sent more than once is NOT safely covered (mirrors the Go
  // keyCoversAllCookies). Require every cookie keyed AND sent exactly once.
  const counts = new Map();
  for (const n of cookieNames) counts.set(n, (counts.get(n) || 0) + 1);
  for (const [n, c] of counts) {
    if (!keyed.has(n)) return false;
    if (c > 1) return false;
  }
  return true;
}

// selectedKeyCoversAllCookies reports whether the recipe SELECTED for this request keys every
// cookie the request carries. Used by the edge worker's credential decision under cookie_allow:
// an allow-listed-but-unkeyed cookie must still bypass the shared edge cache (a kept cookie is
// only safe to cache if the key isolates it — mirrors the server's BypassForCredentials).
export function selectedKeyCoversAllCookies(ir, req) {
  const ctx = { req, upstream: resolveUpstream(ir, req), respHeader: null };
  let tokens = selectKeyTokens(ir, ctx);
  if (!tokens || tokens.length === 0) tokens = DEFAULT_KEY_TOKENS;
  const names = parseCookies(req).map((c) => c.name);
  return keyCoversAllCookies(tokens, names);
}

function buildKey(ir, req, ctx) {
  let tokens = selectKeyTokens(ir, ctx);
  if (!tokens || tokens.length === 0) tokens = DEFAULT_KEY_TOKENS;
  const parts = [];
  for (const t of tokens) parts.push(renderToken(ir, t, req, ctx));
  return parts.join(KEY_SEP);
}

// sanitizeKeyValue removes the 0x1f key SEPARATOR byte from a request-derived token
// value so two different (value, value) splits cannot collide on the same key (WB-S1),
// mirroring Go's writeKeyValue. The byte is an illegitimate control char in a
// path/header/cookie value, so dropping it is safe defense-in-depth.
function sanitizeKeyValue(s) {
  return s.indexOf(KEY_SEP) < 0 ? s : s.split(KEY_SEP).join("");
}

function renderToken(ir, t, req, ctx) {
  switch (t.kind) {
    case "method":
      return reqMethod(req);
    case "host":
      return normalizeHost(req.host);
    case "path":
      return sanitizeKeyValue(req.path);
    case "url":
      return sanitizeKeyValue(req.path) + canonicalQuery(req, true, null);
    case "query":
      return canonicalQuery(req, false, null);
    case "query_allow":
      return canonicalQuery(req, false, t.allow || []);
    case "header":
      return sanitizeKeyValue(headerCombined(req, t.arg));
    case "cookie":
      return sanitizeKeyValue(cookieValue(req, t.arg));
    case "sticky": {
      if (t.arg) {
        const v = cookieValue(req, t.arg);
        if (v !== "") return sanitizeKeyValue(v);
      }
      return req.clientIP;
    }
    case "device":
      // Edge-native classification (D70): classify the User-Agent from the IR ruleset
      // (ir.device) — no X-Cadish-Device header crutch. req.device (an explicit input,
      // used only by the conformance harness when it pre-resolves the class) wins when
      // set, so a test can still inject a class directly; otherwise self-classify.
      if (req.device) return req.device;
      return classifyDevice(ir, req);
    case "geo":
      return req.geo;
    case "geo.continent":
      return req.geoContinent;
    case "geo.region":
      return req.geoRegion;
    case "normalize":
      return normalizeResolve(ir, t.ref, req);
    case "classify":
      return classifyResolve(ir, t.ref, ctx);
    case "tenant":
      // Request-derived resolver wins when present; else the per-site constant.
      if (ir.tenant) return tenantResolve(ir, req);
      return t.arg || "";
    case "literal":
      return t.arg || "";
  }
  return "";
}

// ---------------------------------------------------------------------------
// Cache-key debug header (port of cachekeyhash.go).
//
// A self-contained, synchronous SHA-256 so `decide()` stays sync (WebCrypto's
// crypto.subtle.digest is async-only) AND so the edge produces the IDENTICAL
// 12-hex prefix the Go server emits — crypto/sha256 over the same UTF-8 bytes.
// The conformance suite asserts the bytes match the Go reference.
// ---------------------------------------------------------------------------

const CACHE_KEY_HASH_LEN = 12;

const SHA256_K = new Uint32Array([
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5, 0xd807aa98,
  0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
  0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8,
  0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
  0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819,
  0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
  0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
  0xc67178f2,
]);

// utf8Bytes encodes a JS string to UTF-8 bytes (the same bytes Go's []byte(s)
// yields), so the hash input is byte-identical across the two runtimes.
function utf8Bytes(str) {
  return new TextEncoder().encode(str);
}

function rotr(x, n) {
  return (x >>> n) | (x << (32 - n));
}

// sha256Hex returns the lowercase hex SHA-256 of a JS string (UTF-8 bytes).
function sha256Hex(str) {
  const msg = utf8Bytes(str);
  const len = msg.length;
  // Padded length: message + 0x80 + zeros + 8-byte big-endian bit length, to a
  // 64-byte boundary.
  const withOne = len + 1;
  const total = withOne + ((56 - (withOne % 64) + 64) % 64) + 8;
  const buf = new Uint8Array(total);
  buf.set(msg);
  buf[len] = 0x80;
  const bitLen = len * 8;
  // 64-bit length; JS bit ops are 32-bit, so split high/low. Lengths fit in 53
  // bits safely (TextEncoder output well below 2^53 bytes).
  const hi = Math.floor(bitLen / 0x100000000);
  const lo = bitLen >>> 0;
  buf[total - 8] = (hi >>> 24) & 0xff;
  buf[total - 7] = (hi >>> 16) & 0xff;
  buf[total - 6] = (hi >>> 8) & 0xff;
  buf[total - 5] = hi & 0xff;
  buf[total - 4] = (lo >>> 24) & 0xff;
  buf[total - 3] = (lo >>> 16) & 0xff;
  buf[total - 2] = (lo >>> 8) & 0xff;
  buf[total - 1] = lo & 0xff;

  let h0 = 0x6a09e667,
    h1 = 0xbb67ae85,
    h2 = 0x3c6ef372,
    h3 = 0xa54ff53a,
    h4 = 0x510e527f,
    h5 = 0x9b05688c,
    h6 = 0x1f83d9ab,
    h7 = 0x5be0cd19;

  const w = new Uint32Array(64);
  for (let off = 0; off < total; off += 64) {
    for (let i = 0; i < 16; i++) {
      const j = off + i * 4;
      w[i] = ((buf[j] << 24) | (buf[j + 1] << 16) | (buf[j + 2] << 8) | buf[j + 3]) >>> 0;
    }
    for (let i = 16; i < 64; i++) {
      const s0 = rotr(w[i - 15], 7) ^ rotr(w[i - 15], 18) ^ (w[i - 15] >>> 3);
      const s1 = rotr(w[i - 2], 17) ^ rotr(w[i - 2], 19) ^ (w[i - 2] >>> 10);
      w[i] = (w[i - 16] + s0 + w[i - 7] + s1) >>> 0;
    }
    let a = h0,
      b = h1,
      c = h2,
      d = h3,
      e = h4,
      f = h5,
      g = h6,
      h = h7;
    for (let i = 0; i < 64; i++) {
      const S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
      const ch = (e & f) ^ (~e & g);
      const t1 = (h + S1 + ch + SHA256_K[i] + w[i]) >>> 0;
      const S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
      const maj = (a & b) ^ (a & c) ^ (b & c);
      const t2 = (S0 + maj) >>> 0;
      h = g;
      g = f;
      f = e;
      e = (d + t1) >>> 0;
      d = c;
      c = b;
      b = a;
      a = (t1 + t2) >>> 0;
    }
    h0 = (h0 + a) >>> 0;
    h1 = (h1 + b) >>> 0;
    h2 = (h2 + c) >>> 0;
    h3 = (h3 + d) >>> 0;
    h4 = (h4 + e) >>> 0;
    h5 = (h5 + f) >>> 0;
    h6 = (h6 + g) >>> 0;
    h7 = (h7 + h) >>> 0;
  }
  const hex = (x) => (x >>> 0).toString(16).padStart(8, "0");
  return hex(h0) + hex(h1) + hex(h2) + hex(h3) + hex(h4) + hex(h5) + hex(h6) + hex(h7);
}

// cacheKeyHash returns the first 12 hex chars of sha256(rawKey) — identical to
// Go's pipeline.CacheKeyHash. An empty key yields "" (the header is omitted).
export function cacheKeyHash(rawKey) {
  if (rawKey === "") return "";
  return sha256Hex(rawKey).slice(0, CACHE_KEY_HASH_LEN);
}

// cacheKeyHeaderValue resolves the value `header +cache_key NAME [raw]` emits:
// the raw key under raw, else its 12-hex hash; "" for an empty key.
export function cacheKeyHeaderValue(rawKey, raw) {
  if (rawKey === "") return "";
  return raw ? rawKey : cacheKeyHash(rawKey);
}

// ---------------------------------------------------------------------------
// Template expansion (port of template.go expandTemplate).
// ---------------------------------------------------------------------------

function templateNamed(env, name, classifyFn) {
  switch (name) {
    case "host":
      return [env.host, true];
    case "path":
      return [env.path, true];
    case "query":
      return [env.query, true];
    case "uri":
      return [env.query === "" ? env.path : env.path + "?" + env.query, true];
    case "client_ip":
      return [env.clientIP || "", true];
    case "geo":
      return [env.geo || "", true];
    case "geo.continent":
      return [env.geoContinent || "", true];
    case "geo.region":
      return [env.geoRegion || "", true];
  }
  if (name.startsWith("http.") && name.length > 5) {
    if (!env.header) return ["", true];
    return [headerGetFromMap(env.header, name.slice(5)), true];
  }
  if (name.startsWith("classify.") && name.length > 9) {
    return classifyFn ? classifyFn(name.slice(9)) : ["", false];
  }
  return ["", false];
}

function headerGetFromMap(headerMap, name) {
  const v = headerMap.get(canonicalHeaderKey(name));
  return v && v.length ? v[0] : "";
}

function expandTemplate(tmpl, env, classifyFn) {
  if (!tmpl) return "";
  if (!/[{$]/.test(tmpl)) return tmpl;
  let out = "";
  let i = 0;
  while (i < tmpl.length) {
    const c = tmpl[i];
    if (c === "{") {
      const end = tmpl.indexOf("}", i);
      if (end < 0) {
        out += tmpl.slice(i);
        break;
      }
      const name = tmpl.slice(i + 1, end);
      const [v, ok] = templateNamed(env, name, classifyFn);
      if (ok) out += v;
      else out += tmpl.slice(i, end + 1);
      i = end + 1;
    } else if (c === "$") {
      if (i + 1 >= tmpl.length) {
        out += "$";
        i++;
        continue;
      }
      const n = tmpl[i + 1];
      if (n === "$") {
        out += "$";
        i += 2;
        continue;
      }
      if (n >= "0" && n <= "9") {
        const idx = n.charCodeAt(0) - 48;
        if (env.capture && idx < env.capture.length && env.capture[idx] != null) {
          out += env.capture[idx];
        }
        i += 2;
        continue;
      }
      out += "$";
      i++;
    } else {
      out += c;
      i++;
    }
  }
  return out;
}

// ---------------------------------------------------------------------------
// Header op application (port of pipeline.go applyHeaderRules).
// ---------------------------------------------------------------------------

function cacheStatusToken(cacheStatus) {
  if (cacheStatus === "HIT") return "HIT";
  if (cacheStatus === "HIT-STALE") return "HIT-STALE";
  return "MISS";
}

function headerTemplateEnv(ctx) {
  return {
    host: normalizeHost(ctx.req.host),
    path: ctx.req.path,
    query: canonicalQuery(ctx.req, false, null),
    header: ctx.req.header,
    clientIP: ctx.req.clientIP,
    geo: ctx.req.geo,
    geoContinent: ctx.req.geoContinent,
    geoRegion: ctx.req.geoRegion,
    capture: null,
  };
}

function applyHeaderRules(ir, rules, ctx, cacheStatus, resolveStatus) {
  const ops = [];
  let env = null;
  const classifyFn = (name) => {
    if (!ir.classifiers || !ir.classifiers[name]) return ["", false];
    return [classifyResolve(ir, name, ctx), true];
  };
  for (const r of rules || []) {
    if (!scopeMatches(ir, r.scope, ctx)) continue;
    for (const op of r.ops || []) {
      if (op.op === "cache_status") {
        if (resolveStatus) ops.push({ op: "set", name: op.name, value: cacheStatusToken(cacheStatus) });
        continue;
      }
      if (op.op === "cache_key") {
        // The cache key is the request-built key, not resolvable from a header op's
        // value here. It is surfaced on the deliver decision (cacheKeyHeader/
        // cacheKeyRaw) and materialized from the built key — never emitted as an op.
        continue;
      }
      let value = op.value || "";
      if (op.valueIsTmpl) {
        if (!env) env = headerTemplateEnv(ctx);
        value = expandTemplate(value, env, classifyFn);
      }
      ops.push({ op: op.op, name: op.name, value });
    }
  }
  return ops;
}

// ---------------------------------------------------------------------------
// Upstream routing (port of pipeline.go resolveUpstream).
// ---------------------------------------------------------------------------

function resolveUpstream(ir, req) {
  const routes = (ir.recv && ir.recv.route) || [];
  const def = (ir.upstream && ir.upstream.to) || "";
  if (routes.length === 0) return def;
  // Route conditions evaluate with an empty upstream.
  const ctx = { req, upstream: "", respHeader: null };
  for (const r of routes) if (scopeMatches(ir, r.scope, ctx)) return r.upstream;
  return def;
}

// ---------------------------------------------------------------------------
// The three phases (port of EvalRequest / EvalResponse / EvalDeliver).
// ---------------------------------------------------------------------------

export function evalRequest(ir, req) {
  const upstream = resolveUpstream(ir, req);
  const ctx = { req, upstream, respHeader: null };
  const dec = {
    pass: false,
    synthetic: null,
    redirect: null,
    upstream,
    cacheKey: "",
    purge: null,
    reqHeaderOps: [],
  };

  // respond short-circuits.
  for (const r of (ir.recv && ir.recv.respond) || []) {
    if (req.path === r.path) {
      dec.synthetic = { status: r.status, body: r.body };
      return dec;
    }
  }
  // redirect short-circuits.
  for (const r of (ir.recv && ir.recv.redirect) || []) {
    const rdr = evalRedirect(ir, r, ctx);
    if (rdr) {
      dec.redirect = rdr;
      return dec;
    }
  }
  // purge is delegated at the edge (IR carries none); nothing to do.

  // pass: first matching rule wins.
  for (const sc of (ir.recv && ir.recv.pass) || []) {
    if (scopeMatches(ir, sc, ctx)) {
      dec.pass = true;
      break;
    }
  }
  dec.reqHeaderOps = applyHeaderRules(ir, (ir.recv && ir.recv.headerReq) || [], ctx, "MISS", false);
  dec.cacheKey = buildKey(ir, req, ctx);
  return dec;
}

// trustedHostMatch mirrors Go's hostSet.Match (glob.go) for the redirect
// trusted-host allowlist: an exact (already lower-cased) host, OR a `*.suffix`
// wildcard via HasSuffix on ".suffix". UNLIKE matchHostPattern (used by the `host`
// matcher), a `*.suffix` here does NOT trust the bare apex — exactly as the server's
// hostSet, which stores only the ".suffix" suffix and matches with HasSuffix.
function trustedHostMatch(patterns, host) {
  host = normalizeHost(host);
  for (const p of patterns || []) {
    const lp = p.toLowerCase();
    if (lp.startsWith("*.")) {
      if (host.endsWith(lp.slice(1))) return true; // ".example.com" suffix
    } else if (host === lp) {
      return true;
    }
  }
  return false;
}

// redirectHost resolves the {host} placeholder for a redirect Location safely — the
// faithful port of pipeline.Pipeline.redirectHost (open-redirect defense, F12). The
// inbound request Host is echoed ONLY when it is one of the site's trusted hosts
// (RedirectHosts: exact or `*.suffix`); otherwise the canonical host is used. When the
// site declared no address (ir.site.hosts empty ⇔ server trustedHosts == nil) there is
// no trusted identity to fall back to, so the request host is reflected as-is.
function redirectHost(ir, req) {
  const h = normalizeHost(req.host);
  const site = ir.site || {};
  const hosts = site.hosts || [];
  if (hosts.length === 0) return h; // trustedHosts == nil
  if (trustedHostMatch(site.redirectHosts, h)) return h;
  return site.canonicalHost || "";
}

function evalRedirect(ir, r, ctx) {
  const req = ctx.req;
  const env = {
    host: redirectHost(ir, req),
    path: req.path,
    query: canonicalQuery(req, false, null),
    capture: null,
    header: null,
    clientIP: "",
  };
  if (r.regex) {
    const m = compiledRegExp(r.regex, r.regexFlags).exec(req.path);
    if (!m) return null;
    env.capture = m;
  } else if (!scopeMatches(ir, r.scope, ctx)) {
    return null;
  }
  return { status: r.status, location: expandTemplate(r.target, env, null) };
}

function selectorMatches(rule, status, ir, ctx) {
  switch (rule.selKind) {
    case "status_in":
      return (rule.codes || []).includes(status);
    case "status_not_in":
      return !(rule.codes || []).includes(status);
    case "scope":
      return scopeMatches(ir, rule.scope, ctx);
    case "default":
      return true;
  }
  return false;
}

// ---------------------------------------------------------------------------
// Safe-by-default cacheability helpers (port of pipeline.go safelyShareable /
// hasUncacheableCC / varyCovered / varyStar).
// ---------------------------------------------------------------------------

// respHeaderValues returns all values for a canonical header name from the
// plain-object respHeader (name -> string | string[]).
function respHeaderValues(respHeader, name) {
  if (!respHeader) return [];
  const want = canonicalHeaderKey(name);
  const out = [];
  for (const k of Object.keys(respHeader)) {
    if (canonicalHeaderKey(k) === want) {
      const v = respHeader[k];
      if (Array.isArray(v)) out.push(...v);
      else if (v != null) out.push(v);
    }
  }
  return out;
}

// isUncacheableError mirrors Go's isUncacheableError: a 4xx/5xx that a shared cache
// must not store under a broad selector, EXCEPT the canonical negative-cacheable
// 404/410. An explicit positive `status <code>` selector still opts the status in.
function isUncacheableError(status) {
  return status >= 400 && status !== 404 && status !== 410;
}

// hasUncacheableCC mirrors Go's hasUncacheableCC: scans a single Cache-Control header
// value for a no-store / private / no-cache directive, or s-maxage=0 (a shared-cache
// freshness lifetime of 0 → revalidate before every serve → treated like no-cache).
// Token comparison is whole-name, case-insensitive, so `max-age=60` and `private-data`
// are safe; a positive s-maxage is an operator-overridable freshness hint.
function hasUncacheableCC(value) {
  for (const part of value.split(",")) {
    const p = part.trim();
    const eq = p.indexOf("=");
    const name = (eq >= 0 ? p.slice(0, eq) : p).trim().toLowerCase();
    const val = eq >= 0 ? p.slice(eq + 1).trim() : "";
    if (name === "no-store" || name === "private" || name === "no-cache") return true;
    if (name === "s-maxage" && val.replace(/"/g, "") === "0") return true;
  }
  return false;
}

// varyStar mirrors Go's varyStar: returns true if any Vary value contains "*".
function varyStar(respHeader) {
  for (const v of respHeaderValues(respHeader, "Vary")) {
    for (const part of v.split(",")) {
      if (part.trim() === "*") return true;
    }
  }
  return false;
}

// varyCovered mirrors Go's varyCovered: a Vary value is safe when every listed
// field is Accept-Encoding (handled by the encode layer) or is already included in
// the cache key (keyHeaderNames is the lower-cased set of key header names). An
// empty Vary is always safe; "*" is never safe.
function varyCovered(varyValue, keyHeaderNames) {
  for (const part of varyValue.split(",")) {
    const field = part.trim();
    if (field === "") continue;
    if (field === "*") return false;
    const lf = field.toLowerCase();
    if (lf === "accept-encoding") continue;
    if (keyHeaderNames && keyHeaderNames.includes(lf)) continue;
    return false;
  }
  return true;
}

// safelyShareable mirrors Go's safelyShareable: returns false when the response
// carries Set-Cookie, a no-store/private/no-cache Cache-Control, or a Vary not
// covered by the cache key. All three refuse caching in a shared cache.
function hasSetCookie(respHeader) {
  return respHeaderValues(respHeader, "Set-Cookie").length > 0;
}

function safelyShareable(respHeader, keyHeaderNames) {
  // (Set-Cookie is refused UNCONDITIONALLY by the caller via hasSetCookie — even under
  // cache_unsafe — so it is not re-checked here.)
  // Cache-Control: refuse on no-store / private / no-cache.
  for (const cc of respHeaderValues(respHeader, "Cache-Control")) {
    if (hasUncacheableCC(cc)) return false;
  }
  // Vary: every field must be covered by the cache key or be Accept-Encoding.
  for (const v of respHeaderValues(respHeader, "Vary")) {
    if (!varyCovered(v, keyHeaderNames)) return false;
  }
  return true;
}

// stripCookiesMatches reports whether a `strip_cookies` rule fires for this response,
// using the same scope evaluation as evalDeliver. Mirrors Go's Pipeline.stripCookiesMatches:
// a covered Set-Cookie response is dropped before store/deliver, so it is cacheable; an
// uncovered one stays refused. Keeps the Go and JS cacheability decisions in lockstep.
function stripCookiesMatches(ir, ctx) {
  for (const sc of (ir.response && ir.response.stripCookies) || []) {
    if (scopeMatches(ir, sc, ctx)) return true;
  }
  return false;
}

export function evalResponse(ir, req, status, respHeader) {
  const upstream = resolveUpstream(ir, req);
  const ctx = { req, upstream, respHeader: respHeader || null };
  const dec = { ttlNs: 0, graceNs: 0, maxStaleNs: 0, hitForMissNs: 0, storeTier: "", cacheable: false };
  for (const r of (ir.response && ir.response.ttl) || []) {
    if (!selectorMatches(r, status, ir, ctx)) continue;
    if (r.isHFM) {
      dec.hitForMissNs = parseGoDuration(r.hitForMiss);
      break;
    }
    // SAFE BY DEFAULT (NEG-ALL, mirrors Go EvalResponse): a broad selector
    // (default/scope/status_not_in) must NOT make a transient error status storable —
    // only the canonical negative-cacheable 404/410, or a status EXPLICITLY listed by a
    // positive `status_in` selector, may cache an error. Keeps Go and JS in lockstep.
    if (isUncacheableError(status) && r.selKind !== "status_in") break;
    if (r.fromHeader) {
      // `cache_ttl from_header HEADER`: read the TTL from the named origin RESPONSE
      // header (mirror Go's headerTTL). Absent/empty/unparseable/non-positive/over-cap
      // => the rule does NOT apply, fall through to the next rule (NO break).
      const hv = respHeaderValues(respHeader, r.fromHeader);
      const ns = parseHeaderTTL(hv.length ? hv[0] : "");
      if (ns <= 0) continue;
      dec.ttlNs = ns;
      dec.graceNs = parseGoDuration(r.grace);
      dec.maxStaleNs = parseGoDuration(r.maxStale);
      dec.cacheable = true;
      break;
    }
    dec.ttlNs = parseGoDuration(r.ttl);
    dec.graceNs = parseGoDuration(r.grace);
    // max_stale (D60): the stale-on-error window beyond ttl+grace. Carried on the
    // decision so the entry bounds its salvage path (D70). Zero when unset.
    dec.maxStaleNs = parseGoDuration(r.maxStale);
    dec.cacheable = true;
    break;
  }
  // SAFE BY DEFAULT (mirrors Go's EvalResponse): after a positive cache_ttl rule,
  // downgrade to non-cacheable when the origin response is not safely shareable —
  // Set-Cookie, a private/no-store/no-cache Cache-Control, or a Vary not covered
  // by the cache key. `Vary: *` is never cacheable, even under cache_unsafe.
  // ir.cacheUnsafe opts out of the rest (operator accepted the risk).
  if (dec.cacheable && respHeader != null) {
    // Set-Cookie is NEVER cacheable, unconditionally (not even cache_unsafe), like Vary:*
    // — UNLESS a `strip_cookies` rule covers this response, in which case the cookie is
    // dropped before store/deliver (Varnish's `unset beresp.http.Set-Cookie`), so the
    // cached representation carries no cookie. That explicit per-class opt-in is the only
    // way to cache a cookie-stamping origin; without it the Set-Cookie response is refused.
    const setCookieBlocks = hasSetCookie(respHeader) && !stripCookiesMatches(ir, ctx);
    // Vary coverage is judged against the recipe SELECTED for THIS request, NOT the global
    // union of every recipe's key headers (ir.keyHeaderNames) — mirroring the Go server
    // (keyHeaderNamesForTokens(selectKeyTokens(ctx))). A header keyed only by a DIFFERENT
    // recipe must not be treated as covered here, or the edge would cache a Vary variant the
    // server refuses and serve it cross-variant/cross-tenant.
    const keyHeaders = keyHeaderNamesForTokens(selectKeyTokens(ir, ctx));
    if (varyStar(respHeader) || setCookieBlocks || (!ir.cacheUnsafe && !safelyShareable(respHeader, keyHeaders))) {
      dec.cacheable = false;
      dec.ttlNs = 0;
      dec.graceNs = 0;
      dec.maxStaleNs = 0;
    }
  }
  for (const r of (ir.response && ir.response.storage) || []) {
    if (selectorMatches(r, status, ir, ctx)) {
      dec.storeTier = r.tier;
      break;
    }
  }
  return dec;
}

export function evalDeliver(ir, req, respHeader, cacheStatus) {
  const upstream = resolveUpstream(ir, req);
  const ctx = { req, upstream, respHeader: respHeader || null };
  const headerResp = (ir.response && ir.response.headerResp) || [];
  const dec = {
    respHeaderOps: applyHeaderRules(ir, headerResp, ctx, cacheStatus, true),
    stripCookies: false,
    cors: null,
    cacheStatusHeader: "",
    cacheKeyHeader: "",
    cacheKeyRaw: false,
  };
  for (const r of headerResp) {
    if (!scopeMatches(ir, r.scope, ctx)) continue;
    for (const op of r.ops || []) {
      if (op.op === "cache_status") dec.cacheStatusHeader = op.name;
      if (op.op === "cache_key") {
        dec.cacheKeyHeader = op.name;
        dec.cacheKeyRaw = op.value === "raw";
      }
    }
  }
  for (const sc of (ir.response && ir.response.stripCookies) || []) {
    if (scopeMatches(ir, sc, ctx)) {
      dec.stripCookies = true;
      break;
    }
  }
  const cors = ir.response && ir.response.cors;
  if (cors && scopeMatches(ir, cors.scope, ctx)) {
    dec.cors = {
      allowAllOrigins: !!cors.allowAllOrigins,
      origins: cors.origins || [],
      methods: cors.methods || [],
      headers: cors.headers || [],
    };
  }
  // `replace` body transforms (D75): collect every rule whose scope matches this
  // response, in order. Mirrors the Go EvalDeliver transform loop. The actual body
  // substitution (size cap + Range/HEAD/encoded skip) is applied separately by
  // applyTransforms, so a transform here is only the resolved {old,new} list.
  dec.transforms = [];
  for (const tr of (ir.response && ir.response.transforms) || []) {
    if (scopeMatches(ir, tr.scope, ctx)) dec.transforms.push({ old: tr.old, new: tr.new });
  }
  return dec;
}

// applyTransforms applies the resolved `replace` rules (D75) to a body string,
// mirroring the server's deliver-phase gating (internal/server/transform.go +
// handler.go): skip Range/HEAD/already-encoded responses, apply only within the size
// cap, and pass an over-cap body through UNTRANSFORMED (the over-cap/streaming case is
// a permanent server-only non-goal). Returns { body, transformed }. The cap comes from
// the IR (response.transformMaxBytes); a missing cap means "no transforms projected".
export function applyTransforms(ir, transforms, body, { isRange = false, isHead = false, contentEncoding = "" } = {}) {
  if (body === "" || body == null) return { body: body || "", transformed: false };
  const encoded = contentEncoding !== "";
  if (!transforms || transforms.length === 0 || isRange || isHead || encoded) {
    return { body, transformed: false };
  }
  const cap = (ir.response && ir.response.transformMaxBytes) || 0;
  // byteLength: the server caps on raw byte size; mirror it with the UTF-8 byte length
  // so a multibyte body crosses the cap at the same point Go does.
  if (cap > 0 && utf8ByteLength(body) > cap) {
    return { body, transformed: false }; // over-cap: pass through untransformed
  }
  let s = body;
  for (const r of transforms) {
    if (!r.old) continue;
    s = s.split(r.old).join(r.new); // literal ReplaceAll (no regex), like strings.ReplaceAll
  }
  return { body: s, transformed: true };
}

// utf8ByteLength returns the UTF-8 byte length of a string (TextEncoder is available in
// workerd and modern Node; fall back to a manual count for older runtimes).
function utf8ByteLength(s) {
  if (typeof TextEncoder !== "undefined") return new TextEncoder().encode(s).length;
  let n = 0;
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    if (c < 0x80) n += 1;
    else if (c < 0x800) n += 2;
    else if (c >= 0xd800 && c <= 0xdbff) {
      n += 4;
      i++;
    } else n += 3;
  }
  return n;
}

// resolveOnError returns the FIRST `respond on_error` synthetic whose request-phase
// scope matches (D76), or null. Mirrors pipeline.EvalOnError: source order, first match.
export function resolveOnError(ir, req) {
  for (const oe of (ir.response && ir.response.onError) || []) {
    const ctx = { req, upstream: resolveUpstream(ir, req), respHeader: null };
    if (scopeMatches(ir, oe.scope, ctx)) {
      return { status: oe.status, body: oe.body, contentType: oe.contentType };
    }
  }
  return null;
}

// decideOutage lowers the worker's origin-failure serving precedence (D76/Fix #2),
// mirroring the server's handleOriginError ordering. `salvageable` says a stored copy is
// still within its max_stale window (the worker's cache.peek would return it).
// outageStatus is the status the origin RETURNED (0 ⇒ a THROWN transport failure, the
// legacy model). Precedence:
//   1. servable stale copy within max_stale (any failure shape).
//   2. negative cache — ONLY for a RETURNED status that evalResponse marks cacheable
//      (a transport failure has no status to negatively cache): store + serve it.
//   3. the first matching on_error synthetic.
//   4. the bare outcome: forward the returned status (bareStatus) for a returned failure,
//      or 502 (bareError) for a thrown transport failure.
// Returns the neutral outage decision the conformance suite compares against Go.
export function decideOutage(ir, req, salvageable, outageStatus = 0) {
  if (salvageable) return { kind: "stale" };
  // Negative caching is reachable only when the origin RETURNED a status. The Go server
  // passes the origin response headers to EvalResponse; the conformance harness models the
  // returned status via the case's origin.header, which decide() carries on req's context
  // — but evalResponse here needs the response header explicitly, so the caller threads it.
  if (outageStatus > 0) {
    const rs = evalResponse(ir, req, outageStatus, req._outageRespHeader || null);
    if (rs.cacheable) return { kind: "negativeCache", status: outageStatus };
  }
  // on_error fires on the HARD-failure path: a THROWN transport failure (status 0) or a
  // RETURNED status mapped to a *StatusError. httporigin maps to *StatusError ANY
  // non-success status EXCEPT 404/410 (negativeStatus is ONLY 404||410), so EVERY
  // returned status >= 400 that is NOT 404/410 (403, 405, 429, 5xx, …) takes the
  // hard-failure chain where on_error fires. A returned 404/410 is a Negative response
  // the worker serves directly (entry.js: salvage, else normal store/serve) and NEVER
  // consults on_error — mirroring the Go server's 404/410 path. So skip on_error ONLY
  // for a returned 404/410.
  if (outageStatus === 0 || (outageStatus >= 400 && outageStatus !== 404 && outageStatus !== 410)) {
    const oe = resolveOnError(ir, req);
    if (oe) return { kind: "onError", status: oe.status, body: oe.body, contentType: oe.contentType };
  }
  if (outageStatus > 0) return { kind: "bareStatus", status: outageStatus };
  return { kind: "bareError" };
}

// ---------------------------------------------------------------------------
// Edge cache-tier resolution (the `edge {}` block: local | distribute | skip).
// ---------------------------------------------------------------------------

// resolveEdgeTier picks the edge cache tier for a response: the first per-scope
// policy whose scope matches (evaluated against the response context, so a
// content_type/set_cookie scope works), else ir.edge.default. "local" when the
// site declares no edge block.
export function resolveEdgeTier(ir, req, respHeader) {
  const edge = ir.edge || {};
  const ctx = { req, upstream: resolveUpstream(ir, req), respHeader: respHeader || null };
  for (const pol of edge.policies || []) {
    if (scopeMatches(ir, pol.scope, ctx)) return pol.tier;
  }
  return edge.default || "local";
}

// ---------------------------------------------------------------------------
// Go duration parsing ("1m0s", "24h0m0s", "5s", "1.5s") -> nanoseconds.
// ---------------------------------------------------------------------------

const UNIT_NS = {
  ns: 1,
  us: 1e3,
  "µs": 1e3,
  "μs": 1e3,
  ms: 1e6,
  s: 1e9,
  m: 60e9,
  h: 3600e9,
};

// maxHeaderTTLNs mirrors Go's maxHeaderTTL (one year): a `cache_ttl from_header`
// value is ORIGIN-controlled, so it is capped.
const maxHeaderTTLNs = 365 * 24 * 3600 * 1e9;

// parseHeaderTTL mirrors Go's headerTTL: parse a `cache_ttl from_header HEADER`
// value into ns, returning 0 when the value is absent/empty/unparseable/non-positive
// or over the one-year cap (the caller falls through to the next rule). A bare
// (optionally signed) integer is SECONDS (Cache-Control max-age idiom); any other
// spelling is a cadish duration (300s, 5m, 1h).
function parseHeaderTTL(v) {
  v = (v || "").trim();
  if (v === "") return 0;
  if (/^[+-]?\d+$/.test(v)) {
    const n = Number(v);
    if (!Number.isFinite(n) || n <= 0) return 0;
    const ns = n * 1e9;
    return ns > maxHeaderTTLNs ? 0 : ns;
  }
  let d;
  try {
    d = parseGoDuration(v);
  } catch {
    return 0;
  }
  if (d <= 0 || d > maxHeaderTTLNs) return 0;
  return d;
}

export function parseGoDuration(s) {
  if (!s || s === "0" || s === "0s") return 0;
  let i = 0;
  let total = 0;
  let neg = false;
  if (s[0] === "+" || s[0] === "-") {
    neg = s[0] === "-";
    i = 1;
  }
  while (i < s.length) {
    let j = i;
    while (j < s.length && ((s[j] >= "0" && s[j] <= "9") || s[j] === ".")) j++;
    if (j === i) throw new Error("bad duration: " + s);
    const num = parseFloat(s.slice(i, j));
    let k = j;
    while (k < s.length && !((s[k] >= "0" && s[k] <= "9") || s[k] === ".")) k++;
    const unit = s.slice(j, k);
    const mul = UNIT_NS[unit];
    if (mul === undefined) throw new Error("unknown duration unit " + JSON.stringify(unit) + " in " + s);
    total += num * mul;
    i = k;
  }
  return Math.round(neg ? -total : total);
}

// ---------------------------------------------------------------------------
// Convenience: the full neutral decision used by the conformance suite.
// ---------------------------------------------------------------------------

// decide runs all three phases over a plain input and returns the runtime-neutral
// decision the conformance suite compares against the Go reference. input:
//   { method, host, path, query, header, clientIP, device, geo, geoContinent,
//     geoRegion, origin: { status, header }, cacheStatus }
export function decide(ir, input) {
  if (ir.irVersion !== IR_VERSION) {
    throw new Error("IR version " + ir.irVersion + " != runtime " + IR_VERSION);
  }
  const req = newRequest(input);
  const origin = input.origin || {};
  const status = origin.status || 0;
  const respHeader = origin.header || null;
  const cacheStatus = input.cacheStatus || "MISS";
  const request = evalRequest(ir, req);
  const deliver = evalDeliver(ir, req, respHeader, cacheStatus);
  // Materialize the `header +cache_key` emitted value from the cache key the
  // request phase built (the key is server/request-held, not in the deliver match
  // context) — the same seam the real worker uses (deliver() in entry.js). This is
  // the Go↔JS hash-parity probe: the conformance golden compares this byte-for-byte
  // against pipeline.CacheKeyHeaderValue over the Go-built key. A keyless request
  // (synthetic/redirect → cacheKey "") yields "" so the header is omitted.
  deliver.cacheKeyValue = deliver.cacheKeyHeader
    ? cacheKeyHeaderValue(request.cacheKey, deliver.cacheKeyRaw)
    : "";
  // `replace` body transform probe (D75): apply the matched transforms to the case
  // body with the IR cap + skip gating, the Go↔JS byte-identity assertion (incl.
  // over-cap pass-through). With no body the result is ("", false), matching Go.
  const ceVals = respHeaderValues(respHeader, "Content-Encoding");
  const contentEncoding = ceVals.length ? ceVals[0] : "";
  const tres = applyTransforms(ir, deliver.transforms, input.body || "", {
    isRange: !!input.isRange,
    isHead: !!input.isHead,
    contentEncoding,
  });
  deliver.transformedBody = tres.body;
  deliver.bodyTransformed = tres.transformed;
  const out = {
    request,
    response: evalResponse(ir, req, status, respHeader),
    deliver,
  };
  // Outage serving decision (D76/Fix #2): lowered only for an origin-failure case,
  // mirroring the Go reference (omitted otherwise so the golden matches). For a
  // RETURNED-status outage (outageStatus>0) the negative-cache branch needs the origin
  // response header; thread it onto req the same way the harness feeds origin.header.
  if (input.originFailed) {
    req._outageRespHeader = respHeader;
    out.outage = decideOutage(ir, req, !!input.salvageable, input.outageStatus || 0);
  }
  return out;
}
