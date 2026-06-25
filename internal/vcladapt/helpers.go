package vcladapt

import (
	"strconv"
	"strings"
)

// --- condition extraction ---

// extractMatches returns the string operands of `target (~|==) "S"` in cond.
func extractMatches(cond []token, target string) []string {
	var out []string
	for i := 0; i+2 < len(cond); i++ {
		if cond[i].kind == tIdent && cond[i].text == target &&
			cond[i+1].kind == tPunct && (cond[i+1].text == "~" || cond[i+1].text == "==") &&
			cond[i+2].kind == tStr {
			out = append(out, cond[i+2].text)
		}
	}
	return out
}

// firstMatch is extractMatches' first result (or "").
func firstMatch(cond []token, target string) string {
	if m := extractMatches(cond, target); len(m) > 0 {
		return m[0]
	}
	return ""
}

// extractEq returns the first `target == "S"` operand.
func extractEq(cond []token, target string) string {
	for i := 0; i+2 < len(cond); i++ {
		if cond[i].kind == tIdent && cond[i].text == target &&
			cond[i+1].kind == tPunct && cond[i+1].text == "==" &&
			cond[i+2].kind == tStr {
			return cond[i+2].text
		}
	}
	return ""
}

// headerRef classifies one `req.http.NAME` reference in a condition.
type headerRef struct {
	name   string
	filter string // the `~ "v"` / `== "v"` value-filter VCL (empty ⇒ a bare presence check)
}

// headerRefs returns the `req.http.NAME` references in cond, distinguishing a bare
// presence check (`req.http.Cookie`) from a value filter (`req.http.Cookie ~ "session="`).
// cadish's `pass header NAME` is a presence matcher only — collapsing a value filter to it
// silently widens the bypass to EVERY request with that header (A2), so the caller must
// TODO the filtered form instead.
func headerRefs(cond []token) []headerRef {
	var out []headerRef
	for i := 0; i < len(cond); i++ {
		t := cond[i]
		if t.kind != tIdent || !strings.HasPrefix(t.text, "req.http.") {
			continue
		}
		ref := headerRef{name: strings.TrimPrefix(t.text, "req.http.")}
		if i+2 < len(cond) && cond[i+1].kind == tPunct && cond[i+2].kind == tStr {
			switch cond[i+1].text {
			case "~", "!~", "==", "!=":
				ref.filter = cond[i+1].text + " " + quote(cond[i+2].text)
			}
		}
		out = append(out, ref)
	}
	return out
}

// statusCodes parses `beresp.status (==|!=) CODE [|| …]` → the codes + whether the
// condition is negated (status not in …). It also recognizes the common range form
// `beresp.status >= 500`, expanding it to the discrete 5xx codes cadish's `status`
// selector takes (it has no `>=` operator); note is a non-empty hint when an expansion
// happened, for an inline comment (A-P1).
func statusCodes(cond []token) (codes []string, neg bool, note string, ok bool) {
	for i := 0; i+2 < len(cond); i++ {
		if cond[i].kind == tIdent && cond[i].text == "beresp.status" && cond[i+1].kind == tPunct && cond[i+2].kind == tNum {
			op := cond[i+1].text
			switch op {
			case "==", "!=":
				codes = append(codes, cond[i+2].text)
				if op == "!=" {
					neg = true
				}
				ok = true
			case ">=":
				// Only the conventional 5xx gate maps cleanly; expand to the codes
				// operators actually emit (500–504). Other thresholds are left TODO.
				if cond[i+2].text == "500" {
					codes = append(codes, "500", "501", "502", "503", "504")
					note = "   # VCL `>= 500` expanded to the common 5xx codes — add/remove codes as needed"
					ok = true
				}
			}
		}
	}
	return codes, neg, note, ok
}

// --- body inspection ---

func bodyReturnsPass(body []stmt) bool {
	for _, s := range body {
		if !s.isIf && isReturn(s.simple, "pass") {
			return true
		}
	}
	return false
}

func hasSynth(body []stmt) bool {
	for _, s := range body {
		if !s.isIf && containsText(s.simple, "synth") {
			return true
		}
	}
	return false
}

// synthOf finds `return(synth(CODE, "MSG"))` in body.
func synthOf(body []stmt) (status int, msg string, ok bool) {
	for _, s := range body {
		if s.isIf {
			continue
		}
		toks := s.simple
		for i := 0; i < len(toks); i++ {
			if toks[i].kind == tIdent && toks[i].text == "synth" {
				// Expect: synth ( CODE , "MSG"
				code, m, found := "", "", false
				for j := i + 1; j < len(toks); j++ {
					if toks[j].kind == tNum && code == "" {
						code = toks[j].text
					} else if toks[j].kind == tStr && code != "" {
						m = toks[j].text
						found = true
						break
					}
				}
				if found {
					if n, err := strconv.Atoi(code); err == nil {
						return n, m, true
					}
				}
			}
		}
	}
	return 0, "", false
}

// backendHint finds `set req.backend_hint = NAME;` → NAME.
func backendHint(body []stmt) string {
	for _, s := range body {
		if s.isIf {
			continue
		}
		t := s.simple
		if len(t) >= 4 && t[0].text == "set" && t[1].text == "req.backend_hint" && t[2].text == "=" {
			return t[3].text
		}
	}
	return ""
}

// ttlOfBody extracts ttl/grace/uncacheable from a body's set statements. expr is
// set when a ttl/grace assignment is a non-literal expression (a vmod call like
// std.duration(…)) that can't be mapped to a literal cadish duration — the caller
// TODOs it rather than emitting a bogus token (A1).
func ttlOfBody(body []stmt) (ttl, grace string, hfm, expr bool) {
	for _, s := range body {
		if s.isIf {
			continue
		}
		t := s.simple
		switch {
		case setTarget(t, "beresp.ttl"):
			if v, ok := assignedDuration(t); ok {
				ttl = v
			} else {
				expr = true
			}
		case setTarget(t, "beresp.grace"):
			if v, ok := assignedDuration(t); ok {
				grace = v
			} else {
				expr = true
			}
		case setTarget(t, "beresp.uncacheable") && strings.EqualFold(assignedValue(t), "true"):
			hfm = true
		}
	}
	return ttl, grace, hfm, expr
}

// topLevelTTL extracts a default ttl/grace from statements NOT inside an if. expr is
// set when a ttl/grace value is a non-literal expression (see ttlOfBody / A1).
func topLevelTTL(stmts []stmt) (ttl, grace string, expr bool) {
	for _, s := range stmts {
		if s.isIf {
			continue
		}
		t := s.simple
		switch {
		case setTarget(t, "beresp.ttl"):
			if v, ok := assignedDuration(t); ok {
				ttl = v
			} else {
				expr = true
			}
		case setTarget(t, "beresp.grace"):
			if v, ok := assignedDuration(t); ok {
				grace = v
			} else {
				expr = true
			}
		}
	}
	return ttl, grace, expr
}

// ttlExprSnippet returns the original VCL line(s) that set beresp.ttl/beresp.grace, for
// embedding in a TODO(adapt) when the value is a non-literal expression (A1).
func ttlExprSnippet(stmts []stmt) string {
	var parts []string
	for _, s := range stmts {
		if s.isIf {
			continue
		}
		if setTarget(s.simple, "beresp.ttl") || setTarget(s.simple, "beresp.grace") {
			parts = append(parts, joinTokens(s.simple)+";")
		}
	}
	return strings.Join(parts, " ")
}

// assignedDuration returns the literal duration assigned by `set TARGET = VALUE` only
// when VALUE is a single number/duration token (e.g. `60s`, `2h`). A vmod/function call
// (`std.duration(…)`) or any multi-token expression returns ok=false so the caller can
// flag it TODO(adapt) instead of emitting an invalid literal like `std.duration` (A1).
func assignedDuration(simple []token) (string, bool) {
	for i := 0; i+1 < len(simple); i++ {
		if simple[i].kind == tPunct && simple[i].text == "=" {
			rest := simple[i+1:]
			if len(rest) == 1 && rest[0].kind == tNum {
				return rest[0].text, true
			}
			return "", false
		}
	}
	return "", false
}

// hashData returns the argument of a `hash_data(EXPR)` statement.
func hashData(simple []token) (string, bool) {
	if head(simple) != "hash_data" {
		return "", false
	}
	var inner []token
	depth := 0
	for _, t := range simple {
		if t.kind == tPunct && t.text == "(" {
			depth++
			if depth == 1 {
				continue
			}
		}
		if t.kind == tPunct && t.text == ")" {
			depth--
			if depth == 0 {
				break
			}
		}
		if depth >= 1 {
			inner = append(inner, t)
		}
	}
	if len(inner) == 1 && inner[0].kind == tIdent {
		return inner[0].text, true
	}
	return joinTokens(inner), true
}

// --- statement shape helpers ---

func head(simple []token) string {
	if len(simple) > 0 && simple[0].kind == tIdent {
		return simple[0].text
	}
	return ""
}

func isReturn(simple []token, what string) bool {
	return head(simple) == "return" && containsText(simple, what)
}

func containsText(toks []token, text string) bool {
	for _, t := range toks {
		if t.text == text {
			return true
		}
	}
	return false
}

// hasCall reports whether simple contains a function call '(' (so a value is an
// expression, not a literal).
func hasCall(simple []token) bool {
	for i := 1; i < len(simple); i++ {
		if simple[i].kind == tPunct && simple[i].text == "(" {
			return true
		}
	}
	return false
}

// setHeader matches `set <prefix>.NAME = "VAL"` and returns NAME, VAL.
func setHeader(simple []token, prefix string) (name, val string, ok bool) {
	if len(simple) < 4 || simple[0].text != "set" || simple[2].text != "=" {
		return "", "", false
	}
	id := simple[1]
	if id.kind != tIdent || !strings.HasPrefix(id.text, prefix+".") {
		return "", "", false
	}
	name = strings.TrimPrefix(id.text, prefix+".")
	// A single trailing string literal is a constant value; anything else is an
	// expression (caller TODOs it).
	if len(simple) == 4 && simple[3].kind == tStr {
		val = simple[3].text
	}
	return name, val, true
}

// unsetHeader matches `unset <prefix>.NAME`.
func unsetHeader(simple []token, prefix string) (name string, ok bool) {
	if len(simple) < 2 || simple[0].text != "unset" {
		return "", false
	}
	id := simple[1]
	if id.kind != tIdent || !strings.HasPrefix(id.text, prefix+".") {
		return "", false
	}
	return strings.TrimPrefix(id.text, prefix+"."), true
}

func isUnsetCookie(simple []token) bool {
	if head(simple) != "unset" || len(simple) < 2 {
		return false
	}
	id := strings.ToLower(simple[1].text)
	return strings.HasSuffix(id, ".set-cookie") || strings.HasSuffix(id, ".cookie")
}

func setTarget(simple []token, target string) bool {
	return len(simple) >= 3 && simple[0].text == "set" && simple[1].text == target && simple[2].text == "="
}

func assignedValue(simple []token) string {
	for i := 0; i+1 < len(simple); i++ {
		if simple[i].kind == tPunct && simple[i].text == "=" {
			return simple[i+1].text
		}
	}
	return ""
}

// --- rendering helpers ---

func joinTokens(toks []token) string {
	var parts []string
	for _, t := range toks {
		if t.kind == tStr {
			parts = append(parts, `"`+t.text+`"`)
		} else {
			parts = append(parts, t.text)
		}
	}
	return strings.Join(parts, " ")
}

func snippet(s stmt) string {
	if s.isIf && len(s.clauses) > 0 {
		body := ""
		if len(s.clauses[0].body) > 0 {
			body = " { " + snippetStmts(s.clauses[0].body) + " }"
		}
		return "if (" + joinTokens(s.clauses[0].cond) + ")" + body
	}
	return joinTokens(s.simple) + ";"
}

func snippetStmts(body []stmt) string {
	var parts []string
	for _, s := range body {
		if s.isIf {
			parts = append(parts, "if(…){…}")
			continue
		}
		parts = append(parts, joinTokens(s.simple)+";")
	}
	return strings.Join(parts, " ")
}

func quote(s string) string {
	return `"` + strings.ReplaceAll(s, `"`, `\"`) + `"`
}

// pathGlob turns a VCL substring/path match into a cadish path glob.
func pathGlob(u string) string {
	if u == "/" {
		return "/"
	}
	return u + "*"
}

func templated(s string) bool { return strings.Contains(s, "{{") || strings.Contains(s, "}}") }

func sanitizeName(s string) string {
	if templated(s) {
		return "backend_TODO"
	}
	var b strings.Builder
	for _, r := range s {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '_' {
			b.WriteRune(r)
		} else {
			b.WriteRune('_')
		}
	}
	out := strings.Trim(b.String(), "_")
	if out == "" {
		return "upstream1"
	}
	return out
}

func orDefault(s, d string) string {
	if s == "" {
		return d
	}
	return s
}

func appendUnique(sl []string, x string) []string {
	for _, v := range sl {
		if v == x {
			return sl
		}
	}
	return append(sl, x)
}

func dedupe(sl []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, v := range sl {
		if !seen[v] {
			seen[v] = true
			out = append(out, v)
		}
	}
	return out
}
