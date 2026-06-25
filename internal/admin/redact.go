package admin

import (
	"regexp"
	"strings"
)

// secretDirectiveRe matches a secret-bearing directive (auth_token, access_key,
// secret_key) followed by its value — either a double-quoted string or a bare run
// up to the next whitespace or `;` (the inline S3 sub-directive separator). The
// value is captured so redactSecrets can replace it.
var secretDirectiveRe = regexp.MustCompile(`\b(auth_token|access_key|secret_key)([ \t]+)("(?:[^"\\]|\\.)*"|[^\s;]+)`)

// sensitiveMatcherRe matches a `header` or `cookie` matcher whose NAME token
// looks sensitive (contains authorization, token, secret, auth, password, or ends
// with -key / api-key) followed by a value run — one or more whitespace-separated
// tokens up to `;`, `#`, or end-of-line. Capturing the full run (not just the first
// token) ensures that multi-value / OR'd matchers such as
// `@auth header Authorization Bearer xyz` or `@tok header X-Purge-Token a b c`
// have ALL value tokens redacted, not just the first. Group layout:
//
//	1 — "header" or "cookie"
//	2 — whitespace before the name
//	3 — the header/cookie name (e.g. X-Purge-Token, Authorization)
//	4 — whitespace between name and value run
//	5 — the full value run (everything up to `;`, `#`, or newline)
var sensitiveMatcherRe = regexp.MustCompile(
	`(?i)\b(header|cookie)([ \t]+)` +
		`([A-Za-z0-9_*][-A-Za-z0-9_*]*)` + // group 3: header/cookie name
		`([ \t]+)` + // group 4: whitespace
		`([^;#\n]+)`, // group 5: full value run (to `;`, `#`, or newline)
)

// sensitiveNameRe matches a header/cookie name that carries secrets: any name
// containing "authorization", "token", "secret", "auth", or "password"
// (case-insensitive), or ending with "-key" (e.g. X-Api-Key, api-key).
var sensitiveNameRe = regexp.MustCompile(
	`(?i)(?:authorization|token|secret|auth|password|(?i:.*-key))`,
)

// envRefRe matches a value token that is ENTIRELY an environment reference —
// `${NAME}` or `{$NAME}`. Such a token holds no plaintext secret (the secret
// lives in the environment), so it is preserved; anything else is redacted.
var envRefRe = regexp.MustCompile(`^(?:\$\{[^}]*\}|\{\$[^}]*\})$`)

// redactSecrets replaces the literal value of every secret-bearing directive in a
// Cadishfile with `***`, leaving `${ENV}` / {$ENV} references intact. It is applied
// to the text served by /api/source so a read-only dashboard never exposes
// auth_token / S3 credentials in plaintext (defence in depth: the admin endpoint is
// already token-gated).
//
// In addition to the three directive-level rules (auth_token / access_key /
// secret_key), the function also redacts the VALUE RUN following a header/cookie
// matcher whose NAME looks sensitive (contains authorization, token, secret, auth,
// password, or ends with -key). The matcher keyword anchors the rule so that
// unrelated directives such as `cache_key url host` are never touched.
//
// All value tokens in the run are redacted (FIX C): a matcher such as
// `@auth header Authorization Bearer xyz` previously leaked "xyz" because only
// the first token was captured; now the entire run is collapsed to a single `***`
// (while a lone env reference is still preserved in full).
func redactSecrets(src string) string {
	src = secretDirectiveRe.ReplaceAllStringFunc(src, func(m string) string {
		sub := secretDirectiveRe.FindStringSubmatch(m)
		key, ws, val := sub[1], sub[2], sub[3]
		if envRefRe.MatchString(val) {
			return m
		}
		return key + ws + "***"
	})
	src = sensitiveMatcherRe.ReplaceAllStringFunc(src, func(m string) string {
		sub := sensitiveMatcherRe.FindStringSubmatch(m)
		// sub[1]=keyword, sub[2]=ws1, sub[3]=name, sub[4]=ws2, sub[5]=value run
		keyword, ws1, name, ws2, run := sub[1], sub[2], sub[3], sub[4], sub[5]
		if !sensitiveNameRe.MatchString(name) {
			return m // non-sensitive header/cookie name — leave untouched
		}
		// Trim trailing whitespace from the captured run (the regex is greedy and
		// may include a trailing space before a newline/semicolon).
		trimmed := strings.TrimRight(run, " \t")
		// If the entire value run is a single env reference, preserve it unchanged.
		if envRefRe.MatchString(trimmed) {
			return m
		}
		// One or more literal tokens (possibly mixed with env refs) — redact them
		// all with a single ***. This closes the multi-token / OR'd matcher leak.
		return keyword + ws1 + name + ws2 + "***"
	})
	return src
}
