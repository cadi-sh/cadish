package tlsacme

import "strings"

// normalizeHost lower-cases a host and strips any trailing :port and trailing
// dot. IPv6 literals keep their brackets.
func normalizeHost(host string) string {
	host = strings.TrimSpace(host)
	host = strings.ToLower(host)
	// Strip :port — but not the colons inside an IPv6 literal "[::1]".
	if strings.HasPrefix(host, "[") {
		if i := strings.IndexByte(host, ']'); i >= 0 {
			host = host[:i+1]
		}
	} else if i := strings.LastIndexByte(host, ':'); i >= 0 {
		host = host[:i]
	}
	return strings.TrimSuffix(host, ".")
}

// hostMatcher decides whether a hostname is one cadish is configured to serve.
// It supports exact hosts and "*.suffix" wildcards (one label). It is the basis
// for the autocert HostPolicy — we must never become an open ACME issuer.
type hostMatcher struct {
	exact     map[string]struct{}
	wildcards []string // suffix including leading dot, e.g. ".example.com"
}

func newHostMatcher() *hostMatcher {
	return &hostMatcher{exact: map[string]struct{}{}}
}

// add registers a host pattern (exact or "*.suffix").
func (m *hostMatcher) add(pattern string) {
	pattern = normalizeHost(pattern)
	if pattern == "" {
		return
	}
	if strings.HasPrefix(pattern, "*.") {
		m.wildcards = append(m.wildcards, pattern[1:]) // ".suffix"
		return
	}
	m.exact[pattern] = struct{}{}
}

// matches reports whether host is served. A wildcard "*.example.com" matches
// exactly one extra label ("a.example.com" yes, "a.b.example.com" no, bare
// "example.com" no).
func (m *hostMatcher) matches(host string) bool {
	host = normalizeHost(host)
	if host == "" {
		return false
	}
	if _, ok := m.exact[host]; ok {
		return true
	}
	for _, suffix := range m.wildcards {
		if !strings.HasSuffix(host, suffix) {
			continue
		}
		label := host[:len(host)-len(suffix)]
		if label != "" && !strings.Contains(label, ".") {
			return true
		}
	}
	return false
}

// empty reports whether no host has been registered.
func (m *hostMatcher) empty() bool {
	return len(m.exact) == 0 && len(m.wildcards) == 0
}
