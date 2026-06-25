package pipeline

import "strings"

// pathSet is the compiled form of a `path` matcher's argument list. Rather than
// turn N globs into N regexes, it sorts each pattern into the cheapest structure
// that can answer it:
//
//   - exact patterns (no '*')        -> a hash set (O(1) lookup)
//   - pure-prefix patterns ("/a/*")  -> a byte trie keyed on the prefix
//   - everything else ("*sitemap*")  -> a precompiled glob part-list
//   - a bare "*"                     -> matchAll
//
// Match tries them cheapest-first. The common cases (exact, prefix) never touch
// the glob list. Matching any single pattern means the set matches (OR semantics).
type pathSet struct {
	exact    map[string]struct{}
	prefixes *trieNode
	globs    []*glob
	matchAll bool
}

func newPathSet() *pathSet {
	return &pathSet{exact: map[string]struct{}{}, prefixes: newTrie()}
}

// add classifies and stores one path pattern.
func (s *pathSet) add(pat string) {
	switch {
	case pat == "*":
		s.matchAll = true
	case !strings.Contains(pat, "*"):
		s.exact[pat] = struct{}{}
	case strings.Count(pat, "*") == 1 && strings.HasSuffix(pat, "*"):
		// Pure prefix, e.g. "/a/*" -> prefix "/a/".
		s.prefixes.insert(pat[:len(pat)-1])
	default:
		s.globs = append(s.globs, compileGlob(pat))
	}
}

// Match reports whether path matches any stored pattern.
func (s *pathSet) Match(path string) bool {
	if s.matchAll {
		return true
	}
	if _, ok := s.exact[path]; ok {
		return true
	}
	if s.prefixes.hasPrefixOf(path) {
		return true
	}
	for _, g := range s.globs {
		if g.match(path) {
			return true
		}
	}
	return false
}

// trieNode is a byte trie of prefixes. A node flagged terminal marks the end of a
// stored prefix; hasPrefixOf returns true as soon as the walk over the input
// passes through any terminal node (i.e. some stored prefix is a prefix of input).
type trieNode struct {
	children map[byte]*trieNode
	terminal bool
}

func newTrie() *trieNode { return &trieNode{children: map[byte]*trieNode{}} }

func (t *trieNode) insert(prefix string) {
	cur := t
	for i := 0; i < len(prefix); i++ {
		b := prefix[i]
		next := cur.children[b]
		if next == nil {
			next = newTrie()
			cur.children[b] = next
		}
		cur = next
	}
	cur.terminal = true
}

func (t *trieNode) hasPrefixOf(s string) bool {
	cur := t
	if cur.terminal {
		return true // an empty prefix matches everything
	}
	for i := 0; i < len(s); i++ {
		next := cur.children[s[i]]
		if next == nil {
			return false
		}
		cur = next
		if cur.terminal {
			return true
		}
	}
	return false
}

// glob is a precompiled wildcard pattern for the uncommon cases with a leading or
// interior '*' (e.g. "*sitemap*", "/a/*/b"). '*' matches any run of characters.
type glob struct {
	leadingStar  bool
	trailingStar bool
	parts        []string // non-empty literal segments between stars, in order
}

func compileGlob(pat string) *glob {
	g := &glob{
		leadingStar:  strings.HasPrefix(pat, "*"),
		trailingStar: strings.HasSuffix(pat, "*"),
	}
	for _, p := range strings.Split(pat, "*") {
		if p != "" {
			g.parts = append(g.parts, p)
		}
	}
	return g
}

func (g *glob) match(s string) bool {
	if len(g.parts) == 0 {
		// Pattern was all stars ("*", "**"): matches anything.
		return true
	}
	parts := g.parts
	// Anchor the first part to the start unless there's a leading star.
	if !g.leadingStar {
		if !strings.HasPrefix(s, parts[0]) {
			return false
		}
		s = s[len(parts[0]):]
		parts = parts[1:]
	}
	// Anchor the last part to the end unless there's a trailing star.
	var suffix string
	if !g.trailingStar && len(parts) > 0 {
		suffix = parts[len(parts)-1]
		parts = parts[:len(parts)-1]
	}
	// Remaining parts must appear in order anywhere.
	for _, p := range parts {
		i := strings.Index(s, p)
		if i < 0 {
			return false
		}
		s = s[i+len(p):]
	}
	if suffix != "" {
		return strings.HasSuffix(s, suffix)
	}
	return true
}

// hostSet is the compiled form of a `host` matcher's arg list: exact hosts plus
// "*." wildcard suffixes. OR semantics across args.
type hostSet struct {
	exact    map[string]struct{}
	suffixes []string // includes the leading dot, e.g. ".example.com"
}

func newHostSet() *hostSet { return &hostSet{exact: map[string]struct{}{}} }

func (h *hostSet) add(pat string) {
	pat = strings.ToLower(pat)
	if strings.HasPrefix(pat, "*.") {
		h.suffixes = append(h.suffixes, pat[1:]) // ".example.com"
		return
	}
	h.exact[pat] = struct{}{}
}

func (h *hostSet) Match(host string) bool {
	host = normalizeHost(host)
	if _, ok := h.exact[host]; ok {
		return true
	}
	for _, suf := range h.suffixes {
		if strings.HasSuffix(host, suf) {
			return true
		}
	}
	return false
}
