// Package geo turns a request into a small, bounded geo class (an ISO-ish country
// code like "US"/"ES", or "unknown") for the `{geo}` cache-key normalizer. It is
// the v2b normalizer, mirroring v2a's device classifier: a pure, deterministic
// lookup compiled once at config load and evaluated as a cheap per-request
// pre-pass — no heavy GeoIP database and no new dependency (stdlib net/netip).
//
// The MECHANISM (request → enum) lives here; the DATA is a pluggable Source:
//
//   - a HEADER source reads a CDN/LB-provided country header (e.g. CF-IPCountry)
//     — the common case when a CDN fronts cadish; or
//   - a CIDR-table source resolves the client IP against a CIDR→country table
//     loaded from a file (longest-prefix match).
//
// Unlike {device} there is no universal default, so a site must configure a geo
// source; with none, `{geo}` resolves to "" (documented).
package geo

import (
	"bufio"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"strings"
)

// Unknown is the class returned when a source cannot determine the geo (missing
// header, no CIDR match, invalid IP).
const Unknown = "unknown"

// Source resolves a request's geo class. Sources differ in input — a CDN-set
// country header versus the client IP — so Lookup receives both the resolved
// real client IP and the request headers; a given source uses whichever it
// needs. Implementations must be safe for concurrent use.
type Source interface {
	Lookup(clientIP netip.Addr, hdr http.Header) string
}

// --- header source ---------------------------------------------------------

type headerSource struct{ name string }

// NewHeaderSource builds a Source that reads the geo class from a request header
// (e.g. "CF-IPCountry", "X-Geo-Country") set by an upstream CDN/LB. The value is
// upper-cased; an absent/blank header yields Unknown.
func NewHeaderSource(name string) Source {
	return headerSource{name: http.CanonicalHeaderKey(name)}
}

func (h headerSource) Lookup(_ netip.Addr, hdr http.Header) string {
	if hdr == nil {
		return Unknown
	}
	v := strings.TrimSpace(hdr.Get(h.name))
	if v == "" {
		return Unknown
	}
	return boundGeoClass(v)
}

// maxGeoClassLen caps a geo header value's length. A real geo class is an ISO-ish
// country ("US") or subdivision ("US-UT") code — a handful of bytes. The cap is
// generous yet bounds the cache-key cardinality a client can inject via a spoofed
// geo header (the header source trusts the raw request header; an upstream CDN that
// fronts cadish should overwrite it, but cadish must not let an un-fronted edge be
// turned into an unbounded-key cache-memory DoS — security review round 2).
const maxGeoClassLen = 16

// boundGeoClass normalizes and bounds a geo header value into a small geo class.
// It upper-cases the value and accepts it only when it is at most maxGeoClassLen
// bytes of the ISO-ish geo-code charset (A–Z, 0–9, '-'); anything else (an
// over-long or out-of-charset value, e.g. an attacker-crafted high-cardinality or
// CRLF-laden string) maps to Unknown. This keeps {geo}/{geo.region} cache-key
// cardinality bounded even when the geo header is client-spoofable.
func boundGeoClass(v string) string {
	if len(v) > maxGeoClassLen {
		return Unknown
	}
	v = strings.ToUpper(v)
	for i := 0; i < len(v); i++ {
		c := v[i]
		ok := (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-'
		if !ok {
			return Unknown
		}
	}
	return v
}

// --- CIDR-table source -----------------------------------------------------

// CIDREntry maps a network prefix to a country code.
type CIDREntry struct {
	Prefix  netip.Prefix
	Country string
}

type cidrSource struct{ entries []CIDREntry }

// NewCIDRSource builds a Source that resolves the client IP against a
// CIDR→country table by LONGEST-PREFIX match. Country codes are upper-cased. A
// miss (or invalid IP) yields Unknown.
func NewCIDRSource(entries []CIDREntry) Source {
	es := make([]CIDREntry, len(entries))
	for i, e := range entries {
		es[i] = CIDREntry{Prefix: e.Prefix.Masked(), Country: strings.ToUpper(e.Country)}
	}
	return &cidrSource{entries: es}
}

func (c *cidrSource) Lookup(ip netip.Addr, _ http.Header) string {
	if !ip.IsValid() {
		return Unknown
	}
	ip = ip.Unmap()
	best, bestBits := "", -1
	for _, e := range c.entries {
		if e.Prefix.Bits() > bestBits && e.Prefix.Contains(ip) {
			best, bestBits = e.Country, e.Prefix.Bits()
		}
	}
	if best == "" {
		return Unknown
	}
	return best
}

// LoadCIDRTable parses a CIDR→country table: one `CIDR,COUNTRY` per line (comma
// or whitespace separated), `#` comments and blank lines ignored. e.g.
//
//	# offices
//	203.0.113.0/24, US
//	2001:db8::/32   ES
func LoadCIDRTable(r io.Reader) ([]CIDREntry, error) {
	var out []CIDREntry
	sc := bufio.NewScanner(r)
	line := 0
	for sc.Scan() {
		line++
		t := strings.TrimSpace(sc.Text())
		if t == "" || strings.HasPrefix(t, "#") {
			continue
		}
		cidr, country, ok := splitCIDRCountry(t)
		if !ok {
			return nil, fmt.Errorf("geo: line %d: want `CIDR,COUNTRY`, got %q", line, t)
		}
		p, err := netip.ParsePrefix(cidr)
		if err != nil {
			return nil, fmt.Errorf("geo: line %d: bad CIDR %q: %w", line, cidr, err)
		}
		out = append(out, CIDREntry{Prefix: p, Country: country})
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

// splitCIDRCountry splits a "CIDR,COUNTRY" or "CIDR COUNTRY" line.
func splitCIDRCountry(s string) (cidr, country string, ok bool) {
	var fields []string
	if strings.Contains(s, ",") {
		fields = strings.SplitN(s, ",", 2)
	} else {
		fields = strings.Fields(s)
	}
	if len(fields) < 2 {
		return "", "", false
	}
	cidr = strings.TrimSpace(fields[0])
	country = strings.ToUpper(strings.TrimSpace(fields[1]))
	if cidr == "" || country == "" {
		return "", "", false
	}
	return cidr, country, true
}
