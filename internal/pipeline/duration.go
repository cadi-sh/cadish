package pipeline

import (
	"errors"
	"math"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// maxHeaderTTL is the sane upper bound on an origin-supplied `cache_ttl
// from_header` value. The header is ORIGIN-CONTROLLED, so it is the one duration
// input that is not under operator control; an absurd value must never (a) wrap
// int64 on the seconds multiply (a wrapped-negative TTL still sets Cacheable=true,
// storing an object whose freshness window is already in the PAST → a permanent
// cache-defeating re-fetch on every request) nor (b) over-cache for an
// effectively unbounded time. We cap at one year (365 days): far longer than any
// real CDN max-age, well clear of the int64-nanosecond overflow point, and any
// value above it is rejected (falls through) rather than clamped so the operator's
// own `cache_ttl … ttl/grace` rules — which ARE under operator control and use the
// full parser unbounded — stay authoritative. Operator-authored durations are not
// subject to this cap; only the from_header path is.
const maxHeaderTTL = 365 * 24 * time.Hour

// ParseDuration parses a cadish duration. It is the single source of truth for
// duration syntax across the whole project: the pipeline compiler uses it for
// `cache_ttl … ttl/grace/hit_for_miss`, and `config`/`check` reuse it (via the
// thin `config.ParseDuration` wrapper) for every other duration-valued directive
// — so a value that loads at runtime also lints clean, and vice versa.
//
// It extends Go's time.ParseDuration with day ("d") and week ("w") units, which
// the canonical configs use (e.g. "grace 365d", "grace 24h", "ttl 60s"). Compound
// forms ("1d12h", "1h30m") are accepted. Bare zero ("0") is accepted as a zero
// duration.
//
// Supported units: ns, us (µs), ms, s, m, h, d (=24h), w (=7d).
func ParseDuration(s string) (time.Duration, error) { return parseDuration(s) }

func parseDuration(s string) (time.Duration, error) {
	if s == "" {
		return 0, errors.New("empty duration")
	}
	if s == "0" {
		return 0, nil
	}
	var total time.Duration
	i := 0
	n := len(s)
	neg := false
	if s[0] == '+' || s[0] == '-' {
		neg = s[0] == '-'
		i++
	}
	if i >= n {
		return 0, errors.New("invalid duration " + quote(s))
	}
	for i < n {
		// Parse the numeric (integer or decimal) magnitude.
		start := i
		for i < n && (s[i] >= '0' && s[i] <= '9') {
			i++
		}
		frac := 0.0
		fracDiv := 1.0
		if i < n && s[i] == '.' {
			i++
			for i < n && (s[i] >= '0' && s[i] <= '9') {
				frac = frac*10 + float64(s[i]-'0')
				fracDiv *= 10
				i++
			}
		}
		if i == start || (i == start+1 && s[start] == '.') {
			return 0, errors.New("invalid duration " + quote(s))
		}
		var whole int64
		for j := start; j < n && s[j] >= '0' && s[j] <= '9'; j++ {
			whole = whole*10 + int64(s[j]-'0')
		}
		// Parse the unit.
		ustart := i
		for i < n && !(s[i] >= '0' && s[i] <= '9') && s[i] != '.' {
			i++
		}
		unit := s[ustart:i]
		base, ok := unitDuration(unit)
		if !ok {
			return 0, errors.New("unknown duration unit " + quote(unit) + " in " + quote(s))
		}
		magnitude := float64(whole) + frac/fracDiv
		// Guard the float→int64 conversion and the accumulation against overflow:
		// an out-of-range float→int64 conversion is implementation-defined in Go
		// (on amd64 it wraps to a large negative), so a value like "9999999999h"
		// would silently produce a garbage (often negative) duration. Reject any
		// term or running total that does not fit in int64 nanoseconds.
		ns := magnitude * float64(base)
		if math.IsInf(ns, 0) || math.IsNaN(ns) || ns > float64(math.MaxInt64) || ns < float64(math.MinInt64) {
			return 0, errors.New("duration out of range " + quote(s))
		}
		part := time.Duration(ns)
		if (part > 0 && total > math.MaxInt64-part) || (part < 0 && total < math.MinInt64-part) {
			return 0, errors.New("duration out of range " + quote(s))
		}
		total += part
	}
	if neg {
		total = -total
	}
	return total, nil
}

func unitDuration(u string) (time.Duration, bool) {
	switch u {
	case "ns":
		return time.Nanosecond, true
	case "us", "µs", "μs":
		return time.Microsecond, true
	case "ms":
		return time.Millisecond, true
	case "s":
		return time.Second, true
	case "m":
		return time.Minute, true
	case "h":
		return time.Hour, true
	case "d":
		return 24 * time.Hour, true
	case "w":
		return 7 * 24 * time.Hour, true
	default:
		return 0, false
	}
}

// headerTTL reads the named header from an origin response and parses it as a
// cache TTL for `cache_ttl from_header HEADER`. It returns (dur, true) on a usable
// value and (0, false) when the header is absent, empty, or unparseable — in which
// case the caller treats the from_header rule as not-applicable and falls through.
//
// A bare unsigned integer is interpreted as SECONDS (matching Cache-Control's
// `max-age`, the idiom these origin headers follow, e.g. `X-Cache-Ttl: 300`); any
// other spelling is parsed by the canonical cadish duration parser (so `300s`,
// `5m`, `1h`, `1d` all work). A negative or zero value yields (0, false) — a
// non-positive TTL is not a cacheable instruction (use a status/`pass` rule to not
// cache), so it falls through rather than caching with a zero lifetime.
//
// The value is ORIGIN-controlled, so it is bounded: any value above maxHeaderTTL
// (one year) — including one large enough to overflow the int64-nanosecond
// `seconds × 1e9` multiply and silently wrap NEGATIVE — is rejected and falls
// through exactly like an unparseable header, rather than caching with a wrapped or
// effectively-infinite lifetime. The seconds-overflow point (~9.22e9 s ≈ 292 y) is
// far above the one-year cap, so the cap subsumes the raw overflow guard.
func headerTTL(h http.Header, name string) (time.Duration, bool) {
	if h == nil {
		return 0, false
	}
	v := strings.TrimSpace(h.Get(name))
	if v == "" {
		return 0, false
	}
	if n, err := strconv.ParseInt(v, 10, 64); err == nil {
		// Reject non-positive AND any value whose seconds→ns multiply would
		// overflow int64; both fall through. The maxHeaderTTL cap below is
		// stricter, but keep the explicit overflow bound so the guard is
		// self-evident at the multiply.
		if n <= 0 || n > math.MaxInt64/int64(time.Second) {
			return 0, false
		}
		d := time.Duration(n) * time.Second
		if d > maxHeaderTTL {
			return 0, false
		}
		return d, true
	}
	d, err := parseDuration(v)
	if err != nil || d <= 0 || d > maxHeaderTTL {
		return 0, false
	}
	return d, true
}

func quote(s string) string { return "\"" + s + "\"" }
