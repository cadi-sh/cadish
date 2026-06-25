package config

import (
	"time"

	"github.com/cadi-sh/cadish/internal/pipeline"
)

// ParseDuration parses a cadish duration literal as used by every duration-valued
// directive (`cache_ttl … ttl/grace/hit_for_miss`, `health … interval`, `timeout
// connect/first_byte/between_bytes`, `sign cloudfront … ttl`). It delegates to
// pipeline.ParseDuration — the single source of truth for duration syntax — which
// extends Go's time.ParseDuration with day ("d") and week ("w") units (e.g.
// "60s", "24h", "365d"). Exported so `cadish check` can validate these values at
// LINT time, with a file:line, by reusing the same parser the runtime uses rather
// than reimplementing it.
func ParseDuration(s string) (time.Duration, error) {
	return pipeline.ParseDuration(s)
}
