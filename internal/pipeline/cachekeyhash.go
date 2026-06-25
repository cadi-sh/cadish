package pipeline

import (
	"crypto/sha256"
	"encoding/hex"
)

// cacheKeyHashLen is the number of hex characters of the sha256 prefix emitted by
// `header +cache_key NAME` (48 bits). Short, fixed-width, collision-irrelevant for
// a debug aid, and exactly the width Cloudflare Workers exposes — the parity
// default. The JS edge runtime computes the identical prefix (see edge/runtime).
const cacheKeyHashLen = 12

// CacheKeyHash returns the first 12 hex chars of sha256(rawKey) — the value
// `header +cache_key NAME` (hash form, the default) emits. It is a pure function of
// the already-built cache key, so the Go server and the JS edge runtime produce an
// IDENTICAL hash for the same key (a conformance fixture asserts this). An empty
// key yields an empty string (a request with no key omits the header entirely).
func CacheKeyHash(rawKey string) string {
	if rawKey == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(rawKey))
	return hex.EncodeToString(sum[:])[:cacheKeyHashLen]
}

// CacheKeyHeaderValue resolves the value `header +cache_key NAME[ raw]` emits for a
// request whose computed cache key is rawKey: the raw key string when raw is set,
// else its 12-hex hash. An empty rawKey (pass/synthetic/redirect — no key) yields
// "" so the caller omits the header.
func CacheKeyHeaderValue(rawKey string, raw bool) string {
	if rawKey == "" {
		return ""
	}
	if raw {
		return rawKey
	}
	return CacheKeyHash(rawKey)
}
