// Package lb implements cadish's load-balancing primitives: a pool of backends
// (an Upstream) that picks one backend per request according to a balancing
// policy, keeps the eligible set healthy with active probes and passive
// ejection, and tracks pod/IP churn behind dns:// and k8s:// targets without a
// reload. These are SELF-CONTAINED algorithms; the server wires them in a later
// milestone (M5b).
//
// # An Upstream IS an origin.Origin
//
// Upstream implements origin.Origin (Fetch(ctx, *Request) (*Response, error)),
// so the server treats a load-balanced pool exactly like any other origin: a
// `route @x -> web` makes `web` (an Upstream) the origin for matching requests.
// The streaming/ownership contract from the origin package is honored verbatim —
// Upstream delegates the per-backend fetch to an httporigin-style client and
// returns that origin.Response UNCHANGED (no body buffering, caller owns/closes
// the body).
//
// # The routing-key integration seam (what M5b MUST feed)
//
// Two policies need a routing key the server computes per request: `sticky`
// (hash a cookie value or client IP so a user pins to one backend) and
// `shard_by key` (hash an arbitrary key). The server already computes this value
// via the `{sticky}` normalizer. Rather than widen origin.Request (which is
// backend-agnostic and shared by every origin), the key travels in the context:
//
//	ctx = lb.WithRoutingKey(ctx, stickyValue) // server computes stickyValue
//	resp, err := upstream.Fetch(ctx, req)     // Upstream reads it back
//
// Upstream.Fetch calls RoutingKey(ctx) to read it. The mapping by policy:
//
//   - round_robin / least_conn — routing key IGNORED.
//   - sticky                   — routing key REQUIRED; absent/empty ⇒ Upstream
//     falls back to round_robin for that request (documented, not an error).
//   - shard_by url             — routing key IGNORED; the request Key (URL path)
//     is the hash input instead.
//   - shard_by key             — routing key REQUIRED (same fallback as sticky).
//
// This is the ONLY thing the server must wire beyond constructing the Upstream
// and calling Start(ctx): compute the sticky/shard key and attach it with
// WithRoutingKey before Fetch. origin.Request and origin.Origin are unchanged.
package lb

import "context"

// ctxKey is the unexported context-key type for the routing key, so no other
// package can collide with it.
type ctxKey int

const routingKeyCtxKey ctxKey = iota

// WithRoutingKey returns a child context carrying key as the per-request routing
// key consumed by the sticky / shard_by-key policies. The server computes key
// from the `{sticky}` normalizer (a cookie value, the client IP, …) and attaches
// it before calling Upstream.Fetch. An empty key is treated as "no key".
func WithRoutingKey(ctx context.Context, key string) context.Context {
	return context.WithValue(ctx, routingKeyCtxKey, key)
}

// RoutingKey reads the routing key attached by WithRoutingKey. ok is false (and
// key is "") when none was attached or it was empty.
func RoutingKey(ctx context.Context) (key string, ok bool) {
	v, _ := ctx.Value(routingKeyCtxKey).(string)
	if v == "" {
		return "", false
	}
	return v, true
}
