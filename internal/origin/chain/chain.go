// Package chain composes an ordered list of origins into a single fallback
// origin. A Chain is itself an origin.Origin: it tries [primary, fallback...] in
// order and, when one origin "misses" (a connection/transport error, a 404, or a
// configurable set of HTTP statuses — default 404 + all 5xx), falls through to
// the next. This is how `origin chain s3 -> cloudfront` from the Cadishfile is
// realized: FALLBACK IS COMPOSITION at the origin layer, never baked into any
// concrete origin (httporigin / s3origin know nothing about each other).
//
// On a POSITIVE success (200/206) from any origin, the Chain returns that
// streaming response immediately and the remaining origins are NOT consulted — the
// live body belongs to the caller, who MUST Close it (the standard origin
// contract). A NEGATIVE response (a full-body 404/410, backlog #21) counts as a
// MISS: the Chain falls through to the next origin and Closes the abandoned
// negative body. If every origin misses, the Chain surfaces the last full-body
// negative response (if one was seen) so the server can negatively cache its real
// error page; otherwise the LAST error is surfaced.
package chain

import (
	"context"
	"errors"
	"fmt"

	"github.com/cadi-sh/cadish/internal/origin"
)

// FallThrough decides, given the error a tried origin returned, whether the Chain
// should try the next origin. It receives the origin's error (never nil — it is
// only consulted on a non-success) and reports true to fall through.
type FallThrough func(err error) bool

// Chain is an origin.Origin that tries a list of origins in order, falling
// through on configurable conditions.
type Chain struct {
	origins     []origin.Origin
	fallThrough FallThrough
}

// Option configures a Chain.
type Option func(*Chain)

// WithFallThrough overrides the fall-through predicate. The default is
// DefaultFallThrough (connection error + 404 + any 5xx). A non-falling status
// (e.g. a 403 you want surfaced, or a 401) stops the chain and surfaces that
// error.
func WithFallThrough(ft FallThrough) Option {
	return func(c *Chain) {
		if ft != nil {
			c.fallThrough = ft
		}
	}
}

// WithFallThroughStatuses builds a fall-through predicate from an explicit set of
// HTTP statuses PLUS connection/transport errors (which carry no HTTP status).
// Use this for the common case "fall through on 404 and these specific codes".
// Connection errors (origin.StatusOf == 0) ALWAYS fall through with this option,
// because an origin that could not be reached should never end the chain.
func WithFallThroughStatuses(statuses ...int) Option {
	set := make(map[int]bool, len(statuses))
	for _, s := range statuses {
		set[s] = true
	}
	return WithFallThrough(func(err error) bool {
		st := origin.StatusOf(err)
		if st == 0 {
			return true // connection/transport/context error: try the next origin
		}
		return set[st]
	})
}

// DefaultFallThrough is the default policy: fall through on a connection/transport
// error (no HTTP status), a 404, or any 5xx. A 4xx other than 404 (e.g. 401, 403)
// does NOT fall through by default — it is a definitive answer from the origin and
// is surfaced to the caller.
func DefaultFallThrough(err error) bool {
	st := origin.StatusOf(err)
	switch {
	case st == 0: // connection / transport / context error
		return true
	case st == 404:
		return true
	case st >= 500 && st <= 599:
		return true
	default:
		return false
	}
}

// New builds a Chain over origins (in priority order: first is primary). It
// returns an error if no origins are given. The default fall-through policy is
// DefaultFallThrough; override it with WithFallThrough / WithFallThroughStatuses.
func New(origins []origin.Origin, opts ...Option) (*Chain, error) {
	if len(origins) == 0 {
		return nil, errors.New("chain: at least one origin required")
	}
	c := &Chain{
		origins:     origins,
		fallThrough: DefaultFallThrough,
	}
	for _, opt := range opts {
		opt(c)
	}
	return c, nil
}

// ReplaceOrigins rewrites each member origin in place by applying f, used by
// zero-downtime reload to repoint a transplanted lb pool (the survivor's old
// *lb.Upstream instance) inside a freshly-built chain. f is expected to recurse, so
// a nested chain is rewritten too. It is only safe to call on a chain the caller
// exclusively owns (a just-built, not-yet-published config), which is exactly the
// reload case.
func (c *Chain) ReplaceOrigins(f func(origin.Origin) origin.Origin) {
	for i, o := range c.origins {
		c.origins[i] = f(o)
	}
}

// Fetch implements origin.Origin. It tries each origin in order. On the first
// POSITIVE success (200/206) it returns that streaming response (caller
// owns/closes the body). A NEGATIVE response (a full-body 404/410, backlog #21) is
// treated as a miss: the chain falls through to the next origin, closing the
// abandoned negative body. On a fall-through error it tries the next origin,
// closing the captured upstream body of the error it abandons (an HTTP origin
// attaches the live non-2xx body to a *StatusError); on a non-fall-through error it
// returns that error immediately (body intact for the caller). If every origin falls
// through, the LAST outcome is surfaced — the last negative *Response if one was
// seen after the last error, otherwise the last error.
func (c *Chain) Fetch(ctx context.Context, req *origin.Request) (*origin.Response, error) {
	var (
		lastErr error
		lastNeg *origin.Response // most recent full-body negative response (still open)
	)
	for i, o := range c.origins {
		// Honor context cancellation between attempts so a cancelled request does not
		// keep dialing fallbacks.
		if err := ctx.Err(); err != nil {
			if lastNeg != nil {
				lastNeg.Body.Close()
			}
			if lastErr != nil {
				// We surface the context error, not lastErr — release its captured body.
				origin.CloseStatusErrBody(lastErr)
				return nil, fmt.Errorf("chain: context done after origin %d: %w", i, err)
			}
			return nil, err
		}

		resp, err := o.Fetch(ctx, req)
		if err == nil {
			if !resp.Negative {
				// Positive success: live body handed to the caller. Drop any earlier
				// negative response (and any held fall-through error body) we were
				// holding as the fallback answer.
				if lastNeg != nil {
					lastNeg.Body.Close()
				}
				origin.CloseStatusErrBody(lastErr)
				return resp, nil
			}
			// Negative (full-body 404/410): normally a miss the chain falls through.
			// But when the request carries a body, do NOT fall through: the streamed
			// client body is consumed by this origin and is not replayable, and a
			// body-carrying (non-idempotent) method must not be silently re-issued to
			// another origin. Surface this negative response as the answer. Drop any
			// earlier held negative (there is no earlier one for a body request, since
			// the first failure returns here, but stay consistent and leak-free).
			if req.Body != nil {
				if lastNeg != nil {
					lastNeg.Body.Close()
				}
				return resp, nil
			}
			// Negative miss: hold it as the candidate answer (closing any earlier one,
			// and any held fall-through error body) and fall through to the next origin.
			if lastNeg != nil {
				lastNeg.Body.Close()
			}
			origin.CloseStatusErrBody(lastErr)
			lastNeg = resp
			lastErr = nil
			continue
		}
		// A new error supersedes any previously-held fall-through error; release the
		// captured upstream body of the one we are dropping (an HTTP origin attaches the
		// live non-2xx body to a *StatusError). The error we keep (lastErr) retains its
		// body for whoever finally surfaces it.
		origin.CloseStatusErrBody(lastErr)
		lastErr = err
		// ErrSkip is a no-op decline: the origin returned WITHOUT reading req.Body, so the
		// body is intact and we MUST fall through to the next origin even for a write — a
		// PeerOrigin that skips a read-through (bypass/write/loop/self guard) must hand the
		// request to the real origin, not 404 it (F-C / silent write loss). Don't hold it
		// as the surfaced error.
		if errors.Is(err, origin.ErrSkip) {
			lastErr = nil
			continue
		}
		// Do NOT fall through to another origin when the request carries a body — the
		// consumed-and-non-replayable body plus non-idempotency rationale above. Surface
		// the first origin's error.
		if req.Body != nil {
			if lastNeg != nil {
				lastNeg.Body.Close()
			}
			return nil, err
		}
		if !c.fallThrough(err) {
			// Definitive failure (e.g. a 403 we don't fall through on): surface it now
			// without trying the rest of the chain. Drop any held negative response.
			if lastNeg != nil {
				lastNeg.Body.Close()
			}
			return nil, err
		}
		// else: fall through to the next origin.
	}
	// Every origin fell through. Prefer surfacing a held full-body negative response
	// (so the server can negatively cache the real error page) over a bare error.
	// A negative held from an EARLIER origin can co-exist with a fall-through error
	// captured from a LATER origin (e.g. chain [404, 503]: the 404 is held, then the
	// 503's *StatusError — carrying a live upstream body — is captured but never
	// cleared). When we surface the negative, release that abandoned error's captured
	// body so it is not leaked (no-op for a nil / bodyless error).
	if lastNeg != nil {
		origin.CloseStatusErrBody(lastErr)
		return lastNeg, nil
	}
	// If every origin merely SKIPPED (ErrSkip → lastErr cleared) and none answered,
	// there is no real error to surface — report a miss so the caller (server) treats
	// it as a not-found rather than a nil/nil contract violation. In practice the real
	// origin is always last and never skips, so this is a defensive backstop.
	if lastErr == nil {
		return nil, origin.ErrNotFound
	}
	return nil, lastErr
}
