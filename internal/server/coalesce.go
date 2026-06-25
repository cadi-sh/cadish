package server

import "sync"

// fetchCoalescer single-flights the origin fetch for a given cache key so a herd of
// concurrent requests for the SAME cold object results in ONE origin fetch (the
// thundering-herd / egress guard) instead of N.
//
// Model (deliberately simple — favour obviously-correct over clever): the FIRST
// request for a key becomes the WINNER and runs the real fetch, streaming the body
// to its own client AND populating the cache (via the serve-and-cache tee).
// Concurrent duplicate requests for the same key become WAITERS: they block on the
// winner's call until it finishes, then — only if the winner SUCCEEDED (served a
// cacheable response) — serve the now-populated object straight from cache. If the
// winner FAILED (error / 404 / non-cacheable), the waiters do NOT inherit that
// result; they fall through to run their own normal origin path, so a winner's
// failure is never masked and a real success on a retry is never suppressed.
//
// This is NOT a streaming tee to waiters: they block until the winner finished
// caching, then read from cache. That trades a little added latency on a cold-key
// herd for eliminating the duplicate origin egress, which is the whole point. If the
// winner's object isn't in cache when a waiter wakes (too big to cache, evicted),
// the waiter simply falls through to its own fetch — correctness preserved.
type fetchCoalescer struct {
	mu    sync.Mutex
	calls map[string]*fetchCall
}

// fetchCall is the shared state for one in-flight winner fetch. done is closed by
// the winner when its fetch+serve completes; succeeded reports whether the winner
// served a cacheable success (so waiters may read from cache) — read only AFTER
// done is closed, so no extra synchronisation is needed on it.
type fetchCall struct {
	done      chan struct{}
	succeeded bool
}

func newFetchCoalescer() *fetchCoalescer {
	return &fetchCoalescer{calls: make(map[string]*fetchCall)}
}

// enter registers interest in key. When winner is true the caller is the FIRST
// in-flight request for key and MUST run the real fetch and then call
// finish(key, call, succeeded). When winner is false the caller is a WAITER and
// must wait on call.done, then inspect call.succeeded to decide whether to serve
// from cache (true) or fall through to its own path (false).
func (c *fetchCoalescer) enter(key string) (call *fetchCall, winner bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if existing, ok := c.calls[key]; ok {
		return existing, false
	}
	call = &fetchCall{done: make(chan struct{})}
	c.calls[key] = call
	return call, true
}

// finish is called by the WINNER exactly once when its fetch+serve has completed. It
// records whether the fetch succeeded (so waiters may read from cache), removes the
// key from the in-flight map, and wakes all waiters by closing done.
func (c *fetchCoalescer) finish(key string, call *fetchCall, succeeded bool) {
	c.mu.Lock()
	// Only delete if the map still points at THIS call; defensive guard so a stale
	// finish can't evict a newer winner's entry.
	if c.calls[key] == call {
		delete(c.calls, key)
	}
	c.mu.Unlock()
	call.succeeded = succeeded
	close(call.done)
}

// singleFlight coalesces background revalidations (bgfetch): it admits at most one
// in-flight operation per key. begin reports whether the caller acquired the slot
// (it must call end when done); a caller that did not acquire it should do nothing.
type singleFlight struct {
	mu       sync.Mutex
	inFlight map[string]struct{}
}

func newSingleFlight() *singleFlight {
	return &singleFlight{inFlight: make(map[string]struct{})}
}

// begin acquires the slot for key, returning false if one is already in flight.
func (s *singleFlight) begin(key string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.inFlight[key]; ok {
		return false
	}
	s.inFlight[key] = struct{}{}
	return true
}

// end releases the slot for key.
func (s *singleFlight) end(key string) {
	s.mu.Lock()
	delete(s.inFlight, key)
	s.mu.Unlock()
}
