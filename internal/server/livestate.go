package server

import "github.com/cadi-sh/cadish/internal/cache"

// SiteState is a point-in-time observability view of one bound site: its name,
// its addresses, and its two-tier cache fill. It is read on demand (never mirrored
// into counters) so it cannot drift from the live objects.
type SiteState struct {
	Name      string      `json:"name"`
	Addresses []string    `json:"addresses"`
	Cache     cache.Stats `json:"cache"`
}

// LiveState returns the current per-site cache fill for every bound site. It is
// cheap (lock-free cache atomics) and safe for concurrent use; the admin dashboard
// calls it per scrape/tick.
func (h *Handler) LiveState() []SiteState {
	rt := h.route.Load()
	out := make([]SiteState, 0, len(rt.sites))
	for _, s := range rt.sites {
		st := SiteState{
			Name:      s.Name,
			Addresses: s.Addresses,
		}
		if s.Store != nil {
			st.Cache = s.Store.Stats()
		}
		out = append(out, st)
	}
	return out
}
