package cache

// ObjectMeta is the metadata persisted alongside a cached object so that cache
// hits can be served (and the cache survives a restart) without contacting the
// origin. It carries everything needed to reconstruct the HTTP response headers.
type ObjectMeta struct {
	Key          string `json:"key"`
	Size         int64  `json:"size"`
	ContentType  string `json:"content_type"`
	ETag         string `json:"etag,omitempty"`
	LastModified string `json:"last_modified,omitempty"`
	// ContentEncoding is the stored representation's Content-Encoding (e.g. "gzip" when the
	// origin compressed the body and cadish cached the compressed bytes). It MUST be replayed
	// on every HIT — a cached encoded body served without its Content-Encoding header is an
	// undecodable/corrupt response (RFC 9110 §8.4: the encoding is representation metadata).
	// Empty for the common identity body.
	ContentEncoding string `json:"content_encoding,omitempty"`
	// Vary is the origin's Vary header (when present). cadish partitions its OWN cache by the
	// cache key (EvalResponse only stores a response whose Vary the key covers), but a HIT must
	// still re-emit Vary so a DOWNSTREAM shared cache — or the Cadish Edge tier in front — keeps
	// the variance signal and does not serve one variant to a client needing another (RFC 9111
	// §4.1). Empty when the origin sent no Vary.
	Vary string `json:"vary,omitempty"`
	// Status is the cached HTTP response status. The common positive case (200)
	// is left zero and persisted compactly via omitempty; a NEGATIVE cache entry
	// (e.g. a cached 404/410 for a deleted object, `cache_ttl status 404 410 …`)
	// records its status here so the hit is served with the right code. A zero
	// value means 200 — see EffectiveStatus — which keeps pre-existing index
	// entries (written before this field existed) serving as 200 on reload.
	Status int `json:"status,omitempty"`
	// Tier is an OPTIONAL placement override: "ram" or "disk" forces the object
	// into that tier instead of the automatic size-based routing. It carries a
	// `storage <selector> -> ram|disk` decision from the pipeline. Empty ("") means
	// "route automatically" (the default). It is a write-time hint and is not
	// persisted — on reload, the object lives in whichever tier's index holds it.
	Tier string `json:"-"`
}

// EffectiveStatus returns the response status to serve for this object, mapping
// the zero value to 200 (positive cache entry / legacy index entry).
func (m ObjectMeta) EffectiveStatus() int {
	if m.Status == 0 {
		return 200
	}
	return m.Status
}
