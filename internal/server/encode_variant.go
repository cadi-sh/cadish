package server

import (
	"bytes"
	"io"
	"strconv"

	"github.com/cadi-sh/cadish/internal/cache"
)

// Cached compressed variants (D69)
//
// When `encode` is active, cadish stores the canonical IDENTITY body under the
// logical cache key (unchanged) AND, lazily on the first HIT for a negotiated
// content-coding, a precompressed representation under a DERIVED key. A later HIT
// for the same coding then serves the stored compressed bytes directly, skipping
// the per-HIT compression CPU.
//
// # Bounded cardinality
//
// The variant key is `<key>\x00ce=<codec>` where codec is one of a FIXED small set
// (gzip/br/zstd). The raw Accept-Encoding header is NEVER folded into the key, so a
// logical entry has at most one extra blob per supported codec (≤3) — a bounded
// multiplier, not the unbounded explosion a per-Accept-Encoding key would cause.
// The identity request and a gzip request resolve to the SAME logical entry: the
// freshness index is keyed on the logical key only; variant blobs carry no
// freshness entry and are reached ONLY through serveFromCache, which the caller
// enters solely when the logical key is fresh.
//
// # Self-validation (staleness safety)
//
// The variant blob records the source IDENTITY's fingerprint (its ETag, or
// "len:<size>" when the origin sent no ETag) in its own meta.ETag. On a HIT the
// stored variant is served only when its recorded fingerprint matches the CURRENT
// identity's fingerprint; otherwise it is treated as absent and re-materialized.
// This closes the re-fetch window: if the logical entry is invalidated and re-stored
// with new content, an orphaned old variant blob is detected as stale and replaced
// rather than served. (Invalidation itself is lazy via the freshness index — a
// purged/expired logical key is a MISS, so serveFromCache is not entered for it; the
// orphan blob is later evicted by the tier LRU.)

// variantSep separates the logical key from the variant discriminator. It is NUL
// (0x00). A logical cache key never contains a NUL: tokens join with the unit
// separator 0x1f, and the request path is sanitized of all ASCII control bytes
// (0x00-0x1f, 0x7f) in normalizePath before any key token is rendered (Fix #8), so a
// variant key can never collide with a logical key.
const variantSep = "\x00ce="

// variantKey derives the storage key for the compressed representation of key
// under the given content-coding.
func variantKey(key, codec string) string { return key + variantSep + codec }

// sourceFingerprint returns a token identifying the identity representation a
// variant was derived from, so a stale variant (after a re-fetch with new content)
// is detected — together with a flag reporting whether the identity carries a
// trustworthy validator at all.
//
// A variant may only be cached when the identity has a real validator (ETag and/or
// Last-Modified): those change when the representation changes, so the recorded
// fingerprint reliably detects a re-fetched, different body under the same key. The
// byte size is folded in as an extra discriminator but is NOT a validator on its own
// (two different bodies can share a length), so a representation with neither an ETag
// nor a Last-Modified yields ok=false and is compressed per-HIT (never cached as a
// variant) rather than risk serving a stale precompressed copy.
func sourceFingerprint(meta cache.ObjectMeta) (fp string, ok bool) {
	if meta.ETag == "" && meta.LastModified == "" {
		return "", false
	}
	return meta.ETag + "\x1f" + meta.LastModified + "\x1flen:" + strconv.FormatInt(meta.Size, 10), true
}

// lookupVariant returns a reader over the stored compressed variant for (key,
// codec) when one exists AND was derived from the current identity (srcFP). The
// caller must Close the returned reader. ok is false when there is no usable
// variant (absent, or stale relative to srcFP).
func lookupVariant(store *cache.Store, key, codec, srcFP string) (*cache.Reader, bool) {
	r, ok := store.Get(variantKey(key, codec))
	if !ok {
		return nil, false
	}
	if r.Meta.ETag != srcFP {
		// Orphaned/stale variant from an older generation of this key: ignore it (it
		// will be overwritten by a fresh store below, and LRU-evicted otherwise).
		_ = r.Close()
		return nil, false
	}
	return r, true
}

// storeVariant writes the compressed bytes as the variant blob for (key, codec),
// stamping the source fingerprint into the blob's ETag for later self-validation.
// It is best-effort: any error is swallowed (the response was already served from
// the on-the-fly compression). A variant is small (compressed text), so it routes
// to whichever tier the size policy picks; the explicit known size lets the router
// place it in RAM.
func storeVariant(store *cache.Store, key, codec, srcFP, contentType string, compressed []byte) {
	meta := cache.ObjectMeta{
		Key:         variantKey(key, codec),
		Size:        int64(len(compressed)),
		ContentType: contentType,
		ETag:        srcFP, // fingerprint of the identity this variant was derived from
	}
	w, err := store.Writer(meta)
	if err != nil {
		return
	}
	if _, err := w.Write(compressed); err != nil {
		_ = w.Abort()
		return
	}
	_ = w.Commit()
}

// compressBytes compresses src with the given codec, returning the compressed
// bytes. It returns ok=false when the codec is unrecognized (callers fall back to
// serving identity / the raw path).
func compressBytes(codec string, src []byte) (out []byte, ok bool) {
	var buf bytes.Buffer
	ew := newEncodeWriter(&buf, codec)
	if ew == nil {
		return nil, false
	}
	if _, err := ew.Write(src); err != nil {
		_ = ew.Close()
		return nil, false
	}
	if err := ew.Close(); err != nil {
		return nil, false
	}
	return buf.Bytes(), true
}

// drainReader reads up to limit bytes of r into memory. When the body fits it
// returns the full buffer with exceeded=false. When it is larger (or a read error
// occurs) it returns exceeded=true and a resume reader that re-streams the
// already-consumed prefix followed by the remainder of r, so the caller can stream
// the whole body without losing the bytes drainReader already pulled. r is the
// cache reader; the caller owns closing it.
func drainReader(r io.Reader, limit int) (buf []byte, exceeded bool, resume io.Reader) {
	b, ex, err := readCapped(r, limit)
	if err != nil {
		// A read error: hand back whatever prefix we got followed by r (which will
		// re-surface the same error to the streaming copy).
		return nil, true, resumeReader(b, r)
	}
	if ex {
		return nil, true, resumeReader(b, r)
	}
	return b, false, nil
}
