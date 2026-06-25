package server

import (
	"compress/gzip"
	"io"
	"net/http"
	"strconv"
	"strings"

	"github.com/andybalholm/brotli"
	"github.com/klauspost/compress/zstd"

	"github.com/cadi-sh/cadish/internal/pipeline"
)

// negotiateEncoding picks the codec to use for a response, given the configured
// preference order (enc.Codecs) and the client's Accept-Encoding header. It
// returns the wire Content-Encoding token ("gzip"/"br"/"zstd") of the first
// configured codec the client accepts, or "" when the client accepts none of
// them (so the response is served uncompressed). A missing/empty Accept-Encoding
// header means the client signalled no preference (identity only): no codec.
//
// Accept-Encoding is parsed per RFC 9110 §12.5.3: a comma-separated list of
// codings each with an optional `;q=` weight. A weight of 0 (q=0) excludes that
// coding (including `identity;q=0` and `*;q=0`). A bare `*` (or `*;q>0`) accepts
// any coding not otherwise named. Tokens we cannot compress with are ignored.
func negotiateEncoding(enc *pipeline.EncodeDecision, accept string) string {
	if enc == nil || len(enc.Codecs) == 0 {
		return ""
	}
	accept = strings.TrimSpace(accept)
	if accept == "" {
		return "" // no Accept-Encoding ⇒ identity only.
	}
	// Build the client's acceptability map: coding token → accepted?
	// star tracks the `*` wildcard's acceptability when present.
	accepted := map[string]bool{}
	starSet := false
	starOK := false
	for _, part := range strings.Split(accept, ",") {
		token, q := parseCoding(part)
		if token == "" {
			continue
		}
		ok := q > 0
		if token == "*" {
			starSet, starOK = true, ok
			continue
		}
		accepted[token] = ok
	}
	clientAccepts := func(codec string) bool {
		if ok, named := accepted[codec]; named {
			return ok
		}
		if starSet {
			return starOK
		}
		return false
	}
	for _, codec := range enc.Codecs {
		if clientAccepts(codec) {
			return codec
		}
	}
	return ""
}

// parseCoding parses one Accept-Encoding element ("gzip", "br;q=0.5",
// "identity;q=0") into its lower-cased coding token and its q-weight (default
// 1.0). A malformed q is treated as the default 1.0 (lenient parsing).
func parseCoding(part string) (token string, q float64) {
	part = strings.TrimSpace(part)
	if part == "" {
		return "", 0
	}
	q = 1.0
	if i := strings.IndexByte(part, ';'); i >= 0 {
		params := part[i+1:]
		token = strings.ToLower(strings.TrimSpace(part[:i]))
		for _, p := range strings.Split(params, ";") {
			p = strings.TrimSpace(p)
			if v, ok := strings.CutPrefix(p, "q="); ok {
				if f, err := strconv.ParseFloat(strings.TrimSpace(v), 64); err == nil {
					q = f
				}
			}
		}
		return token, q
	}
	return strings.ToLower(part), q
}

// contentTypeIncluded reports whether the response Content-Type matches the
// configured include list. A list entry "text/*" matches any "text/…" type; an
// exact entry matches the media type (ignoring any ";charset=…" parameter and
// case). An empty Content-Type never matches (we do not guess).
func contentTypeIncluded(ct string, types []string) bool {
	if ct == "" {
		return false
	}
	// Strip parameters ("text/html; charset=utf-8" → "text/html") and lower-case.
	if i := strings.IndexByte(ct, ';'); i >= 0 {
		ct = ct[:i]
	}
	ct = strings.ToLower(strings.TrimSpace(ct))
	if ct == "" {
		return false
	}
	top := ct
	if i := strings.IndexByte(ct, '/'); i >= 0 {
		top = ct[:i]
	}
	for _, t := range types {
		t = strings.ToLower(t)
		if t == ct {
			return true
		}
		if strings.HasSuffix(t, "/*") && t[:len(t)-1] == top+"/" {
			return true
		}
	}
	return false
}

// encodeApplies reports whether on-the-fly compression should engage for this
// response. It mirrors transformsApply's gating discipline: it is skipped for
// Range and HEAD (a partial/empty body can't be safely re-encoded) and for a
// body that already carries a Content-Encoding (never double-encode). It further
// requires a negotiated codec, an included Content-Type, and a body at or above
// the size floor. size < 0 means an unknown length (chunked/streamed origin):
// the floor cannot be pre-checked, so we engage (streaming compression is cheap
// to abandon — but here we simply compress). When this returns false the raw
// fast path is untouched (zero-extra-copy invariant).
func encodeApplies(enc *pipeline.EncodeDecision, codec string, hdr http.Header, size int64, isRange, isHead bool) bool {
	if enc == nil || codec == "" || isRange || isHead {
		return false
	}
	if hdr.Get("Content-Encoding") != "" {
		return false
	}
	if !contentTypeIncluded(hdr.Get("Content-Type"), enc.Types) {
		return false
	}
	if size >= 0 && size < int64(enc.MinLength) {
		return false
	}
	return true
}

// applyEncodeHeaders sets the response headers for a compressed representation:
// Content-Encoding, an appended Vary: Accept-Encoding, and it drops
// Content-Length (the compressed size is unknown up front; the response goes out
// chunked). A present strong ETag is weakened (prefixed `W/`) because a
// compressed representation is not byte-identical to the stored one, so the
// strong validator would otherwise mismatch. A missing or already-weak ETag is
// left as-is. It is called only when encodeApplies returned true.
func applyEncodeHeaders(hdr http.Header, codec string) {
	hdr.Set("Content-Encoding", codec)
	addVaryAcceptEncoding(hdr)
	hdr.Del("Content-Length")
	weakenETag(hdr)
}

// addVaryAcceptEncoding adds "Accept-Encoding" to the Vary header without
// duplicating it (case-insensitive). A "*" Vary is left untouched.
func addVaryAcceptEncoding(hdr http.Header) {
	const want = "Accept-Encoding"
	for _, v := range hdr.Values("Vary") {
		for _, tok := range strings.Split(v, ",") {
			tok = strings.TrimSpace(tok)
			if tok == "*" || strings.EqualFold(tok, want) {
				return
			}
		}
	}
	hdr.Add("Vary", want)
}

// weakenETag converts a present strong ETag (`"abc"`) into a weak one
// (`W/"abc"`). A missing or already-weak validator is left unchanged.
func weakenETag(hdr http.Header) {
	et := hdr.Get("ETag")
	if et == "" || strings.HasPrefix(et, "W/") {
		return
	}
	hdr.Set("ETag", "W/"+et)
}

// encodeWriter is an io.WriteCloser that compresses with the negotiated codec and
// forwards the bytes to the underlying writer. Close flushes and finalizes the
// codec stream; it does NOT close the underlying writer.
type encodeWriter struct {
	io.WriteCloser
}

// ensureVaryForEncode adds "Vary: Accept-Encoding" when an `encode` policy is
// configured and the response is a compression CANDIDATE (a 200 with an included
// Content-Type and no pre-existing Content-Encoding) — even if THIS request
// negotiated to identity (no codec, or a body below the size floor). cadish's own
// cache always stores the identity bytes, so this is for correctness with a
// downstream shared cache: it must key the identity and compressed representations
// separately rather than serve one to a client that needs the other. The dedup in
// addVaryAcceptEncoding makes this idempotent with applyEncodeHeaders' own Vary.
func ensureVaryForEncode(enc *pipeline.EncodeDecision, hdr http.Header, statusOK bool) {
	if enc == nil || !statusOK {
		return
	}
	if hdr.Get("Content-Encoding") != "" {
		return
	}
	if !contentTypeIncluded(hdr.Get("Content-Type"), enc.Types) {
		return
	}
	addVaryAcceptEncoding(hdr)
}

// newEncodeWriter wraps w with a streaming compressor for the given codec. The
// returned closer MUST be Closed to flush the trailer. codec must be one of
// "gzip"/"br"/"zstd" (a negotiated token); an unrecognized codec returns nil.
func newEncodeWriter(w io.Writer, codec string) *encodeWriter {
	switch codec {
	case "gzip":
		return &encodeWriter{gzip.NewWriter(w)}
	case "br":
		return &encodeWriter{brotli.NewWriter(w)}
	case "zstd":
		zw, err := zstd.NewWriter(w)
		if err != nil {
			return nil
		}
		return &encodeWriter{zw}
	default:
		return nil
	}
}
