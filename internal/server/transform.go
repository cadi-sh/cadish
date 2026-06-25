package server

import (
	"bytes"
	"io"
	"net/http"
	"strings"

	"github.com/cadi-sh/cadish/internal/pipeline"
)

// maxTransformBody caps the body size cadish will buffer to apply `replace`
// body transforms. Responses larger than this stream through untransformed and
// are never fully buffered (so a large-media response keeps its zero-extra-copy
// fast path). 1 MiB comfortably covers HTML/JSON pages, the intended targets.
const maxTransformBody = 1 << 20

// transformsApply reports whether deliver-phase body transforms can run for this
// response. They are skipped for Range requests and HEAD (a partial/empty body
// can't be safely substituted) and for content-encoded bodies (substituting in
// compressed bytes would corrupt them). Callers also gate on the body size cap.
func transformsApply(repls []pipeline.Replacement, hdr http.Header, isRange, isHead bool) bool {
	return len(repls) > 0 && !isRange && !isHead && hdr.Get("Content-Encoding") == ""
}

// applyReplacements returns body with each literal replacement applied in order.
func applyReplacements(body []byte, repls []pipeline.Replacement) []byte {
	if len(repls) == 0 {
		return body
	}
	s := string(body)
	for _, r := range repls {
		if r.Old == "" {
			continue
		}
		s = strings.ReplaceAll(s, r.Old, r.New)
	}
	return []byte(s)
}

// readCapped reads from r up to limit+1 bytes. If the body is at most limit bytes
// it returns the full body with exceeded=false. If it is larger, it returns the
// first limit+1 bytes read with exceeded=true; the caller must then stream the
// remainder untransformed via io.MultiReader(bytes.NewReader(buf), r).
func readCapped(r io.Reader, limit int) (buf []byte, exceeded bool, err error) {
	buf, err = io.ReadAll(io.LimitReader(r, int64(limit)+1))
	if err != nil {
		return buf, false, err
	}
	if len(buf) > limit {
		return buf, true, nil
	}
	return buf, false, nil
}

// resumeReader reconstructs the original stream after a capped read overran the
// limit: the already-read prefix followed by whatever remains in r.
func resumeReader(buf []byte, r io.Reader) io.Reader {
	return io.MultiReader(bytes.NewReader(buf), r)
}
