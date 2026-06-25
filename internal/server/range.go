package server

import (
	"errors"
	"strconv"
	"strings"
)

// errInvalidRange signals a Range header we don't satisfy with a 206 but that
// should fall back to a full 200 response (malformed, multi-range, or no "bytes="
// prefix — i.e. forms a normal client wouldn't expect a 416 for).
var errInvalidRange = errors.New("invalid range")

// errUnsatisfiableRange signals a syntactically valid single byte range that
// cannot be satisfied for this object's size (e.g. start >= size). Per RFC 7233
// the response MUST be 416 with a Content-Range of "bytes */size", NOT a 200 with
// the full body — returning the whole object for "bytes=5000000000-" would be a
// bandwidth-amplification foot-gun on a public video endpoint.
var errUnsatisfiableRange = errors.New("unsatisfiable range")

// httpRange is a resolved byte range [start, start+length).
type httpRange struct {
	start, length int64
}

// parseSingleRange parses a single-range "bytes=" header against a known total
// size and returns the resolved range. We support exactly one range (sufficient
// for video seeking / HLS); multi-range requests fall back to the full body by
// returning errInvalidRange, which the caller treats as "serve 200 full".
//
// Forms handled:
//
//	bytes=START-END   -> [START, END]
//	bytes=START-      -> [START, size-1]
//	bytes=-SUFFIX     -> last SUFFIX bytes
func parseSingleRange(header string, size int64) (httpRange, error) {
	const prefix = "bytes="
	// A non-positive size has no satisfiable byte range. Guard here so callers
	// (and fuzzers) can never coax out a negative/overflowing offset or length
	// that would drive a bad slice or CopyN downstream.
	if size <= 0 {
		return httpRange{}, errUnsatisfiableRange
	}
	if !strings.HasPrefix(header, prefix) {
		return httpRange{}, errInvalidRange
	}
	spec := strings.TrimSpace(header[len(prefix):])
	if spec == "" || strings.Contains(spec, ",") {
		return httpRange{}, errInvalidRange // multi-range unsupported
	}
	dash := strings.IndexByte(spec, '-')
	if dash < 0 {
		return httpRange{}, errInvalidRange
	}
	startStr := strings.TrimSpace(spec[:dash])
	endStr := strings.TrimSpace(spec[dash+1:])

	if startStr == "" {
		// suffix range: last N bytes.
		n, err := strconv.ParseInt(endStr, 10, 64)
		if err != nil {
			return httpRange{}, errInvalidRange // malformed number
		}
		if n <= 0 {
			// "bytes=-0" and "bytes=-" with a non-positive suffix are unsatisfiable.
			return httpRange{}, errUnsatisfiableRange
		}
		if n > size {
			n = size
		}
		return httpRange{start: size - n, length: n}, nil
	}

	start, err := strconv.ParseInt(startStr, 10, 64)
	if err != nil {
		return httpRange{}, errInvalidRange // malformed number
	}
	if start < 0 {
		return httpRange{}, errInvalidRange
	}
	if start >= size {
		// Start beyond EOF: valid syntax, unsatisfiable -> 416 (not a 200 of the
		// whole file).
		return httpRange{}, errUnsatisfiableRange
	}

	end := size - 1
	if endStr != "" {
		end, err = strconv.ParseInt(endStr, 10, 64)
		if err != nil {
			return httpRange{}, errInvalidRange // malformed number
		}
		if end < start {
			// e.g. "bytes=10-5": unsatisfiable.
			return httpRange{}, errUnsatisfiableRange
		}
		if end >= size {
			end = size - 1
		}
	}
	return httpRange{start: start, length: end - start + 1}, nil
}

// contentRange formats the Content-Range header value for a resolved range.
func (r httpRange) contentRange(size int64) string {
	return "bytes " + strconv.FormatInt(r.start, 10) + "-" +
		strconv.FormatInt(r.start+r.length-1, 10) + "/" + strconv.FormatInt(size, 10)
}
