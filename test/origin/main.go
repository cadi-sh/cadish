// Command test-origin is a small, configurable HTTP origin for exercising
// cadish end-to-end: deterministic synthetic objects, tunable latency, optional
// flakiness, ETag/Last-Modified, and Range support. It is a test tool, not part
// of the cadish server.
//
// Usage:
//
//	test-origin -addr :9000 -latency 0ms -flaky 0.0
//
// Routes:
//
//	GET /obj/<name>?size=<bytes>   deterministic body of <size> bytes (default 64KiB),
//	                               strong ETag, Last-Modified, Cache-Control, Range-capable
//	GET /health                    200 OK
//	GET /slow?ms=<n>               sleep <n> ms then 200 (overrides -latency)
//	GET /flap                      alternates 200/503 each hit (stampede/hit-for-miss tests)
//	any other path                 404
//
// The hit counter is exposed at GET /_stats (JSON) so tests can assert request
// coalescing (N concurrent client requests -> 1 origin hit).
package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"sync/atomic"
	"time"
)

func main() {
	addr := flag.String("addr", ":9000", "listen address")
	latency := flag.Duration("latency", 0, "artificial latency added to every object response")
	flaky := flag.Float64("flaky", 0, "probability [0,1] that an object request returns 503 (deterministic by hit count)")
	flag.Parse()

	s := &server{latency: *latency, flaky: *flaky}
	mux := http.NewServeMux()
	mux.HandleFunc("/obj/", s.object)
	mux.HandleFunc("/health", func(w http.ResponseWriter, _ *http.Request) { w.Write([]byte("OK")) })
	mux.HandleFunc("/slow", s.slow)
	mux.HandleFunc("/flap", s.flap)
	mux.HandleFunc("/_stats", s.stats)

	log.Printf("test-origin listening on %s (latency=%s flaky=%.2f)", *addr, *latency, *flaky)
	srv := &http.Server{Addr: *addr, Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	log.Fatal(srv.ListenAndServe())
}

type server struct {
	latency  time.Duration
	flaky    float64
	hits     atomic.Int64
	flapHits atomic.Int64
}

// objectBody returns a deterministic body of n bytes for a given name, so the
// same request always yields identical content (stable ETags across restarts).
func objectBody(name string, n int) []byte {
	buf := make([]byte, 0, n)
	seed := sha256.Sum256([]byte(name))
	block := seed[:]
	for len(buf) < n {
		buf = append(buf, block...)
		next := sha256.Sum256(block)
		block = next[:]
	}
	return buf[:n]
}

func (s *server) object(w http.ResponseWriter, r *http.Request) {
	hit := s.hits.Add(1)
	if s.flaky > 0 && float64(hit%100)/100.0 < s.flaky {
		http.Error(w, "flaky 503", http.StatusServiceUnavailable)
		return
	}
	if s.latency > 0 {
		time.Sleep(s.latency)
	}
	size := 64 * 1024
	if q := r.URL.Query().Get("size"); q != "" {
		if v, err := strconv.Atoi(q); err == nil && v >= 0 {
			size = v
		}
	}
	name := r.URL.Path[len("/obj/"):]
	body := objectBody(name, size)
	sum := sha256.Sum256(body)
	etag := `"` + hex.EncodeToString(sum[:16]) + `"`
	w.Header().Set("ETag", etag)
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Cache-Control", "public, max-age=60")
	w.Header().Set("Last-Modified", time.Unix(0, 0).UTC().Format(http.TimeFormat))
	// http.ServeContent gives us conditional + Range (206) handling for free.
	http.ServeContent(w, r, name, time.Unix(0, 0), bytes.NewReader(body))
}

func (s *server) slow(w http.ResponseWriter, r *http.Request) {
	ms, _ := strconv.Atoi(r.URL.Query().Get("ms"))
	time.Sleep(time.Duration(ms) * time.Millisecond)
	fmt.Fprintf(w, "slept %dms\n", ms)
}

func (s *server) flap(w http.ResponseWriter, _ *http.Request) {
	if s.flapHits.Add(1)%2 == 0 {
		http.Error(w, "flap 503", http.StatusServiceUnavailable)
		return
	}
	w.Write([]byte("flap OK"))
}

func (s *server) stats(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]int64{"object_hits": s.hits.Load()})
}
