//go:build integration

// Package integration is a real-binary end-to-end harness (backlog #4 / task #34): it
// brings up the cadish image built from deploy/Dockerfile in front of the test-origin
// and a MinIO S3 bucket (docker-compose.yml), exercises the REAL distroless binary over
// the network, and tears the stack down. The httptest suite in test/e2e already covers
// behavior in-process; this validates the actual built artifact, container wiring, and
// the disk/cache volume + S3 path that httptest can't.
//
// Gated behind `//go:build integration` so the default `go test ./...` never starts
// Docker. Run it explicitly (needs a working Docker daemon):
//
//	go test -tags integration ./test/integration -v
package integration

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"sync"
	"testing"
	"time"
)

const (
	cadishBase = "http://localhost:18080"
	originStat = "http://localhost:19000/_stats"
	composeF   = "docker-compose.yml"
)

// TestMain brings the compose stack up (building images), waits for cadish to serve,
// runs the suite, then tears the stack down. If Docker is unavailable the suite is
// skipped rather than failed — the harness is opt-in infrastructure.
func TestMain(m *testing.M) {
	if _, err := exec.LookPath("docker"); err != nil {
		fmt.Println("integration: docker not found, skipping")
		os.Exit(0)
	}

	up := exec.Command("docker", "compose", "-f", composeF, "up", "--build", "-d")
	up.Stdout, up.Stderr = os.Stdout, os.Stderr
	if err := up.Run(); err != nil {
		fmt.Printf("integration: compose up failed: %v\n", err)
		down()
		os.Exit(1)
	}

	if err := waitForCadish(3 * time.Minute); err != nil {
		fmt.Printf("integration: cadish did not become ready: %v\n", err)
		dumpLogs()
		down()
		os.Exit(1)
	}

	code := m.Run()
	down()
	os.Exit(code)
}

func down() {
	c := exec.Command("docker", "compose", "-f", composeF, "down", "-v")
	c.Stdout, c.Stderr = os.Stdout, os.Stderr
	_ = c.Run()
}

func dumpLogs() {
	c := exec.Command("docker", "compose", "-f", composeF, "logs", "--tail", "40")
	c.Stdout, c.Stderr = os.Stdout, os.Stderr
	_ = c.Run()
}

// waitForCadish polls a cacheable path until cadish answers 200 (origin reachable
// through the proxy) or the deadline elapses.
func waitForCadish(d time.Duration) error {
	ctx, cancel := context.WithTimeout(context.Background(), d)
	defer cancel()
	for {
		resp, err := doGet("http.local", "/obj/_probe?size=1")
		if err == nil {
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return nil
			}
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("timed out (last err=%v)", err)
		case <-time.After(time.Second):
		}
	}
}

// doGet issues a GET to cadish for the given virtual host + path.
func doGet(host, path string) (*http.Response, error) {
	req, err := http.NewRequest(http.MethodGet, cadishBase+path, nil)
	if err != nil {
		return nil, err
	}
	req.Host = host
	return http.DefaultClient.Do(req)
}

// getBody issues a GET and returns status, the X-Cache header, and the body bytes.
func getBody(t *testing.T, host, path string) (int, string, []byte) {
	t.Helper()
	resp, err := doGet(host, path)
	if err != nil {
		t.Fatalf("GET %s%s: %v", host, path, err)
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	return resp.StatusCode, resp.Header.Get("X-Cache"), b
}

func originHits(t *testing.T) int64 {
	t.Helper()
	resp, err := http.Get(originStat)
	if err != nil {
		t.Fatalf("origin /_stats: %v", err)
	}
	defer resp.Body.Close()
	var s struct {
		ObjectHits int64 `json:"object_hits"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&s); err != nil {
		t.Fatalf("decode /_stats: %v", err)
	}
	return s.ObjectHits
}

// TestHTTPMissThenHit proves a plain-HTTP upstream object is fetched once (MISS) then
// served from cache (HIT) with identical bytes — through the real binary over Docker.
func TestHTTPMissThenHit(t *testing.T) {
	const path = "/obj/alpha"

	st1, xc1, b1 := getBody(t, "http.local", path)
	if st1 != http.StatusOK {
		t.Fatalf("first GET status = %d, want 200", st1)
	}
	if len(b1) == 0 {
		t.Fatal("first GET returned an empty body")
	}

	st2, xc2, b2 := getBody(t, "http.local", path)
	if st2 != http.StatusOK {
		t.Fatalf("second GET status = %d, want 200", st2)
	}
	if string(b1) != string(b2) {
		t.Fatal("HIT body differs from MISS body")
	}
	if !strings.Contains(strings.ToUpper(xc2), "HIT") {
		t.Fatalf("second GET X-Cache = %q, want a HIT (first was %q)", xc2, xc1)
	}
}

// TestQueryForwardedToOrigin documents a defect the harness surfaced: cadish builds the
// upstream request from the path ONLY (origin.Request.Key = preq.Path; httporigin never
// appends the query), so a cacheable GET never forwards its query string to the origin.
// The cache key distinguishes by query, but every distinct-query key fetches the same
// path-only origin response. Skipped until that is fixed (then it becomes live coverage).
func TestQueryForwardedToOrigin(t *testing.T) {
	// The origin honors ?size=, so a forwarded query yields a body of that exact size.
	if _, _, b := getBody(t, "http.local", "/obj/sized?size=4096"); len(b) != 4096 {
		t.Fatalf("origin body = %d bytes, want 4096 (query not forwarded)", len(b))
	}
}

// TestRequestCoalescing fires many concurrent requests for one uncached key; the proxy
// must coalesce them into a SINGLE origin fetch (origin /_stats delta == 1).
func TestRequestCoalescing(t *testing.T) {
	const path = "/obj/coalesce?size=8192"
	before := originHits(t)

	const n = 20
	var wg sync.WaitGroup
	errs := make(chan error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			resp, err := doGet("http.local", path)
			if err != nil {
				errs <- err
				return
			}
			_, _ = io.Copy(io.Discard, resp.Body)
			_ = resp.Body.Close()
			if resp.StatusCode != http.StatusOK {
				errs <- fmt.Errorf("status %d", resp.StatusCode)
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatalf("concurrent GET failed: %v", err)
	}

	if delta := originHits(t) - before; delta != 1 {
		t.Fatalf("origin hits delta = %d, want 1 (requests not coalesced)", delta)
	}
}

// TestS3Origin proves the S3-compatible upstream fetches a MinIO object and caches it.
//
// It documents a second defect the harness surfaced: `internal/config/origin.go` builds
// s3origin.Config WITHOUT AccessKey/SecretKey, so the SDK signs every request with EMPTY
// static credentials — MinIO rejects that (502), and the SDK cannot fall back to a true
// anonymous (unsigned) request even though the bucket is public-read (a direct anonymous
// GET to MinIO returns 200). Authenticated S3 origins also can't work because the
// Cadishfile credentials are never plumbed through. Skipped until S3 credential wiring
// (and/or an explicit anonymous mode) lands; then it becomes live coverage.
func TestS3Origin(t *testing.T) {
	const path = "/greeting.txt"
	const want = "hello-from-minio\n"

	st1, _, b1 := getBody(t, "s3.local", path)
	if st1 != http.StatusOK {
		t.Fatalf("first S3 GET status = %d, want 200 (body=%q)", st1, string(b1))
	}
	if string(b1) != want {
		t.Fatalf("S3 body = %q, want %q", string(b1), want)
	}

	st2, xc2, b2 := getBody(t, "s3.local", path)
	if st2 != http.StatusOK || string(b2) != want {
		t.Fatalf("second S3 GET = (%d, %q)", st2, string(b2))
	}
	if !strings.Contains(strings.ToUpper(xc2), "HIT") {
		t.Fatalf("second S3 GET X-Cache = %q, want a HIT", xc2)
	}
}
