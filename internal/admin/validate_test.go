package admin

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cadi-sh/cadish/internal/config"
	"github.com/cadi-sh/cadish/internal/metrics"
)

// postValidate POSTs src to /api/validate with the given token and decodes the
// JSON response into a validateResponse.
func postValidate(t *testing.T, srv *Server, token, src string) (*httptest.ResponseRecorder, validateResponse) {
	t.Helper()
	req := httptest.NewRequest("POST", "/api/validate", strings.NewReader(src))
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	srv.routes().ServeHTTP(rec, req)
	var v validateResponse
	if rec.Code == http.StatusOK {
		if err := json.Unmarshal(rec.Body.Bytes(), &v); err != nil {
			t.Fatalf("decode: %v\n%s", err, rec.Body.String())
		}
	}
	return rec, v
}

// /api/source returns the running site's Cadishfile so the editor can pre-load.
func TestSourceEndpoint(t *testing.T) {
	srv, _ := newTestServer(t)
	rec := do(t, srv, "GET", "/api/source", "secret")
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d", rec.Code)
	}
	var sr sourceResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &sr); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !strings.Contains(sr.Source, "example.com") {
		t.Errorf("source missing config text: %q", sr.Source)
	}
	if sr.Error != "" {
		t.Errorf("unexpected error: %q", sr.Error)
	}
}

// TestSourceEndpointNeverLeaksAbsolutePath proves /api/source returns only the base
// filename in Path and routes a read error through stripPathFromError, so a token
// holder cannot learn the host directory layout (#16 hardening, restored for the
// sibling endpoint — R37). Mirrors handleConfig's stripping policy.
func TestSourceEndpointNeverLeaksAbsolutePath(t *testing.T) {
	dir := t.TempDir() // an absolute path with a recognizable directory prefix
	// Success case: a readable config — Path must be the bare filename, not the abs path.
	cfgPath := filepath.Join(dir, "Cadishfile")
	if err := os.WriteFile(cfgPath, []byte("example.com {\n  cache_key url\n}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	ac := &config.AdminConfig{Listen: "127.0.0.1:0", AuthToken: "secret", Metrics: true}
	srv := New(ac, metrics.New(), fakeLive{}, nil, nil, cfgPath)
	rec := do(t, srv, "GET", "/api/source", "secret")
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d", rec.Code)
	}
	var sr sourceResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &sr); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if sr.Path != "Cadishfile" {
		t.Errorf("Path = %q, want bare filename %q", sr.Path, "Cadishfile")
	}
	if strings.Contains(sr.Path, dir) || strings.ContainsAny(sr.Path, `/\`) {
		t.Errorf("Path leaks a directory: %q (dir %q)", sr.Path, dir)
	}

	// Error case: a non-existent config file — the os.ReadFile error embeds the abs
	// path; it must be stripped to the base filename before reaching the caller.
	missing := filepath.Join(dir, "nope", "Cadishfile")
	srv2 := New(ac, metrics.New(), fakeLive{}, nil, nil, missing)
	rec2 := do(t, srv2, "GET", "/api/source", "secret")
	var sr2 sourceResponse
	if err := json.Unmarshal(rec2.Body.Bytes(), &sr2); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if sr2.Error == "" {
		t.Fatal("expected a read error for a missing config file")
	}
	if strings.Contains(sr2.Error, dir) {
		t.Errorf("error string leaks the absolute directory: %q (dir %q)", sr2.Error, dir)
	}
	if strings.Contains(sr2.Path, dir) {
		t.Errorf("Path leaks the absolute directory: %q (dir %q)", sr2.Path, dir)
	}
}

// errReader fails every Read, simulating a broken request body (e.g. a truncated
// upload). The handler must not echo the raw transport error back to the caller.
type errReader struct{}

func (errReader) Read([]byte) (int, error) {
	return 0, errors.New("simulated transport read failure: 0xdeadbeef")
}

// A body-read failure must return a GENERIC message, never the raw error string —
// the raw error can leak internal/transport detail. (Config PARSE errors are a
// different path and are deliberately surfaced; those are tested elsewhere.)
func TestValidateBodyReadErrorIsGeneric(t *testing.T) {
	srv, _ := newTestServer(t)
	req := httptest.NewRequest("POST", "/api/validate", errReader{})
	req.Header.Set("Authorization", "Bearer secret")
	rec := httptest.NewRecorder()
	srv.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status %d, want 400", rec.Code)
	}
	body := rec.Body.String()
	if strings.Contains(body, "0xdeadbeef") || strings.Contains(body, "simulated transport") {
		t.Errorf("response leaked the raw read error: %q", body)
	}
	if !strings.Contains(body, "invalid request body") {
		t.Errorf("response = %q, want generic \"invalid request body\"", body)
	}
}

// D5: a body over the 1 MiB cap returns 413 (Request Entity Too Large) instead of
// silently truncating to 1 MiB and returning 200. A body exactly at the limit is
// accepted (200).
func TestValidateOversizedBodyIs413(t *testing.T) {
	srv, _ := newTestServer(t)
	// Build a syntactically valid config padded past the limit with comment bytes.
	header := "example.com {\n  cache_key url\n}\n"
	pad := maxValidateBytes + 1 - len(header)
	oversized := header + "# " + strings.Repeat("x", pad)
	if len(oversized) <= maxValidateBytes {
		t.Fatalf("test setup: body %d not over limit %d", len(oversized), maxValidateBytes)
	}
	req := httptest.NewRequest("POST", "/api/validate", strings.NewReader(oversized))
	req.Header.Set("Authorization", "Bearer secret")
	rec := httptest.NewRecorder()
	srv.routes().ServeHTTP(rec, req)
	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversized body: status %d, want 413\n%s", rec.Code, rec.Body.String())
	}
}

// D5: a body exactly at the 1 MiB limit is still validated (200), not rejected.
func TestValidateAtLimitBodyIs200(t *testing.T) {
	srv, _ := newTestServer(t)
	header := "example.com {\n  cache_key url\n}\n"
	pad := maxValidateBytes - len(header)
	atLimit := header + "# " + strings.Repeat("x", pad-2) // exactly maxValidateBytes
	if len(atLimit) != maxValidateBytes {
		t.Fatalf("test setup: body %d != limit %d", len(atLimit), maxValidateBytes)
	}
	req := httptest.NewRequest("POST", "/api/validate", strings.NewReader(atLimit))
	req.Header.Set("Authorization", "Bearer secret")
	rec := httptest.NewRecorder()
	srv.routes().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("at-limit body: status %d, want 200\n%s", rec.Code, rec.Body.String())
	}
}

func TestValidateAuthRequired(t *testing.T) {
	srv, _ := newTestServer(t)
	rec, _ := postValidate(t, srv, "", "example.com {\n  cache_key url\n}\n")
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("no token: status %d, want 401", rec.Code)
	}
}

func TestValidateOnlyPOST(t *testing.T) {
	srv, _ := newTestServer(t)
	rec := do(t, srv, "GET", "/api/validate", "secret")
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("GET /api/validate: status %d, want 405", rec.Code)
	}
}

// A valid config returns the full check report, no parse/compile errors, and a
// canonical formatted body.
func TestValidateValid(t *testing.T) {
	srv, _ := newTestServer(t)
	src := "example.com {\n  @img path /img/*\n  cache_key url host\n  strip_cookies @img\n}\n"
	rec, v := postValidate(t, srv, "secret", src)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
	}
	if !v.OK {
		t.Errorf("OK = false, want true (errors: %+v / %+v)", v.ParseError, v.CompileErrors)
	}
	if v.ParseError != nil {
		t.Errorf("ParseError = %+v, want nil", v.ParseError)
	}
	if len(v.CompileErrors) != 0 {
		t.Errorf("CompileErrors = %+v, want none", v.CompileErrors)
	}
	if v.Report == nil || len(v.Report.Sites) != 1 {
		t.Fatalf("Report = %+v, want 1 site", v.Report)
	}
	if v.Report.Sites[0].MatcherCount < 1 {
		t.Errorf("matcher_count = %d, want >=1", v.Report.Sites[0].MatcherCount)
	}
	if v.Formatted == "" {
		t.Error("Formatted is empty")
	}
}

// A syntactically broken config surfaces a parse error with a position.
func TestValidateParseError(t *testing.T) {
	srv, _ := newTestServer(t)
	// Unterminated site block: an open brace with no close.
	src := "example.com {\n  cache_key url\n"
	rec, v := postValidate(t, srv, "secret", src)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
	}
	if v.OK {
		t.Error("OK = true, want false for a parse error")
	}
	if v.ParseError == nil {
		t.Fatal("ParseError = nil, want a positioned parse error")
	}
	if v.ParseError.Line <= 0 {
		t.Errorf("ParseError.Line = %d, want > 0", v.ParseError.Line)
	}
	if v.ParseError.Message == "" {
		t.Error("ParseError.Message is empty")
	}
	if v.ParseError.Position == "" {
		t.Error("ParseError.Position is empty")
	}
}

// A config that parses but fails to compile (unknown directive) surfaces a
// compile error with a position; no parse error.
func TestValidateCompileError(t *testing.T) {
	srv, _ := newTestServer(t)
	src := "example.com {\n  cache_key url\n  not_a_real_directive foo\n}\n"
	rec, v := postValidate(t, srv, "secret", src)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
	}
	if v.ParseError != nil {
		t.Fatalf("ParseError = %+v, want nil (it parses)", v.ParseError)
	}
	if v.OK {
		t.Error("OK = true, want false for a compile error")
	}
	if len(v.CompileErrors) == 0 {
		t.Fatal("CompileErrors empty, want at least one")
	}
	ce := v.CompileErrors[0]
	if ce.Line <= 0 {
		t.Errorf("CompileError.Line = %d, want > 0", ce.Line)
	}
	if !strings.Contains(ce.Message, "not_a_real_directive") {
		t.Errorf("CompileError.Message = %q, want it to name the directive", ce.Message)
	}
	// The check report is still produced (best-effort analysis).
	if v.Report == nil {
		t.Error("Report = nil, want best-effort report alongside the compile error")
	}
}

// The Formatted output round-trips: re-validating the formatted body yields the
// same formatted body (Format is idempotent) and no errors.
func TestValidateFormatRoundTrips(t *testing.T) {
	srv, _ := newTestServer(t)
	// Deliberately messy input (semicolons, odd indent) to exercise the formatter.
	src := "example.com {\n@img path /img/* ;\ncache_key url host\nstrip_cookies @img\n}\n"
	_, v := postValidate(t, srv, "secret", src)
	if !v.OK {
		t.Fatalf("first pass not OK: %+v / %+v", v.ParseError, v.CompileErrors)
	}
	if v.Formatted == "" {
		t.Fatal("Formatted empty")
	}
	_, v2 := postValidate(t, srv, "secret", v.Formatted)
	if !v2.OK {
		t.Fatalf("second pass not OK: %+v / %+v", v2.ParseError, v2.CompileErrors)
	}
	if v2.Formatted != v.Formatted {
		t.Errorf("Format not idempotent:\n--- first ---\n%s\n--- second ---\n%s", v.Formatted, v2.Formatted)
	}
}
