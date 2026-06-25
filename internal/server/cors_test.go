package server

import (
	"net/http"
	"testing"

	"github.com/cadi-sh/cadish/internal/pipeline"
)

// TestApplyCORS_EchoesSingleOrigin verifies that applyCORS mirrors the edge
// (edge/entry.js): with an explicit origin allow-list it echoes the request's
// Origin (a SINGLE value) when allowed, and emits no Access-Control-Allow-Origin
// at all when the request Origin is missing or not allowed. A comma-joined list
// is invalid per the Fetch spec, so it must never appear.
func TestApplyCORS_EchoesSingleOrigin(t *testing.T) {
	allow := &pipeline.CORSDecision{Origins: []string{"https://a.example", "https://b.example"}}

	t.Run("allowed origin is echoed verbatim with Vary", func(t *testing.T) {
		hdr := http.Header{}
		applyCORS(hdr, allow, "https://b.example")
		if got := hdr.Get("Access-Control-Allow-Origin"); got != "https://b.example" {
			t.Fatalf("ACAO = %q, want %q", got, "https://b.example")
		}
		if got := hdr.Get("Vary"); got != "Origin" {
			t.Fatalf("Vary = %q, want Origin", got)
		}
	})

	t.Run("disallowed origin yields no ACAO header", func(t *testing.T) {
		hdr := http.Header{}
		applyCORS(hdr, allow, "https://evil.example")
		if _, ok := hdr["Access-Control-Allow-Origin"]; ok {
			t.Fatalf("ACAO present = %q, want absent", hdr.Get("Access-Control-Allow-Origin"))
		}
	})

	t.Run("missing request Origin yields no ACAO header", func(t *testing.T) {
		hdr := http.Header{}
		applyCORS(hdr, allow, "")
		if _, ok := hdr["Access-Control-Allow-Origin"]; ok {
			t.Fatalf("ACAO present = %q, want absent", hdr.Get("Access-Control-Allow-Origin"))
		}
	})

	t.Run("never comma-joins multiple origins", func(t *testing.T) {
		hdr := http.Header{}
		applyCORS(hdr, allow, "https://a.example")
		if got := hdr.Get("Access-Control-Allow-Origin"); got == "https://a.example, https://b.example" {
			t.Fatalf("ACAO is a comma-joined list %q — invalid per Fetch spec", got)
		}
	})

	t.Run("wildcard still emits star", func(t *testing.T) {
		hdr := http.Header{}
		applyCORS(hdr, &pipeline.CORSDecision{AllowAllOrigins: true}, "https://a.example")
		if got := hdr.Get("Access-Control-Allow-Origin"); got != "*" {
			t.Fatalf("ACAO = %q, want *", got)
		}
	})
}
