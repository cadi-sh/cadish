package check

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestSandboxedImportNoFileRead verifies that CheckSourceSandboxed does NOT read
// files referenced by `import` directives — the core security property. We write
// a real file with secret content to t.TempDir(), point an import at it with an
// absolute path, and assert the secret does not appear anywhere in the serialised
// Report or its diagnostics. This would catch a regression where the sandbox
// accidentally fell through to the real disk resolver.
func TestSandboxedImportNoFileRead(t *testing.T) {
	dir := t.TempDir()
	secret := "SUPER_SECRET_TOKEN_abc123xyz"
	secretPath := filepath.Join(dir, "secret.cadish")
	if err := os.WriteFile(secretPath, []byte("# "+secret+"\ncache_key url\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	src := []byte("example.com {\n  import " + secretPath + "\n  cache_key host\n}\n")
	rep, err := CheckSourceSandboxed("Cadishfile", src)
	if err != nil {
		t.Fatalf("CheckSourceSandboxed returned unexpected error: %v", err)
	}

	// Marshal the full report to JSON so we can search for any accidental leakage
	// regardless of which field it might end up in.
	b, err := json.Marshal(rep)
	if err != nil {
		t.Fatalf("marshal report: %v", err)
	}
	got := string(b)

	if strings.Contains(got, secret) {
		t.Errorf("sandboxed analysis leaked secret file content into the report:\n%s", got)
	}

	// The import should still produce a visible diagnostic (not silently dropped)
	// with a playground-appropriate code/message.
	if len(rep.Diagnostics) == 0 {
		t.Error("expected at least one diagnostic for the blocked import, got none")
	}
	found := false
	for _, d := range rep.Diagnostics {
		if strings.Contains(strings.ToLower(d.Message), "import") ||
			strings.Contains(strings.ToLower(d.Code), "import") {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected a diagnostic mentioning 'import', got: %+v", rep.Diagnostics)
	}
}

// TestSandboxedImportRelativeNoFileRead checks the same property for a relative
// import path — the most common attacker form when the process CWD is interesting.
func TestSandboxedImportRelativeNoFileRead(t *testing.T) {
	dir := t.TempDir()
	secret := "RELATIVE_SECRET_uvw456"
	if err := os.WriteFile(filepath.Join(dir, "frag.cadish"), []byte("# "+secret+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	src := []byte("example.com {\n  import frag.cadish\n  cache_key host\n}\n")
	// Use a filename whose Dir() would be dir, so a relative import would expand there.
	rep, err := CheckSourceSandboxed(filepath.Join(dir, "Cadishfile"), src)
	if err != nil {
		t.Fatalf("CheckSourceSandboxed: %v", err)
	}

	b, _ := json.Marshal(rep)
	if strings.Contains(string(b), secret) {
		t.Errorf("sandboxed analysis leaked relative-import secret:\n%s", string(b))
	}

	// Still must produce an import-related diagnostic.
	found := false
	for _, d := range rep.Diagnostics {
		if strings.Contains(strings.ToLower(d.Message), "import") ||
			strings.Contains(strings.ToLower(d.Code), "import") {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected an import diagnostic in sandboxed mode, got: %+v", rep.Diagnostics)
	}
}

// TestSandboxedGeoMaxmindNoFileProbe verifies that a `geo { source maxmind PATH }`
// in sandbox mode does NOT stat/open the path. We point the path at a nonexistent
// location and at a real readable file; in both cases the sandboxed analysis must
// succeed without returning an invalid-geo-source error (i.e. it never opened or
// probed the path), and must not leak path contents.
func TestSandboxedGeoMaxmindNoFileProbe(t *testing.T) {
	dir := t.TempDir()

	for _, tc := range []struct {
		name string
		path string
	}{
		{"nonexistent", "/nonexistent/path/to/geo.mmdb"},
		{"real-file-as-mmdb", filepath.Join(dir, "fake.mmdb")},
	} {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			if tc.name == "real-file-as-mmdb" {
				secret := "GEO_SECRET_def789"
				if err := os.WriteFile(tc.path, []byte(secret), 0o644); err != nil {
					t.Fatal(err)
				}
				src := []byte("example.com {\n  geo { source maxmind " + tc.path + " }\n  cache_key {geo}\n}\n")
				rep, err := CheckSourceSandboxed("Cadishfile", src)
				if err != nil {
					t.Fatalf("CheckSourceSandboxed: %v", err)
				}
				b, _ := json.Marshal(rep)
				if strings.Contains(string(b), secret) {
					t.Errorf("sandboxed analysis leaked geo file content: %s", string(b))
				}
				// Must NOT emit invalid-geo-source (that code requires a file probe).
				for _, d := range rep.Diagnostics {
					if d.Code == "invalid-geo-source" {
						t.Errorf("sandbox emitted invalid-geo-source (requires file probe): %+v", d)
					}
				}
				for _, s := range rep.Sites {
					for _, d := range s.Diagnostics {
						if d.Code == "invalid-geo-source" {
							t.Errorf("sandbox emitted invalid-geo-source in site diag: %+v", d)
						}
					}
				}
			} else {
				src := []byte("example.com {\n  geo { source maxmind " + tc.path + " }\n  cache_key {geo}\n}\n")
				rep, err := CheckSourceSandboxed("Cadishfile", src)
				if err != nil {
					t.Fatalf("CheckSourceSandboxed: %v", err)
				}
				// Must NOT emit invalid-geo-source for nonexistent path either
				// (doing so would confirm the file was probed).
				for _, d := range rep.Diagnostics {
					if d.Code == "invalid-geo-source" {
						t.Errorf("sandbox emitted invalid-geo-source for nonexistent path (requires file probe): %+v", d)
					}
				}
				for _, s := range rep.Sites {
					for _, d := range s.Diagnostics {
						if d.Code == "invalid-geo-source" {
							t.Errorf("sandbox emitted invalid-geo-source in site diag: %+v", d)
						}
					}
				}
			}
		})
	}
}

// TestSandboxedPreservesOtherDiagnostics verifies that the sandboxed path still
// produces all non-filesystem diagnostics (e.g. unknown-directive, arity errors).
func TestSandboxedPreservesOtherDiagnostics(t *testing.T) {
	src := []byte(`example.com {
    @weird unknown_type foo
    not_a_real_directive
    cache_key
}`)
	rep, err := CheckSourceSandboxed("Cadishfile", src)
	if err != nil {
		t.Fatalf("CheckSourceSandboxed: %v", err)
	}
	c := codes(rep)
	if c["unknown-matcher-type"] == 0 {
		t.Errorf("expected unknown-matcher-type diagnostic")
	}
	if c["unknown-directive"] == 0 {
		t.Errorf("expected unknown-directive diagnostic")
	}
	if c["cache-key-empty"] == 0 {
		t.Errorf("expected cache-key-empty diagnostic (cache_key with no tokens)")
	}
}

// TestOnDiskImportResolutionUnchanged verifies the existing Check() and
// CheckSource() paths STILL resolve imports from disk — the sandbox must not
// affect them. This is a regression guard for the original on-disk behaviour.
func TestOnDiskImportResolutionUnchanged(t *testing.T) {
	// Reuse the existing testdata/import_main.cadish fixture which imports
	// testdata/import_frag.cadish on disk — this exercises the non-sandboxed path.
	r, err := Check(td("import_main.cadish"))
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if errs, _ := r.Counts(); errs != 0 {
		t.Fatalf("on-disk Check produced unexpected errors:\n%s", render(t, r))
	}
	s := firstSite(t, r)
	if s.MatcherCount != 2 {
		t.Errorf("MatcherCount = %d, want 2 (local + imported fragment)", s.MatcherCount)
	}
}
