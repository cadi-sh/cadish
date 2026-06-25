package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/cadi-sh/cadish/internal/config"
)

// writeNamedCadishfile writes src into a fresh temp dir under the given name
// and returns the full path. The temp dir is cleaned up by t. A named file (vs
// the shared writeCadishfile helper) lets the self-import test reference its own
// filename.
func writeNamedCadishfile(t *testing.T, name, src string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(src), 0o644); err != nil {
		t.Fatalf("write %s: %v", name, err)
	}
	return path
}

// TestCheckRunParity is the core invariant of `cadish check`: a config that
// config.Load (the `cadish run` build) REJECTS must ALSO be rejected by
// `cadish check` (non-zero exit), and a config check ACCEPTS must load. This
// closes the divergence where `check` passed configs that `run` then refused
// to start.
//
// Each row is a self-contained Cadishfile. wantLoadErr says whether
// config.Load rejects it; the test then asserts runCheck's exit code agrees
// (non-zero exactly when config.Load fails at build time).
func TestCheckRunParity(t *testing.T) {
	cases := []struct {
		name        string
		file        string
		src         string
		wantLoadErr bool // config.Load (run) rejects it at build time
	}{
		{
			name: "cache_without_upstream",
			file: "c.cadish",
			src: `example.com {
    cache { ram 10MiB }
}`,
			wantLoadErr: true, // "site has no upstream to fetch from"
		},
		{
			name: "chain_undeclared_upstream",
			file: "c.cadish",
			src: `example.com {
    upstream a { to http://127.0.0.1:9000 }
    origin chain a -> ghost
}`,
			wantLoadErr: true, // "origin chain references undeclared upstream"
		},
		{
			name: "duplicate_upstream",
			file: "c.cadish",
			src: `example.com {
    upstream b { to http://127.0.0.1:9000 }
    upstream b { to http://127.0.0.1:9001 }
}`,
			wantLoadErr: true, // "duplicate upstream"
		},
		{
			name: "sticky_without_cookie_name",
			file: "c.cadish",
			src: `example.com {
    upstream a {
        to http://127.0.0.1:9000
        to http://127.0.0.1:9001
        sticky by cookie else client_ip
    }
}`,
			wantLoadErr: true, // "sticky: expected else, got ..."
		},
		{
			name: "valid_minimal",
			file: "c.cadish",
			src: `example.com {
    upstream a { to http://127.0.0.1:9000 }
    cache { ram 10MiB }
}`,
			wantLoadErr: false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path := writeNamedCadishfile(t, tc.file, tc.src)

			_, loadErr := config.Load(path)
			if (loadErr != nil) != tc.wantLoadErr {
				t.Fatalf("config.Load err=%v, wantLoadErr=%v", loadErr, tc.wantLoadErr)
			}

			var out, errOut bytes.Buffer
			code := runCheck(path, false, false, &out, &errOut)

			if tc.wantLoadErr {
				if code == 0 {
					t.Fatalf("DIVERGENCE: config.Load rejected the config but `check` passed (exit 0).\nLoad err: %v\ncheck out:\n%s", loadErr, out.String())
				}
			} else {
				if code != 0 {
					t.Fatalf("config.Load accepted the config but `check` failed (exit %d).\ncheck out:\n%s\ncheck err:\n%s", code, out.String(), errOut.String())
				}
			}
		})
	}
}

// TestCheckRunParitySelfImport is the reverse divergence (F2): a top-level
// self-referential `import` must produce the SAME verdict from `cadish check`
// and `cadish run` (config.Load). config.Load treats a top-level import as a
// no-op and starts fine, so `check` must not hard-fail it.
func TestCheckRunParitySelfImport(t *testing.T) {
	src := `import self.cadish
example.com {
    upstream a { to http://127.0.0.1:9000 }
    cache { ram 10MiB }
}`
	path := writeNamedCadishfile(t, "self.cadish", src)

	if _, err := config.Load(path); err != nil {
		t.Fatalf("config.Load (run) rejected self-import, but run accepts it: %v", err)
	}

	var out, errOut bytes.Buffer
	code := runCheck(path, false, false, &out, &errOut)
	if code != 0 {
		t.Fatalf("DIVERGENCE (F2): config.Load accepts a top-level self-import but `check` exit=%d.\ncheck out:\n%s\ncheck err:\n%s", code, out.String(), errOut.String())
	}
}
