package config

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/cadi-sh/cadish/internal/lb"
	"github.com/cadi-sh/cadish/internal/origin/httporigin"
)

// TestLoadString proves a Cadishfile held in memory compiles through the same path
// as Load (the seam the ingress controller renders into).
func TestLoadString(t *testing.T) {
	src := "x.test {\n\tupstream a { to http://h:80 }\n\troute -> a\n}\n"
	cfg, err := LoadString("<generated>", src)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cfg.Close() })
	if len(cfg.Sites) != 1 {
		t.Fatalf("want 1 site, got %d", len(cfg.Sites))
	}
}

// TestUpstreamOriginSelection verifies a trivial single-backend upstream becomes a
// plain httporigin (no lb pool), while a multi-backend or sticky upstream becomes an
// lb.Upstream with its sticky spec recorded.
func TestUpstreamOriginSelection(t *testing.T) {
	dir := t.TempDir()
	cfgText := `x.com {
	cache { ram 8MiB }
	upstream solo { to http://a.internal:8080 }
	upstream pool {
		to http://b1.internal:8080
		to http://b2.internal:8080
		sticky by cookie SID
	}
	route @img -> pool
	@img path /img/*
	cache_ttl default ttl 60s
}
`
	path := filepath.Join(dir, "Cadishfile")
	if err := os.WriteFile(path, []byte(cfgText), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	defer cfg.Close()

	s := cfg.Sites[0]
	if _, ok := s.Origins["solo"].(*httporigin.Origin); !ok {
		t.Errorf("solo origin = %T, want *httporigin.Origin (trivial single backend)", s.Origins["solo"])
	}
	if _, ok := s.Origins["pool"].(*lb.Upstream); !ok {
		t.Errorf("pool origin = %T, want *lb.Upstream", s.Origins["pool"])
	}
	if s.StickySpecs["pool"] == nil {
		t.Error("pool should have a recorded sticky spec")
	}
	if s.DefaultUpstreamName != "solo" {
		t.Errorf("DefaultUpstreamName = %q, want solo (first declared)", s.DefaultUpstreamName)
	}
	if len(cfg.pools) != 1 {
		t.Errorf("cfg.pools = %d, want 1 (only the lb upstream)", len(cfg.pools))
	}
}

func TestParseSize(t *testing.T) {
	cases := []struct {
		in   string
		want int64
		ok   bool
	}{
		{"2GiB", 2 << 30, true},
		{"8GiB", 8 << 30, true},
		{"2TiB", 2 << 40, true},
		{"64MiB", 64 << 20, true},
		{"512KiB", 512 << 10, true},
		{"1000", 1000, true},
		{"1KB", 1000, true},
		{"1.5GiB", int64(1.5 * (1 << 30)), true},
		{"500B", 500, true},
		{"", 0, false},
		{"abc", 0, false},
		{"-5MiB", 0, false},
	}
	for _, c := range cases {
		got, err := ParseSize(c.in)
		if c.ok && err != nil {
			t.Errorf("ParseSize(%q) error: %v", c.in, err)
			continue
		}
		if !c.ok && err == nil {
			t.Errorf("ParseSize(%q) = %d, want error", c.in, got)
			continue
		}
		if c.ok && got != c.want {
			t.Errorf("ParseSize(%q) = %d, want %d", c.in, got, c.want)
		}
	}
}

// TestLoadMinimalExample loads the repo's example config (with a dummy origin) to
// exercise the full splice+compile+store+origin path.
func TestLoadConfig(t *testing.T) {
	dir := t.TempDir()
	cfgText := `cdn.example.com, *.cdn.example.com {
	cache {
		ram 64MiB
		disk ` + filepath.Join(dir, "cache") + ` 1GiB
		tier .ts .mp4 -> disk
		tier .m3u8 .jpg -> ram
	}
	upstream s3 { to https://s3.example.com
		bucket media }
	upstream cf { to https://cf.example.com }
	origin chain s3 -> cf
	cache_ttl default ttl 5m grace 1h
	header +cache_status X-Cache
}
`
	path := filepath.Join(dir, "Cadishfile")
	if err := os.WriteFile(path, []byte(cfgText), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	defer cfg.Close()

	if len(cfg.Sites) != 1 {
		t.Fatalf("sites = %d, want 1", len(cfg.Sites))
	}
	s := cfg.Sites[0]
	if len(s.Addresses) != 2 {
		t.Fatalf("addresses = %v", s.Addresses)
	}
	if s.Store == nil || s.Pipeline == nil {
		t.Fatal("store/pipeline nil")
	}
	if s.Origin == nil {
		t.Fatal("default origin nil (should be the chain)")
	}
	if _, ok := s.Origins["s3"]; !ok {
		t.Fatal("missing s3 origin")
	}
	if _, ok := s.Origins["cf"]; !ok {
		t.Fatal("missing cf origin")
	}
}

func TestLoadErrors(t *testing.T) {
	dir := t.TempDir()
	write := func(text string) string {
		p := filepath.Join(dir, "Cadishfile")
		if err := os.WriteFile(p, []byte(text), 0o644); err != nil {
			t.Fatal(err)
		}
		return p
	}

	// No upstream => error.
	if _, err := Load(write("x.com {\n\tcache { ram 8MiB }\n}\n")); err == nil {
		t.Error("expected error for site with no upstream")
	}

	// Bad cache size => positioned error.
	if _, err := Load(write("x.com {\n\tcache { ram notasize }\n\tupstream b { to http://o }\n}\n")); err == nil {
		t.Error("expected error for bad cache size")
	}

	// origin chain referencing an undeclared upstream.
	if _, err := Load(write("x.com {\n\tupstream a { to http://o }\n\torigin chain a -> ghost\n}\n")); err == nil {
		t.Error("expected error for chain referencing undeclared upstream")
	}
}
