package config

import (
	"testing"
	"time"
)

// A well-formed `server { … }` block populates every inbound knob.
func TestServerBlock(t *testing.T) {
	f := parseFile(t, `{
  server {
    maxconn 4096
    read_timeout 15s
    idle_timeout 90s
  }
}
example.com {
  cache_ttl default ttl 60s
}`)
	sc, err := serverConfigFromFile(f)
	if err != nil {
		t.Fatalf("serverConfigFromFile: %v", err)
	}
	if sc == nil {
		t.Fatal("expected a ServerConfig, got nil")
	}
	if sc.MaxConn != 4096 {
		t.Errorf("MaxConn = %d, want 4096", sc.MaxConn)
	}
	if sc.ReadTimeout != 15*time.Second {
		t.Errorf("ReadTimeout = %v, want 15s", sc.ReadTimeout)
	}
	if sc.IdleTimeout != 90*time.Second {
		t.Errorf("IdleTimeout = %v, want 90s", sc.IdleTimeout)
	}
}

// A partial block leaves the omitted fields zero (the server resolves zero → the
// current default const, so behaviour is unchanged for an omitted field).
func TestServerBlockPartial(t *testing.T) {
	f := parseFile(t, `{
  server {
    maxconn 100
  }
}
example.com {
  cache_ttl default ttl 60s
}`)
	sc, err := serverConfigFromFile(f)
	if err != nil {
		t.Fatalf("serverConfigFromFile: %v", err)
	}
	if sc == nil || sc.MaxConn != 100 {
		t.Fatalf("MaxConn = %+v, want 100", sc)
	}
	if sc.ReadTimeout != 0 || sc.IdleTimeout != 0 {
		t.Errorf("omitted timeouts should be zero (server applies the default const), got read=%v idle=%v", sc.ReadTimeout, sc.IdleTimeout)
	}
}

// No block -> nil (defaults apply at the server; zero cost).
func TestServerBlockAbsent(t *testing.T) {
	f := parseFile(t, `example.com {
  cache_ttl default ttl 60s
}`)
	sc, err := serverConfigFromFile(f)
	if err != nil {
		t.Fatalf("serverConfigFromFile: %v", err)
	}
	if sc != nil {
		t.Fatalf("expected nil (no block), got %+v", sc)
	}
}

// Bad values and unknown sub-directives are positioned config errors.
func TestServerBlockErrors(t *testing.T) {
	cases := []string{
		"{ server { maxconn -1 } }\nx { cache_ttl default ttl 60s }",
		"{ server { maxconn notanint } }\nx { cache_ttl default ttl 60s }",
		"{ server { read_timeout nope } }\nx { cache_ttl default ttl 60s }",
		"{ server { bogus 1 } }\nx { cache_ttl default ttl 60s }",
	}
	for _, src := range cases {
		f := parseFile(t, src)
		if _, err := serverConfigFromFile(f); err == nil {
			t.Errorf("expected error for %q, got nil", src)
		}
	}
}

// A second global `server {}` block is a positioned error (Finding 8), not a silent
// last-write-wins that would drop the first block's knobs.
func TestServerBlockDuplicateRejected(t *testing.T) {
	f := parseFile(t, `{
  server { maxconn 100 }
  server { maxconn 200 }
}
example.com {
  cache_ttl default ttl 60s
}`)
	_, err := serverConfigFromFile(f)
	if err == nil {
		t.Fatal("expected an error for a duplicate global `server` block, got nil")
	}
}

// The whole-config Load path threads the block onto Config.Server.
func TestServerBlockThreadedOntoConfig(t *testing.T) {
	cfg, err := LoadString("test", `{
  server { maxconn 64; read_timeout 5s }
}
example.com {
  upstream s { to https://example.org }
  cache_ttl default ttl 60s
}`)
	if err != nil {
		t.Fatalf("LoadString: %v", err)
	}
	defer cfg.Close()
	if cfg.Server == nil || cfg.Server.MaxConn != 64 || cfg.Server.ReadTimeout != 5*time.Second {
		t.Fatalf("Config.Server = %+v, want maxconn 64 read_timeout 5s", cfg.Server)
	}
}
