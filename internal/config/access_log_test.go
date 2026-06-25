package config

import (
	"os"
	"strings"
	"testing"

	"github.com/cadi-sh/cadish/internal/cadishfile"
)

func parseAccessLogOff(t *testing.T, src string) (bool, error) {
	t.Helper()
	f, err := cadishfile.Parse("test", []byte(src))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	return accessLogOffFromFile(f)
}

// Absent `access_log` => hub on (off=false).
func TestAccessLogAbsentIsOn(t *testing.T) {
	off, err := parseAccessLogOff(t, "example.com {\n  cache_key url\n}\n")
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if off {
		t.Error("absent access_log => off=true, want false (hub on)")
	}
}

// `access_log off` in the global block disables the hub.
func TestAccessLogOff(t *testing.T) {
	src := "{\n  access_log off\n}\nexample.com {\n  cache_key url\n}\n"
	off, err := parseAccessLogOff(t, src)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if !off {
		t.Error("`access_log off` => off=false, want true")
	}
}

// A value other than `off` is a positioned config error.
func TestAccessLogBadValue(t *testing.T) {
	src := "{\n  access_log /var/log/access.json\n}\nexample.com {\n  cache_key url\n}\n"
	_, err := parseAccessLogOff(t, src)
	if err == nil {
		t.Fatal("expected an error for a non-`off` access_log value")
	}
	if !strings.Contains(err.Error(), "off") {
		t.Errorf("error should mention `off`; got %q", err.Error())
	}
}

// access_log off flows through config.Load into Config.AccessLogOff.
func TestLoadAccessLogOff(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/Cadishfile"
	src := "{\n  access_log off\n}\nexample.com {\n  upstream u {\n    to http://127.0.0.1:9\n  }\n  cache_ttl default ttl 1m\n}\n"
	if err := os.WriteFile(path, []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	defer cfg.Close()
	if !cfg.AccessLogOff {
		t.Error("Config.AccessLogOff = false, want true")
	}
}
