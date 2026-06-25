package config

import (
	"strings"
	"testing"

	"github.com/cadi-sh/cadish/internal/cadishfile"
)

func parseStrictHost(t *testing.T, src string) (bool, error) {
	t.Helper()
	f, err := cadishfile.Parse("test", []byte(src))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	return strictHostFromFile(f)
}

// Absent `strict_host` => lenient (false), the backward-compatible default.
func TestStrictHostAbsentIsLenient(t *testing.T) {
	on, err := parseStrictHost(t, "example.com {\n  cache_key url\n}\n")
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if on {
		t.Error("absent strict_host => on=true, want false (lenient)")
	}
}

// Bare `strict_host` in the global block enables strict-host routing.
func TestStrictHostOn(t *testing.T) {
	src := "{\n  strict_host\n}\nexample.com {\n  cache_key url\n}\n"
	on, err := parseStrictHost(t, src)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if !on {
		t.Error("`strict_host` => on=false, want true")
	}
}

// `strict_host` takes no args — a value is a positioned config error.
func TestStrictHostRejectsArgs(t *testing.T) {
	src := "{\n  strict_host on\n}\nexample.com {\n  cache_key url\n}\n"
	_, err := parseStrictHost(t, src)
	if err == nil {
		t.Fatal("strict_host with an argument should be an error")
	}
	if !strings.Contains(err.Error(), "strict_host") {
		t.Errorf("error should mention strict_host; got %q", err.Error())
	}
}
