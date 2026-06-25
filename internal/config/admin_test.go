package config

import (
	"strings"
	"testing"

	"github.com/cadi-sh/cadish/internal/cadishfile"
)

func parseAdmin(t *testing.T, src string) (*AdminConfig, error) {
	t.Helper()
	f, err := cadishfile.Parse("test", []byte(src))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	return adminFromFile(f)
}

func TestAdminAbsentIsNil(t *testing.T) {
	ac, err := parseAdmin(t, "example.com {\n  cache_key url\n}\n")
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if ac != nil {
		t.Fatalf("admin = %+v, want nil when no admin block", ac)
	}
}

func TestAdminFullBlock(t *testing.T) {
	src := "{\n" +
		"  admin {\n" +
		"    listen :9090\n" +
		"    auth_token s3kr3t-token\n" +
		"    metrics\n" +
		"  }\n" +
		"}\n" +
		"example.com {\n  cache_key url\n}\n"
	ac, err := parseAdmin(t, src)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if ac == nil {
		t.Fatal("admin is nil, want configured")
	}
	if ac.Listen != ":9090" {
		t.Errorf("Listen = %q, want :9090", ac.Listen)
	}
	if ac.AuthToken != "s3kr3t-token" {
		t.Errorf("AuthToken = %q, want s3kr3t-token", ac.AuthToken)
	}
	if !ac.Metrics {
		t.Errorf("Metrics = false, want true (metrics flag present)")
	}
}

func TestAdminDefaultListen(t *testing.T) {
	// listen omitted -> a sane default bind so the operator can just set a token.
	src := "{\n  admin {\n    auth_token abc\n  }\n}\nexample.com {\n  cache_key url\n}\n"
	ac, err := parseAdmin(t, src)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if ac.Listen != defaultAdminListen {
		t.Errorf("Listen = %q, want default %q", ac.Listen, defaultAdminListen)
	}
	if ac.Metrics {
		t.Errorf("Metrics defaulted true, want false unless flagged")
	}
}

func TestAdminRequiresToken(t *testing.T) {
	// An admin block with no auth_token is a hard error: an unauthenticated admin
	// surface would leak config + metrics. Refuse to start.
	src := "{\n  admin {\n    listen :9090\n  }\n}\nexample.com {\n  cache_key url\n}\n"
	_, err := parseAdmin(t, src)
	if err == nil {
		t.Fatal("expected error for admin block without auth_token")
	}
	if !strings.Contains(err.Error(), "auth_token") {
		t.Errorf("error %q does not mention auth_token", err)
	}
}

func TestAdminUnknownDirective(t *testing.T) {
	src := "{\n  admin {\n    auth_token abc\n    frobnicate yes\n  }\n}\nexample.com {\n  cache_key url\n}\n"
	_, err := parseAdmin(t, src)
	if err == nil {
		t.Fatal("expected error for unknown admin directive")
	}
	if !strings.Contains(err.Error(), "frobnicate") {
		t.Errorf("error %q does not mention the unknown directive", err)
	}
}

func TestAdminListenNeedsArg(t *testing.T) {
	src := "{\n  admin {\n    auth_token abc\n    listen\n  }\n}\nexample.com {\n  cache_key url\n}\n"
	_, err := parseAdmin(t, src)
	if err == nil {
		t.Fatal("expected error for listen with no address")
	}
}
