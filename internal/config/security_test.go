package config

import (
	"os"
	"strings"
	"testing"

	"github.com/cadi-sh/cadish/internal/cadishfile"
)

func parseSecurity(t *testing.T, src string) (*SecurityConfig, error) {
	t.Helper()
	f, err := cadishfile.Parse("test", []byte(src))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	return securityFromFile(f)
}

// Absent `security` block => nil config (audit log off by default).
func TestSecurityAbsentIsNil(t *testing.T) {
	sc, err := parseSecurity(t, "example.com {\n  cache_key url\n}\n")
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if sc != nil {
		t.Errorf("absent security block => %+v, want nil", sc)
	}
}

// `security { audit_log <dir> }` captures the path.
func TestSecurityAuditLogPath(t *testing.T) {
	src := "{\n  security {\n    audit_log /var/log/cadish/waf\n  }\n}\nexample.com {\n  cache_key url\n}\n"
	sc, err := parseSecurity(t, src)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if sc == nil || sc.AuditLogPath != "/var/log/cadish/waf" {
		t.Errorf("AuditLogPath = %+v, want /var/log/cadish/waf", sc)
	}
}

// `security { audit_log off }` normalizes to "off" (disabled).
func TestSecurityAuditLogOff(t *testing.T) {
	src := "{\n  security {\n    audit_log off\n  }\n}\nexample.com {\n  cache_key url\n}\n"
	sc, err := parseSecurity(t, src)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if sc == nil || sc.AuditLogPath != "off" {
		t.Errorf("AuditLogPath = %+v, want off", sc)
	}
}

// An unknown directive inside `security {}` is a positioned config error.
func TestSecurityUnknownDirective(t *testing.T) {
	src := "{\n  security {\n    bogus on\n  }\n}\nexample.com {\n  cache_key url\n}\n"
	_, err := parseSecurity(t, src)
	if err == nil {
		t.Fatal("expected an error for an unknown security directive")
	}
	if !strings.Contains(err.Error(), "unknown") {
		t.Errorf("error should mention unknown; got %q", err.Error())
	}
}

// audit_log with the wrong arity is a positioned config error.
func TestSecurityAuditLogArity(t *testing.T) {
	src := "{\n  security {\n    audit_log\n  }\n}\nexample.com {\n  cache_key url\n}\n"
	_, err := parseSecurity(t, src)
	if err == nil {
		t.Fatal("expected an error for audit_log with no value")
	}
}

// security block flows through config.Load into Config.Security.
func TestLoadSecurity(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/Cadishfile"
	src := "{\n  security {\n    audit_log " + dir + "/audit\n  }\n}\nexample.com {\n  upstream u {\n    to http://127.0.0.1:9\n  }\n  cache_ttl default ttl 1m\n}\n"
	if err := os.WriteFile(path, []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	defer cfg.Close()
	if cfg.Security == nil || cfg.Security.AuditLogPath != dir+"/audit" {
		t.Errorf("Config.Security = %+v, want AuditLogPath %s/audit", cfg.Security, dir)
	}
}
