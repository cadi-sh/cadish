package config

import (
	"strings"
	"testing"
)

// TestSandboxDoesNotLeakEnv is the security regression for env-var exfiltration via the admin
// /api/validate sandbox: a structural validator echoes its (resolved) argument into the error
// message, so the SANDBOX path must NOT resolve {$VAR} against the real environment — otherwise
// a token-authed caller reads any env var (S3 secret_key, auth_token, signing keys) one per
// request. The CLI (non-sandbox) path still substitutes the real env.
func TestSandboxDoesNotLeakEnv(t *testing.T) {
	const secret = "TOPSECRET-AKIA-DEADBEEF"
	t.Setenv("ZZ_ENVLEAK_SECRET", secret)
	src := "site {\n upstream web { to http://h:80 }\n cache { ram {$ZZ_ENVLEAK_SECRET} }\n}\n"

	// SANDBOX: the error must NOT contain the resolved secret (placeholder → empty).
	if err := ValidateStructureSandboxed("Cadishfile", src); err == nil {
		t.Fatal("expected a structural size error")
	} else if strings.Contains(err.Error(), secret) {
		t.Fatalf("ENV LEAK: sandbox error echoed the resolved secret: %v", err)
	} else if strings.Contains(err.Error(), "TOPSECRET") {
		t.Fatalf("ENV LEAK: sandbox error carries the secret: %v", err)
	}

	// CLI (non-sandbox) path DOES substitute the real env (operator already has it). The
	// resolved value reaches the size validator — confirming the sandbox flag is what gates it,
	// not a blanket removal of substitution.
	if err := ValidateStructure("Cadishfile", src, "."); err == nil {
		t.Fatal("expected a structural size error on the CLI path too")
	} else if !strings.Contains(err.Error(), secret) {
		t.Errorf("CLI path should resolve {$VAR} to the real env value, got: %v", err)
	}
}
