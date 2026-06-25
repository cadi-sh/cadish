package ingress

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// Artifact-level guards for the two staging deploy bugs (audit 2026-06-24). The
// envtest e2e constructs the controller programmatically with a cluster-admin client,
// so it cannot catch a manifest flag-form bug or a missing RBAC verb. These pure-text
// assertions over the shipped manifests can — and belong in the green gate.

func readDeploy(t *testing.T, rel string) string {
	t.Helper()
	// Tests run with CWD = package dir (internal/ingress); deploy/ is two levels up.
	b, err := os.ReadFile(filepath.Join("..", "..", "deploy", rel))
	if err != nil {
		t.Fatalf("read %s: %v", rel, err)
	}
	return string(b)
}

// TestLeaderElectFlagFormInManifests: `-leader-elect` must be passed as a SINGLE
// `-leader-elect=<bool>` token. The two-token form (`-leader-elect` then `"true"`)
// makes Go's flag.Parse stop at the positional and silently drop every later flag —
// the staging bug that sent the lease to the wrong namespace. Flag any known bool flag
// followed by a separate value token.
func TestLeaderElectFlagFormInManifests(t *testing.T) {
	files := []string{"k8s/ingress-controller.yaml"}
	// Bare bool flags that must never be followed by a separate value list item.
	boolFlag := regexp.MustCompile(`(?m)^\s*-\s*-leader-elect\s*$`)
	for _, f := range files {
		src := readDeploy(t, f)
		if boolFlag.MatchString(src) {
			t.Errorf("%s: `-leader-elect` appears as a bare arg (two-token form) — use `-leader-elect=<bool>` so flag.Parse does not drop later flags", f)
		}
		if !strings.Contains(src, "-leader-elect=") {
			t.Errorf("%s: expected a `-leader-elect=<bool>` token", f)
		}
	}
}

// TestControllerRBACGrantsServices: the status writer reads the publish Service to
// resolve the advertised address; without `services` get the GET is RBAC-forbidden and
// status.loadBalancer never populates (the second staging bug). The controller
// ClusterRole MUST grant services get.
func TestControllerRBACGrantsServices(t *testing.T) {
	src := readDeploy(t, "k8s/rbac-controller.yaml")
	// crude but sufficient: the controller ClusterRole must mention a services resource
	// with a get verb. Assert both tokens are present (the file is small + single-role).
	if !strings.Contains(src, "services") {
		t.Error("rbac-controller.yaml: controller ClusterRole does not grant `services` (status writer cannot read the publish Service)")
	}
	if !regexp.MustCompile(`(?s)services.*?get|get.*?services`).MatchString(src) {
		t.Error("rbac-controller.yaml: `services` is present but without a `get` verb")
	}
}

// TestScopedRBACManifestOmitsClusterWideSecretReads: the C1 scoped alternative
// (rbac-controller-scoped.yaml) must NOT grant cluster-wide secrets/configmaps in its
// ClusterRole (that is the whole point — those reads move to per-namespace Roles). It must
// still carry the per-namespace read Role (`cadish-ingress-reads`).
func TestScopedRBACManifestOmitsClusterWideSecretReads(t *testing.T) {
	src := readDeploy(t, "k8s/rbac-controller-scoped.yaml")
	// Isolate the ClusterRole document (between `kind: ClusterRole` and the next `---`).
	clusterRole := regexp.MustCompile(`(?s)kind: ClusterRole\b.*?\n---`).FindString(src)
	if clusterRole == "" {
		t.Fatal("rbac-controller-scoped.yaml: no ClusterRole document found")
	}
	// Strip comment lines so a NOTE mentioning "secrets"/"configmaps" is not a false hit;
	// the assertion targets the actual `resources:` rule.
	var ruleLines []string
	for _, ln := range strings.Split(clusterRole, "\n") {
		if !strings.HasPrefix(strings.TrimSpace(ln), "#") {
			ruleLines = append(ruleLines, ln)
		}
	}
	rules := strings.Join(ruleLines, "\n")
	if regexp.MustCompile(`resources:.*\b(secrets|configmaps)\b`).MatchString(rules) {
		t.Error("rbac-controller-scoped.yaml: ClusterRole must NOT grant cluster-wide secrets/configmaps (that defeats the scoped variant)")
	}
	if !strings.Contains(src, "cadish-ingress-reads") {
		t.Error("rbac-controller-scoped.yaml: missing the per-namespace `cadish-ingress-reads` read Role")
	}
	// The per-namespace read Role must still grant secrets+configmaps reads somewhere.
	if !regexp.MustCompile(`(?s)cadish-ingress-reads.*?secrets.*?configmaps|secrets.*?configmaps.*?cadish-ingress-reads`).MatchString(src) {
		t.Error("rbac-controller-scoped.yaml: per-namespace read Role does not grant secrets+configmaps")
	}
}
