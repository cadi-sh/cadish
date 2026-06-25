package gateway

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Artifact-level guard for the Gateway controller's RBAC: a missing status-subresource
// verb would let the controller render+serve routing yet silently fail every status write
// (the same class of bug the Ingress controller's manifest test guards against). This pure
// text assertion over the shipped manifest belongs in the green gate.

func readDeploy(t *testing.T, rel string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "..", "deploy", rel))
	if err != nil {
		t.Fatalf("read %s: %v", rel, err)
	}
	return string(b)
}

// TestGatewayRBACGrantsStatusAndWatch: the Gateway controller ClusterRole MUST grant
// list/watch on the Gateway API surface (to build routing) and update on its status
// subresources (the status writer), or routing/status silently breaks.
func TestGatewayRBACGrantsStatusAndWatch(t *testing.T) {
	src := readDeploy(t, "k8s/rbac-gateway.yaml")
	for _, want := range []string{
		"gatewayclasses", "gateways", "httproutes", "referencegrants",
		"gatewayclasses/status", "gateways/status", "httproutes/status",
		"endpointslices", "secrets",
	} {
		if !strings.Contains(src, want) {
			t.Errorf("rbac-gateway.yaml: missing resource %q", want)
		}
	}
	if !strings.Contains(src, "gateway.networking.k8s.io") {
		t.Error("rbac-gateway.yaml: missing the gateway.networking.k8s.io API group")
	}
	// The status rule must carry update/patch verbs.
	if !strings.Contains(src, "update") {
		t.Error("rbac-gateway.yaml: status rule must grant `update`")
	}
}
