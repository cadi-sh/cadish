package gateway

import (
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
)

// TestGrantFromGroupMustMatch pins Fix #10: a ReferenceGrant's From.Group is matched
// per spec. An HTTPRoute / Gateway lives in the Gateway-API group
// (gateway.networking.k8s.io), so a From entry must name that group. An empty
// From.Group means the CORE group ("") — which does NOT contain HTTPRoute/Gateway — so
// it must NOT admit a cross-namespace HTTPRoute reference. Only the explicit
// Gateway-API group admits it.
func TestGrantFromGroupMustMatch(t *testing.T) {
	mk := func(group gatewayv1.Group) *gatewayv1.ReferenceGrant {
		return &gatewayv1.ReferenceGrant{
			ObjectMeta: metav1.ObjectMeta{Namespace: "team-b", Name: "g"},
			Spec: gatewayv1.ReferenceGrantSpec{
				From: []gatewayv1.ReferenceGrantFrom{{Group: group, Kind: "HTTPRoute", Namespace: "team-a"}},
				To:   []gatewayv1.ReferenceGrantTo{{Group: "", Kind: "Service"}},
			},
		}
	}

	// Explicit Gateway-API group: admitted.
	if !grantFromAdmits(mk(gatewayv1.GroupName), "team-a", "HTTPRoute") {
		t.Errorf("explicit gateway-api From.Group should admit HTTPRoute")
	}
	// Empty group (= core group): must NOT admit an HTTPRoute (it lives in the
	// gateway-api group, not core).
	if grantFromAdmits(mk(""), "team-a", "HTTPRoute") {
		t.Errorf("empty From.Group (core group) must NOT admit an HTTPRoute; spec wants an explicit gateway-api group match")
	}
	// A wrong group: not admitted.
	if grantFromAdmits(mk("example.com"), "team-a", "HTTPRoute") {
		t.Errorf("a foreign From.Group must not admit an HTTPRoute")
	}
}
