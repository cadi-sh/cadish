package ingress

import (
	networkingv1 "k8s.io/api/networking/v1"
)

// ControllerName is the value an IngressClass's spec.controller must carry for cadish
// to own it (the IngressClass → controller binding, design §15).
const ControllerName = "cadi.sh/ingress-controller"

// legacyClassAnnotation is the pre-IngressClass way to select a controller, still
// honored for backward compatibility.
const legacyClassAnnotation = "kubernetes.io/ingress.class"

// Matches reports whether this controller (named className) should serve ing, honoring
// the three Kubernetes selection mechanisms in precedence order (design §15):
//
//  1. spec.ingressClassName == className (the modern, authoritative field);
//  2. the legacy kubernetes.io/ingress.class annotation == className (used only when
//     spec.ingressClassName is unset);
//  3. the default-class fallback: an Ingress that sets NEITHER is served iff this
//     controller's IngressClass is marked default (isDefaultClass).
//
// A spec.ingressClassName that names a DIFFERENT class is never overridden by the
// legacy annotation or the default fallback.
func Matches(ing *networkingv1.Ingress, className string, isDefaultClass bool) bool {
	if ing == nil {
		return false
	}
	// 1. Explicit spec class wins outright (match or mismatch).
	if ing.Spec.IngressClassName != nil {
		return *ing.Spec.IngressClassName == className
	}
	// 2. Legacy annotation (only when spec class is unset).
	if v, ok := ing.Annotations[legacyClassAnnotation]; ok {
		return v == className
	}
	// 3. No class at all → ours only if we are the default IngressClass.
	return isDefaultClass
}
