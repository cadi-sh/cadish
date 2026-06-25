package ingress

// These helpers — TLSPlan, HostPolicyUnion, SecretRef — project per-Ingress spec.tls
// into the cadish TLS model. They ARE wired into the controller's reconcile loop (D61):
// TLSPlan splits each host into a BYO Secret cert (served via Server.SetDynamicCerts) or
// an ACME-issued host (a generated `tls acme` directive), and HostPolicyUnion bounds the
// ACME issuer to watched hosts. See docs/ingress-controller.md.

import (
	"crypto/x509"
	"fmt"
	"sort"
	"strings"

	networkingv1 "k8s.io/api/networking/v1"
)

// SecretRef is one TLS Secret to load as a bring-your-own / cert-manager certificate,
// with the hosts it terminates.
type SecretRef struct {
	Namespace string
	Name      string
	Hosts     []string
}

// certCoversHost reports whether a parsed leaf certificate's SANs (DNSNames, honoring
// "*.suffix" wildcards) cover host. It is the per-host coverage check the TLS projection
// uses to avoid registering a BYO cert for a host the cert does NOT actually certify
// (F10: a multi-host spec.tls Secret whose cert only covers some of the listed hosts —
// serving it for the others is a silent SAN mismatch). x509.Certificate.VerifyHostname
// implements exactly this matching (including single-label wildcards), so we reuse it.
func certCoversHost(leaf *x509.Certificate, host string) bool {
	if leaf == nil {
		return false
	}
	return leaf.VerifyHostname(normHost(host)) == nil
}

// TLSPlan projects every Ingress's spec.tls[] into the cadish TLS model
// (Secrets-if-present-else-ACME, design §19):
//
//   - a spec.tls[] entry whose Secret EXISTS (secretExists reports true) becomes a
//     SecretRef — cadish serves that BYO/cert-manager certificate directly;
//   - a spec.tls[] entry whose Secret is MISSING contributes its hosts to acmeHosts —
//     cadish auto-provisions them via ACME.
//
// The returned acmeHosts is the ACME HostPolicy allow-set (deduplicated, sorted): it is
// NEVER an open issuer — only hosts explicitly named in a watched Ingress's TLS block
// are eligible. secretExists is the controller's Secret-lister membership check (it is
// injected so the projection is pure and unit-testable).
//
// TLS host ownership is ALIGNED TO ROUTING (FIX 2, confused-deputy guard): a host's
// routing is owned by the OLDEST Ingress that declares a rule for it (first-claim /
// oldest-wins, matching the translator's merge). A spec.tls host may only contribute a
// BYO cert (or an ACME host) from the SAME namespace that owns the host's routing —
// otherwise a tenant in namespace A could register a cert for a host that namespace B
// routes (cross-namespace cert hijack). Cross-namespace entries are returned as rejects
// (surfaced as Events) and never registered. First-claim also wins on dynamic-cert
// collisions within the owner namespace: a host is claimed by exactly one BYO secret —
// the one on the oldest Ingress — so the served cert is deterministic, never sort-order
// or last-writer dependent.
//
// Spec.TLS-only hosts (hosts with no routing rule) are also subject to cross-namespace
// ownership (FIX B): routingHostOwners seeds ownership from TLS entries too, so a host
// that appears only in spec.tls gets a namespace owner and the existing guard below
// rejects a different namespace's later claim.
// certCovers, when non-nil, reports whether the Secret ns/name's certificate SANs
// actually cover host (F10). A BYO host the cert does NOT cover is NOT registered with the
// wrong cert: it is surfaced as a mismatch Reject (warning Event) and falls through to
// ACME like a Secret-less host. A nil certCovers disables the check (coverage assumed) —
// used by older unit tests that only exercise existence/ownership.
func TLSPlan(ingresses []*networkingv1.Ingress, secretExists func(ns, name string) bool, certCovers func(ns, name, host string) bool) (acmeHosts []string, secretRefs []SecretRef, rejects []Reject) {
	owner := routingHostOwners(ingresses)

	// Process Ingresses oldest-first so the first-claim (oldest) BYO secret wins a host.
	ings := make([]*networkingv1.Ingress, 0, len(ingresses))
	for _, ing := range ingresses {
		if ing != nil {
			ings = append(ings, ing)
		}
	}
	sortIngresses(ings)

	acmeSet := map[string]struct{}{}
	// Deduplicate BYO refs by (namespace, name), unioning their hosts.
	type refKey struct{ ns, name string }
	byRef := map[refKey]map[string]struct{}{}
	var refOrder []refKey
	byoClaimed := map[string]string{} // host → "ns/name" of the Ingress that claimed its BYO cert

	for _, ing := range ings {
		for _, tlsEntry := range ing.Spec.TLS {
			byo := tlsEntry.SecretName != "" && secretExists(ing.Namespace, tlsEntry.SecretName)
			for _, h := range tlsEntry.Hosts {
				hn := normHost(h)
				if hn == "" {
					continue
				}
				// Ownership: a host whose routing is owned by ANOTHER namespace must not
				// take a cert (BYO or ACME) from this Ingress's namespace.
				if ownNs, ok := owner[hn]; ok && ownNs != ing.Namespace {
					rejects = append(rejects, Reject{
						Ingress: key(ing),
						Reason: fmt.Sprintf("spec.tls host %q is owned by namespace %q's routing; a TLS cert for it may only come from that namespace (cross-namespace cert hijack rejected)",
							hn, ownNs),
					})
					continue
				}
				if byo {
					// F10 SAN guard: the Secret EXISTS and parses, but its certificate must
					// actually cover this host. A multi-host spec.tls entry can list a host the
					// cert does NOT certify (SAN mismatch); serving the cert for it completes the
					// handshake with the WRONG cert (silent hostname mismatch at the client). So
					// register the BYO cert ONLY for covered hosts; an uncovered host is reported
					// (warning Event) and falls through to ACME like a Secret-less host.
					if certCovers != nil && !certCovers(ing.Namespace, tlsEntry.SecretName, hn) {
						rejects = append(rejects, Reject{
							Ingress: key(ing),
							Reason: fmt.Sprintf("spec.tls host %q is NOT in the SANs of Secret %s/%s's certificate; refusing to serve a mismatched cert for it (falling back to ACME issuance)",
								hn, ing.Namespace, tlsEntry.SecretName),
						})
						if _, claimed := byoClaimed[hn]; !claimed {
							acmeSet[hn] = struct{}{}
						}
						continue
					}
					// First-claim wins: a host is bound to exactly one BYO secret (oldest).
					if first, claimed := byoClaimed[hn]; claimed {
						if first != key(ing) {
							// A later Ingress in the owner namespace re-references the host;
							// keep the first claim. Not an error worth an Event (same tenant).
							continue
						}
					} else {
						byoClaimed[hn] = key(ing)
					}
					k := refKey{ns: ing.Namespace, name: tlsEntry.SecretName}
					set, ok := byRef[k]
					if !ok {
						set = map[string]struct{}{}
						byRef[k] = set
						refOrder = append(refOrder, k)
					}
					set[hn] = struct{}{}
					continue
				}
				// Secret missing (or unnamed) → ACME for this host (unless already BYO).
				if _, claimed := byoClaimed[hn]; !claimed {
					acmeSet[hn] = struct{}{}
				}
			}
		}
	}

	acmeHosts = sortedKeys(acmeSet)
	// Stable ref order: by namespace then name.
	sort.Slice(refOrder, func(i, j int) bool {
		if refOrder[i].ns != refOrder[j].ns {
			return refOrder[i].ns < refOrder[j].ns
		}
		return refOrder[i].name < refOrder[j].name
	})
	for _, k := range refOrder {
		secretRefs = append(secretRefs, SecretRef{Namespace: k.ns, Name: k.name, Hosts: sortedKeys(byRef[k])})
	}
	return acmeHosts, secretRefs, rejects
}

// routingHostOwners maps each host to the namespace of the OLDEST Ingress that
// declares it — either via a routing rule (spec.rules[].host) or a TLS entry
// (spec.tls[].hosts). Rule hosts are seeded first (they carry routing state), then
// TLS-only hosts (hosts that appear in spec.tls but have no matching rule anywhere in
// the ingress set). Both use the same oldest-wins / first-claim semantics so that:
//
//   - A host with a routing rule is owned by the namespace of the oldest rule (same as
//     the translator's merge), and its TLS cert must come from that namespace.
//   - A host that is TLS-only (SNI-only, no route) is owned by the namespace of the
//     oldest TLS claim, preventing a later namespace from registering a cert for a
//     hostname the first namespace has already declared. (FIX B: closes the gap where
//     a spec.tls-only host had no owner, so the cross-namespace guard was silently
//     skipped and any namespace could claim a cert for it oldest-claim / no namespace
//     constraint.)
//
// Within the same namespace oldest-wins is fine (consistent with prior behaviour).
func routingHostOwners(ingresses []*networkingv1.Ingress) map[string]string {
	ings := make([]*networkingv1.Ingress, 0, len(ingresses))
	for _, ing := range ingresses {
		if ing != nil {
			ings = append(ings, ing)
		}
	}
	sortIngresses(ings) // oldest-first, then ns/name (same order Translate uses)
	owner := map[string]string{}
	var wildcardOrder []string // literal "*.suffix" hosts in oldest-claim (first-claim) order
	// Pass 1: rule hosts (higher priority — routing ownership takes precedence).
	for _, ing := range ings {
		for _, rule := range ing.Spec.Rules {
			if h := normHost(rule.Host); h != "" {
				if _, ok := owner[h]; !ok {
					owner[h] = ing.Namespace
					if strings.HasPrefix(h, "*.") {
						wildcardOrder = append(wildcardOrder, h)
					}
				}
			}
		}
	}
	// Pass 2: TLS-only hosts — hosts that appear in spec.tls but have no routing rule
	// anywhere in the ingress set. If pass 1 already established an owner for a host,
	// that owner stands (rule ownership wins). Otherwise the oldest TLS claim wins.
	for _, ing := range ings {
		for _, tlsEntry := range ing.Spec.TLS {
			for _, h := range tlsEntry.Hosts {
				if h = normHost(h); h != "" {
					if _, ok := owner[h]; !ok {
						owner[h] = ing.Namespace
						if strings.HasPrefix(h, "*.") {
							wildcardOrder = append(wildcardOrder, h)
						}
					}
				}
			}
		}
	}
	// Pass 3 (wildcard subdomain ownership, Fix 2 — mirrors the Gateway controller's
	// wildcardListenerOwner guard): a CONCRETE host (e.g. app.example.com) that a YOUNGER
	// Ingress in a DIFFERENT namespace claimed exactly is REASSIGNED to the namespace of
	// the OLDEST `*.suffix` wildcard that covers it. Without this a hostile namespace could
	// register an exact Ingress for a subdomain of another namespace's wildcard — which
	// wins at serving time (exact-before-wildcard) — and steal/blackhole the subdomain and
	// its cert slot. A SAME-namespace exact-under-own-wildcard is left untouched (a
	// namespace owns the concrete subdomains of its own wildcard). The OLDEST wildcard wins
	// (wildcardOrder is first-claim order), keeping routing and TLS ownership in agreement.
	if len(wildcardOrder) > 0 {
		for h, ns := range owner {
			if strings.HasPrefix(h, "*.") {
				continue // a wildcard host itself is owned by its own first claim
			}
			if wns, ok := wildcardHostOwner(h, wildcardOrder, owner); ok && wns != ns {
				owner[h] = wns
			}
		}
	}
	return owner
}

// wildcardHostOwner returns the namespace of the OLDEST `*.suffix` wildcard that covers
// the concrete host, mirroring the Gateway controller's wildcardListenerOwner. order is
// the literal wildcard hosts in first-claim (oldest) order; owner maps each to its ns.
func wildcardHostOwner(host string, order []string, owner map[string]string) (string, bool) {
	for _, w := range order {
		suffix := w[1:] // ".example.com" (w is "*.example.com")
		if strings.HasSuffix(host, suffix) && len(host) > len(suffix) {
			return owner[w], true
		}
	}
	return "", false
}

// HostPolicyUnion is the full set of hostnames cadish is willing to terminate TLS for:
// every host named in any watched Ingress's TLS block (BYO and ACME alike), plus every
// rule host. It bounds the ACME issuer to known hosts (never open). Deduplicated and
// sorted.
func HostPolicyUnion(ingresses []*networkingv1.Ingress) []string {
	set := map[string]struct{}{}
	for _, ing := range ingresses {
		if ing == nil {
			continue
		}
		for _, tls := range ing.Spec.TLS {
			for _, h := range tls.Hosts {
				if h = normHost(h); h != "" {
					set[h] = struct{}{}
				}
			}
		}
		for _, rule := range ing.Spec.Rules {
			if h := normHost(rule.Host); h != "" {
				set[h] = struct{}{}
			}
		}
	}
	return sortedKeys(set)
}

func normHost(h string) string { return strings.ToLower(strings.TrimSpace(h)) }

func sortedKeys(m map[string]struct{}) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
