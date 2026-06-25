package ingress

// Per-namespace ACME domain allow-list (A2, hostile-multi-tenant hardening).
//
// The ACME issuer is already bounded to the watched-host union (TLSPlan never opens it),
// but ANY watched host is eligible — a tenant could trigger issuance for a domain it
// should not own. This adds an OPERATOR-CURATED, OFF-BY-DEFAULT allow-list that maps a
// namespace to the domain suffixes it is permitted to auto-issue certificates for. When
// the policy is unset (nil/empty), behaviour is UNCHANGED: every watched ACME host is
// eligible (the single-trust-domain default). When set, a host whose OWNING namespace is
// not permitted that domain is excluded from the ACME HostPolicy and surfaced as an Event.
//
// Ownership of a host is the SAME first-claim ownership routing and TLS use
// (routingHostOwners), so the allow-list is evaluated against the namespace that actually
// owns the host — consistent with A1 and D64.

import (
	"fmt"
	"sort"
	"strings"
)

// ACMEDomainPolicy maps a namespace to the domain suffixes it is permitted to auto-issue
// ACME certificates for. A nil or empty map disables the allow-list (all watched hosts
// eligible). The suffixes are matched at a label boundary (apex or subdomain); a bare
// "*.suffix" entry is normalised to "suffix" (suffix matching already covers subdomains).
type ACMEDomainPolicy map[string][]string

// Allowed reports whether namespace ns is permitted to auto-issue a certificate for host.
// A nil/empty policy permits everything (off). Otherwise ns must have an entry and host
// must fall under one of its permitted suffixes (apex or any subdomain).
func (p ACMEDomainPolicy) Allowed(ns, host string) bool {
	if len(p) == 0 {
		return true // allow-list disabled
	}
	host = normHost(host)
	for _, suffix := range p[ns] {
		if hostUnderSuffix(host, suffix) {
			return true
		}
	}
	return false
}

// hostUnderSuffix reports whether host is suffix itself (apex) or a subdomain of it
// (label-boundary match), so "example.com" matches "example.com" and "www.example.com"
// but NOT "notexample.com".
func hostUnderSuffix(host, suffix string) bool {
	suffix = strings.TrimPrefix(normHost(suffix), "*.")
	if suffix == "" {
		return false
	}
	if host == suffix {
		return true
	}
	return strings.HasSuffix(host, "."+suffix)
}

// FilterACMEDomains splits acmeHosts into the hosts that are PERMITTED for ACME issuance
// (kept) and a Reject for each host whose OWNER namespace is not allowed its domain by the
// policy. owner maps host → owning namespace (routingHostOwners). A nil/empty policy keeps
// every host (off-by-default — unchanged single-trust-domain behaviour). A host with no
// known owner is kept (it cannot be attributed to a namespace, so the allow-list cannot
// apply — it stays bounded by the watched-host union as before). kept preserves input
// order; rejects are sorted for deterministic Events.
func FilterACMEDomains(acmeHosts []string, owner map[string]string, policy ACMEDomainPolicy) (kept []string, rejects []Reject) {
	if len(policy) == 0 {
		return acmeHosts, nil
	}
	for _, h := range acmeHosts {
		ns, ok := owner[normHost(h)]
		if !ok {
			kept = append(kept, h) // unattributed → cannot apply the per-namespace rule
			continue
		}
		if policy.Allowed(ns, h) {
			kept = append(kept, h)
			continue
		}
		rejects = append(rejects, Reject{
			Ingress: ns + "/", // owner namespace; no single Ingress attributable
			Reason: fmt.Sprintf("ACME issuance for host %q is not permitted: namespace %q is not in the ACME domain allow-list for that domain (per-namespace ACME allow-list)",
				normHost(h), ns),
		})
	}
	sort.Slice(rejects, func(i, j int) bool { return rejects[i].Reason < rejects[j].Reason })
	return kept, rejects
}

// ParseACMEDomainPolicy parses the operator-curated allow-list flag value into an
// ACMEDomainPolicy. The format is a ';'-separated list of "namespace=suffix[,suffix…]"
// entries, e.g. "team-a=team-a.example.com,*.svc.example.com ; team-b=team-b.example.com".
// An empty spec yields a nil policy (OFF — the default). A malformed entry (no '=' or an
// empty namespace) is a configuration error.
func ParseACMEDomainPolicy(spec string) (ACMEDomainPolicy, error) {
	spec = strings.TrimSpace(spec)
	if spec == "" {
		return nil, nil // off by default
	}
	out := ACMEDomainPolicy{}
	for _, entry := range strings.Split(spec, ";") {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		eq := strings.IndexByte(entry, '=')
		if eq < 0 {
			return nil, fmt.Errorf("acme domain policy entry %q is missing '=' (expected namespace=suffix[,suffix])", entry)
		}
		ns := strings.TrimSpace(entry[:eq])
		if ns == "" {
			return nil, fmt.Errorf("acme domain policy entry %q has an empty namespace", entry)
		}
		var suffixes []string
		for _, s := range strings.Split(entry[eq+1:], ",") {
			if s = normHost(s); s != "" {
				suffixes = append(suffixes, strings.TrimPrefix(s, "*."))
			}
		}
		if len(suffixes) == 0 {
			return nil, fmt.Errorf("acme domain policy entry for namespace %q has no domain suffixes", ns)
		}
		out[ns] = append(out[ns], suffixes...)
	}
	if len(out) == 0 {
		return nil, nil
	}
	return out, nil
}
