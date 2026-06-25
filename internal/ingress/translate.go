// Package ingress translates Kubernetes Ingress objects into a Cadishfile and runs
// the in-cluster controller that keeps cadish's live routing in sync with them.
//
// The translator is PURE: Translate emits Cadishfile TEXT (one site per host) and
// feeds it back through the existing internal/config compiler — it never bypasses the
// parser or teaches it Kubernetes concepts. Backends become
// `upstream … { to k8s://svc.ns:port }` (Layer 1 resolves the pods), pathTypes become
// `path` matchers, and Ingress most-specific-wins is reproduced via cadish's
// first-match-wins `route` ordering. A malformed object never panics: it is collected
// as a Reject and skipped, so one bad Ingress can never take serving down.
package ingress

import (
	"fmt"
	"sort"
	"strings"

	"github.com/cadi-sh/cadish/internal/cadishfile"
	"github.com/cadi-sh/cadish/internal/config"
	networkingv1 "k8s.io/api/networking/v1"
)

// Inputs is the snapshot the translator renders: the matched Ingress objects, the
// referenced policy fragments (keyed "ns/name"), and the controller's class name.
type Inputs struct {
	// Ingresses are the candidate Ingress objects (the controller pre-filters by class
	// via identity.Matches; Translate additionally guards on spec.ingressClassName).
	Ingresses []*networkingv1.Ingress
	// Policies maps "ns/name" -> a cadi.sh/policy ConfigMap's Cadishfile fragment.
	Policies map[string]string
	// ClassName is the controller's IngressClass name (e.g. "cadish").
	ClassName string
	// DefaultClass is true when this controller's IngressClass is marked default, so an
	// Ingress that sets no class at all is still ours (see identity.Matches).
	DefaultClass bool
	// ACMEHosts is the set of hosts (lowercased) whose spec.tls Secret is ABSENT, so
	// cadish auto-issues their certificate via ACME (Secrets-if-present-else-ACME,
	// design §19). The translator emits a `tls acme` directive on those sites, which
	// flows through cfg.TLS into the manager's HostPolicy on apply. Hosts WITH a Secret
	// get their cert via the controller's typed side-channel (Server.SetDynamicCerts)
	// and so get NO `tls` directive here.
	ACMEHosts map[string]bool
	// ACMEEmail is the ACME account contact rendered into generated `tls acme`
	// directives (optional).
	ACMEEmail string
	// Caps holds the operator-configured per-namespace resource caps (B1,
	// hostile-multi-tenant hardening). The zero value disables every cap, so the
	// translator behaves exactly as before (default off = unlimited = unchanged).
	Caps ResourceCaps
}

// Reject records one Ingress (or fragment) element that was skipped, with a reason.
// The controller turns each into a Kubernetes warning Event; serving is unaffected.
type Reject struct {
	Ingress string // "ns/name"
	Reason  string
}

// routeEntry is one (host, path) backend mapping collected from the Ingress set.
type routeEntry struct {
	host     string
	path     string
	pathType networkingv1.PathType
	ns       string
	svc      string
	port     string
	policy   string // "ns/name" cadi.sh/policy ref for this host's Ingress, or ""
}

const defaultBackendName = "u_default"

// policyAnnotation names the ConfigMap (as "ns/name") whose Cadishfile fragment is
// layered into a matched Ingress's host site (Task 3).
const policyAnnotation = "cadi.sh/policy"

// sslRedirectAnnotation, when "true" on an Ingress, forces the HTTP→HTTPS redirect for
// that Ingress's hosts even without local TLS (Ingress mode gates the redirect to TLS
// hosts by default; this is the opt-in for TLS terminated upstream at an LB/Cloudflare).
const sslRedirectAnnotation = "cadi.sh/ssl-redirect"

// RenderedSite is one host's rendered Cadishfile block plus the keys of the Ingresses
// that contributed a rule (or policy) to it. The controller uses these to compile
// site-by-site and DROP ONLY a site that breaks the combined compile (FIX 3), emitting a
// targeted Event for each contributing Ingress, instead of freezing all routing.
type RenderedSite struct {
	Host      string
	Text      string   // the full "host { … }\n" block
	Ingresses []string // contributing Ingress keys "ns/name" (sorted)
}

// Translate emits a Cadishfile projecting the merged Ingress set and returns it plus
// any per-element rejects. It is deterministic: identical inputs render byte-identical
// output (so the controller can skip no-op swaps).
func Translate(in Inputs) (string, []Reject) {
	sites, rejects := TranslateSites(in)
	var b strings.Builder
	for _, s := range sites {
		b.WriteString(s.Text)
	}
	return b.String(), rejects
}

// TranslateSites is Translate decomposed into per-host RenderedSite blocks (FIX 3). The
// concatenation of the blocks' Text (in order) is byte-identical to Translate's output.
func TranslateSites(in Inputs) ([]RenderedSite, []Reject) {
	var rejects []Reject

	// Oldest-wins merge: sort contributing Ingresses by creationTimestamp, then
	// namespace/name as a stable tiebreaker.
	ings := matchingIngresses(in)
	sort.SliceStable(ings, func(i, j int) bool {
		ti, tj := ings[i].CreationTimestamp, ings[j].CreationTimestamp
		if !ti.Equal(&tj) {
			return ti.Before(&tj)
		}
		return key(ings[i]) < key(ings[j])
	})

	// Cross-namespace ROUTING host-ownership (A1, first-claim lock — mirrors the TLS
	// host-ownership D64 added). A host's routing is OWNED by the namespace of the OLDEST
	// Ingress that declares it (computed by routingHostOwners — the SAME helper and
	// ordering TLSPlan uses, so routing and TLS ownership AGREE on the owner per host).
	// An Ingress in a DIFFERENT namespace that contributes rules (or a defaultBackend)
	// for that host is REJECTED for that host and never merged — so a hostile tenant
	// cannot claim/parasitize another namespace's hostname's routing (e.g. add a `/`
	// catch-all to victim.com). Same-namespace Ingresses still merge: a namespace owns
	// its own host. Reject reasons are deduped per (Ingress, host) below so a multi-path
	// foreign claim emits one Event per host, not one per path.
	owner := routingHostOwners(ings)
	rejectedHost := map[string]bool{} // "ingressKey\x00host" already rejected (dedup)

	// Per-namespace resource caps (B1): bound a noisy/hostile tenant's site/route count.
	// OFF by default (zero ResourceCaps → caps is a no-op, byte-identical output). Excess
	// is rejected oldest-Ingress-first (ings is already creation-time sorted above), so the
	// earlier sites/routes keep rendering and only the newest over-the-line ones drop, each
	// with a per-Ingress Event. Reject reasons are deduped per (Ingress, host) like the
	// foreign-host rejects so a multi-path over-cap claim emits one site Event per host.
	caps := newCapCounter(in.Caps)
	cappedHost := map[string]bool{} // "ingressKey\x00host" site-cap reject already emitted (dedup)
	foreignHost := func(ing *networkingv1.Ingress, host string) bool {
		ownNs, ok := owner[host]
		if !ok || ownNs == ing.Namespace {
			return false
		}
		dk := key(ing) + "\x00" + host
		if !rejectedHost[dk] {
			rejectedHost[dk] = true
			rejects = append(rejects, Reject{
				Ingress: key(ing),
				Reason: fmt.Sprintf("host %q routing is owned by namespace %q (oldest Ingress first-claim); a rule for it may only come from that namespace (cross-namespace routing claim rejected)",
					host, ownNs),
			})
		}
		return true
	}

	// Collect route entries (oldest-wins on duplicate (host, path, pathType)) and each
	// Ingress's spec.defaultBackend. A defaultBackend is the PER-INGRESS terminal
	// fallback: it applies ONLY to the hosts that Ingress itself declares (F8 — one
	// Ingress's defaultBackend must NOT bleed into a host owned by another Ingress).
	// We therefore record the parsed defaultBackend keyed by its owning Ingress and,
	// after collecting rules, fan it out to that Ingress's own hosts (oldest-wins per
	// host). Policy refs are tracked per host so Task-3 layering can find them.
	entries := []routeEntry{}
	seen := map[string]string{} // "host\x00path\x00type" -> owning ingress key
	hostPolicy := map[string]string{}
	hostIngs := map[string]map[string]bool{} // host -> set of contributing Ingress keys
	defByOwner := map[string]*routeEntry{}   // ingress key -> its parsed defaultBackend
	ownerHosts := map[string][]string{}      // ingress key -> the hosts it declares (in order)
	addHostIng := func(host, k string) {
		s := hostIngs[host]
		if s == nil {
			s = map[string]bool{}
			hostIngs[host] = s
		}
		s[k] = true
	}

	for _, ing := range ings {
		k := key(ing)
		policyRef := ing.Annotations[policyAnnotation]

		// spec.defaultBackend → this Ingress's per-host terminal fallback (scoped to
		// its OWN hosts below; never a cross-Ingress global). Parsed here; fanned out
		// after the rule loop once this Ingress's host set is known.
		if be := ing.Spec.DefaultBackend; be != nil {
			if ns, svc, port, ok := backendTarget(ing.Namespace, be); ok {
				defByOwner[k] = &routeEntry{ns: ns, svc: svc, port: port}
			} else {
				rejects = append(rejects, Reject{Ingress: k, Reason: "spec.defaultBackend has no service.name/port"})
			}
		}

		for ri := range ing.Spec.Rules {
			rule := &ing.Spec.Rules[ri]
			host := strings.ToLower(strings.TrimSpace(rule.Host))
			if host == "" {
				if rule.HTTP != nil && len(rule.HTTP.Paths) > 0 {
					rejects = append(rejects, Reject{Ingress: k, Reason: "rule with empty host is unsupported; set an explicit host or spec.defaultBackend"})
				}
				continue
			}
			// Validate host syntax in the translator rather than relying on the API server
			// (FIX 5): a malformed host must be rejected (Reject/Event) and never emitted
			// into the Cadishfile, where it could break the compile or render a bogus site.
			if !validIngressHost(host) {
				rejects = append(rejects, Reject{Ingress: k, Reason: fmt.Sprintf("rule host %q is not a valid DNS hostname", rule.Host)})
				continue
			}
			// A1 routing host-ownership: a foreign-namespace claim on an owned host is
			// rejected (Event) and its rules/policy/host are NOT merged for that host.
			if foreignHost(ing, host) {
				continue
			}
			// B1 site cap: a NEW host for this namespace beyond MaxSitesPerNamespace is
			// rejected (the namespace's earlier hosts already rendered). An already-admitted
			// host (a second Ingress / second rule on the same host) is not re-charged.
			if ok, reason := caps.admitHost(ing.Namespace, host); !ok {
				dk := k + "\x00" + host
				if !cappedHost[dk] {
					cappedHost[dk] = true
					rejects = append(rejects, Reject{Ingress: k, Reason: reason})
				}
				continue
			}
			if policyRef != "" {
				// Confine a cadi.sh/policy ref to the Ingress's OWN namespace: a
				// cross-namespace (or malformed) ref must never be layered into this
				// site, or one tenant could pull another's policy. This is the
				// authoritative per-host gate (gatherPolicies also refuses to read a
				// foreign ConfigMap). Reject and skip; the routes still render.
				refNs, refName := splitNN(policyRef)
				if refNs != ing.Namespace || refName == "" {
					rejects = append(rejects, Reject{Ingress: k, Reason: fmt.Sprintf("cadi.sh/policy %q must reference a ConfigMap in the Ingress's own namespace %q", policyRef, ing.Namespace)})
				} else if _, ok := hostPolicy[host]; !ok {
					hostPolicy[host] = policyRef
				}
			}
			// Always register the host so it becomes a site, even with no usable paths
			// (e.g. a host-only rule paired with spec.defaultBackend).
			ensureHost(&entries, host)
			addHostIng(host, k)
			// Record this host under its owning Ingress so a spec.defaultBackend can be
			// scoped to exactly the hosts THIS Ingress declares (F8). Deduped per owner.
			if !containsStr(ownerHosts[k], host) {
				ownerHosts[k] = append(ownerHosts[k], host)
			}
			if rule.HTTP == nil {
				continue
			}
			for pi := range rule.HTTP.Paths {
				p := &rule.HTTP.Paths[pi]
				ns, svc, port, ok := backendTarget(ing.Namespace, &p.Backend)
				if !ok {
					rejects = append(rejects, Reject{Ingress: k, Reason: fmt.Sprintf("path %q has no service.name/port", p.Path)})
					continue
				}
				pt := pathTypeOf(p)
				path := normalizePath(p.Path, pt)
				dk := host + "\x00" + path + "\x00" + string(pt)
				if owner, dup := seen[dk]; dup {
					if owner != k {
						rejects = append(rejects, Reject{Ingress: k, Reason: fmt.Sprintf("duplicate path %s %q on host %s (older Ingress wins)", pt, path, host)})
					}
					continue
				}
				// B1 route cap: a route beyond MaxRoutesPerNamespace for this namespace is
				// rejected (the namespace's earlier routes already rendered). Charged only
				// for a route we actually admit (after the duplicate-path dedup above).
				if ok, reason := caps.admitRoute(ing.Namespace, host, path); !ok {
					rejects = append(rejects, Reject{Ingress: k, Reason: reason})
					continue
				}
				seen[dk] = k
				entries = append(entries, routeEntry{
					host: host, path: path, pathType: pt,
					ns: ns, svc: svc, port: port, policy: policyRef,
				})
			}
		}
	}

	// Fan each Ingress's spec.defaultBackend out to the hosts THAT Ingress declares
	// (F8: scoped, never global). When two Ingresses claim the same host with a
	// defaultBackend, the older one wins (the Ingress list is already creation-time
	// sorted) and the loser is rejected — mirroring the per-path oldest-wins merge.
	hostDefault := map[string]*routeEntry{}
	defOwnerOfHost := map[string]string{}
	for _, ing := range ings {
		k := key(ing)
		be := defByOwner[k]
		if be == nil {
			continue
		}
		for _, host := range ownerHosts[k] {
			if owner, ok := defOwnerOfHost[host]; ok {
				if owner != k {
					rejects = append(rejects, Reject{Ingress: k, Reason: fmt.Sprintf("duplicate spec.defaultBackend for host %s (older Ingress wins)", host)})
				}
				continue
			}
			hostDefault[host] = be
			defOwnerOfHost[host] = k
		}
	}

	sites := renderSites(entries, hostPolicy, hostDefault, in.Policies, in.ACMEHosts, in.ACMEEmail, in.Caps.MaxFragmentBytes, &rejects)
	for i := range sites {
		sites[i].Ingresses = sortedBoolKeys(hostIngs[sites[i].Host])
	}
	return sites, rejects
}

// containsStr reports whether s is in xs.
func containsStr(xs []string, s string) bool {
	for _, x := range xs {
		if x == s {
			return true
		}
	}
	return false
}

// sortedBoolKeys returns the keys of a string set, sorted (nil-safe).
func sortedBoolKeys(m map[string]bool) []string {
	if len(m) == 0 {
		return nil
	}
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// ensureHost records a host that has no path rules (so it still becomes a site).
func ensureHost(entries *[]routeEntry, host string) {
	for _, e := range *entries {
		if e.host == host {
			return
		}
	}
	*entries = append(*entries, routeEntry{host: host, path: "", pathType: ""})
}

// matchingIngresses returns the subset this controller owns, via the full IngressClass
// matching rules (spec class, legacy annotation, default-class fallback) — the same
// identity.Matches the controller uses, so a legacy-annotation or default-class Ingress
// (which has no spec.ingressClassName) is NOT dropped by the translator's own guard.
func matchingIngresses(in Inputs) []*networkingv1.Ingress {
	out := make([]*networkingv1.Ingress, 0, len(in.Ingresses))
	for _, ing := range in.Ingresses {
		if ing == nil {
			continue
		}
		if Matches(ing, in.ClassName, in.DefaultClass) {
			out = append(out, ing)
		}
	}
	return out
}

func key(ing *networkingv1.Ingress) string { return ing.Namespace + "/" + ing.Name }

// pathTypeOf returns the path's PathType, defaulting a nil/unknown value to Prefix
// (Kubernetes requires PathType; treat absence as the common Prefix case).
func pathTypeOf(p *networkingv1.HTTPIngressPath) networkingv1.PathType {
	if p.PathType == nil {
		return networkingv1.PathTypePrefix
	}
	switch *p.PathType {
	case networkingv1.PathTypeExact:
		return networkingv1.PathTypeExact
	case networkingv1.PathTypeImplementationSpecific:
		return networkingv1.PathTypeImplementationSpecific
	default:
		return networkingv1.PathTypePrefix
	}
}

// normalizePath trims surrounding whitespace and, for non-Exact path types, a single trailing
// slash (keeping the root "/"); an empty path becomes "/". An EXACT path is preserved verbatim:
// Ingress `pathType: Exact` "/foo/" must match ONLY "/foo/", so stripping its trailing slash
// (→ "/foo") would silently re-point the rule to a different path. Prefix/ImplementationSpecific
// keep the trim (a prefix is slash-insensitive at its boundary).
func normalizePath(p string, pt networkingv1.PathType) string {
	p = strings.TrimSpace(p)
	if p == "" {
		return "/"
	}
	if pt == networkingv1.PathTypeExact {
		return p // preserve an Exact path exactly (incl. a meaningful trailing slash)
	}
	if len(p) > 1 {
		p = strings.TrimRight(p, "/")
		if p == "" {
			p = "/"
		}
	}
	return p
}

// render assembles the Cadishfile text: one site per host (sorted), each with its
// deduplicated upstreams, specificity-ordered routes, an optional bare catch-all from
// a Prefix "/" rule, and the host's OWN spec.defaultBackend route emitted LAST.
// hostPolicy maps a host to its cadi.sh/policy ref; hostDefault maps a host to the
// per-Ingress defaultBackend that applies to it (F8: scoped, never global); policies
// holds the fragment text (layered in Task 3). A bad fragment is reported via rejects
// and skipped.
func renderSites(entries []routeEntry, hostPolicy map[string]string, hostDefault map[string]*routeEntry, policies map[string]string, acmeHosts map[string]bool, acmeEmail string, maxFragmentBytes int, rejects *[]Reject) []RenderedSite {
	byHost := map[string][]routeEntry{}
	var hosts []string
	for _, e := range entries {
		if _, ok := byHost[e.host]; !ok {
			hosts = append(hosts, e.host)
		}
		byHost[e.host] = append(byHost[e.host], e)
	}
	// Hosts with a policy but no route entry (host-only rules) still need a site.
	for h := range hostPolicy {
		if _, ok := byHost[h]; !ok {
			hosts = append(hosts, h)
			byHost[h] = nil
		}
	}
	// NOTE: an ACME host named ONLY in spec.tls (no rule, no backend) is intentionally
	// NOT forced into a site — a site with no `upstream` cannot serve (or compile), and
	// issuing a cert for a host that serves nothing is pointless. Such a host simply
	// drops out of the ACME allow-set; the HostPolicy stays bounded to served hosts.
	sort.Strings(hosts)

	sites := make([]RenderedSite, 0, len(hosts))
	for _, host := range hosts {
		var b strings.Builder
		writeSite(&b, host, byHost[host], hostDefault[host], hostPolicy[host], policies, acmeHosts[host], acmeEmail, maxFragmentBytes, rejects)
		sites = append(sites, RenderedSite{Host: host, Text: b.String()})
	}
	return sites
}

// writeSite emits one `host { … }` block.
func writeSite(b *strings.Builder, host string, entries []routeEntry, def *routeEntry, policyRef string, policies map[string]string, acme bool, acmeEmail string, maxFragmentBytes int, rejects *[]Reject) {
	// Collect distinct upstreams used by this site's routes (+ the default backend).
	type up struct{ name, target string }
	upByName := map[string]string{}
	var upNames []string
	addUp := func(ns, svc, port string) string {
		name := upstreamName(ns, svc, port)
		target := fmt.Sprintf("k8s://%s.%s:%s", svc, ns, port)
		if _, ok := upByName[name]; !ok {
			upByName[name] = target
			upNames = append(upNames, name)
		}
		return name
	}

	// Specificity sort: Exact before Prefix/Impl; longer path first; lexical tiebreak.
	routed := make([]routeEntry, 0, len(entries))
	for _, e := range entries {
		if e.path == "" {
			continue // host-only entry: no route
		}
		routed = append(routed, e)
	}
	sort.SliceStable(routed, func(i, j int) bool {
		ri, rj := specRank(routed[i]), specRank(routed[j])
		if ri != rj {
			return ri < rj
		}
		if len(routed[i].path) != len(routed[j].path) {
			return len(routed[i].path) > len(routed[j].path)
		}
		return routed[i].path < routed[j].path
	})

	// Pre-assign upstream names + matcher names so the upstream block can be emitted
	// first (cleaner, and matcher refs resolve regardless of order).
	type routeLine struct {
		matcher string // "" for a bare catch-all
		def     string // matcher definition line (without leading tab), "" if catch-all
		upName  string
	}
	var lines []routeLine
	var matcherNames []string // the @rN matcher names, for the terminal no-match respond
	hasCatchAll := false
	mi := 0
	for _, e := range routed {
		upName := addUp(e.ns, e.svc, e.port)
		if isCatchAll(e) {
			lines = append(lines, routeLine{matcher: "", def: "", upName: upName})
			hasCatchAll = true
			continue
		}
		mname := fmt.Sprintf("@r%d", mi)
		mi++
		matcherNames = append(matcherNames, mname)
		lines = append(lines, routeLine{matcher: mname, def: mname + " " + pathMatcherArgs(e), upName: upName})
	}
	var defName string
	if def != nil {
		defName = addUp(def.ns, def.svc, def.port)
	}

	// Terminal no-match behavior (F7): a site whose paths are all scoped (no Prefix "/"
	// catch-all) and that has NO spec.defaultBackend must 404 every UNMATCHED path —
	// otherwise resolveUpstream returns "" and the handler falls back to the site's
	// first declared upstream, silently serving EVERY path from one backend (breaking
	// path-scoped isolation). We emit a terminal `respond !@r0 !@r1 … 404`: it fires for
	// any path matching NONE of the route matchers. With a catch-all or a defaultBackend
	// the bare `route ->` is the terminal fallback instead, so no respond is emitted.
	// A site with no path matchers at all (matcherNames empty) gets no terminal respond
	// (there is nothing to 404 against, and a respond-only site has no upstream to
	// compile); such a degenerate host is handled exactly as before.
	emitTerminal404 := !hasCatchAll && defName == "" && len(matcherNames) > 0

	// Validate + resolve the policy fragment (Task 3). On a bad fragment, skip it.
	var fragment string
	if policyRef != "" {
		if frag, ok := policies[policyRef]; ok {
			if maxFragmentBytes > 0 && len(frag) > maxFragmentBytes {
				// B1 fragment-size cap: reject an over-size cadi.sh/policy fragment BEFORE
				// validating/compiling it (the expensive step a hostile tenant would abuse).
				*rejects = append(*rejects, Reject{Ingress: policyRef, Reason: fmt.Sprintf("cadi.sh/policy fragment is %d bytes, exceeding the per-namespace fragment cap of %d bytes (fragment dropped)", len(frag), maxFragmentBytes)})
			} else if err := validateFragment(frag); err != nil {
				*rejects = append(*rejects, Reject{Ingress: policyRef, Reason: fmt.Sprintf("invalid cadi.sh/policy fragment: %v", err)})
			} else {
				fragment = frag
			}
		} else {
			*rejects = append(*rejects, Reject{Ingress: policyRef, Reason: "cadi.sh/policy ConfigMap not found"})
		}
	}

	b.WriteString(host)
	b.WriteString(" {\n")
	// ACME TLS: a spec.tls host with no Secret auto-issues. Only emitted when the site
	// actually has an upstream to serve (a site with no upstream can't serve or even
	// compile). Emitted before routes so it is deterministic and independent of route
	// ordering; the BYO-Secret case carries no `tls` directive (its cert arrives via
	// Server.SetDynamicCerts).
	if acme && len(upNames) > 0 {
		if acmeEmail != "" {
			fmt.Fprintf(b, "\ttls acme %s\n", acmeEmail)
		} else {
			b.WriteString("\ttls acme\n")
		}
	}
	// Upstreams (sorted for determinism).
	sort.Strings(upNames)
	for _, n := range upNames {
		fmt.Fprintf(b, "\tupstream %s { to %s }\n", n, upByName[n])
	}
	// Routes in specificity order; bare catch-alls (Prefix "/") after matcher routes;
	// the global default last (sort already puts "/" last among rank-1, but emit any
	// catch-all lines after the matcher lines explicitly).
	var bare []routeLine
	for _, l := range lines {
		if l.matcher == "" {
			bare = append(bare, l)
			continue
		}
		fmt.Fprintf(b, "\t%s\n", l.def)
		fmt.Fprintf(b, "\troute %s -> %s\n", l.matcher, l.upName)
	}
	for _, l := range bare {
		fmt.Fprintf(b, "\troute -> %s\n", l.upName)
	}
	if defName != "" {
		fmt.Fprintf(b, "\troute -> %s\n", defName)
	}
	// Terminal no-match 404 (F7): emitted AFTER the routes so the matcher names it
	// negates are already defined. `respond !@r0 !@r1 … 404` fires only for a path that
	// matches none of the route matchers, so matched paths still route normally.
	if emitTerminal404 {
		b.WriteString("\trespond")
		for _, m := range matcherNames {
			b.WriteString(" !")
			b.WriteString(m)
		}
		b.WriteString(" 404\n")
	}
	// Policy fragment directives, layered after the routes (Task 3).
	if fragment != "" {
		for _, ln := range strings.Split(strings.TrimRight(fragment, "\n"), "\n") {
			b.WriteString("\t")
			b.WriteString(ln)
			b.WriteString("\n")
		}
	}
	b.WriteString("}\n")
}

// Combine concatenates a base Cadishfile (globals: cache/admin/tls defaults) with the
// translator-generated sites, base first so global blocks precede the generated sites.
func Combine(base, generated string) string {
	base = strings.TrimRight(base, "\n")
	if base == "" {
		return generated
	}
	return base + "\n" + generated
}

// deniedFragmentDirectives is the set of directive keywords a cadi.sh/policy fragment
// may NOT carry: anything that defines a backend, a route, or a credential. A policy
// fragment is POLICY-ONLY (cache/header/security policy); allowing it to define an
// upstream/cluster/origin or a `to` target would let a tenant's ConfigMap proxy an
// arbitrary host (SSRF / cloud-metadata) or a service in ANOTHER namespace, bypassing
// the namespace-locked normal Ingress path; `route` would let it re-wire routing and
// `sign` would let it mint credentials. (FIX 1.)
//
// `import` is also denied (FIX A): pipeline.SpliceImports resolves import paths against
// the controller pod's filesystem via FileImportResolver; a tenant-supplied fragment
// containing `import /etc/passwd` (or any other pod-local path) would cause
// config.LoadString to read that file, and any parse error of the file content is
// propagated into the Ingress status — making the first token of arbitrary files
// tenant-readable. Blocking the directive before any filesystem I/O closes the gap.
var deniedFragmentDirectives = map[string]bool{
	"upstream": true,
	"cluster":  true,
	"origin":   true,
	"route":    true,
	"to":       true,
	"sign":     true,
	"import":   true,
	// `geo` is denied (FIX A): `geo { source cidr <path> }` and
	// `geo { source maxmind <path> }` open an absolute filesystem path during
	// config.LoadString. A parse/read error echoes the file's first token via %q
	// into the Ingress status reject reason, making arbitrary pod files
	// tenant-readable. Blocking the directive before any filesystem I/O closes
	// the gap (same approach as `import`).
	"geo": true,
}

// validateFragment validates a cadi.sh/policy fragment IN ISOLATION (wrapped in a
// throwaway site with a dummy upstream) so it is rejected before it is layered into a
// real site — the routes still render without it (graceful degradation). Returns nil
// when the fragment is valid, POLICY-ONLY Cadishfile that stays WITHIN the synthetic
// site.
//
// A compile-only check is NOT sufficient: the Cadishfile grammar admits multiple
// top-level sites, so a fragment carrying balanced extra braces (e.g. a leading "}")
// can close the synthetic site and open a SECOND site for an arbitrary hostname — a
// valid parse that, layered verbatim, injects a foreign site (cross-tenant traffic
// hijack). We therefore FIRST parse the fragment structurally and require that nothing
// escaped the synthetic site: exactly one site, no globals, no top-level body.
//
// Policy fragments are additionally RESTRICTED (FIX 1): they must not reference the
// controller pod's environment ({$VAR} would leak the admin token / any secret when the
// combined config is env-substituted) and must not carry backend/route/credential
// directives (which would enable SSRF, cross-namespace proxying, or route rewiring).
// Only then do we run the config compiler's semantic check (bad directive values, etc.).
func validateFragment(frag string) error {
	// Env-exfiltration guard: a policy fragment must never reference the process env.
	// {$VAR} placeholders would otherwise expand against the CONTROLLER POD's environment
	// when the combined config is compiled (config.SubstituteEnv), leaking secrets such
	// as the admin token. Reject outright so the fragment is never layered.
	if containsEnvPlaceholder(frag) {
		return fmt.Errorf("environment-variable placeholders ({$VAR}) are not allowed in a policy fragment")
	}

	// Parse the fragment ALONE (in a bare synthetic site, no injected upstream/route) so
	// we can inspect exactly the fragment's own directives for the structural and
	// allow-list checks.
	bare := buildBareFragmentWrapper(frag)
	f, err := cadishfile.Parse("<policy>", []byte(bare))
	if err != nil {
		return err
	}
	if f.Global != nil || len(f.Body) != 0 || len(f.Sites) != 1 {
		return fmt.Errorf("fragment must stay within its site (unbalanced braces or extra blocks)")
	}

	// Directive allow-list: a policy fragment is policy-only. Reject any backend/route/
	// credential-defining directive (recursively, so a nested `to` is caught too).
	if name := firstDeniedDirective(f.Sites[0].Body); name != "" {
		return fmt.Errorf("directive %q is not allowed in a policy fragment (policy fragments are policy-only: no backends, routes, or credentials)", name)
	}

	// Semantic guard: the fragment's directive values must be valid. Compile it inside a
	// wrapper carrying a dummy upstream+route so it is a complete, compilable site.
	cfg, err := config.LoadString("<policy>", buildFragmentWrapper(frag))
	if cfg != nil {
		_ = cfg.Close()
	}
	return err
}

// firstDeniedDirective walks the node list (recursing into directive blocks) and returns
// the first directive keyword that is in deniedFragmentDirectives, or "" when none is.
func firstDeniedDirective(nodes []cadishfile.Node) string {
	for _, n := range nodes {
		d, ok := n.(*cadishfile.Directive)
		if !ok {
			continue
		}
		if deniedFragmentDirectives[d.Name] {
			return d.Name
		}
		if name := firstDeniedDirective(d.Block); name != "" {
			return name
		}
	}
	return ""
}

// containsEnvPlaceholder reports whether s contains an UNESCAPED "{$" env-expansion span
// (the trigger for config.SubstituteEnv). A backslash-escaped "\{" is not a placeholder.
func containsEnvPlaceholder(s string) bool {
	for i := 0; i+1 < len(s); i++ {
		if s[i] == '\\' { // skip the escaped character
			i++
			continue
		}
		if s[i] == '{' && s[i+1] == '$' {
			return true
		}
	}
	return false
}

// buildBareFragmentWrapper wraps a fragment in a synthetic site with NO injected
// upstream/route, so the parsed site Body is EXACTLY the fragment's own directives (used
// for the structural breakout check and the directive allow-list). It need not compile.
func buildBareFragmentWrapper(frag string) string {
	var b strings.Builder
	b.WriteString("_validate.test {\n")
	for _, ln := range strings.Split(strings.TrimRight(frag, "\n"), "\n") {
		b.WriteString("\t")
		b.WriteString(ln)
		b.WriteString("\n")
	}
	b.WriteString("}\n")
	return b.String()
}

// buildFragmentWrapper wraps a policy fragment in a synthetic, single site with a dummy
// upstream + route so the fragment can be validated as it will be layered (each line
// indented one tab inside the host block). validateFragment and the structural guard
// share this exact rendering.
func buildFragmentWrapper(frag string) string {
	var b strings.Builder
	b.WriteString("_validate.test {\n\tupstream _v { to http://x:80 }\n\troute -> _v\n")
	for _, ln := range strings.Split(strings.TrimRight(frag, "\n"), "\n") {
		b.WriteString("\t")
		b.WriteString(ln)
		b.WriteString("\n")
	}
	b.WriteString("}\n")
	return b.String()
}

// specRank ranks Exact above Prefix/ImplementationSpecific for the first-match-wins
// route order.
func specRank(e routeEntry) int {
	if e.pathType == networkingv1.PathTypeExact {
		return 0
	}
	return 1
}

// isCatchAll reports whether a (non-Exact) path "/" should become a bare catch-all
// route (matches every path) rather than a path matcher.
func isCatchAll(e routeEntry) bool {
	return e.pathType != networkingv1.PathTypeExact && e.path == "/"
}

// pathMatcherArgs renders the `path` matcher args for a route entry:
//   - Exact "/p"            -> "path /p"            (matches only /p)
//   - Prefix/Impl "/p"      -> "path /p /p/*"       (matches /p and any /p/… subpath,
//     reproducing Kubernetes element-wise Prefix: /p never matches /prefix)
func pathMatcherArgs(e routeEntry) string {
	if e.pathType == networkingv1.PathTypeExact {
		return "path " + e.path
	}
	return fmt.Sprintf("path %s %s/*", e.path, e.path)
}

// upstreamName builds a deterministic, syntactically valid upstream name from the
// (namespace, service, port) triple.
func upstreamName(ns, svc, port string) string {
	return "u_" + sanitize(ns) + "_" + sanitize(svc) + "_" + sanitize(port)
}

// validIngressHost reports whether host is a syntactically valid Ingress rule host: a
// DNS name of dot-separated DNS-1123 labels, optionally prefixed with a single "*."
// wildcard label. host is assumed already lowercased and trimmed.
func validIngressHost(host string) bool {
	if host == "" || len(host) > 253 {
		return false
	}
	if strings.HasPrefix(host, "*.") {
		host = host[2:] // the remainder must be a normal DNS name (no further wildcards)
		if host == "" {
			return false
		}
	}
	for _, label := range strings.Split(host, ".") {
		if !validDNSLabel(label) {
			return false
		}
	}
	return true
}

// validDNSLabel reports whether s is a single DNS-1123 label: 1–63 chars of [a-z0-9] and
// interior '-' (not leading or trailing).
func validDNSLabel(s string) bool {
	if s == "" || len(s) > 63 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z', c >= '0' && c <= '9':
			// ok
		case c == '-':
			if i == 0 || i == len(s)-1 {
				return false
			}
		default:
			return false
		}
	}
	return true
}

// sanitize maps any character outside [A-Za-z0-9_] to '_' so a DNS-1123 service name
// (which may contain '-' and '.') becomes a valid Cadishfile word token.
func sanitize(s string) string {
	var b strings.Builder
	for _, r := range s {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '_' {
			b.WriteRune(r)
		} else {
			b.WriteByte('_')
		}
	}
	return b.String()
}

// backendTarget extracts (namespace, service, port) from a backend; ok is false when
// the backend has no usable service.name/port. Port is the numeric port when set, else
// the named port (Layer 1 resolves named ports against the EndpointSlice).
func backendTarget(ns string, be *networkingv1.IngressBackend) (string, string, string, bool) {
	if be == nil || be.Service == nil || be.Service.Name == "" {
		return "", "", "", false
	}
	svc := be.Service.Name
	port := ""
	if be.Service.Port.Number != 0 {
		port = fmt.Sprintf("%d", be.Service.Port.Number)
	} else if be.Service.Port.Name != "" {
		port = be.Service.Port.Name
	}
	if port == "" {
		return "", "", "", false
	}
	return ns, svc, port, true
}
