package lb

import (
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"strconv"
	"strings"
)

// fingerprint computes a stable content hash of the pool's identity-defining
// configuration, used by zero-downtime reload to decide whether a pool can be
// TRANSPLANTED across a reload (kept running with its warm health FSM / ejection
// state / goroutines) or must be rebuilt.
//
// Two configs hash equal iff every field that affects the pool's backend set,
// routing topology, health probing or transport behavior is identical:
//   - Name;
//   - the dial-target SET (Backends[].Raw, ORDER-INSENSITIVE — reordering `to`
//     lines does not change the pool);
//   - Policy, Shard and Replicas (the ring topology);
//   - the Health spec (every field);
//   - the Host-header policy, MaxConns and Timeouts.
//
// Passive-ejection tuning is intentionally NOT included: it is not surfaced through
// lb.Config today (every pool uses the package defaults), so it can never differ
// between two loaded configs. The Sticky spec is also excluded: it tells the SERVER
// how to derive the routing key (rebuilt every reload from the site) and does not
// change the pool's own backends, ring or health, so a pool whose only change is its
// sticky cookie name can still be transplanted.
func (c Config) fingerprint() string {
	var b strings.Builder
	// A field separator that cannot appear inside a target token, so distinct field
	// layouts can never alias to the same string.
	const sep = "\x1f"

	b.WriteString("name=")
	b.WriteString(c.Name)
	b.WriteString(sep)
	// Kind ("upstream" vs "cluster") is part of identity: two pools with the same name
	// and otherwise-identical fields but a different Kind must not collide and wrongly
	// transplant across a reload.
	b.WriteString("kind=")
	b.WriteString(c.Kind)
	b.WriteString(sep)

	// Order-insensitive target set.
	raws := make([]string, len(c.Backends))
	for i := range c.Backends {
		raws[i] = c.Backends[i].Raw
	}
	sort.Strings(raws)
	b.WriteString("targets=")
	for _, r := range raws {
		b.WriteString(r)
		b.WriteString("\x1e") // intra-list separator
	}
	b.WriteString(sep)

	b.WriteString("policy=")
	b.WriteString(strconv.Itoa(int(c.Policy)))
	b.WriteString(sep)
	b.WriteString("shard=")
	b.WriteString(strconv.Itoa(int(c.Shard)))
	b.WriteString(sep)
	b.WriteString("replicas=")
	b.WriteString(strconv.Itoa(c.Replicas))
	b.WriteString(sep)

	b.WriteString("health=")
	if c.Health == nil {
		b.WriteString("nil")
	} else {
		h := c.Health
		b.WriteString(h.Method)
		b.WriteString("|")
		b.WriteString(h.Path)
		b.WriteString("|")
		b.WriteString(strconv.Itoa(h.ExpectCode))
		for _, c := range h.ExpectCodes {
			b.WriteString(",")
			b.WriteString(strconv.Itoa(c))
		}
		for _, cls := range h.ExpectClasses {
			b.WriteString(",")
			b.WriteString(strconv.Itoa(cls))
			b.WriteString("xx")
		}
		b.WriteString("|")
		b.WriteString(strconv.FormatInt(int64(h.Interval), 10))
		b.WriteString("|")
		b.WriteString(strconv.Itoa(h.Window))
		b.WriteString("|")
		b.WriteString(strconv.Itoa(h.Threshold))
	}
	b.WriteString(sep)

	b.WriteString("hosthdr=")
	b.WriteString(strconv.Itoa(int(c.HostHeader.Policy)))
	b.WriteString("|")
	b.WriteString(c.HostHeader.Value)
	b.WriteString(sep)

	b.WriteString("maxconns=")
	b.WriteString(strconv.Itoa(c.MaxConns))
	b.WriteString(sep)

	b.WriteString("timeouts=")
	b.WriteString(strconv.FormatInt(int64(c.Timeouts.Connect), 10))
	b.WriteString("|")
	b.WriteString(strconv.FormatInt(int64(c.Timeouts.FirstByte), 10))
	b.WriteString("|")
	b.WriteString(strconv.FormatInt(int64(c.Timeouts.BetweenBytes), 10))
	b.WriteString(sep)

	// Per-upstream transport knobs (D59). These change the dialed connection's TLS
	// ServerName / keep-alive behavior, so a pool that differs only here must NOT be
	// transplanted with its old transport across a reload — include them in the identity.
	b.WriteString("sni=")
	b.WriteString(c.SNI)
	b.WriteString(sep)
	b.WriteString("reuse=")
	b.WriteString(strconv.FormatBool(c.DisableReuse))
	b.WriteString(sep)
	// TLSVERIFY knobs (per-upstream origin TLS verification). These change how the
	// origin handshake is verified / which ALPN is offered, so two pools differing
	// ONLY here must NOT be transplanted with each other's transport across a reload
	// (the spec's per-upstream isolation invariant). CAFile (the path) plus CAPEMHash
	// (a content hash of the loaded PEM bytes) together stand in for the loaded RootCAs
	// pool, which is not stably hashable: hashing the CONTENT — not just the path — makes
	// a CA rotated IN PLACE (same path, new bytes) force a fresh pool instead of keeping
	// the old RootCAs across a reload (Finding 4).
	b.WriteString("insecure=")
	b.WriteString(strconv.FormatBool(c.Insecure))
	b.WriteString(sep)
	b.WriteString("cafile=")
	b.WriteString(c.CAFile)
	b.WriteString(sep)
	b.WriteString("capem=")
	b.WriteString(c.CAPEMHash)
	b.WriteString(sep)
	b.WriteString("alpn=")
	for _, p := range c.ALPN {
		b.WriteString(p)
		b.WriteString("\x1e")
	}
	b.WriteString(sep)

	// Dynamic re-resolution knobs (the inline `resolve [interval] [nameserver ip:port…]`).
	// They change WHICH resolver the pool runs (interval / nameserver set + ORDER), so a
	// pool differing only here must be rebuilt — else editing `resolve` and reloading keeps
	// the OLD resolver until restart (Finding 2). The nameserver ORDER is meaningful
	// (fall-through), so hash them IN ORDER, each length-prefixed so two distinct lists can
	// never alias to the same byte string.
	b.WriteString("resolveiv=")
	b.WriteString(strconv.FormatInt(int64(c.ResolveInterval), 10))
	b.WriteString(sep)
	b.WriteString("nameservers=")
	for _, ns := range c.Nameservers {
		b.WriteString(strconv.Itoa(len(ns)))
		b.WriteString(":")
		b.WriteString(ns)
		b.WriteString("\x1e")
	}

	sum := sha256.Sum256([]byte(b.String()))
	return hex.EncodeToString(sum[:])
}

// HasK8sBackend reports whether any backend target is a k8s:// endpoint, i.e. one
// resolved through the injected/shared EndpointResolver (a Kubernetes client) rather
// than DNS or a fixed address. Zero-downtime reload uses it to avoid transplanting a
// pool onto a config whose owned k8s client is about to be torn down.
func (u *Upstream) HasK8sBackend() bool {
	for i := range u.cfg.Backends {
		if u.cfg.Backends[i].Scheme == SchemeK8s {
			return true
		}
	}
	return false
}

// Fingerprint returns this pool's content fingerprint (see Config.fingerprint). It
// is the cross-package seam the config layer uses to diff pools across a reload: two
// pools with the same Name and the same Fingerprint are the same steady upstream and
// can be transplanted (kept running) rather than rebuilt.
func (u *Upstream) Fingerprint() string { return u.cfg.fingerprint() }
