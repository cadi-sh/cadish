package server

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
)

// cfgIPDenyAudit denies a specific real client IP and runs behind a trusted proxy, so
// a request must be resolved to its XFF client for the `ip` ACL — and the SAME
// resolved IP must appear in the audit record. This is the cross-consumer
// consistency cell: the IP the ACL decides on and the IP the audit log records must
// not diverge (a divergence would let an operator's logs disagree with the enforced
// decision, or — worse — an attacker pass the ACL while a different IP is logged).
const cfgIPDenyAudit = `test.local {
	cache { ram 64MiB }
	upstream backend { to %s }
	trust_proxy 10.0.0.0/8
	@banned ip 203.0.113.9/32
	deny @banned
	cache_ttl default ttl 60s
}
`

// TestACLAndAuditUseSameResolvedIP proves the `ip` ACL decision and the audit-log
// client field key off the IDENTICAL trusted-proxy-resolved real client IP — not the
// socket peer (the proxy), and not a divergent value between the two consumers.
func TestACLAndAuditUseSameResolvedIP(t *testing.T) {
	origin := newCountingOrigin(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "ok")
	})
	h, _ := buildHandler(t, nil, cfgIPDenyAudit, origin.srv.URL)
	buf := &syncBuffer{}
	h.auditLog = newAuditLogWriter(buf, nil, 16)
	t.Cleanup(func() { _ = h.auditLog.Close() })

	// Peer is the trusted proxy (10.0.0.5); the banned real client (203.0.113.9) is
	// the rightmost-untrusted XFF entry. The ACL must DENY (resolved to the client),
	// and the audit record must log that SAME client — never the 10.0.0.5 peer.
	xff := http.Header{"X-Forwarded-For": {"203.0.113.9, 10.0.0.5"}}
	if rec := doFrom(h, "GET", "http://test.local/x", "10.0.0.5:1234", xff); rec.Code != http.StatusForbidden {
		t.Fatalf("banned client behind trusted proxy: got %d, want 403 (ACL resolved to XFF client)", rec.Code)
	}

	// A different real client behind the same proxy is NOT banned -> 200 (proves the
	// ACL keyed on the XFF client, not the shared proxy peer).
	xffOK := http.Header{"X-Forwarded-For": {"198.51.100.50, 10.0.0.5"}}
	if rec := doFrom(h, "GET", "http://test.local/x", "10.0.0.5:1234", xffOK); rec.Code != http.StatusOK {
		t.Fatalf("unbanned client behind trusted proxy: got %d, want 200", rec.Code)
	}

	if err := h.auditLog.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	if len(lines) != 1 {
		t.Fatalf("got %d audit lines, want 1 (only the enforced deny):\n%s", len(lines), buf.String())
	}
	var w auditWire
	if err := json.Unmarshal([]byte(lines[0]), &w); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	// The load-bearing assertion: the audit client == the XFF-resolved real client the
	// ACL decided on, NOT the 10.0.0.5 socket peer.
	if w.Client != "203.0.113.9" {
		t.Errorf("audit Client = %q, want 203.0.113.9 (the ACL-resolved real client, not the proxy peer)", w.Client)
	}
	if w.Action != "deny" || w.Status != 403 {
		t.Errorf("audit record wrong: %+v", w)
	}
}

// TestACLUntrustedPeerSpoofProof is the direct-facing control for the same config
// shape WITHOUT trust_proxy: a direct client setting X-Forwarded-For to the banned
// IP must NOT pass the ACL as that IP — the ACL keys on the socket peer, so the spoof
// is inert (the banned IP is never reached, and a peer that is the banned IP is what
// gets denied).
func TestACLUntrustedPeerSpoofProof(t *testing.T) {
	origin := newCountingOrigin(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "ok")
	})
	// No trust_proxy: direct-facing. Ban the peer 198.51.100.9 directly.
	cfg := `test.local {
	cache { ram 64MiB }
	upstream backend { to %s }
	@banned ip 198.51.100.9/32
	deny @banned
	cache_ttl default ttl 60s
}
`
	h, _ := buildHandler(t, nil, cfg, origin.srv.URL)

	// A NON-banned direct peer that spoofs XFF=banned-as-someone-else must still pass:
	// XFF is ignored with no trust_proxy, so the ACL sees the real peer (203.0.113.1).
	xffSpoof := http.Header{"X-Forwarded-For": {"198.51.100.9"}} // try to look banned? irrelevant; or to look allowed
	if rec := doFrom(h, "GET", "http://test.local/x", "203.0.113.1:5000", xffSpoof); rec.Code != http.StatusOK {
		t.Fatalf("direct peer with spoofed XFF: got %d, want 200 (XFF ignored, peer not banned)", rec.Code)
	}

	// The banned peer cannot ESCAPE the ban by spoofing XFF to an allowed-looking IP:
	// XFF is ignored, the ACL sees the real banned peer -> 403.
	xffEvade := http.Header{"X-Forwarded-For": {"203.0.113.1"}}
	if rec := doFrom(h, "GET", "http://test.local/x", "198.51.100.9:5000", xffEvade); rec.Code != http.StatusForbidden {
		t.Fatalf("banned peer spoofing XFF to evade: got %d, want 403 (XFF ignored, real peer banned)", rec.Code)
	}
}
