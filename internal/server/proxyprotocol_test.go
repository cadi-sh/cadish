package server

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/cadi-sh/cadish/internal/config"
)

// buildProxyServer builds a *Server from cfgText (a Cadishfile template with one %s
// for the origin URL) and serves it on a fresh loopback listener via Serve. It
// returns the live address. The PROXY-protocol wrap (when configured) is installed by
// ListenAndServe; here we exercise the plain Serve path, so the test wraps the
// listener the same way the server's plain-HTTP path does.
func buildProxyServer(t *testing.T, cfgText, originURL string) (*Server, string) {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "Cadishfile")
	if err := os.WriteFile(path, []byte(fmt.Sprintf(cfgText, originURL)), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	srv, err := NewServer(cfg, "127.0.0.1:0", Options{Logger: discardLogger()})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	// Mirror ListenAndServe's plain-HTTP path: wrap the listener when proxy_protocol
	// is configured.
	if wrap := srv.proxyListenerWrap(); wrap != nil {
		wln, werr := wrap(ln)
		if werr != nil {
			t.Fatalf("wrap listener: %v", werr)
		}
		ln = wln
	}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Shutdown(testCtx(t)) })
	return srv, ln.Addr().String()
}

// rawRequest dials addr, optionally writes a PROXY v1 prefix, then a minimal GET, and
// returns the raw response status line + headers (enough to read the status code).
func rawRequest(t *testing.T, addr, proxyLine, path string) string {
	t.Helper()
	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(3 * time.Second))
	if proxyLine != "" {
		if _, err := io.WriteString(c, proxyLine); err != nil {
			t.Fatalf("write proxy line: %v", err)
		}
	}
	req := "GET " + path + " HTTP/1.1\r\nHost: test.local\r\nConnection: close\r\n\r\n"
	if _, err := io.WriteString(c, req); err != nil {
		// A rejected connection may already be closed by the server — that is itself a
		// valid outcome for the spoof test, so don't fail here.
		return ""
	}
	br := bufio.NewReader(c)
	status, err := br.ReadString('\n')
	if err != nil {
		return ""
	}
	return status
}

// cfgIPACL denies the LB subnet (10.0.0.0/8) so a DIRECT connection from the LB is
// 403, but a recovered PUBLIC client IP is allowed — proving the PROXY-recovered IP
// feeds the single `ip` ACL path (spec test 1).
const cfgIPACL = `test.local {
	cache { ram 16MiB }
	upstream backend { to %s }
	@lbnet ip 10.0.0.0/8
	deny @lbnet
	cache_ttl default ttl 60s
}
`

// SECURITY / spec test 1: a trusted peer's PROXY header rewrites RemoteAddr so the
// recovered PUBLIC client IP is allowed by an ACL that denies the LB subnet. The
// trust set is 127.0.0.0/8 (the loopback the test dials from).
func TestServerProxyProtocolRecoversClientIP(t *testing.T) {
	origin := newCountingOrigin(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "ok")
	})
	cfg := `{
	proxy_protocol { trust 127.0.0.0/8 }
}
` + cfgIPACL
	_, addr := buildProxyServer(t, cfg, origin.srv.URL)

	// PROXY header advertises a public client (203.0.113.5) that is NOT in the denied
	// 10.0.0.0/8 — so the request is allowed (200/cache), proving the recovered IP fed
	// the ACL rather than the loopback socket peer.
	status := rawRequest(t, addr, "PROXY TCP4 203.0.113.5 198.51.100.2 5000 80\r\n", "/ok")
	if status == "" || status[9:12] == "403" {
		t.Fatalf("recovered public client should be allowed; status line = %q", status)
	}
}

// SECURITY / spec test 1 (negative): the SAME PROXY header advertising a client IN
// the denied LB subnet is denied — proving the recovered IP (not the socket peer) is
// what the ACL evaluates.
func TestServerProxyProtocolDeniesRecoveredLBClient(t *testing.T) {
	origin := newCountingOrigin(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "ok")
	})
	cfg := `{
	proxy_protocol { trust 127.0.0.0/8 }
}
` + cfgIPACL
	_, addr := buildProxyServer(t, cfg, origin.srv.URL)

	status := rawRequest(t, addr, "PROXY TCP4 10.9.9.9 198.51.100.2 5000 80\r\n", "/ok")
	if status[9:12] != "403" {
		t.Fatalf("recovered client in denied subnet should be 403; status = %q", status)
	}
}

// Off (no proxy_protocol) -> bare listener: a request with NO PROXY header works
// normally and RemoteAddr is the socket peer (the loopback), which is NOT in the
// denied 10.0.0.0/8, so it is allowed. This is the zero-cost regression (spec test 7).
func TestServerProxyProtocolOffIsBareListener(t *testing.T) {
	origin := newCountingOrigin(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "ok")
	})
	srv, addr := buildProxyServer(t, cfgIPACL, origin.srv.URL)
	if srv.proxyProtoEnabled() {
		t.Fatal("expected proxy-protocol OFF")
	}
	// No PROXY header, plain GET — must succeed.
	status := rawRequest(t, addr, "", "/ok")
	if status == "" || status[9:12] == "403" {
		t.Fatalf("bare listener request should succeed; status = %q", status)
	}
}
