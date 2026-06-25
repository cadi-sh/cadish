package proxyproto

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"net"
	"testing"
)

// readFrom is a tiny helper: parse a header out of a byte slice via a bufio.Reader,
// the same shape the listener wrapper uses on an accepted connection.
func readFrom(t *testing.T, b []byte) (*Header, error) {
	t.Helper()
	return ReadHeader(bufio.NewReader(bytes.NewReader(b)))
}

func TestParseV1TCP4(t *testing.T) {
	h, err := readFrom(t, []byte("PROXY TCP4 192.0.2.1 198.51.100.2 56324 443\r\nGET / HTTP/1.1\r\n"))
	if err != nil {
		t.Fatalf("ReadHeader: %v", err)
	}
	if h.Local {
		t.Fatalf("v1 PROXY must not be a LOCAL header")
	}
	if got := h.Source.String(); got != "192.0.2.1:56324" {
		t.Fatalf("source = %q, want 192.0.2.1:56324", got)
	}
	if got := h.Dest.String(); got != "198.51.100.2:443" {
		t.Fatalf("dest = %q, want 198.51.100.2:443", got)
	}
}

func TestParseV1TCP6(t *testing.T) {
	h, err := readFrom(t, []byte("PROXY TCP6 2001:db8::1 2001:db8::2 4000 443\r\n"))
	if err != nil {
		t.Fatalf("ReadHeader: %v", err)
	}
	if got := h.Source.String(); got != "[2001:db8::1]:4000" {
		t.Fatalf("source = %q, want [2001:db8::1]:4000", got)
	}
}

func TestParseV1Unknown(t *testing.T) {
	// PROXY UNKNOWN: the LB could not determine the address. Treat like LOCAL —
	// fall back to the real socket peer, do not fail.
	h, err := readFrom(t, []byte("PROXY UNKNOWN\r\n"))
	if err != nil {
		t.Fatalf("ReadHeader: %v", err)
	}
	if !h.Local {
		t.Fatalf("PROXY UNKNOWN should map to Local (use socket peer)")
	}
}

func TestParseV1UnknownWithGarbage(t *testing.T) {
	// UNKNOWN may carry arbitrary remaining fields up to the CRLF — they are ignored.
	h, err := readFrom(t, []byte("PROXY UNKNOWN 65535 65535 65535 65535\r\n"))
	if err != nil {
		t.Fatalf("ReadHeader: %v", err)
	}
	if !h.Local {
		t.Fatalf("PROXY UNKNOWN should map to Local")
	}
}

func TestParseV1Malformed(t *testing.T) {
	cases := map[string][]byte{
		"missing crlf":      []byte("PROXY TCP4 192.0.2.1 198.51.100.2 56324 443"),
		"bad proto":         []byte("PROXY TCP9 192.0.2.1 198.51.100.2 1 2\r\n"),
		"too few fields":    []byte("PROXY TCP4 192.0.2.1 198.51.100.2 56324\r\n"),
		"too many fields":   []byte("PROXY TCP4 192.0.2.1 198.51.100.2 56324 443 7\r\n"),
		"bad src ip":        []byte("PROXY TCP4 not-an-ip 198.51.100.2 56324 443\r\n"),
		"bad port":          []byte("PROXY TCP4 192.0.2.1 198.51.100.2 99999 443\r\n"),
		"v6 addr in tcp4":   []byte("PROXY TCP4 2001:db8::1 198.51.100.2 1 2\r\n"),
		"v4 addr in tcp6":   []byte("PROXY TCP6 192.0.2.1 2001:db8::2 1 2\r\n"),
		"lf only no cr":     []byte("PROXY TCP4 192.0.2.1 198.51.100.2 1 2\n"),
		"leading space":     []byte(" PROXY TCP4 192.0.2.1 198.51.100.2 1 2\r\n"),
		"empty line":        []byte("\r\n"),
		"only signature":    []byte("PROXY"),
		"negative port-ish": []byte("PROXY TCP4 192.0.2.1 198.51.100.2 -1 2\r\n"),
	}
	for name, in := range cases {
		if _, err := readFrom(t, in); err == nil {
			t.Errorf("%s: expected error, got nil", name)
		}
	}
}

// v2 fixtures ----------------------------------------------------------------

func v2Header(ver, fam byte, addr []byte) []byte {
	out := make([]byte, 0, 16+len(addr))
	out = append(out, v2Signature...)
	out = append(out, ver)
	out = append(out, fam)
	var l [2]byte
	binary.BigEndian.PutUint16(l[:], uint16(len(addr)))
	out = append(out, l[:]...)
	out = append(out, addr...)
	return out
}

func TestParseV2ProxyIPv4(t *testing.T) {
	// version=2 command=PROXY (0x21); family=AF_INET proto=STREAM (0x11).
	var addr [12]byte
	copy(addr[0:4], net.IPv4(192, 0, 2, 1).To4())
	copy(addr[4:8], net.IPv4(198, 51, 100, 2).To4())
	binary.BigEndian.PutUint16(addr[8:10], 56324)
	binary.BigEndian.PutUint16(addr[10:12], 443)

	b := v2Header(0x21, 0x11, addr[:])
	b = append(b, []byte("GET / HTTP/1.1\r\n")...)

	h, err := readFrom(t, b)
	if err != nil {
		t.Fatalf("ReadHeader: %v", err)
	}
	if h.Local {
		t.Fatalf("PROXY command should not be Local")
	}
	if got := h.Source.String(); got != "192.0.2.1:56324" {
		t.Fatalf("source = %q, want 192.0.2.1:56324", got)
	}
	if got := h.Dest.String(); got != "198.51.100.2:443" {
		t.Fatalf("dest = %q, want 198.51.100.2:443", got)
	}
}

func TestParseV2ProxyIPv6(t *testing.T) {
	var addr [36]byte
	copy(addr[0:16], net.ParseIP("2001:db8::1").To16())
	copy(addr[16:32], net.ParseIP("2001:db8::2").To16())
	binary.BigEndian.PutUint16(addr[32:34], 4000)
	binary.BigEndian.PutUint16(addr[34:36], 443)

	b := v2Header(0x21, 0x21, addr[:]) // family=AF_INET6 proto=STREAM
	h, err := readFrom(t, b)
	if err != nil {
		t.Fatalf("ReadHeader: %v", err)
	}
	if got := h.Source.String(); got != "[2001:db8::1]:4000" {
		t.Fatalf("source = %q, want [2001:db8::1]:4000", got)
	}
}

func TestParseV2ProxyWithTLVTrailer(t *testing.T) {
	// addr block longer than the fixed IPv4 tuple: trailing bytes are TLVs we skip.
	addr := make([]byte, 12+8) // 8 bytes of TLV padding
	copy(addr[0:4], net.IPv4(10, 0, 0, 5).To4())
	copy(addr[4:8], net.IPv4(10, 0, 0, 9).To4())
	binary.BigEndian.PutUint16(addr[8:10], 1234)
	binary.BigEndian.PutUint16(addr[10:12], 80)

	b := v2Header(0x21, 0x11, addr)
	b = append(b, []byte("trailing app bytes")...)

	h, err := readFrom(t, b)
	if err != nil {
		t.Fatalf("ReadHeader: %v", err)
	}
	if got := h.Source.String(); got != "10.0.0.5:1234" {
		t.Fatalf("source = %q, want 10.0.0.5:1234", got)
	}
}

func TestParseV2Local(t *testing.T) {
	// command=LOCAL (0x20): health check, no client tuple. family/addr may be AF_UNSPEC.
	b := v2Header(0x20, 0x00, nil)
	h, err := readFrom(t, b)
	if err != nil {
		t.Fatalf("ReadHeader: %v", err)
	}
	if !h.Local {
		t.Fatalf("LOCAL command should be Local (use socket peer)")
	}
}

func TestParseV2Malformed(t *testing.T) {
	cases := map[string][]byte{
		"bad version":      v2Header(0x31, 0x11, make([]byte, 12)),         // version nibble != 2
		"bad command":      v2Header(0x2F, 0x11, make([]byte, 12)),         // command nibble invalid
		"short ipv4 addr":  v2Header(0x21, 0x11, make([]byte, 11)),         // < 12 bytes for AF_INET
		"short ipv6 addr":  v2Header(0x21, 0x21, make([]byte, 35)),         // < 36 bytes for AF_INET6
		"truncated header": v2Signature[:8],                                // not even the full signature
		"sig then eof":     append(append([]byte{}, v2Signature...), 0x21), // ver only, no rest
	}
	for name, in := range cases {
		if _, err := readFrom(t, in); err == nil {
			t.Errorf("%s: expected error, got nil", name)
		}
	}
}

func TestGarbageHeaderRejected(t *testing.T) {
	// Not PROXY v1, not the v2 signature -> rejected (no raw fallback at the parser).
	cases := [][]byte{
		[]byte("GET / HTTP/1.1\r\nHost: x\r\n\r\n"),
		[]byte("\x16\x03\x01\x00\x00"), // a TLS ClientHello record start
		[]byte("hello world"),
		{},
	}
	for i, in := range cases {
		if _, err := readFrom(t, in); err == nil {
			t.Errorf("case %d: expected error for garbage header", i)
		}
	}
}
