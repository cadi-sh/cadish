// Package proxyproto is a small, dependency-free reader for the HAProxy PROXY
// protocol (v1 text + v2 binary) headers, used by cadish's opt-in PROXY-protocol
// listener (internal/server) to recover the real client address when cadish sits
// behind an L4/TCP-passthrough load balancer (HAProxy send-proxy, AWS NLB, GCP TCP
// LB) that prepends the original client/server tuple before the TLS/HTTP bytes.
//
// Scope (owner decision 2026-06-24: in-tree, NO external dependency):
//
//   - v1: the text line "PROXY <proto> <src> <dst> <sport> <dport>\r\n" where
//     <proto> is TCP4 | TCP6 | UNKNOWN. UNKNOWN (the LB could not determine the
//     tuple) maps to a LOCAL header — the caller falls back to the socket peer.
//   - v2: the 12-byte signature, a version/command byte, a family/protocol byte,
//     and a 2-byte address-block length, followed by the address block. We parse
//     the PROXY command's AF_INET / AF_INET6 source+dest tuples; AF_UNIX and the
//     LOCAL command map to a LOCAL header. Any address-block bytes beyond the fixed
//     tuple are TLVs, which we deliberately SKIP (we only need the source address).
//
// We intentionally do NOT fall back to the raw stream on a malformed header — the
// listener treats a parse failure from a trusted peer as a rejection (a downgrade
// an attacker could otherwise force). Trust gating lives in the listener, not here.
package proxyproto

import (
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strconv"
	"strings"
)

// Header is a parsed PROXY header. When Local is true the header carried no usable
// client tuple (v1 UNKNOWN, v2 LOCAL command, or a non-TCP family) and the caller
// should use the real socket peer; Source/Dest are then zero.
type Header struct {
	Local  bool
	Source netip.AddrPort
	Dest   netip.AddrPort
}

// v2Signature is the 12-byte PROXY v2 binary signature.
var v2Signature = []byte{0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A}

// v1Prefix is the start of every PROXY v1 (and the first 5 bytes of v2, which also
// begin "\r\n\r\n\x00" — disambiguated by reading the full signature).
const v1Prefix = "PROXY"

// maxV1Line bounds a v1 header line so a trusted-but-buggy peer cannot make us read
// unboundedly. The longest legitimate v1 line ("PROXY TCP6 <39> <39> <5> <5>\r\n")
// is well under 108 bytes — the spec's stated maximum.
const maxV1Line = 108

// ReadHeader reads and parses exactly one PROXY header (v1 or v2) from br, leaving
// br positioned at the first application byte after the header. It distinguishes the
// versions by peeking the leading bytes: the v2 binary signature, else the v1 text
// prefix. A header that is neither, or is malformed, returns an error (the caller
// must NOT fall back to the raw stream — that would be an attacker-forceable
// downgrade).
func ReadHeader(br *bufio.Reader) (*Header, error) {
	sig, err := br.Peek(len(v2Signature))
	if err == nil && string(sig) == string(v2Signature) {
		return readV2(br)
	}
	// Not the v2 signature. It must be a v1 text header beginning with "PROXY ".
	// Peek the prefix to fail fast on non-PROXY bytes (e.g. a TLS ClientHello).
	p, perr := br.Peek(len(v1Prefix))
	if perr != nil {
		return nil, fmt.Errorf("proxyproto: short header: %w", firstErr(perr, err))
	}
	if string(p) != v1Prefix {
		return nil, errors.New("proxyproto: not a PROXY protocol header")
	}
	return readV1(br)
}

func firstErr(errs ...error) error {
	for _, e := range errs {
		if e != nil {
			return e
		}
	}
	return io.ErrUnexpectedEOF
}

// readV1 parses the text header line. It reads up to and including the CRLF,
// rejecting a line that exceeds maxV1Line or lacks the CRLF terminator.
func readV1(br *bufio.Reader) (*Header, error) {
	line, err := readV1Line(br)
	if err != nil {
		return nil, err
	}
	// Must be CRLF-terminated (LF alone is invalid).
	if !strings.HasSuffix(line, "\r\n") {
		return nil, errors.New("proxyproto: v1 header not CRLF-terminated")
	}
	line = strings.TrimSuffix(line, "\r\n")

	fields := strings.Split(line, " ")
	if len(fields) < 2 || fields[0] != "PROXY" {
		return nil, errors.New("proxyproto: malformed v1 header")
	}
	switch fields[1] {
	case "UNKNOWN":
		// The LB could not determine the tuple; ignore any remaining fields and
		// fall back to the socket peer.
		return &Header{Local: true}, nil
	case "TCP4", "TCP6":
		// Exactly: PROXY <proto> <src> <dst> <sport> <dport>
		if len(fields) != 6 {
			return nil, fmt.Errorf("proxyproto: v1 %s header needs 6 fields, got %d", fields[1], len(fields))
		}
		wantV4 := fields[1] == "TCP4"
		src, err := parseV1AddrPort(fields[2], fields[4], wantV4)
		if err != nil {
			return nil, fmt.Errorf("proxyproto: v1 source: %w", err)
		}
		dst, err := parseV1AddrPort(fields[3], fields[5], wantV4)
		if err != nil {
			return nil, fmt.Errorf("proxyproto: v1 dest: %w", err)
		}
		return &Header{Source: src, Dest: dst}, nil
	default:
		return nil, fmt.Errorf("proxyproto: unknown v1 protocol %q", fields[1])
	}
}

// readV1Line reads bytes up to the first '\n', bounded by maxV1Line. The first byte
// must be 'P' (no leading whitespace allowed); a line longer than the bound, or EOF
// before any '\n', is an error.
func readV1Line(br *bufio.Reader) (string, error) {
	var sb strings.Builder
	for i := 0; i < maxV1Line; i++ {
		b, err := br.ReadByte()
		if err != nil {
			return "", fmt.Errorf("proxyproto: reading v1 header: %w", firstErr(err))
		}
		sb.WriteByte(b)
		if b == '\n' {
			return sb.String(), nil
		}
	}
	return "", errors.New("proxyproto: v1 header too long (no CRLF within bound)")
}

func parseV1AddrPort(ipStr, portStr string, wantV4 bool) (netip.AddrPort, error) {
	addr, err := netip.ParseAddr(ipStr)
	if err != nil {
		return netip.AddrPort{}, fmt.Errorf("bad ip %q", ipStr)
	}
	if wantV4 && !addr.Is4() {
		return netip.AddrPort{}, fmt.Errorf("expected IPv4, got %q", ipStr)
	}
	if !wantV4 && !addr.Is6() {
		return netip.AddrPort{}, fmt.Errorf("expected IPv6, got %q", ipStr)
	}
	// Ports are 0..65535 decimal, no sign, no leading +.
	if portStr == "" || (portStr[0] != '0' && !(portStr[0] >= '1' && portStr[0] <= '9')) {
		return netip.AddrPort{}, fmt.Errorf("bad port %q", portStr)
	}
	port, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil {
		return netip.AddrPort{}, fmt.Errorf("bad port %q", portStr)
	}
	// Unmap an IPv4-mapped IPv6 (`::ffff:1.2.3.4`) to its bare IPv4 — the v2 parser already
	// does this. Without it, a v1 TCP6 header would store an Is4In6 address that a trusted-proxy
	// / `ip` ACL written for the bare IPv4 would NOT match (while the same client over v2 would),
	// an inconsistent trust decision between the two PROXY-protocol versions. (Done after the
	// family check, which validates the ANNOUNCED TCP4/TCP6 family.)
	return netip.AddrPortFrom(addr.Unmap(), uint16(port)), nil
}

// PROXY v2 family/command constants.
const (
	v2VerCmd    = 12 // index of the version/command byte
	v2FamProto  = 13 // index of the family/protocol byte
	v2LenOffset = 14 // index of the 2-byte big-endian address length
	v2HeaderLen = 16 // signature(12) + verCmd + famProto + len(2)

	v2Version = 0x20 // high nibble of verCmd

	cmdLocal = 0x00 // low nibble of verCmd
	cmdProxy = 0x01

	famUnspec = 0x00 // high nibble of famProto
	famINET   = 0x10
	famINET6  = 0x20
	famUNIX   = 0x30
)

// readV2 parses the binary header. It reads the 16-byte fixed block, validates the
// version, then reads the declared address block. For the PROXY command over
// AF_INET/AF_INET6 it parses the source+dest tuple (skipping any trailing TLVs); the
// LOCAL command, AF_UNSPEC, and AF_UNIX map to a LOCAL header (use the socket peer).
func readV2(br *bufio.Reader) (*Header, error) {
	hdr := make([]byte, v2HeaderLen)
	if _, err := io.ReadFull(br, hdr); err != nil {
		return nil, fmt.Errorf("proxyproto: reading v2 header: %w", firstErr(err))
	}
	verCmd := hdr[v2VerCmd]
	if verCmd&0xF0 != v2Version {
		return nil, fmt.Errorf("proxyproto: bad v2 version 0x%02x", verCmd)
	}
	cmd := verCmd & 0x0F
	if cmd != cmdLocal && cmd != cmdProxy {
		return nil, fmt.Errorf("proxyproto: bad v2 command 0x%02x", cmd)
	}

	addrLen := binary.BigEndian.Uint16(hdr[v2LenOffset : v2LenOffset+2])
	addr := make([]byte, addrLen)
	if _, err := io.ReadFull(br, addr); err != nil {
		return nil, fmt.Errorf("proxyproto: reading v2 address block: %w", firstErr(err))
	}

	if cmd == cmdLocal {
		// Health-check connection the LB originated itself: no client tuple.
		return &Header{Local: true}, nil
	}

	fam := hdr[v2FamProto] & 0xF0
	switch fam {
	case famINET:
		if len(addr) < 12 {
			return nil, errors.New("proxyproto: v2 AF_INET address block too short")
		}
		src := netip.AddrPortFrom(
			netip.AddrFrom4([4]byte(addr[0:4])),
			binary.BigEndian.Uint16(addr[8:10]),
		)
		dst := netip.AddrPortFrom(
			netip.AddrFrom4([4]byte(addr[4:8])),
			binary.BigEndian.Uint16(addr[10:12]),
		)
		return &Header{Source: src, Dest: dst}, nil
	case famINET6:
		if len(addr) < 36 {
			return nil, errors.New("proxyproto: v2 AF_INET6 address block too short")
		}
		src := netip.AddrPortFrom(
			netip.AddrFrom16([16]byte(addr[0:16])).Unmap(),
			binary.BigEndian.Uint16(addr[32:34]),
		)
		dst := netip.AddrPortFrom(
			netip.AddrFrom16([16]byte(addr[16:32])).Unmap(),
			binary.BigEndian.Uint16(addr[34:36]),
		)
		return &Header{Source: src, Dest: dst}, nil
	case famUnspec, famUNIX:
		// No usable TCP/IP client tuple — fall back to the socket peer.
		return &Header{Local: true}, nil
	default:
		return nil, fmt.Errorf("proxyproto: unknown v2 family 0x%02x", fam)
	}
}

// SourceTCPAddr returns the recovered source as a *net.TCPAddr (the type the listener
// wrapper reports as RemoteAddr), or nil for a Local header.
func (h *Header) SourceTCPAddr() *net.TCPAddr {
	if h.Local || !h.Source.IsValid() {
		return nil
	}
	return net.TCPAddrFromAddrPort(h.Source)
}
