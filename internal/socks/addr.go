// Package socks holds every low-level SOCKS5 piece Club Connect needs: address encoding and
// decoding, the client side (used to talk to Psiphon, Tor and Aether), the UDP ASSOCIATE client,
// the reply writer and the connect-only gate used by the WARP chains.
package socks

import (
	"bufio"
	"errors"
	"io"
	"net"
	"net/netip"
	"strconv"
)

// Protocol constants (RFC 1928).
const (
	Version5 = 5

	CmdConnect      = 1
	CmdUDPAssociate = 3

	AtypIPv4   = 1
	AtypDomain = 3
	AtypIPv6   = 4

	RepSuccess          = 0
	RepGeneralFailure   = 1
	RepConnRefused      = 5
	RepCmdNotSupported  = 7
	RepAddrNotSupported = 8
)

// ErrBadAddrType is returned for an ATYP byte that is not IPv4, IPv6 or a domain name.
var ErrBadAddrType = errors.New("bad address type")

// AddrBytes encodes ATYP + address + port the way SOCKS5 wants it. IP literals are sent as real
// addresses (v4 / v6) instead of as a "domain name" that happens to look like one.
func AddrBytes(host string, port int) []byte {
	var b []byte
	if ip, err := netip.ParseAddr(host); err == nil {
		ip = ip.Unmap()
		if ip.Is4() {
			a := ip.As4()
			b = append([]byte{AtypIPv4}, a[:]...)
		} else {
			a := ip.As16()
			b = append([]byte{AtypIPv6}, a[:]...)
		}
	} else {
		if len(host) > 255 {
			host = host[:255]
		}
		b = append([]byte{AtypDomain, byte(len(host))}, host...)
	}
	return append(b, byte(port>>8), byte(port))
}

// SplitHostPort is net.SplitHostPort plus the numeric port.
func SplitHostPort(addr string) (host string, port int, err error) {
	h, ps, err := net.SplitHostPort(addr)
	if err != nil {
		return "", 0, err
	}
	p, err := strconv.Atoi(ps)
	if err != nil {
		return "", 0, err
	}
	return h, p, nil
}

// ReadAddr reads the address part of a request after its ATYP byte. raw is ATYP + address
// exactly as the peer wrote it (the port is not included).
func ReadAddr(br *bufio.Reader, atyp byte) (host string, raw []byte, err error) {
	switch atyp {
	case AtypIPv4, AtypIPv6:
		n := 4
		if atyp == AtypIPv6 {
			n = 16
		}
		b := make([]byte, n)
		if _, err = io.ReadFull(br, b); err != nil {
			return
		}
		return net.IP(b).String(), append([]byte{atyp}, b...), nil
	case AtypDomain:
		l, e := br.ReadByte()
		if e != nil {
			return "", nil, e
		}
		b := make([]byte, l)
		if _, err = io.ReadFull(br, b); err != nil {
			return
		}
		return string(b), append([]byte{AtypDomain, l}, b...), nil
	}
	return "", nil, ErrBadAddrType
}

// ReadReplyAddr reads the BND.ADDR / BND.PORT part of a reply whose ATYP byte was atyp.
// ip is nil for a domain-name address.
func ReadReplyAddr(r io.Reader, atyp byte) (ip net.IP, port int, err error) {
	switch atyp {
	case AtypIPv4:
		b := make([]byte, 4)
		if _, err = io.ReadFull(r, b); err != nil {
			return
		}
		ip = net.IP(b)
	case AtypIPv6:
		b := make([]byte, 16)
		if _, err = io.ReadFull(r, b); err != nil {
			return
		}
		ip = net.IP(b)
	case AtypDomain:
		l := make([]byte, 1)
		if _, err = io.ReadFull(r, l); err != nil {
			return
		}
		if _, err = io.CopyN(io.Discard, r, int64(l[0])); err != nil {
			return
		}
	default:
		err = ErrUnknownAtyp
		return
	}
	pb := make([]byte, 2)
	if _, err = io.ReadFull(r, pb); err != nil {
		return
	}
	port = int(pb[0])<<8 | int(pb[1])
	return
}

// Reply writes a SOCKS5 reply with the given code; bind (optional) fills BND.ADDR/BND.PORT.
func Reply(c net.Conn, code byte, bind *net.UDPAddr) {
	r := []byte{Version5, code, 0, AtypIPv4, 0, 0, 0, 0, 0, 0}
	if bind != nil {
		if ip4 := bind.IP.To4(); ip4 != nil {
			copy(r[4:8], ip4)
		}
		r[8], r[9] = byte(bind.Port>>8), byte(bind.Port)
	}
	c.Write(r)
}
