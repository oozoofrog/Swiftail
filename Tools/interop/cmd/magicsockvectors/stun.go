package main

import (
	"encoding/binary"
	"net/netip"

	"tailscale.com/net/stun"
)

// stunPart is the STUN section. It provides reference values for STUN parsing (unit 3).
type stunPart struct {
	Requests []stunRequest `json:"requests"`
	Parse    []stunCase    `json:"parse"`
}

// stunRequest is the bytes from `stun.Request(txID)`.
type stunRequest struct {
	TxID   string `json:"txID"`
	Packet string `json:"packet"`
}

// stunCase is the result of passing one packet to `stun.Is` (plus byte 1 must be 0x01) and `stun.ParseResponse`.
// LooksLikeSTUN uses the same criteria as magicsock's classifier (`packetLooksLike`).
type stunCase struct {
	Name          string `json:"name"`
	Packet        string `json:"packet"`
	LooksLikeSTUN bool   `json:"looksLikeSTUN"`
	TxID          string `json:"txID,omitempty"`
	Mapped        string `json:"mapped,omitempty"`
	Error         string `json:"error,omitempty"`
}

func buildSTUN() stunPart {
	txID := stun.TxID{0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98}
	part := stunPart{}
	part.Requests = []stunRequest{{TxID: hexString(txID[:]), Packet: hexString(stun.Request(txID))}}

	ipv4 := stun.Response(txID, netip.MustParseAddrPort("127.0.0.1:41641"))
	ipv4Other := stun.Response(txID, netip.MustParseAddrPort("192.0.2.77:65535"))
	ipv6 := stun.Response(txID, netip.MustParseAddrPort("[2001:db8::7]:5060"))

	// 0x8020: a server incorrectly moved the XOR-MAPPED-ADDRESS number into the comprehension-optional range (stun.go comment).
	alternate := append([]byte(nil), ipv4...)
	binary.BigEndian.PutUint16(alternate[20:], 0x8020)

	// Response containing only MAPPED-ADDRESS.
	mapped := response(txID, attribute(0x0001, []byte{0, 1, 0x0b, 0xb8, 192, 0, 2, 5}))
	// Response with SOFTWARE first (5 bytes, requiring padding) followed by XOR-MAPPED-ADDRESS.
	withSoftware := response(txID, append(attribute(0x8022, []byte("hello")), ipv4[20:]...))
	// Discard bytes after the declared length.
	trailing := append(append([]byte(nil), ipv4...), 0xde, 0xad, 0xbe, 0xef)
	// XOR-MAPPED-ADDRESS takes precedence when both XOR-MAPPED-ADDRESS and MAPPED-ADDRESS are present.
	both := response(txID, append(ipv4[20:], attribute(0x0001, []byte{0, 1, 0x00, 0x50, 10, 0, 0, 1})...))

	cases := []struct {
		name   string
		packet []byte
	}{
		{"IPv4 response", ipv4},
		{"IPv4 response with port 65535", ipv4Other},
		{"IPv6 response", ipv6},
		{"XOR-MAPPED-ADDRESS 0x8020", alternate},
		{"Response with only MAPPED-ADDRESS", mapped},
		{"XOR-MAPPED-ADDRESS after a SOFTWARE attribute", withSoftware},
		{"Bytes appended after the declared length", trailing},
		{"XOR-MAPPED-ADDRESS takes precedence over MAPPED-ADDRESS", both},

		{"19 bytes", ipv4[:19]},
		{"Wrong cookie", mutate(ipv4, 4, 0x20)},
		{"Request type 00 01", mutate(ipv4, 0, 0x00, 0x01)},
		{"Type 01 11 (error response)", mutate(ipv4, 1, 0x11)},
		{"Top two bits are not zero", mutate(ipv4, 0, 0x41)},
		{"Declared length exceeds remaining bytes", mutate(ipv4, 3, byte(len(ipv4)-20+1))},
		{"Attribute length exceeds remaining bytes", mutate(ipv4, 23, 0xff)},
		{"Attribute header is four bytes short", response(txID, []byte{0x00, 0x20, 0x00})},
		{"family 3", mutate(ipv4, 25, 0x03)},
		{"family 0", mutate(ipv4, 25, 0x00)},
		{"XOR address is too short for its family", response(txID, attribute(0x0020, []byte{0, 2, 0x12, 0x34, 1, 2, 3, 4}))},
		{"No address attribute (only SOFTWARE)", response(txID, attribute(0x8022, []byte("tailnode")))},
		{"No attributes", response(txID, nil)},
		{"MAPPED-ADDRESS family 3", response(txID, attribute(0x0001, []byte{0, 3, 0x0b, 0xb8, 192, 0, 2, 5}))},
	}

	for _, c := range cases {
		entry := stunCase{
			Name:          c.name,
			Packet:        hexString(c.packet),
			LooksLikeSTUN: stun.Is(c.packet) && c.packet[1] == 0x01,
		}
		id, addr, err := stun.ParseResponse(c.packet)
		if err != nil {
			entry.Error = err.Error()
		} else {
			entry.TxID = hexString(id[:])
			entry.Mapped = addr.String()
		}
		part.Parse = append(part.Parse, entry)
	}
	return part
}

// response appends attributes to a success response header (length = number of attribute bytes).
func response(txID stun.TxID, attributes []byte) []byte {
	out := []byte{0x01, 0x01, 0, 0, 0x21, 0x12, 0xa4, 0x42}
	binary.BigEndian.PutUint16(out[2:], uint16(len(attributes)))
	out = append(out, txID[:]...)
	return append(out, attributes...)
}

// attribute constructs one TLV, zero-padded to a 4-byte boundary.
func attribute(kind uint16, value []byte) []byte {
	out := binary.BigEndian.AppendUint16(nil, kind)
	out = binary.BigEndian.AppendUint16(out, uint16(len(value)))
	out = append(out, value...)
	for len(out)%4 != 0 {
		out = append(out, 0)
	}
	return out
}

// mutate overwrites bytes beginning at offset in a copy of packet.
func mutate(packet []byte, offset int, values ...byte) []byte {
	out := append([]byte(nil), packet...)
	copy(out[offset:], values)
	return out
}
