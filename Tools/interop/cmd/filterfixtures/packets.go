package main

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net/netip"
)

// Packet construction follows the field offsets in net/packet/packet.go:132-408.
// The code below writes test inputs independently. It does not duplicate the reference parser or decision code.
func ipPacket(src, dst string, proto uint8, payload []byte) []byte {
	source, destination := netip.MustParseAddr(src), netip.MustParseAddr(dst)
	var b []byte
	if source.Is4() && destination.Is4() {
		b = make([]byte, 20+len(payload))
		b[0], b[8], b[9] = 0x45, 64, proto
		binary.BigEndian.PutUint16(b[2:4], uint16(len(b)))
		copy(b[12:16], source.AsSlice())
		copy(b[16:20], destination.AsSlice())
		copy(b[20:], payload)
		binary.BigEndian.PutUint16(b[10:12], checksum(b[:20]))
	} else if source.Is6() && destination.Is6() {
		b = make([]byte, 40+len(payload))
		b[0], b[6], b[7] = 0x60, proto, 64
		binary.BigEndian.PutUint16(b[4:6], uint16(len(payload)))
		copy(b[8:24], source.AsSlice())
		copy(b[24:40], destination.AsSlice())
		copy(b[40:], payload)
	} else {
		panic("test packet address family mismatch")
	}
	return b
}

func checksum(b []byte) uint16 {
	var sum uint32
	for len(b) >= 2 {
		sum += uint32(binary.BigEndian.Uint16(b[:2]))
		b = b[2:]
	}
	if len(b) != 0 {
		sum += uint32(b[0]) << 8
	}
	for sum>>16 != 0 {
		sum = sum&0xffff + sum>>16
	}
	return ^uint16(sum)
}

func transportPacket(src, dst string, proto uint8, sport, dport uint16, flags uint8) []byte {
	length := 8
	if proto == 6 {
		length = 20
	} else if proto == 132 {
		length = 12
	}
	payload := make([]byte, length)
	binary.BigEndian.PutUint16(payload[:2], sport)
	binary.BigEndian.PutUint16(payload[2:4], dport)
	checkOffset := 6
	if proto == 6 {
		payload[12], payload[13] = 0x50, flags
		checkOffset = 16
	} else if proto == 17 {
		binary.BigEndian.PutUint16(payload[4:6], uint16(length))
	}
	if proto == 6 || proto == 17 {
		pseudo := append([]byte{}, netip.MustParseAddr(src).AsSlice()...)
		pseudo = append(pseudo, netip.MustParseAddr(dst).AsSlice()...)
		if netip.MustParseAddr(src).Is4() {
			pseudo = append(pseudo, 0, proto, 0, byte(length))
		} else {
			pseudo = append(pseudo, 0, 0, 0, byte(length), 0, 0, 0, proto)
		}
		value := checksum(append(pseudo, payload...))
		if value == 0 && proto == 17 {
			value = 0xffff
		}
		binary.BigEndian.PutUint16(payload[checkOffset:checkOffset+2], value)
	}
	return ipPacket(src, dst, proto, payload)
}

func icmpPacket(src, dst string, kind, code uint8) []byte {
	proto := uint8(1)
	payload := []byte{kind, code, 0, 0, 0, 0, 0, 0}
	pseudo := []byte{}
	if netip.MustParseAddr(src).Is6() {
		proto = 58
		pseudo = append(pseudo, netip.MustParseAddr(src).AsSlice()...)
		pseudo = append(pseudo, netip.MustParseAddr(dst).AsSlice()...)
		pseudo = append(pseudo, 0, 0, 0, 8, 0, 0, 0, proto)
	}
	binary.BigEndian.PutUint16(payload[2:4], checksum(append(pseudo, payload...)))
	return ipPacket(src, dst, proto, payload)
}

func inbound(name string, b []byte) step {
	return step{Name: name, Direction: "in", Packet: hex.EncodeToString(b)}
}

func outbound(name string, b []byte) step {
	return step{Name: name, Direction: "out", Packet: hex.EncodeToString(b)}
}

func differs(st step, expected, reason string) step {
	st.SwiftailExpected, st.SwiftailDiffers = expected, reason
	return st
}

func replace(name, rules string, locals []string) step {
	return step{Name: name, Direction: "replace", Rules: rules, LocalAddresses: locals}
}

func rule(src, dst string, first, last uint16, proto string) string {
	return fmt.Sprintf(`[{"SrcIPs":[%q],"DstPorts":[{"IP":%q,"Ports":{"First":%d,"Last":%d}}],"IPProto":%s}]`, src, dst, first, last, proto)
}
