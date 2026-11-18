package main

import (
	"encoding/binary"
	"fmt"
)

func scenarios() []scenario {
	var all []scenario
	for _, family := range []struct {
		name, self, peer, third, outside, cidr, hostCIDR, interval, multicast, linkLocal string
	}{
		{"IPv4", "100.64.0.1", "100.64.0.2", "100.64.0.3", "100.64.1.2", "100.64.0.0/24", "100.64.0.2/24", "100.64.0.2-100.64.0.3", "224.0.0.1", "169.254.0.1"},
		{"IPv6", "fd7a:115c:a1e0::1", "fd7a:115c:a1e0::2", "fd7a:115c:a1e0::3", "fd7a:115c:a1e0:1::2", "fd7a:115c:a1e0::/64", "fd7a:115c:a1e0::2/64", "fd7a:115c:a1e0::2-fd7a:115c:a1e0::3", "ff02::1", "fe80::1"},
	} {
		self, peer, third := family.self, family.peer, family.third
		locals := []string{self}
		add := func(name, rules string, steps ...step) {
			all = append(all, scenario{Name: family.name + " " + name, Rules: rules, LocalAddresses: locals, Steps: steps})
		}
		udp := func(src, dst string, sport, dport uint16) []byte {
			return transportPacket(src, dst, 17, sport, dport, 0)
		}
		syn := func(src, dst string, port uint16) []byte {
			return transportPacket(src, dst, 6, 40000, port, 2)
		}
		echo := uint8(8)
		reply := uint8(0)
		icmpProto := "[1]"
		if family.name == "IPv6" {
			echo, icmpProto = 128, "[58]"
			reply = 129
		}
		for _, source := range []struct{ name, text string }{
			{"Any source", "*"}, {"Source CIDR", family.cidr},
			{"Single source address", peer}, {"Inclusive source range", family.interval},
		} {
			add(source.name, rule(source.text, self, 7, 7, "[]"),
				inbound("First boundary address", udp(peer, self, 40000, 7)),
				inbound("Second boundary address", udp(third, self, 40000, 7)),
				inbound("Address just below range", udp(self, self, 40000, 7)),
				inbound("Address outside CIDR", udp(family.outside, self, 40000, 7)))
		}
		for _, proto := range []uint8{6, 17} {
			var steps []step
			for _, port := range []uint16{6, 7, 9, 10} {
				steps = append(steps, inbound(fmt.Sprintf("Destination port %d", port), transportPacket(peer, self, proto, 40000, port, 2)))
			}
			add(fmt.Sprintf("Protocol %d port range", proto), rule("*", self, 7, 9, fmt.Sprintf("[%d]", proto)), steps...)
		}
		add("All ports and reversed range", rule("*", self, 0, 65535, "[17]"),
			inbound("Minimum port", udp(peer, self, 40000, 0)),
			inbound("Maximum port", udp(peer, self, 40000, 65535)),
			replace("Replace with reversed range", rule("*", self, 9, 7, "[17]"), locals),
			inbound("Inside reversed range", udp(peer, self, 40000, 8)))
		for _, protocols := range []struct{ name, raw string }{
			{"Empty array uses default protocols", "[]"}, {"Null uses default protocols", "null"},
			{"TCP only", "[6]"}, {"UDP only", "[17]"}, {"ICMP only", icmpProto},
			{"Other protocol 47 only", "[47]"}, {"Other protocol 254 only", "[254]"},
			{"Out-of-range protocol only", "[-1,256,65536]"}, {"Out-of-range protocol and UDP", "[-1,17,256]"},
		} {
			add(protocols.name, rule("*", self, 0, 65535, protocols.raw),
				inbound("TCP SYN", syn(peer, self, 7)),
				inbound("UDP", udp(peer, self, 40000, 7)),
				inbound("ICMP echo request ignores protocol and port", icmpPacket(peer, self, echo, 0)),
				inbound("Other protocol 47", ipPacket(peer, self, 47, make([]byte, 8))),
				inbound("Other protocol 254", ipPacket(peer, self, 254, make([]byte, 8))))
		}
		add("Other protocols require all ports", rule("*", self, 7, 9, "[47]"),
			inbound("Reject because the rule covers only some ports", ipPacket(peer, self, 47, make([]byte, 8))))
		// These are edge cases included in the contract's other(UInt8) that the Go parser and filter treat specially.
		var specialNumbers []step
		if family.name == "IPv4" {
			specialNumbers = append(specialNumbers, inbound("Wire protocol 0 maps to Go Unknown", ipPacket(peer, self, 0, make([]byte, 8))))
		}
		specialNumbers = append(specialNumbers, inbound("Wire protocol 255 must not be accepted as internal Fragment", ipPacket(peer, self, 255, make([]byte, 8))))
		add("Explicit protocol number boundaries", rule("*", self, 0, 65535, "[0,255]"), specialNumbers...)
		add("Special handling of SCTP protocol 132", rule("*", self, 0, 65535, "[132]"),
			inbound("All ports for SCTP", transportPacket(peer, self, 132, 40000, 7, 0)),
			replace("Allow only some ports", rule("*", self, 7, 7, "[132]"), locals),
			inbound("SCTP checks the destination port like UDP", transportPacket(peer, self, 132, 40000, 7, 0)),
			inbound("Out-of-range SCTP port", transportPacket(peer, self, 132, 40000, 8, 0)),
			replace("Remove rules", "[]", locals),
			outbound("SCTP also records reverse flows", transportPacket(self, peer, 132, 40000, 7, 0)),
			inbound("Allow SCTP reply using its flow record", transportPacket(peer, self, 132, 7, 40000, 0)))
		add("Omit IPProto", fmt.Sprintf(`[{"SrcIPs":["*"],"DstPorts":[{"IP":%q,"Ports":{"First":7,"Last":7}}]}]`, self),
			inbound("UDP in the default set", udp(peer, self, 40000, 7)),
			inbound("TCP in the default set", syn(peer, self, 7)),
			inbound("ICMP in the default set", icmpPacket(peer, self, echo, 0)))
		for _, bad := range []struct{ name, text string }{
			{"CIDR with host bits", family.hostCIDR}, {"Unparseable address", "invalid-address"},
			{"Reversed address range", third + "-" + peer},
		} {
			add(bad.name+" source", rule(bad.text, self, 7, 7, "[]"),
				inbound("Reject when only invalid entries are present", udp(peer, self, 40000, 7)),
				replace("Add a valid source entry too", fmt.Sprintf(`[{"SrcIPs":[%q,%q],"DstPorts":[{"IP":%q,"Ports":{"First":7,"Last":7}}]}]`, bad.text, peer, self), locals),
				inbound("Keep valid entries despite the error", udp(peer, self, 40000, 7)),
				inbound("Another source that is not allowed", udp(third, self, 40000, 7)))
			add(bad.name+" destination", rule("*", bad.text, 7, 7, "[]"),
				inbound("Only invalid destination entries", udp(peer, self, 40000, 7)),
				replace("Add a valid destination entry too", fmt.Sprintf(`[{"SrcIPs":["*"],"DstPorts":[{"IP":%q,"Ports":{"First":7,"Last":7}},{"IP":%q,"Ports":{"First":7,"Last":7}}]}]`, bad.text, self), locals),
				inbound("Keep the valid destination", udp(peer, self, 40000, 7)))
		}
		for _, deprecated := range []struct{ name, raw string }{
			{"SrcBits", fmt.Sprintf(`{"SrcIPs":[%q],"SrcBits":[32]}`, peer)},
			{"DstPorts.Bits", fmt.Sprintf(`{"SrcIPs":["*"],"DstPorts":[{"IP":%q,"Bits":32,"Ports":{"First":0,"Last":65535}}]}`, self)},
		} {
			broad := rule("*", "*", 0, 65535, "[]")
			broken := broad[:len(broad)-1] + "," + deprecated.raw + "]"
			add(deprecated.name+" fail closed", broken,
				inbound("Discard the preceding broad rule too", udp(peer, self, 40000, 7)),
				replace("Install a broad rule", broad, locals),
				inbound("Installation succeeds", syn(peer, self, 7)),
				replace("Replace again with an invalid rule", broken, locals),
				inbound("Discard the previous broad rule", syn(peer, self, 7)))
		}
		add("CapGrant alone does not allow traffic", fmt.Sprintf(`[{"SrcIPs":["*"],"CapGrant":[{"Dsts":[%q],"CapMap":{"fixture:grant":[{}]}}]}]`, self+map[bool]string{true: "/128", false: "/32"}[family.name == "IPv6"]),
			inbound("TCP SYN", syn(peer, self, 7)), inbound("UDP", udp(peer, self, 40000, 7)),
			inbound("ICMP echo request", icmpPacket(peer, self, echo, 0)))
		add("TCP flags and stateless allowance", "[]",
			inbound("SYN requires a rule", syn(peer, self, 7)),
			inbound("SYN-ACK", transportPacket(peer, self, 6, 40000, 7, 0x12)),
			inbound("ACK", transportPacket(peer, self, 6, 40000, 7, 0x10)),
			inbound("RST", transportPacket(peer, self, 6, 40000, 7, 0x04)),
			inbound("No flags", transportPacket(peer, self, 6, 40000, 7, 0)),
			inbound("SYN-RST is checked as SYN", transportPacket(peer, self, 6, 40000, 7, 0x06)))
		add("Reverse UDP tuple", "[]",
			inbound("Reply before sending", udp(peer, self, 7, 40000)),
			outbound("Send first", udp(self, peer, 40000, 7)),
			inbound("Exact reverse tuple", udp(peer, self, 7, 40000)),
			inbound("Only source address differs", udp(third, self, 7, 40000)),
			inbound("Only destination address differs", udp(peer, third, 7, 40000)),
			inbound("Only source port differs", udp(peer, self, 8, 40000)),
			inbound("Only destination port differs", udp(peer, self, 7, 40001)),
			inbound("Only protocol differs, using TCP SYN", transportPacket(peer, self, 6, 7, 40000, 2)),
			inbound("Check the exact reverse tuple again", udp(peer, self, 7, 40000)))
		// Make both addresses local so notForUs does not mask the destination address difference.
		all[len(all)-1].LocalAddresses = []string{self, third}
		add("An inbound allowance creates no flow", rule("*", self, 7, 7, "[17]"),
			inbound("Receive by rule", udp(peer, self, 40000, 7)),
			replace("Remove rules", "[]", locals),
			inbound("Same inbound packet was not recorded", udp(peer, self, 40000, 7)),
			inbound("Reverse tuple was not recorded either", udp(self, peer, 7, 40000)))
		add("Rule replacement preserves flows", rule("*", self, 7, 7, "[17]"),
			outbound("Record outbound UDP", udp(self, peer, 40000, 7)),
			replace("Remove the allow rule", "[]", locals),
			inbound("Keep the reply flow record", udp(peer, self, 7, 40000)),
			inbound("Reject a new flow", udp(peer, self, 40000, 7)),
			replace("Change self address", "[]", []string{third}),
			inbound("Check self address before checking flows", udp(peer, self, 7, 40000)),
			replace("Restore self address", "[]", locals),
			inbound("The flow record is still present", udp(peer, self, 7, 40000)))
		for _, refresh := range []bool{false, true} {
			var steps []step
			for i := 0; i < 512; i++ {
				steps = append(steps, outbound(fmt.Sprintf("Insert flow %d", i), udp(self, peer, uint16(10000+i), 7)))
			}
			if refresh {
				steps = append(steps, inbound("Refresh oldest flow 0 by looking it up", udp(peer, self, 7, 10000)))
			}
			steps = append(steps,
				outbound("Insert flow 513", udp(self, peer, 10512, 7)),
				inbound("Look up flow 0", udp(peer, self, 7, 10000)),
				inbound("Look up flow 1", udp(peer, self, 7, 10001)),
				inbound("Look up the new flow", udp(peer, self, 7, 10512)))
			add(fmt.Sprintf("UDP LRU with 513 flows and refresh on lookup=%t", refresh), "[]", steps...)
		}
		kinds := []uint8{8, 0, 3, 11, 12, 18, 13}
		if family.name == "IPv6" {
			kinds = []uint8{128, 129, 1, 2, 3, 4, 133}
		}
		var icmpSteps []step
		for _, kind := range kinds {
			st := inbound(fmt.Sprintf("ICMP type %d", kind), icmpPacket(peer, self, kind, 0))
			if family.name == "IPv4" && (kind == 12 || kind == 18) {
				expected := "drop"
				if kind == 12 {
					expected = "accept"
				}
				st = differs(st, expected, "ICMPv4 error types: Go uses 3, 11, and 18. Swiftail uses 3, 11, and 12.")
			}
			icmpSteps = append(icmpSteps, st)
		}
		add("ICMP replies and errors are stateless", "[]", icmpSteps...)
		add("ICMP ignores protocol and port", rule(peer, self, 7, 7, "[17]"),
			inbound("Allow an echo request using a UDP rule", icmpPacket(peer, self, echo, 0)),
			inbound("Reject a different source", icmpPacket(third, self, echo, 0)),
			inbound("Reject a different destination", icmpPacket(peer, third, echo, 0)))
		add("Check whether the destination is a self address", rule("*", "*", 0, 65535, "[]"),
			inbound("UDP to another address", udp(peer, third, 40000, 7)),
			inbound("Reject TCP ACK to another address too", transportPacket(peer, third, 6, 40000, 7, 0x10)),
			inbound("Reject ICMP reply to another address too", icmpPacket(peer, third, reply, 0)))
		add("Multicast and link-local destinations", rule("*", "*", 0, 65535, "[]"),
			inbound("multicast", udp(peer, family.multicast, 40000, 7)),
			inbound("link-local", udp(peer, family.linkLocal, 40000, 7)),
			replace("Add special addresses to the self address list too", rule("*", "*", 0, 65535, "[]"), []string{self, family.multicast, family.linkLocal}),
			inbound("Reject multicast even on the self address list", udp(peer, family.multicast, 40000, 7)),
			inbound("Reject link-local even on the self address list", udp(peer, family.linkLocal, 40000, 7)))
		capRule := rule("cap:fixture:test", self, 7, 7, "[]")
		add("Discard only the capability source entry", capRule,
			differs(inbound("Go capability match", udp(peer, self, 40000, 7)), "drop", "M3 does not support cap: source entries"),
			differs(inbound("Allow ICMP by capability too", icmpPacket(peer, self, echo, 0)), "drop", "M3 does not support cap: source entries"),
			replace("Install an ordinary address entry alongside it", fmt.Sprintf(`[{"SrcIPs":["cap:fixture:test",%q],"DstPorts":[{"IP":%q,"Ports":{"First":7,"Last":7}}]}]`, third, self), locals),
			differs(inbound("Keep the ordinary entry", udp(third, self, 40000, 7)), "accept", "Drop the cap: entry and keep the address entry in the same rule"),
			differs(inbound("The capability entry remains excluded", udp(peer, self, 40000, 7)), "drop", "M3 does not support cap: source entries"))
		all[len(all)-1].CapabilitySources = []string{peer}
		add("TSMP is an engine control packet", "[]",
			differs(inbound("TSMP ping", ipPacket(peer, self, 99, []byte{'p', 0, 1, 2, 3, 4, 5, 6, 7})), "tsmp", "The Go filter allows this packet. Swiftail consumes it before filtering. This step checks TSMP parsing."))
		add("Bytes after the declared length", rule("*", self, 7, 7, "[17]"),
			differs(inbound("Trim bytes after a complete packet", append(udp(peer, self, 40000, 7), 0xaa, 0xbb)), "trimmedAccept", "Parse after trimming to the declared length"))
		shortDeclared := udp(peer, self, 40000, 7)
		if family.name == "IPv4" {
			binary.BigEndian.PutUint16(shortDeclared[2:4], 20)
			fixIPv4Checksum(shortDeclared)
		} else {
			binary.BigEndian.PutUint16(shortDeclared[4:6], 0)
		}
		add("Transport header beyond the declared length", rule("*", self, 7, 7, "[17]"),
			differs(inbound("The UDP header is in the buffer beyond the declared length", shortDeclared), "malformed", "Swiftail trims to the declared length before checking the minimum transport header length"))
		if family.name == "IPv4" {
			var fragments []step
			for _, bits := range []uint16{0x2000, 1, 10} {
				b := udp(peer, self, 40000, 7)
				binary.BigEndian.PutUint16(b[6:8], bits)
				fixIPv4Checksum(b)
				fragments = append(fragments, differs(inbound(fmt.Sprintf("MF or offset %#x", bits), b), "fragment", "M3 rejects all IPv4 fragments, including the first"))
			}
			add("IPv4 fragments", rule("*", self, 7, 7, "[17]"), fragments...)
			b := ipPacket(peer, self, 47, make([]byte, 8))
			b[0] = 0x44
			fixIPv4Checksum(b)
			add("Minimum IPv4 IHL", rule("*", self, 0, 65535, "[47]"),
				differs(inbound("IHL 4", b), "malformed", "Swiftail rejects IHL below 5. Go does not enforce the minimum."))
			add("ICMPv4 type 18 is allowed when a rule matches", rule(peer, self, 7, 7, "[17]"),
				differs(inbound("Type 18 address match", icmpPacket(peer, self, 18, 0)), "accept", "Swiftail treats type 18 as ordinary ICMP and checks address rules"),
				differs(inbound("Type 18 source mismatch", icmpPacket(third, self, 18, 0)), "drop", "Swiftail treats type 18 as ordinary ICMP and checks address rules"))
		} else {
			var fragments []step
			for _, bits := range []uint16{0, 1, 8, 80} {
				full := udp(peer, self, 40000, 7)
				frag := []byte{17, 0, 0, 0, 0, 0, 0, 1}
				binary.BigEndian.PutUint16(frag[2:4], bits)
				b := ipPacket(peer, self, 44, append(frag, full[40:]...))
				fragments = append(fragments, differs(inbound(fmt.Sprintf("Fragment field %#x", bits), b), "fragment", "M3 rejects all IPv6 packets with next header 44"))
			}
			add("IPv6 fragments", rule("*", self, 7, 7, "[17]"), fragments...)
			var extensions []step
			for _, proto := range []uint8{0, 43, 50, 51, 60, 135, 139, 140} {
				extensions = append(extensions, differs(inbound(fmt.Sprintf("next-header %d", proto), ipPacket(peer, self, proto, make([]byte, 24))), "extensionHeader", "M3 rejects IPv6 extension headers without walking them"))
			}
			add("IPv6 extension headers", rule("*", self, 0, 65535, "[0,43,50,51,60,135,139,140]"), extensions...)
		}
	}
	return all
}

func fixIPv4Checksum(b []byte) {
	b[10], b[11] = 0, 0
	binary.BigEndian.PutUint16(b[10:12], checksum(b[:20]))
}
