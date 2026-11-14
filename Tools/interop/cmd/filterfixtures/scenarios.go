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
			{"출발지 전체", "*"}, {"출발지 CIDR", family.cidr},
			{"출발지 단일 주소", peer}, {"출발지 양끝 포함 범위", family.interval},
		} {
			add(source.name, rule(source.text, self, 7, 7, "[]"),
				inbound("첫 경계 주소", udp(peer, self, 40000, 7)),
				inbound("둘째 경계 주소", udp(third, self, 40000, 7)),
				inbound("범위 바로 아래 주소", udp(self, self, 40000, 7)),
				inbound("CIDR 밖 주소", udp(family.outside, self, 40000, 7)))
		}
		for _, proto := range []uint8{6, 17} {
			var steps []step
			for _, port := range []uint16{6, 7, 9, 10} {
				steps = append(steps, inbound(fmt.Sprintf("목적 포트 %d", port), transportPacket(peer, self, proto, 40000, port, 2)))
			}
			add(fmt.Sprintf("프로토콜 %d 포트 범위", proto), rule("*", self, 7, 9, fmt.Sprintf("[%d]", proto)), steps...)
		}
		add("포트 전체와 역순 범위", rule("*", self, 0, 65535, "[17]"),
			inbound("포트 최솟값", udp(peer, self, 40000, 0)),
			inbound("포트 최댓값", udp(peer, self, 40000, 65535)),
			replace("역순 범위로 교체", rule("*", self, 9, 7, "[17]"), locals),
			inbound("역순 범위 가운데", udp(peer, self, 40000, 8)))
		for _, protocols := range []struct{ name, raw string }{
			{"기본 프로토콜 빈 배열", "[]"}, {"기본 프로토콜 null", "null"},
			{"TCP만", "[6]"}, {"UDP만", "[17]"}, {"ICMP만", icmpProto},
			{"기타 47만", "[47]"}, {"기타 254만", "[254]"},
			{"범위 밖 번호만", "[-1,256,65536]"}, {"범위 밖 번호와 UDP", "[-1,17,256]"},
		} {
			add(protocols.name, rule("*", self, 0, 65535, protocols.raw),
				inbound("TCP SYN", syn(peer, self, 7)),
				inbound("UDP", udp(peer, self, 40000, 7)),
				inbound("ICMP echo request 프로토콜과 포트는 무시", icmpPacket(peer, self, echo, 0)),
				inbound("기타 프로토콜 47", ipPacket(peer, self, 47, make([]byte, 8))),
				inbound("기타 프로토콜 254", ipPacket(peer, self, 254, make([]byte, 8))))
		}
		add("기타 프로토콜은 포트 전체만", rule("*", self, 7, 9, "[47]"),
			inbound("전체 포트가 아니므로 거절", ipPacket(peer, self, 47, make([]byte, 8))))
		// 계약의 other(UInt8)에 포함되지만 Go 파서·필터가 특별 취급하는 경계다.
		var specialNumbers []step
		if family.name == "IPv4" {
			specialNumbers = append(specialNumbers, inbound("와이어 번호 0은 Go Unknown", ipPacket(peer, self, 0, make([]byte, 8))))
		}
		specialNumbers = append(specialNumbers, inbound("와이어 번호 255는 내부 Fragment로 허용하지 않음", ipPacket(peer, self, 255, make([]byte, 8))))
		add("명시 프로토콜 번호 경계", rule("*", self, 0, 65535, "[0,255]"), specialNumbers...)
		add("SCTP 번호 132의 특별 취급", rule("*", self, 0, 65535, "[132]"),
			inbound("전체 포트 SCTP", transportPacket(peer, self, 132, 40000, 7, 0)),
			replace("일부 포트만 허용", rule("*", self, 7, 7, "[132]"), locals),
			inbound("SCTP는 UDP처럼 목적 포트로 검사", transportPacket(peer, self, 132, 40000, 7, 0)),
			inbound("범위 밖 SCTP 포트", transportPacket(peer, self, 132, 40000, 8, 0)),
			replace("규칙 제거", "[]", locals),
			outbound("SCTP도 역방향 흐름을 기록", transportPacket(self, peer, 132, 40000, 7, 0)),
			inbound("SCTP 응답 기록으로 허용", transportPacket(peer, self, 132, 7, 40000, 0)))
		add("IPProto 생략", fmt.Sprintf(`[{"SrcIPs":["*"],"DstPorts":[{"IP":%q,"Ports":{"First":7,"Last":7}}]}]`, self),
			inbound("UDP 기본 집합", udp(peer, self, 40000, 7)),
			inbound("TCP 기본 집합", syn(peer, self, 7)),
			inbound("ICMP 기본 집합", icmpPacket(peer, self, echo, 0)))
		for _, bad := range []struct{ name, text string }{
			{"호스트 비트 CIDR", family.hostCIDR}, {"해석 불가 주소", "invalid-address"},
			{"역순 주소 범위", third + "-" + peer},
		} {
			add(bad.name+" 출발지", rule(bad.text, self, 7, 7, "[]"),
				inbound("잘못된 항목만 있으면 거절", udp(peer, self, 40000, 7)),
				replace("유효한 출발지 항목도 추가", fmt.Sprintf(`[{"SrcIPs":[%q,%q],"DstPorts":[{"IP":%q,"Ports":{"First":7,"Last":7}}]}]`, bad.text, peer, self), locals),
				inbound("오류가 있어도 유효 항목 보존", udp(peer, self, 40000, 7)),
				inbound("허용되지 않은 다른 출발지", udp(third, self, 40000, 7)))
			add(bad.name+" 목적지", rule("*", bad.text, 7, 7, "[]"),
				inbound("잘못된 목적지 항목만", udp(peer, self, 40000, 7)),
				replace("유효한 목적지 항목도 추가", fmt.Sprintf(`[{"SrcIPs":["*"],"DstPorts":[{"IP":%q,"Ports":{"First":7,"Last":7}},{"IP":%q,"Ports":{"First":7,"Last":7}}]}]`, bad.text, self), locals),
				inbound("유효 목적지 보존", udp(peer, self, 40000, 7)))
		}
		for _, deprecated := range []struct{ name, raw string }{
			{"SrcBits", fmt.Sprintf(`{"SrcIPs":[%q],"SrcBits":[32]}`, peer)},
			{"DstPorts.Bits", fmt.Sprintf(`{"SrcIPs":["*"],"DstPorts":[{"IP":%q,"Bits":32,"Ports":{"First":0,"Last":65535}}]}`, self)},
		} {
			broad := rule("*", "*", 0, 65535, "[]")
			broken := broad[:len(broad)-1] + "," + deprecated.raw + "]"
			add(deprecated.name+" 전체 닫힘", broken,
				inbound("앞의 넓은 규칙도 버림", udp(peer, self, 40000, 7)),
				replace("넓은 규칙 설치", broad, locals),
				inbound("설치 성공", syn(peer, self, 7)),
				replace("오류 규칙으로 다시 교체", broken, locals),
				inbound("이전 넓은 규칙을 유지하지 않음", syn(peer, self, 7)))
		}
		add("CapGrant만으로 열리지 않음", fmt.Sprintf(`[{"SrcIPs":["*"],"CapGrant":[{"Dsts":[%q],"CapMap":{"fixture:grant":[{}]}}]}]`, self+map[bool]string{true: "/128", false: "/32"}[family.name == "IPv6"]),
			inbound("TCP SYN", syn(peer, self, 7)), inbound("UDP", udp(peer, self, 40000, 7)),
			inbound("ICMP echo request", icmpPacket(peer, self, echo, 0)))
		add("TCP 플래그와 무상태 허용", "[]",
			inbound("SYN은 규칙 필요", syn(peer, self, 7)),
			inbound("SYN-ACK", transportPacket(peer, self, 6, 40000, 7, 0x12)),
			inbound("ACK", transportPacket(peer, self, 6, 40000, 7, 0x10)),
			inbound("RST", transportPacket(peer, self, 6, 40000, 7, 0x04)),
			inbound("플래그 없음", transportPacket(peer, self, 6, 40000, 7, 0)),
			inbound("SYN-RST는 SYN으로 검사", transportPacket(peer, self, 6, 40000, 7, 0x06)))
		add("UDP 역방향 튜플", "[]",
			inbound("보내기 전 응답", udp(peer, self, 7, 40000)),
			outbound("먼저 보냄", udp(self, peer, 40000, 7)),
			inbound("정확한 역방향", udp(peer, self, 7, 40000)),
			inbound("출발 주소만 다름", udp(third, self, 7, 40000)),
			inbound("목적 주소만 다름", udp(peer, third, 7, 40000)),
			inbound("출발 포트만 다름", udp(peer, self, 8, 40000)),
			inbound("목적 포트만 다름", udp(peer, self, 7, 40001)),
			inbound("프로토콜만 TCP SYN", transportPacket(peer, self, 6, 7, 40000, 2)),
			inbound("정확한 역방향 재확인", udp(peer, self, 7, 40000)))
		// 목적 주소 차이가 notForUs에 가려지지 않도록 두 주소 모두 자기 주소로 둔다.
		all[len(all)-1].LocalAddresses = []string{self, third}
		add("수신 허용은 흐름을 만들지 않음", rule("*", self, 7, 7, "[17]"),
			inbound("규칙으로 수신", udp(peer, self, 40000, 7)),
			replace("규칙 제거", "[]", locals),
			inbound("같은 수신은 기록되지 않음", udp(peer, self, 40000, 7)),
			inbound("역방향도 기록되지 않음", udp(self, peer, 7, 40000)))
		add("규칙 교체와 흐름 유지", rule("*", self, 7, 7, "[17]"),
			outbound("UDP 송신 기록", udp(self, peer, 40000, 7)),
			replace("허용 규칙 제거", "[]", locals),
			inbound("응답 기록 유지", udp(peer, self, 7, 40000)),
			inbound("새 흐름은 거절", udp(peer, self, 40000, 7)),
			replace("자기 주소 변경", "[]", []string{third}),
			inbound("흐름보다 자기 주소 검사 우선", udp(peer, self, 7, 40000)),
			replace("자기 주소 복원", "[]", locals),
			inbound("기록은 계속 유지", udp(peer, self, 7, 40000)))
		for _, refresh := range []bool{false, true} {
			var steps []step
			for i := 0; i < 512; i++ {
				steps = append(steps, outbound(fmt.Sprintf("흐름 %d 삽입", i), udp(self, peer, uint16(10000+i), 7)))
			}
			if refresh {
				steps = append(steps, inbound("가장 오래된 흐름 0 조회로 갱신", udp(peer, self, 7, 10000)))
			}
			steps = append(steps,
				outbound("513번째 흐름 삽입", udp(self, peer, 10512, 7)),
				inbound("흐름 0 조회", udp(peer, self, 7, 10000)),
				inbound("흐름 1 조회", udp(peer, self, 7, 10001)),
				inbound("새 흐름 조회", udp(peer, self, 7, 10512)))
			add(fmt.Sprintf("UDP LRU 513개 조회갱신=%t", refresh), "[]", steps...)
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
				st = differs(st, expected, "ICMPv4 오류 집합: Go는 3·11·18, Swiftail은 3·11·12")
			}
			icmpSteps = append(icmpSteps, st)
		}
		add("ICMP 응답과 오류는 무상태", "[]", icmpSteps...)
		add("ICMP는 프로토콜과 포트 무시", rule(peer, self, 7, 7, "[17]"),
			inbound("UDP 규칙으로 echo request 허용", icmpPacket(peer, self, echo, 0)),
			inbound("다른 출발지는 거절", icmpPacket(third, self, echo, 0)),
			inbound("다른 목적지는 거절", icmpPacket(peer, third, echo, 0)))
		add("목적지 자기 주소 검사", rule("*", "*", 0, 65535, "[]"),
			inbound("다른 주소 UDP", udp(peer, third, 40000, 7)),
			inbound("다른 주소 TCP ACK도 거절", transportPacket(peer, third, 6, 40000, 7, 0x10)),
			inbound("다른 주소 ICMP reply도 거절", icmpPacket(peer, third, reply, 0)))
		add("multicast와 link-local 목적지", rule("*", "*", 0, 65535, "[]"),
			inbound("multicast", udp(peer, family.multicast, 40000, 7)),
			inbound("link-local", udp(peer, family.linkLocal, 40000, 7)),
			replace("특수 주소도 자기 주소 목록에 넣음", rule("*", "*", 0, 65535, "[]"), []string{self, family.multicast, family.linkLocal}),
			inbound("자기 주소여도 multicast 거절", udp(peer, family.multicast, 40000, 7)),
			inbound("자기 주소여도 link-local 거절", udp(peer, family.linkLocal, 40000, 7)))
		capRule := rule("cap:fixture:test", self, 7, 7, "[]")
		add("cap 출발지는 항목만 버림", capRule,
			differs(inbound("Go capability 일치", udp(peer, self, 40000, 7)), "drop", "cap: 출발지 항목은 M3에서 지원하지 않음"),
			differs(inbound("ICMP도 capability로 허용", icmpPacket(peer, self, echo, 0)), "drop", "cap: 출발지 항목은 M3에서 지원하지 않음"),
			replace("일반 주소 항목도 함께 설치", fmt.Sprintf(`[{"SrcIPs":["cap:fixture:test",%q],"DstPorts":[{"IP":%q,"Ports":{"First":7,"Last":7}}]}]`, third, self), locals),
			differs(inbound("일반 항목은 보존", udp(third, self, 40000, 7)), "accept", "cap:만 버리고 같은 규칙의 주소 항목은 유지"),
			differs(inbound("cap 항목은 계속 제외", udp(peer, self, 40000, 7)), "drop", "cap: 출발지 항목은 M3에서 지원하지 않음"))
		all[len(all)-1].CapabilitySources = []string{peer}
		add("TSMP는 엔진 제어 패킷", "[]",
			differs(inbound("TSMP ping", ipPacket(peer, self, 99, []byte{'p', 0, 1, 2, 3, 4, 5, 6, 7})), "tsmp", "Go 필터는 허용하지만 Swiftail 엔진이 필터 전에 소비; 여기서는 tsmp 해석만 확인"))
		add("선언 길이 뒤의 바이트", rule("*", self, 7, 7, "[17]"),
			differs(inbound("완전한 패킷 뒤 바이트는 잘라냄", append(udp(peer, self, 40000, 7), 0xaa, 0xbb)), "trimmedAccept", "선언 길이로 자른 뒤 해석"))
		shortDeclared := udp(peer, self, 40000, 7)
		if family.name == "IPv4" {
			binary.BigEndian.PutUint16(shortDeclared[2:4], 20)
			fixIPv4Checksum(shortDeclared)
		} else {
			binary.BigEndian.PutUint16(shortDeclared[4:6], 0)
		}
		add("선언 길이 밖의 전송 머리", rule("*", self, 7, 7, "[17]"),
			differs(inbound("버퍼에는 있지만 선언 길이 안에는 UDP 머리가 없음", shortDeclared), "malformed", "Swiftail은 선언 길이로 자른 뒤 전송 머리 최소 길이를 검사"))
		if family.name == "IPv4" {
			var fragments []step
			for _, bits := range []uint16{0x2000, 1, 10} {
				b := udp(peer, self, 40000, 7)
				binary.BigEndian.PutUint16(b[6:8], bits)
				fixIPv4Checksum(b)
				fragments = append(fragments, differs(inbound(fmt.Sprintf("MF 또는 오프셋 %#x", bits), b), "fragment", "M3은 IPv4 첫 조각·비첫 조각 모두 거절"))
			}
			add("IPv4 조각", rule("*", self, 7, 7, "[17]"), fragments...)
			b := ipPacket(peer, self, 47, make([]byte, 8))
			b[0] = 0x44
			fixIPv4Checksum(b)
			add("IPv4 IHL 최솟값", rule("*", self, 0, 65535, "[47]"),
				differs(inbound("IHL 4", b), "malformed", "Swiftail은 IHL 5 미만 거절; Go는 최솟값 미검사"))
			add("ICMPv4 type 18도 규칙이 있으면 허용", rule(peer, self, 7, 7, "[17]"),
				differs(inbound("type 18 주소 일치", icmpPacket(peer, self, 18, 0)), "accept", "type 18은 Swiftail에서 일반 ICMP이므로 주소 규칙 검사"),
				differs(inbound("type 18 출발지 불일치", icmpPacket(third, self, 18, 0)), "drop", "type 18은 Swiftail에서 일반 ICMP이므로 주소 규칙 검사"))
		} else {
			var fragments []step
			for _, bits := range []uint16{0, 1, 8, 80} {
				full := udp(peer, self, 40000, 7)
				frag := []byte{17, 0, 0, 0, 0, 0, 0, 1}
				binary.BigEndian.PutUint16(frag[2:4], bits)
				b := ipPacket(peer, self, 44, append(frag, full[40:]...))
				fragments = append(fragments, differs(inbound(fmt.Sprintf("Fragment 필드 %#x", bits), b), "fragment", "M3은 IPv6 next-header 44를 모두 거절"))
			}
			add("IPv6 조각", rule("*", self, 7, 7, "[17]"), fragments...)
			var extensions []step
			for _, proto := range []uint8{0, 43, 50, 51, 60, 135, 139, 140} {
				extensions = append(extensions, differs(inbound(fmt.Sprintf("next-header %d", proto), ipPacket(peer, self, proto, make([]byte, 24))), "extensionHeader", "M3은 IPv6 확장 헤더를 순회하지 않고 거절"))
			}
			add("IPv6 확장 헤더", rule("*", self, 0, 65535, "[0,43,50,51,60,135,139,140]"), extensions...)
		}
	}
	return all
}

func fixIPv4Checksum(b []byte) {
	b[10], b[11] = 0, 0
	binary.BigEndian.PutUint16(b[10:12], checksum(b[:20]))
}
