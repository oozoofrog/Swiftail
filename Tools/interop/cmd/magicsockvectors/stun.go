package main

import (
	"encoding/binary"
	"net/netip"

	"tailscale.com/net/stun"
)

// stunPart는 STUN 절이다. STUN 해석(단위 3)의 기준값이다.
type stunPart struct {
	Requests []stunRequest `json:"requests"`
	Parse    []stunCase    `json:"parse"`
}

// stunRequest는 `stun.Request(txID)`의 바이트다.
type stunRequest struct {
	TxID   string `json:"txID"`
	Packet string `json:"packet"`
}

// stunCase는 패킷 하나를 `stun.Is`(+ 바이트 1이 0x01)와 `stun.ParseResponse`에 넣은 결과다.
// LooksLikeSTUN은 magicsock의 분류(`packetLooksLike`)와 같은 조건이다.
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

	// 0x8020: XOR-MAPPED-ADDRESS 번호를 comprehension-optional 범위로 잘못 옮긴 서버(stun.go 주석).
	alternate := append([]byte(nil), ipv4...)
	binary.BigEndian.PutUint16(alternate[20:], 0x8020)

	// MAPPED-ADDRESS만 있는 응답.
	mapped := response(txID, attribute(0x0001, []byte{0, 1, 0x0b, 0xb8, 192, 0, 2, 5}))
	// SOFTWARE(패딩이 필요한 5바이트)가 먼저 오고 XOR-MAPPED-ADDRESS가 뒤에 오는 응답.
	withSoftware := response(txID, append(attribute(0x8022, []byte("hello")), ipv4[20:]...))
	// 선언 길이 뒤에 붙은 바이트는 버린다.
	trailing := append(append([]byte(nil), ipv4...), 0xde, 0xad, 0xbe, 0xef)
	// XOR-MAPPED-ADDRESS와 MAPPED-ADDRESS가 함께 있으면 앞의 것이 정본이다.
	both := response(txID, append(ipv4[20:], attribute(0x0001, []byte{0, 1, 0x00, 0x50, 10, 0, 0, 1})...))

	cases := []struct {
		name   string
		packet []byte
	}{
		{"IPv4 응답", ipv4},
		{"IPv4 응답, 포트 65535", ipv4Other},
		{"IPv6 응답", ipv6},
		{"XOR-MAPPED-ADDRESS 0x8020", alternate},
		{"MAPPED-ADDRESS만 있는 응답", mapped},
		{"SOFTWARE 속성 뒤의 XOR-MAPPED-ADDRESS", withSoftware},
		{"선언 길이 뒤에 붙은 바이트", trailing},
		{"XOR와 MAPPED가 함께 있으면 XOR가 정본", both},

		{"19바이트", ipv4[:19]},
		{"cookie가 틀림", mutate(ipv4, 4, 0x20)},
		{"요청 타입 00 01", mutate(ipv4, 0, 0x00, 0x01)},
		{"타입 01 11(오류 응답)", mutate(ipv4, 1, 0x11)},
		{"상위 2비트가 0이 아님", mutate(ipv4, 0, 0x41)},
		{"선언 길이가 남은 바이트보다 큼", mutate(ipv4, 3, byte(len(ipv4)-20+1))},
		{"속성 길이가 남은 바이트보다 큼", mutate(ipv4, 23, 0xff)},
		{"속성 머리가 4바이트 모자람", response(txID, []byte{0x00, 0x20, 0x00})},
		{"family 3", mutate(ipv4, 25, 0x03)},
		{"family 0", mutate(ipv4, 25, 0x00)},
		{"XOR 주소가 family보다 짧음", response(txID, attribute(0x0020, []byte{0, 2, 0x12, 0x34, 1, 2, 3, 4}))},
		{"주소 속성 없음(SOFTWARE만)", response(txID, attribute(0x8022, []byte("tailnode")))},
		{"속성 없음", response(txID, nil)},
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

// response는 성공 응답 머리(길이 = 속성 바이트 수)에 속성들을 붙인다.
func response(txID stun.TxID, attributes []byte) []byte {
	out := []byte{0x01, 0x01, 0, 0, 0x21, 0x12, 0xa4, 0x42}
	binary.BigEndian.PutUint16(out[2:], uint16(len(attributes)))
	out = append(out, txID[:]...)
	return append(out, attributes...)
}

// attribute는 TLV 하나를 4바이트 경계까지 0으로 채워 만든다.
func attribute(kind uint16, value []byte) []byte {
	out := binary.BigEndian.AppendUint16(nil, kind)
	out = binary.BigEndian.AppendUint16(out, uint16(len(value)))
	out = append(out, value...)
	for len(out)%4 != 0 {
		out = append(out, 0)
	}
	return out
}

// mutate는 packet의 복사본에서 offset부터 바이트를 덮어쓴다.
func mutate(packet []byte, offset int, values ...byte) []byte {
	out := append([]byte(nil), packet...)
	copy(out[offset:], values)
	return out
}
