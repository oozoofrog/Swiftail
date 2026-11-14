package main

import (
	"net/netip"

	"go4.org/mem"
	"golang.org/x/crypto/nacl/box"
	"golang.org/x/crypto/nacl/secretbox"
	"tailscale.com/disco"
	"tailscale.com/types/key"
)

// discoPart는 disco 절이다.
type discoPart struct {
	Messages []sealedMessage `json:"messages"`
	Parse    []parseCase     `json:"parse"`
}

// sealedMessage는 메시지 하나와 그것을 보낸 쪽 → 받는 쪽으로 봉한 겉 형식이다.
// 평문과 봉한 패킷만 Go가 만든 바이트이고 나머지 필드는 같은 메시지를 사람이 읽는 형태로 적은 것이다.
type sealedMessage struct {
	Name      string `json:"name"`
	Sender    string `json:"sender"`
	Receiver  string `json:"receiver"`
	Message   result `json:"message"`
	Plaintext string `json:"plaintext"`
	Nonce     string `json:"nonce"`
	Packet    string `json:"packet"`
}

// parseCase는 평문을 `disco.Parse`에 넣은 결과다. 오류면 Error에 Go의 오류 문장이, 아니면 Result가 있다.
type parseCase struct {
	Name      string  `json:"name"`
	Plaintext string  `json:"plaintext"`
	Result    *result `json:"result,omitempty"`
	Error     string  `json:"error,omitempty"`
}

// result는 해석된 메시지다. Kind에 따라 쓰는 필드가 다르다.
// relay는 Go가 해석하지만 Swiftail은 해석하지 않는 종류(0x04–0x09)다.
type result struct {
	Kind      string   `json:"kind"`
	TxID      string   `json:"txID,omitempty"`
	NodeKey   string   `json:"nodeKey,omitempty"`
	Padding   *int     `json:"padding,omitempty"`
	Src       string   `json:"src,omitempty"`
	Endpoints []string `json:"endpoints,omitempty"`
}

func buildDisco(a, b testKey) discoPart {
	part := discoPart{}

	nodeKey := [32]byte{}
	for i := range nodeKey {
		nodeKey[i] = 0x30 + byte(i)
	}
	txID := [12]byte{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc}
	txID2 := [12]byte{0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7, 0xc8, 0xc9, 0xca, 0xcb}

	type send struct {
		name       string
		sender, to testKey
		message    disco.Message
	}
	sends := []send{
		{"Ping, NodeKey 있음", a, b, &disco.Ping{TxID: txID, NodeKey: key.NodePublicFromRaw32(mem.B(nodeKey[:]))}},
		{"Ping, NodeKey 없음", a, b, &disco.Ping{TxID: txID2}},
		{"Ping, NodeKey와 패딩 10", a, b, &disco.Ping{TxID: txID, NodeKey: key.NodePublicFromRaw32(mem.B(nodeKey[:])), Padding: 10}},
		{"Pong, IPv4", b, a, &disco.Pong{TxID: txID, Src: netip.MustParseAddrPort("127.0.0.1:41641")}},
		{"Pong, IPv6", b, a, &disco.Pong{TxID: txID2, Src: netip.MustParseAddrPort("[2001:db8::7]:5060")}},
		{"CallMeMaybe, 주소 0개", a, b, &disco.CallMeMaybe{}},
		{"CallMeMaybe, 주소 1개", a, b, &disco.CallMeMaybe{MyNumber: []netip.AddrPort{
			netip.MustParseAddrPort("192.0.2.1:41641"),
		}}},
		{"CallMeMaybe, 주소 3개(IPv4 둘, IPv6 하나)", b, a, &disco.CallMeMaybe{MyNumber: []netip.AddrPort{
			netip.MustParseAddrPort("127.0.0.1:41641"),
			netip.MustParseAddrPort("[2001:db8::7]:5060"),
			netip.MustParseAddrPort("198.51.100.9:1"),
		}}},
	}

	for index, s := range sends {
		plaintext := s.message.AppendMarshal(nil)
		nonce := fixedNonce(index)
		packet := seal(s.sender, s.to, plaintext, nonce)
		verifySealed(s.sender, s.to, plaintext, packet)

		parsed, err := disco.Parse(plaintext)
		check(err)
		part.Messages = append(part.Messages, sealedMessage{
			Name:      s.name,
			Sender:    s.sender.Name,
			Receiver:  s.to.Name,
			Message:   describe(parsed),
			Plaintext: hexString(plaintext),
			Nonce:     hexString(nonce[:]),
			Packet:    hexString(packet),
		})
	}

	part.Parse = parseCases(txID, nodeKey)
	return part
}

// fixedNonce는 메시지 번호에서 정해지는 24바이트다. 같은 키로 봉하는 메시지끼리 nonce가 겹치지 않게 한다.
func fixedNonce(index int) [24]byte {
	var n [24]byte
	for i := range n {
		n[i] = byte(index*24 + i)
	}
	return n
}

// seal은 `magic ‖ 보낸 쪽 공개 키 ‖ nonce ‖ secretbox(평문)`을 고정 nonce로 만든다(노트 3.1·3.2 3).
func seal(from, to testKey, plaintext []byte, nonce [24]byte) []byte {
	private := raw32(from.Seed)
	peer := raw32(to.Public)
	var shared [32]byte
	box.Precompute(&shared, &peer, &private)

	packet := append([]byte(disco.Magic), mustHex(from.Public)...)
	packet = append(packet, nonce[:]...)
	return secretbox.Seal(packet, plaintext, &nonce, &shared)
}

// verifySealed는 Go가 실제로 쓰는 열기 경로(`key.DiscoPrivate.Shared(...).Open`)로 봉한 바이트를 열어 본다.
func verifySealed(from, to testKey, plaintext, packet []byte) {
	require(disco.LooksLikeDiscoWrapper(packet), "disco로 보이지 않는다")
	source, ok := disco.Source(packet)
	require(ok && equal(source, mustHex(from.Public)), "보낸 쪽 키를 읽지 못했다")

	receiver := key.DiscoPrivateFromRaw32(mem.B(mustHex(to.Seed)))
	sender := key.DiscoPublicFromRaw32(mem.B(source))
	opened, ok := receiver.Shared(sender).Open(packet[len(disco.Magic)+32:])
	require(ok, "Go가 봉한 바이트를 열지 못했다")
	require(equal(opened, plaintext), "열린 평문이 다르다")
}

func raw32(hexValue string) [32]byte {
	var out [32]byte
	copy(out[:], mustHex(hexValue))
	return out
}

func describe(message disco.Message) result {
	switch m := message.(type) {
	case *disco.Ping:
		padding := m.Padding
		out := result{Kind: "ping", TxID: hexString(m.TxID[:]), Padding: &padding}
		if !m.NodeKey.IsZero() {
			raw := m.NodeKey.Raw32()
			out.NodeKey = hexString(raw[:])
		}
		return out
	case *disco.Pong:
		return result{Kind: "pong", TxID: hexString(m.TxID[:]), Src: m.Src.String()}
	case *disco.CallMeMaybe:
		endpoints := []string{}
		for _, endpoint := range m.MyNumber {
			endpoints = append(endpoints, endpoint.String())
		}
		return result{Kind: "callMeMaybe", Endpoints: endpoints}
	default:
		return result{Kind: "relay"}
	}
}

// parseCases는 노트 7.2 1의 경계를 `disco.Parse`에 넣은 결과다.
func parseCases(txID [12]byte, nodeKey [32]byte) []parseCase {
	body := func(length int, prefix ...byte) []byte {
		out := make([]byte, length)
		copy(out, prefix)
		return out
	}
	withHeader := func(kind, version byte, body []byte) []byte {
		return append([]byte{kind, version}, body...)
	}
	// 주소 i를 만드는 18바이트: IPv4-mapped 192.0.2.<i>:<1000+i>.
	mapped := func(i byte) []byte {
		out := make([]byte, 18)
		out[10], out[11] = 0xff, 0xff
		copy(out[12:], []byte{192, 0, 2, i})
		out[16], out[17] = 0x03, 0xe8+i
		return out
	}
	// 보통 IPv6 2001:db8::<i>:<2000+i>.
	native := func(i byte) []byte {
		out := make([]byte, 18)
		copy(out, []byte{0x20, 0x01, 0x0d, 0xb8})
		out[15] = i
		out[16], out[17] = 0x07, 0xd0+i
		return out
	}
	join := func(parts ...[]byte) []byte {
		var out []byte
		for _, part := range parts {
			out = append(out, part...)
		}
		return out
	}

	pingBody := func(extra ...[]byte) []byte { return join(append([][]byte{txID[:]}, extra...)...) }
	pongBody := func(src []byte) []byte { return join(txID[:], src, []byte{0x13, 0x88}) }

	cases := []struct {
		name      string
		plaintext []byte
	}{
		{"평문 0바이트", nil},
		{"평문 1바이트", []byte{0x01}},

		{"Ping 본문 11바이트", withHeader(0x01, 0, txID[:11])},
		{"Ping 본문 12바이트(TxID만)", withHeader(0x01, 0, pingBody())},
		{"Ping 본문 13바이트(NodeKey 자리가 모자람)", withHeader(0x01, 0, pingBody([]byte{0xaa}))},
		{"Ping 본문 43바이트(NodeKey 자리가 1바이트 모자람)", withHeader(0x01, 0, pingBody(nodeKey[:31]))},
		{"Ping 본문 44바이트(NodeKey)", withHeader(0x01, 0, pingBody(nodeKey[:]))},
		{"Ping 본문 45바이트(NodeKey와 패딩 1)", withHeader(0x01, 0, pingBody(nodeKey[:], []byte{0}))},
		{"Ping 본문 44바이트, 32바이트가 모두 0인 NodeKey", withHeader(0x01, 0, pingBody(body(32)))},
		{"Ping 본문 76바이트, 0 NodeKey와 패딩", withHeader(0x01, 0, pingBody(body(64)))},
		{"Ping version 7", withHeader(0x01, 7, pingBody(nodeKey[:]))},
		{"Ping 본문 1000바이트(NodeKey와 긴 패딩)", withHeader(0x01, 0, join(pingBody(nodeKey[:]), body(956)))},

		{"Pong 본문 29바이트", withHeader(0x02, 0, pongBody(mapped(1))[:29])},
		{"Pong 본문 30바이트, IPv4-mapped", withHeader(0x02, 0, pongBody(mapped(1)[:16]))},
		{"Pong 본문 30바이트, IPv6", withHeader(0x02, 0, pongBody(native(1)[:16]))},
		{"Pong 본문 31바이트(뒤 바이트 무시)", withHeader(0x02, 0, join(pongBody(mapped(1)[:16]), []byte{0xee}))},
		{"Pong version 1", withHeader(0x02, 1, pongBody(mapped(1)[:16]))},

		{"CallMeMaybe 본문 0바이트", withHeader(0x03, 0, nil)},
		{"CallMeMaybe 본문 17바이트", withHeader(0x03, 0, mapped(1)[:17])},
		{"CallMeMaybe 본문 18바이트(주소 1개, IPv4-mapped)", withHeader(0x03, 0, mapped(1))},
		{"CallMeMaybe 본문 19바이트", withHeader(0x03, 0, join(mapped(1), []byte{0}))},
		{"CallMeMaybe 본문 35바이트", withHeader(0x03, 0, join(mapped(1), mapped(2))[:35])},
		{"CallMeMaybe 본문 36바이트(주소 2개, IPv4-mapped와 IPv6)", withHeader(0x03, 0, join(mapped(1), native(2)))},
		{"CallMeMaybe version 1, 본문 18바이트", withHeader(0x03, 1, mapped(1))},

		{"종류 0x00", withHeader(0x00, 0, body(30))},
		{"종류 0x0a", withHeader(0x0a, 0, body(30))},
		{"종류 0xff", withHeader(0xff, 0, body(30))},
		{"종류 0x04(BindUDPRelayEndpoint), 본문 72바이트", withHeader(0x04, 0, body(72))},
		{"종류 0x05, 본문 72바이트", withHeader(0x05, 0, body(72))},
		{"종류 0x06, 본문 72바이트", withHeader(0x06, 0, body(72))},
		{"종류 0x07(CallMeMaybeVia), 본문 142바이트", withHeader(0x07, 0, body(142))},
		{"종류 0x08, 본문 68바이트", withHeader(0x08, 0, body(68))},
		{"종류 0x09, 본문 146바이트", withHeader(0x09, 0, body(146))},
	}

	var out []parseCase
	for _, c := range cases {
		entry := parseCase{Name: c.name, Plaintext: hexString(c.plaintext)}
		parsed, err := disco.Parse(c.plaintext)
		if err != nil {
			entry.Error = err.Error()
		} else {
			described := describe(parsed)
			entry.Result = &described
		}
		out = append(out, entry)
	}
	return out
}
