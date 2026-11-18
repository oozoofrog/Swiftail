package main

import (
	"net/netip"

	"go4.org/mem"
	"golang.org/x/crypto/nacl/box"
	"golang.org/x/crypto/nacl/secretbox"
	"tailscale.com/disco"
	"tailscale.com/types/key"
)

// discoPart is the disco section.
type discoPart struct {
	Messages []sealedMessage `json:"messages"`
	Parse    []parseCase     `json:"parse"`
}

// sealedMessage is one message and its outer format sealed from sender to recipient.
// Go generates only the plaintext and sealed packet bytes. The other fields describe the same message in human-readable form.
type sealedMessage struct {
	Name      string `json:"name"`
	Sender    string `json:"sender"`
	Receiver  string `json:"receiver"`
	Message   result `json:"message"`
	Plaintext string `json:"plaintext"`
	Nonce     string `json:"nonce"`
	Packet    string `json:"packet"`
}

// parseCase is the result of passing plaintext to `disco.Parse`. Error holds Go's error text on failure, and Result holds the result on success.
type parseCase struct {
	Name      string  `json:"name"`
	Plaintext string  `json:"plaintext"`
	Result    *result `json:"result,omitempty"`
	Error     string  `json:"error,omitempty"`
}

// result is a parsed message. The fields used depend on Kind.
// relay covers types (0x04–0x09) that Go parses and Swiftail does not.
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
		{"Ping with NodeKey", a, b, &disco.Ping{TxID: txID, NodeKey: key.NodePublicFromRaw32(mem.B(nodeKey[:]))}},
		{"Ping without NodeKey", a, b, &disco.Ping{TxID: txID2}},
		{"Ping with NodeKey and 10 bytes of padding", a, b, &disco.Ping{TxID: txID, NodeKey: key.NodePublicFromRaw32(mem.B(nodeKey[:])), Padding: 10}},
		{"Pong, IPv4", b, a, &disco.Pong{TxID: txID, Src: netip.MustParseAddrPort("127.0.0.1:41641")}},
		{"Pong, IPv6", b, a, &disco.Pong{TxID: txID2, Src: netip.MustParseAddrPort("[2001:db8::7]:5060")}},
		{"CallMeMaybe with no addresses", a, b, &disco.CallMeMaybe{}},
		{"CallMeMaybe with one address", a, b, &disco.CallMeMaybe{MyNumber: []netip.AddrPort{
			netip.MustParseAddrPort("192.0.2.1:41641"),
		}}},
		{"CallMeMaybe with three addresses (two IPv4 and one IPv6)", b, a, &disco.CallMeMaybe{MyNumber: []netip.AddrPort{
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

// fixedNonce is 24 bytes derived from the message number. It keeps nonces distinct for messages sealed with the same key.
func fixedNonce(index int) [24]byte {
	var n [24]byte
	for i := range n {
		n[i] = byte(index*24 + i)
	}
	return n
}

// seal produces `magic ‖ sender public key ‖ nonce ‖ secretbox(plaintext)` with a fixed nonce (notes §3.1 and §3.2 item 3).
func seal(from, to testKey, plaintext []byte, nonce [24]byte) []byte {
	private := raw32(from.Seed)
	peer := raw32(to.Public)
	var shared [32]byte
	box.Precompute(&shared, &peer, &private)

	packet := append([]byte(disco.Magic), mustHex(from.Public)...)
	packet = append(packet, nonce[:]...)
	return secretbox.Seal(packet, plaintext, &nonce, &shared)
}

// verifySealed opens the sealed bytes through Go's actual opening path (`key.DiscoPrivate.Shared(...).Open`).
func verifySealed(from, to testKey, plaintext, packet []byte) {
	require(disco.LooksLikeDiscoWrapper(packet), "packet does not look like disco")
	source, ok := disco.Source(packet)
	require(ok && equal(source, mustHex(from.Public)), "could not read the sender's key")

	receiver := key.DiscoPrivateFromRaw32(mem.B(mustHex(to.Seed)))
	sender := key.DiscoPublicFromRaw32(mem.B(source))
	opened, ok := receiver.Shared(sender).Open(packet[len(disco.Magic)+32:])
	require(ok, "Go could not open the sealed bytes")
	require(equal(opened, plaintext), "opened plaintext differs")
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

// parseCases contains the results of passing the edge cases in notes §7.2 item 1 to `disco.Parse`.
func parseCases(txID [12]byte, nodeKey [32]byte) []parseCase {
	body := func(length int, prefix ...byte) []byte {
		out := make([]byte, length)
		copy(out, prefix)
		return out
	}
	withHeader := func(kind, version byte, body []byte) []byte {
		return append([]byte{kind, version}, body...)
	}
	// 18 bytes for address i: IPv4-mapped 192.0.2.<i>:<1000+i>.
	mapped := func(i byte) []byte {
		out := make([]byte, 18)
		out[10], out[11] = 0xff, 0xff
		copy(out[12:], []byte{192, 0, 2, i})
		out[16], out[17] = 0x03, 0xe8+i
		return out
	}
	// Native IPv6 2001:db8::<i>:<2000+i>.
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
		{"Empty plaintext", nil},
		{"1-byte plaintext", []byte{0x01}},

		{"11-byte Ping body", withHeader(0x01, 0, txID[:11])},
		{"12-byte Ping body (TxID only)", withHeader(0x01, 0, pingBody())},
		{"13-byte Ping body (too short for NodeKey)", withHeader(0x01, 0, pingBody([]byte{0xaa}))},
		{"43-byte Ping body (one byte short of NodeKey)", withHeader(0x01, 0, pingBody(nodeKey[:31]))},
		{"44-byte Ping body (NodeKey)", withHeader(0x01, 0, pingBody(nodeKey[:]))},
		{"45-byte Ping body (NodeKey and one byte of padding)", withHeader(0x01, 0, pingBody(nodeKey[:], []byte{0}))},
		{"44-byte Ping body with a 32-byte all-zero NodeKey", withHeader(0x01, 0, pingBody(body(32)))},
		{"76-byte Ping body with a zero NodeKey and padding", withHeader(0x01, 0, pingBody(body(64)))},
		{"Ping version 7", withHeader(0x01, 7, pingBody(nodeKey[:]))},
		{"1000-byte Ping body (NodeKey and long padding)", withHeader(0x01, 0, join(pingBody(nodeKey[:]), body(956)))},

		{"29-byte Pong body", withHeader(0x02, 0, pongBody(mapped(1))[:29])},
		{"30-byte Pong body, IPv4-mapped", withHeader(0x02, 0, pongBody(mapped(1)[:16]))},
		{"30-byte Pong body, IPv6", withHeader(0x02, 0, pongBody(native(1)[:16]))},
		{"31-byte Pong body (trailing byte ignored)", withHeader(0x02, 0, join(pongBody(mapped(1)[:16]), []byte{0xee}))},
		{"Pong version 1", withHeader(0x02, 1, pongBody(mapped(1)[:16]))},

		{"Empty CallMeMaybe body", withHeader(0x03, 0, nil)},
		{"17-byte CallMeMaybe body", withHeader(0x03, 0, mapped(1)[:17])},
		{"18-byte CallMeMaybe body (one IPv4-mapped address)", withHeader(0x03, 0, mapped(1))},
		{"19-byte CallMeMaybe body", withHeader(0x03, 0, join(mapped(1), []byte{0}))},
		{"35-byte CallMeMaybe body", withHeader(0x03, 0, join(mapped(1), mapped(2))[:35])},
		{"36-byte CallMeMaybe body (IPv4-mapped and IPv6 addresses)", withHeader(0x03, 0, join(mapped(1), native(2)))},
		{"CallMeMaybe version 1 with an 18-byte body", withHeader(0x03, 1, mapped(1))},

		{"Type 0x00", withHeader(0x00, 0, body(30))},
		{"Type 0x0a", withHeader(0x0a, 0, body(30))},
		{"Type 0xff", withHeader(0xff, 0, body(30))},
		{"Type 0x04 (BindUDPRelayEndpoint), 72-byte body", withHeader(0x04, 0, body(72))},
		{"Type 0x05, 72-byte body", withHeader(0x05, 0, body(72))},
		{"Type 0x06, 72-byte body", withHeader(0x06, 0, body(72))},
		{"Type 0x07 (CallMeMaybeVia), 142-byte body", withHeader(0x07, 0, body(142))},
		{"Type 0x08, 68-byte body", withHeader(0x08, 0, body(68))},
		{"Type 0x09, 146-byte body", withHeader(0x09, 0, body(146))},
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
