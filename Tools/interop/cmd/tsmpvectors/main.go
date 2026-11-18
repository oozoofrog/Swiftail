// tsmpvectors generates TSMP disco key advertisement vectors for SwiftailEngine unit tests using the Go reference implementation
// and produces Tests/SwiftailEngineTests/Fixtures/tsmp-vectors.json.
//
// Contents: the bytes from `packet.TSMPDiscoKeyAdvertisement.Marshal` for each (source address, destination address, disco key) tuple. Before writing the
// bytes, the tool parses them again with `packet.Parsed.Decode` and `AsTSMPDiscoAdvertisement` to check that the addresses and key match.
// Parser edge cases (short body, another type byte, IPv6, and IPv4 and IPv6 fragments) include the results of `Parsed.Decode` and
// `AsTSMPDiscoAdvertisement`.
//
// Public keys are made using SHA-256("swiftail-vectors/tsmp/<number>") as X25519 private key input (public test values,
// never production keys). Addresses are tailnet addresses for documentation and tests. With no time, randomness, or production values, output is deterministic.
//
// Origin: tailscale.com v1.104.6 (`net/packet/tsmp.go`, identical to v1.104.7), BSD-3-Clause.
//
// Run `go run ./cmd/tsmpvectors <output file>` in Tools/interop (use the environment variables in README.md).
// If no output file is supplied, write to standard output.
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"runtime/debug"

	"go4.org/mem"
	"golang.org/x/crypto/curve25519"
	"tailscale.com/net/packet"
	"tailscale.com/types/ipproto"
	"tailscale.com/types/key"
)

const reference = "tailscale.com v1.104.6"

type vectors struct {
	Reference      string          `json:"reference"`
	Advertisements []advertisement `json:"advertisements"`
	Parse          []parseCase     `json:"parse"`
}

// advertisement is the input and output of one Marshal call.
type advertisement struct {
	Name   string `json:"name"`
	Src    string `json:"src"`
	Dst    string `json:"dst"`
	Key    string `json:"key"`
	Packet string `json:"packet"`
}

// parseCase is the result of passing a handcrafted TSMP packet to AsTSMPDiscoAdvertisement. Key is empty for non-advertisements.
type parseCase struct {
	Name   string `json:"name"`
	Packet string `json:"packet"`
	Key    string `json:"key,omitempty"`
}

func main() {
	check(verifyReference())

	k1, k2 := testKey(1), testKey(2)
	inputs := []struct {
		name     string
		src, dst string
		key      key.DiscoPublic
	}{
		{"ipv4", "100.64.0.1", "100.64.0.2", k1},
		{"ipv4-other-key", "100.101.102.103", "100.64.0.1", k2},
		{"ipv6", "fd7a:115c:a1e0::1", "fd7a:115c:a1e0::2", k1},
	}
	var out vectors
	out.Reference = reference
	for _, in := range inputs {
		ad := packet.TSMPDiscoKeyAdvertisement{Src: netip.MustParseAddr(in.src), Dst: netip.MustParseAddr(in.dst), Key: in.key}
		b, err := ad.Marshal()
		check(err)
		got, ok := parse(b)
		require(ok && got.Src == ad.Src && got.Dst == ad.Dst && got.Key == ad.Key, "%s: reparsed value differs", in.name)
		out.Advertisements = append(out.Advertisements, advertisement{
			Name: in.name, Src: in.src, Dst: in.dst, Key: hexKey(in.key), Packet: hex.EncodeToString(b),
		})
	}

	// Parsing boundaries: 33-byte body (valid), 34 bytes (trailing byte), 32 bytes (short), and type 'p' (ping).
	base := packet.TSMPDiscoKeyAdvertisement{Src: netip.MustParseAddr("100.64.0.2"), Dst: netip.MustParseAddr("100.64.0.1"), Key: k2}
	full, err := base.Marshal()
	check(err)
	payload := full[20:]
	cases := []struct {
		name    string
		payload []byte
	}{
		{"payload-33", payload},
		{"payload-34-trailing", append(append([]byte{}, payload...), 0xEE)},
		{"payload-32-short", payload[:32]},
		{"type-ping", append([]byte{'p'}, payload[1:]...)},
		{"zero-key", append([]byte{'a'}, make([]byte, 32)...)},
	}
	var packets []parseInput
	for _, c := range cases {
		packets = append(packets, parseInput{c.name, packet.Generate(packet.IP4Header{IPProto: 99, Src: base.Src, Dst: base.Dst}, c.payload)})
	}

	// IPv6 advertisement and fragments. The fragment header (Next Header 44) contains next header 99, offset (8-byte units) and M bit, and ID 1.
	// For IPv4 fragments, change only the flags and offset field and recompute the header checksum. Offset 10 is Go's `minFragBlks`.
	v6Src, v6Dst := netip.MustParseAddr("fd7a:115c:a1e0::2"), netip.MustParseAddr("fd7a:115c:a1e0::1")
	v6 := func(proto uint8, body []byte) []byte {
		return packet.Generate(packet.IP6Header{IPProto: ipproto.Proto(proto), Src: v6Src, Dst: v6Dst}, body)
	}
	fragment := func(offset uint16, more bool) []byte {
		field := offset << 3
		if more {
			field |= 1
		}
		return append([]byte{99, 0, byte(field >> 8), byte(field), 0, 0, 0, 1}, payload...)
	}
	v4 := packet.Generate(packet.IP4Header{IPProto: 99, Src: base.Src, Dst: base.Dst}, payload)
	packets = append(packets,
		parseInput{"ipv6-payload-33", v6(99, payload)},
		parseInput{"ipv4-fragment-more", withIPv4FlagsAndOffset(v4, 0x2000)},
		parseInput{"ipv4-fragment-offset-1", withIPv4FlagsAndOffset(v4, 0x0001)},
		parseInput{"ipv4-fragment-offset-10", withIPv4FlagsAndOffset(v4, 0x000A)},
		parseInput{"ipv6-first-fragment-more", v6(44, fragment(0, true))},
		parseInput{"ipv6-first-fragment-last", v6(44, fragment(0, false))},
		parseInput{"ipv6-later-fragment", v6(44, fragment(10, false))},
	)
	for _, in := range packets {
		pc := parseCase{Name: in.name, Packet: hex.EncodeToString(in.packet)}
		if got, ok := parse(in.packet); ok {
			pc.Key = hexKey(got.Key)
		}
		out.Parse = append(out.Parse, pc)
	}

	data, err := json.MarshalIndent(out, "", "  ")
	check(err)
	data = append(data, '\n')
	if len(os.Args) < 2 {
		_, err = os.Stdout.Write(data)
		check(err)
		return
	}
	check(os.WriteFile(os.Args[1], data, 0o644))
}

type parseInput struct {
	name   string
	packet []byte
}

// withIPv4FlagsAndOffset copies IPv4 packet b, sets its flags and fragment offset field to v, and recomputes the header checksum.
func withIPv4FlagsAndOffset(b []byte, v uint16) []byte {
	out := append([]byte{}, b...)
	out[6], out[7] = byte(v>>8), byte(v)
	out[10], out[11] = 0, 0
	var sum uint32
	for i := 0; i < 20; i += 2 {
		sum += uint32(out[i])<<8 | uint32(out[i+1])
	}
	for sum > 0xFFFF {
		sum = sum&0xFFFF + sum>>16
	}
	checksum := ^uint16(sum)
	out[10], out[11] = byte(checksum>>8), byte(checksum)
	return out
}

func parse(b []byte) (packet.TSMPDiscoKeyAdvertisement, bool) {
	var p packet.Parsed
	p.Decode(b)
	return p.AsTSMPDiscoAdvertisement()
}

func testKey(number int) key.DiscoPublic {
	seed := sha256.Sum256([]byte(fmt.Sprintf("swiftail-vectors/tsmp/%d", number)))
	var public [32]byte
	curve25519.ScalarBaseMult(&public, &seed)
	return key.DiscoPublicFromRaw32(mem.B(public[:]))
}

func hexKey(k key.DiscoPublic) string {
	raw := k.Raw32()
	return hex.EncodeToString(raw[:])
}

// verifyReference checks that the build used the reference version of tailscale.com without a replace.
func verifyReference() error {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return fmt.Errorf("build information is missing")
	}
	for _, dep := range info.Deps {
		if dep.Path != "tailscale.com" {
			continue
		}
		if dep.Replace != nil {
			return fmt.Errorf("tailscale.com has a replace: %s", dep.Replace.Path)
		}
		if "tailscale.com "+dep.Version != reference {
			return fmt.Errorf("not the reference version: %s", dep.Version)
		}
		return nil
	}
	return fmt.Errorf("tailscale.com is not a dependency")
}

func check(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func require(ok bool, format string, args ...any) {
	if !ok {
		check(fmt.Errorf(format, args...))
	}
}
