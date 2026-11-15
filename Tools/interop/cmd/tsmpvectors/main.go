// tsmpvectors는 SwiftailEngine 단위 시험의 TSMP disco 키 광고 벡터를 Go 기준 구현으로 뽑아
// Tests/SwiftailEngineTests/Fixtures/tsmp-vectors.json을 만든다.
//
// 담는 것: (출발 주소, 목적 주소, disco 키)마다 `packet.TSMPDiscoKeyAdvertisement.Marshal`의 바이트. 도구는 그
// 바이트를 `packet.Parsed.Decode`와 `AsTSMPDiscoAdvertisement`로 다시 해석해 같은 주소와 키가 나오는지 확인한 뒤에
// 쓴다. 해석 쪽 경계 사례(짧은 본문, 다른 종류 바이트, IPv6, IPv4·IPv6 조각)는 `Parsed.Decode`와
// `AsTSMPDiscoAdvertisement`의 결과를 담는다.
//
// 키는 SHA-256("swiftail-vectors/tsmp/<번호>")를 X25519 개인 키 입력으로 써서 만든 공개 키다(시험용 공개 값, 운영
// 키가 아니다). 주소는 문서·시험용 tailnet 주소다. 시각·난수·운영 값은 쓰지 않으므로 출력은 결정적이다.
//
// 출처 tailscale.com v1.104.6(`net/packet/tsmp.go`, v1.104.7과 같다), BSD-3-Clause.
//
// 실행: Tools/interop에서 `go run ./cmd/tsmpvectors <출력 파일>`(환경 변수는 README.md의 것).
// 출력 파일을 주지 않으면 표준 출력에 쓴다.
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

// advertisement는 Marshal 한 번의 입력과 출력이다.
type advertisement struct {
	Name   string `json:"name"`
	Src    string `json:"src"`
	Dst    string `json:"dst"`
	Key    string `json:"key"`
	Packet string `json:"packet"`
}

// parseCase는 손으로 만든 TSMP 패킷 하나를 AsTSMPDiscoAdvertisement에 넣은 결과다. 광고가 아니면 Key가 비어 있다.
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
		require(ok && got.Src == ad.Src && got.Dst == ad.Dst && got.Key == ad.Key, "%s: 다시 해석한 값이 다르다", in.name)
		out.Advertisements = append(out.Advertisements, advertisement{
			Name: in.name, Src: in.src, Dst: in.dst, Key: hexKey(in.key), Packet: hex.EncodeToString(b),
		})
	}

	// 해석 경계: 본문 33바이트(정상), 34바이트(뒤에 남는 바이트), 32바이트(짧음), 종류 'p'(ping).
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

	// IPv6 광고와 조각. 조각 머리(Next Header 44)는 다음 머리 99, offset(8바이트 단위)·M 비트, ID 1이다.
	// IPv4 조각은 flags·offset 필드만 바꾸고 머리 체크섬을 다시 계산한다. offset 10은 Go `minFragBlks`다.
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

// withIPv4FlagsAndOffset는 IPv4 패킷 b의 flags·fragment offset 필드를 v로 바꾸고 머리 체크섬을 다시 계산한 사본이다.
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

// verifyReference는 replace 없이 기준 버전의 tailscale.com으로 빌드되었는지 확인한다.
func verifyReference() error {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return fmt.Errorf("빌드 정보가 없다")
	}
	for _, dep := range info.Deps {
		if dep.Path != "tailscale.com" {
			continue
		}
		if dep.Replace != nil {
			return fmt.Errorf("tailscale.com이 replace 되었다: %s", dep.Replace.Path)
		}
		if "tailscale.com "+dep.Version != reference {
			return fmt.Errorf("기준 버전이 아니다: %s", dep.Version)
		}
		return nil
	}
	return fmt.Errorf("tailscale.com이 의존에 없다")
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
