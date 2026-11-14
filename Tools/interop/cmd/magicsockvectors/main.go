// magicsockvectors는 SwiftailMagicsock 단위 시험의 고정 벡터를 Go 기준 구현으로 뽑아
// Tests/SwiftailMagicsockTests/Fixtures/magicsock-vectors.json을 만든다.
//
// 담는 것:
//   - disco: 메시지 종류별 평문(`disco.*.AppendMarshal`)과, 같은 평문을 NaCl box로 봉한 겉 형식 전체.
//     봉하기는 `box.Precompute` + `secretbox.Seal`(고정 nonce)이다. Go의 `key.DiscoShared.Seal`은 nonce를 안에서
//     뽑으므로 고정 nonce가 필요한 이 도구는 같은 계산을 직접 부른다. 만든 바이트는 `key.DiscoPrivate.Shared(...).Open`
//     으로 다시 열어 Go의 실제 열기 경로와 같은지 확인한 뒤에 쓴다.
//   - disco 경계 사례: 평문을 `disco.Parse`에 넣은 결과(메시지 또는 오류).
//   - stun: `stun.Request`, `stun.Response`와 `stun.ParseResponse`의 결과.
//
// 키는 SHA-256("swiftail-vectors/disco/<번호>")를 X25519 개인 키 입력으로 쓴다(시험용 공개 값, 운영 키가 아니다).
// nonce는 메시지 번호에서 정해지는 고정 값이다. 현재 시각·난수·운영 값은 쓰지 않으므로 출력은 결정적이다.
//
// 출처 tailscale.com v1.104.6(`disco/disco.go`, `types/key/disco.go`, `net/stun/stun.go`), BSD-3-Clause.
//
// 실행: Tools/interop에서 `go run ./cmd/magicsockvectors <출력 파일>`(환경 변수는 README.md의 것).
// 출력 파일을 주지 않으면 표준 출력에 쓴다.
package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"runtime/debug"

	"golang.org/x/crypto/curve25519"
)

const reference = "tailscale.com v1.104.6"

// vectors는 JSON 파일의 최상위다.
type vectors struct {
	Reference string    `json:"reference"`
	Keys      []testKey `json:"keys"`
	Disco     discoPart `json:"disco"`
	STUN      stunPart  `json:"stun"`
}

// testKey는 시험용 disco 키 하나다. seed가 X25519 개인 키 입력이다.
type testKey struct {
	Name   string `json:"name"`
	Seed   string `json:"seed"`
	Public string `json:"public"`
}

func main() {
	check(verifyReference())

	keys := []testKey{newTestKey("a", 1), newTestKey("b", 2)}
	out := vectors{
		Reference: reference,
		Keys:      keys,
		Disco:     buildDisco(keys[0], keys[1]),
		STUN:      buildSTUN(),
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

func newTestKey(name string, number int) testKey {
	seed := sha256.Sum256([]byte(fmt.Sprintf("swiftail-vectors/disco/%d", number)))
	var public [32]byte
	curve25519.ScalarBaseMult(&public, &seed)
	return testKey{Name: name, Seed: hexString(seed[:]), Public: hexString(public[:])}
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

func hexString(b []byte) string { return hex.EncodeToString(b) }

func mustHex(s string) []byte {
	b, err := hex.DecodeString(s)
	check(err)
	return b
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

func equal(a, b []byte) bool { return bytes.Equal(a, b) }
