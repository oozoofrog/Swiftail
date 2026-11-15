// argon2fixtures는 golang.org/x/crypto의 argon2.Key(Argon2i, 버전 0x13) 출력을 여러 인자로 뽑아
// 표준 출력에 JSON으로 쓴다. Swift 구현은 읽거나 호출하지 않는다.
// TKA 인자의 값은 tailscale.com/tka.DisablementKDF와도 견주어, 다르면 실패한다.
package main

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"

	"golang.org/x/crypto/argon2"
	"tailscale.com/tka"
)

const reference = "golang.org/x/crypto v0.58.0 argon2.Key, tailscale.com v1.104.6 tka.DisablementKDF"

type vector struct {
	Password    string `json:"password"`
	Salt        string `json:"salt"`
	Iterations  uint32 `json:"iterations"`
	MemoryKiB   uint32 `json:"memoryKiB"`
	Parallelism uint8  `json:"parallelism"`
	Output      string `json:"output"`
}

type params struct {
	password, salt []byte
	t, m           uint32
	p              uint8
	keyLen         uint32
}

// pattern은 i번째 바이트가 (i·mul + add) mod 256인 바이트열이다. 시험 전용 고정 입력이다.
func pattern(n, mul, add int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(i*mul + add)
	}
	return b
}

func cases() []params {
	var out []params
	pw, salt := pattern(16, 7, 1), pattern(16, 3, 2)
	// 패스 수·메모리·병렬도 격자(m ≥ 8p만).
	for t := uint32(1); t <= 4; t++ {
		for _, m := range []uint32{8, 32, 64, 1024} {
			for _, p := range []uint8{1, 2, 4, 8} {
				if m >= 8*uint32(p) {
					out = append(out, params{pw, salt, t, m, p, 32})
				}
			}
		}
	}
	// 출력 길이: 64 이하는 H 한 번, 그보다 길면 H'의 긴 경로(RFC 9106 3.3).
	for _, k := range []uint32{4, 31, 63, 64, 65, 96, 100, 128, 129, 1024} {
		out = append(out, params{pw, salt, 2, 32, 2, k})
	}
	// 비밀·솔트 길이.
	for _, n := range []int{0, 1, 32, 127, 128, 129} {
		out = append(out, params{pattern(n, 11, 5), salt, 1, 16, 2, 32})
	}
	for _, n := range []int{0, 1, 8, 39, 64, 200} {
		out = append(out, params{pw, pattern(n, 13, 9), 1, 16, 2, 32})
	}
	// 메모리가 4p의 배수가 아닐 때(H0에는 m, 블록 수는 m'). 두 조각 이상의 주소 블록이 필요한 크기 하나.
	out = append(out,
		params{pw, salt, 2, 33, 4, 32},
		params{pw, salt, 1, 37, 2, 32},
		params{pw, salt, 1, 1023, 8, 32},
		params{pw, salt, 1, 4096, 1, 32},
	)
	// TKA 끄기 비밀의 인자 그대로(tailscale.com/tka/state.go DisablementKDF).
	out = append(out, params{bytes.Repeat([]byte{0xa5}, 32), []byte("tailscale network-lock disablement salt"), 4, 16 * 1024, 4, 32})
	return out
}

func main() {
	if len(os.Args) != 1 {
		fmt.Fprintln(os.Stderr, "사용법: argon2fixtures > argon2i-go.json")
		os.Exit(2)
	}
	var vectors []vector
	for _, c := range cases() {
		key := argon2.Key(c.password, c.salt, c.t, c.m, c.p, c.keyLen)
		vectors = append(vectors, vector{hex.EncodeToString(c.password), hex.EncodeToString(c.salt), c.t, c.m, c.p, hex.EncodeToString(key)})
	}
	last := vectors[len(vectors)-1]
	if got := hex.EncodeToString(tka.DisablementKDF(bytes.Repeat([]byte{0xa5}, 32))); got != last.Output {
		fmt.Fprintf(os.Stderr, "tka.DisablementKDF와 argon2.Key가 다르다: %s != %s\n", got, last.Output)
		os.Exit(1)
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(struct {
		Reference string   `json:"reference"`
		Vectors   []vector `json:"vectors"`
	}{reference, vectors}); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
