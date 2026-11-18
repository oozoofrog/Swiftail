// argon2fixtures generates golang.org/x/crypto argon2.Key output (Argon2i, version 0x13) for several parameter sets
// and writes it as JSON to standard output. It does not read or call the Swift implementation.
// It also compares the result for the TKA parameters with tailscale.com/tka.DisablementKDF and fails if they differ.
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

// pattern is a byte sequence whose ith byte is (i·mul + add) mod 256. It is fixed input for tests only.
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
	// Grid of pass counts, memory sizes, and degrees of parallelism (m ≥ 8p only).
	for t := uint32(1); t <= 4; t++ {
		for _, m := range []uint32{8, 32, 64, 1024} {
			for _, p := range []uint8{1, 2, 4, 8} {
				if m >= 8*uint32(p) {
					out = append(out, params{pw, salt, t, m, p, 32})
				}
			}
		}
	}
	// Output length: One H for 64 or fewer, or the long H' path for larger outputs (RFC 9106 §3.3).
	for _, k := range []uint32{4, 31, 63, 64, 65, 96, 100, 128, 129, 1024} {
		out = append(out, params{pw, salt, 2, 32, 2, k})
	}
	// Secret and salt lengths.
	for _, n := range []int{0, 1, 32, 127, 128, 129} {
		out = append(out, params{pattern(n, 11, 5), salt, 1, 16, 2, 32})
	}
	for _, n := range []int{0, 1, 8, 39, 64, 200} {
		out = append(out, params{pw, pattern(n, 13, 9), 1, 16, 2, 32})
	}
	// Memory not divisible by 4p (m in H0 and m' blocks). One size that needs at least two address blocks in a slice.
	out = append(out,
		params{pw, salt, 2, 33, 4, 32},
		params{pw, salt, 1, 37, 2, 32},
		params{pw, salt, 1, 1023, 8, 32},
		params{pw, salt, 1, 4096, 1, 32},
	)
	// Exact TKA disablement secret parameters (tailscale.com/tka/state.go DisablementKDF).
	out = append(out, params{bytes.Repeat([]byte{0xa5}, 32), []byte("tailscale network-lock disablement salt"), 4, 16 * 1024, 4, 32})
	return out
}

func main() {
	if len(os.Args) != 1 {
		fmt.Fprintln(os.Stderr, "Usage: argon2fixtures > argon2i-go.json")
		os.Exit(2)
	}
	var vectors []vector
	for _, c := range cases() {
		key := argon2.Key(c.password, c.salt, c.t, c.m, c.p, c.keyLen)
		vectors = append(vectors, vector{hex.EncodeToString(c.password), hex.EncodeToString(c.salt), c.t, c.m, c.p, hex.EncodeToString(key)})
	}
	last := vectors[len(vectors)-1]
	if got := hex.EncodeToString(tka.DisablementKDF(bytes.Repeat([]byte{0xa5}, 32))); got != last.Output {
		fmt.Fprintf(os.Stderr, "tka.DisablementKDF and argon2.Key differ: %s != %s\n", got, last.Output)
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
