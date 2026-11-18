// ed25519fixtures writes the verdicts of two Go implementations as JSON for each Ed25519 verification input.
//
//   - zip215: Verify from github.com/hdevalence/ed25519consensus (ZIP-215 rules)
//   - standard: Verify from the Go standard library's crypto/ed25519
//
// ChaCha8 with a fixed seed generates the inputs, so every run produces the same JSON. All fixture keys are public
// test-only values. Constructed signatures (small-order components and noncanonical encodings) use point arithmetic
// from filippo.io/edwards25519.
//
// Given a directory argument, writes ed25519-verify.json there. With no argument, writes the same JSON to standard output.
package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/rand/v2"
	"os"
	"path/filepath"
	"runtime"
	"runtime/debug"

	"filippo.io/edwards25519"
	"github.com/hdevalence/ed25519consensus"
)

type verifyCase struct {
	Kind      string `json:"kind"`
	Index     int    `json:"index"`
	PublicKey string `json:"publicKey"`
	Signature string `json:"signature"`
	Message   string `json:"message"`
	ZIP215    bool   `json:"zip215"`
	Standard  bool   `json:"standard"`
}

type fixture struct {
	Go               string       `json:"go"`
	Ed25519consensus string       `json:"ed25519consensus"`
	Edwards25519     string       `json:"edwards25519"`
	CaseCount        int          `json:"caseCount"`
	Cases            []verifyCase `json:"cases"`
}

// zip215Encodings contains the 14 point encodings used by cases in ed25519consensus v0.2.0 zip215_test.go (in file
// order). cases[14·i + j] uses public key zip215Encodings[i], R = zip215Encodings[j], S = 0, and the message "Zcash".
// main_test.go checks that this construction matches the 196 cases in the original file.
var zip215Encodings = []string{
	"0100000000000000000000000000000000000000000000000000000000000000",
	"c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a",
	"0000000000000000000000000000000000000000000000000000000000000080",
	"26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05",
	"ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
	"26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85",
	"0000000000000000000000000000000000000000000000000000000000000000",
	"c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa",
	"0100000000000000000000000000000000000000000000000000000000000080",
	"ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
	"edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
	"edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
	"eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
	"eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
}

// torsionEncodings contains canonical encodings of the 8 points whose order divides 8. They are the first eight zip215Encodings
// entries (0000…80 is the canonical encoding of y = 0, x = −√−1). The last six entries are noncanonical encodings of the same points.
var torsionEncodings = zip215Encodings[:8]

func main() {
	data, err := evaluate()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	switch len(os.Args) {
	case 1:
		os.Stdout.Write(data)
	case 2:
		if err := os.WriteFile(filepath.Join(os.Args[1], "ed25519-verify.json"), data, 0o644); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
	default:
		fmt.Fprintln(os.Stderr, "Usage: ed25519fixtures [directory]")
		os.Exit(2)
	}
}

// standardVerify calls crypto/ed25519.Verify. Go panics if the public key length differs from 32, so record
// false in that case (the same as the Swift API contract).
func standardVerify(publicKey, message, signature []byte) bool {
	if len(publicKey) != ed25519.PublicKeySize {
		return false
	}
	return ed25519.Verify(publicKey, message, signature)
}

type generator struct {
	rng   *rand.ChaCha8
	cases []verifyCase
	count map[string]int
}

func (g *generator) bytes(n int) []byte {
	b := make([]byte, n)
	g.rng.Read(b)
	return b
}

func (g *generator) add(kind string, publicKey, message, signature []byte) {
	g.cases = append(g.cases, verifyCase{
		Kind:      kind,
		Index:     g.count[kind],
		PublicKey: hex.EncodeToString(publicKey),
		Signature: hex.EncodeToString(signature),
		Message:   hex.EncodeToString(message),
		ZIP215:    ed25519consensus.Verify(publicKey, message, signature),
		Standard:  standardVerify(publicKey, message, signature),
	})
	g.count[kind]++
}

// key is a test key pair and private scalar a (the clamped value from RFC 8032 §5.1.5).
type key struct {
	private ed25519.PrivateKey
	public  []byte
	a       *edwards25519.Scalar
}

func (g *generator) key() key {
	private := ed25519.NewKeyFromSeed(g.bytes(ed25519.SeedSize))
	h := sha512.Sum512(private.Seed())
	a, err := edwards25519.NewScalar().SetBytesWithClamping(h[:32])
	if err != nil {
		panic(err)
	}
	return key{private, []byte(private.Public().(ed25519.PublicKey)), a}
}

func (g *generator) scalar() *edwards25519.Scalar {
	s, err := edwards25519.NewScalar().SetUniformBytes(g.bytes(64))
	if err != nil {
		panic(err)
	}
	return s
}

func point(encoding string) *edwards25519.Point {
	p, err := new(edwards25519.Point).SetBytes(mustHex(encoding))
	if err != nil {
		panic(err)
	}
	return p
}

func mustHex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

// challenge is k = SHA-512(R ‖ A ‖ M) mod L.
func challenge(r, publicKey, message []byte) *edwards25519.Scalar {
	h := sha512.New()
	h.Write(r)
	h.Write(publicKey)
	h.Write(message)
	k, err := edwards25519.NewScalar().SetUniformBytes(h.Sum(nil))
	if err != nil {
		panic(err)
	}
	return k
}

// signWith computes S = r + k·a for the given R bytes. R need not equal [r]B (it may include a small-order point).
func signWith(r *edwards25519.Scalar, rBytes, publicKey []byte, a *edwards25519.Scalar, message []byte) []byte {
	k := challenge(rBytes, publicKey, message)
	s := edwards25519.NewScalar().MultiplyAdd(k, a, r)
	return append(append([]byte{}, rBytes...), s.Bytes()...)
}

func flipBit(b []byte, bit int) []byte {
	c := append([]byte{}, b...)
	c[bit/8] ^= 1 << (bit % 8)
	return c
}

// order is L in 32 little-endian bytes.
var order = mustHex("edd3f55c1a631258d69cf7a2def9de1400000000000000000000000000000010")

// addOrder adds L to the 32-byte little-endian S (S < L, so the result is below 2^254).
func addOrder(s []byte) []byte {
	out := make([]byte, 32)
	carry := 0
	for i := range 32 {
		v := int(s[i]) + int(order[i]) + carry
		out[i] = byte(v)
		carry = v >> 8
	}
	return out
}

func evaluate() ([]byte, error) {
	seed := sha256.Sum256([]byte("swiftail-fixtures/ed25519"))
	g := &generator{rng: rand.NewChaCha8(seed), count: map[string]int{}}

	// 1. 196 ZIP-215 vectors.
	for _, a := range zip215Encodings {
		for _, r := range zip215Encodings {
			g.add("zip215", mustHex(a), []byte("Zcash"), append(mustHex(r), make([]byte, 32)...))
		}
	}

	// 2. Valid signatures: message lengths 0–200.
	var valid []struct {
		k                  key
		message, signature []byte
	}
	for n := 0; n <= 200; n++ {
		k := g.key()
		message := g.bytes(n)
		signature := ed25519.Sign(k.private, message)
		g.add("valid", k.public, message, signature)
		valid = append(valid, struct {
			k                  key
			message, signature []byte
		}{k, message, signature})
	}

	// 3. Single-bit flips: all 512 signature bits, all 256 public key bits, and the first 64 message bits.
	base := valid[32]
	for bit := range 512 {
		g.add("flipSignature", base.k.public, base.message, flipBit(base.signature, bit))
	}
	for bit := range 256 {
		g.add("flipPublicKey", flipBit(base.k.public, bit), base.message, base.signature)
	}
	for bit := range 64 {
		g.add("flipMessage", base.k.public, flipBit(base.message, bit), base.signature)
	}

	// 4. Noncanonical S (S + L) and S = L.
	for _, v := range valid[:16] {
		g.add("nonCanonicalS", v.k.public, v.message, append(append([]byte{}, v.signature[:32]...), addOrder(v.signature[32:])...))
	}
	g.add("nonCanonicalS", base.k.public, base.message, append(append([]byte{}, base.signature[:32]...), order...))

	// 5. The top three bits of sig[63].
	for _, v := range valid[:8] {
		for _, bit := range []byte{0x20, 0x40, 0x80} {
			s := append([]byte{}, v.signature...)
			s[63] |= bit
			g.add("highBits", v.k.public, v.message, s)
		}
	}

	// 6. Small-order A. If R = [r]B + T and S = r, then [8]([S]B − [k]A − R) = [8](−[k]A − T) = 0.
	for _, a := range torsionEncodings {
		for _, t := range torsionEncodings {
			r := g.scalar()
			rPoint := new(edwards25519.Point).Add(new(edwards25519.Point).ScalarBaseMult(r), point(t))
			g.add("smallOrderA", mustHex(a), g.bytes(16), append(rPoint.Bytes(), r.Bytes()...))
		}
	}
	// Small-order A and R, S = 0, and a random message.
	for _, a := range torsionEncodings {
		for _, r := range torsionEncodings {
			g.add("smallOrderZeroS", mustHex(a), g.bytes(16), append(mustHex(r), make([]byte, 32)...))
		}
	}

	// 7. Noncanonical encodings: y = p + 0…18 (all representable because they are below 2^255) with sign bits 0 and 1, and x = 0
	// with the sign bit set in 0100…80 and ecff…ff. Some points are off the curve (both rules reject them).
	var nonCanonical [][]byte
	for y := range 19 {
		for _, sign := range []byte{0, 0x80} {
			e := mustHex("edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f")
			e[0] += byte(y)
			e[31] |= sign
			nonCanonical = append(nonCanonical, e)
		}
	}
	nonCanonical = append(nonCanonical,
		mustHex("0100000000000000000000000000000000000000000000000000000000000080"),
		mustHex("ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"))
	identity := mustHex(torsionEncodings[0])
	for _, e := range nonCanonical {
		// As A: R = [r]B, S = r. Standard verification accepts only when [k]A = 0 (when A is the identity).
		r := g.scalar()
		g.add("nonCanonicalA", e, g.bytes(16), append(new(edwards25519.Point).ScalarBaseMult(r).Bytes(), r.Bytes()...))
		// As R: A = identity, S = 0. ZIP-215 accepts small-order R. Standard verification rejects the noncanonical R bytes.
		g.add("nonCanonicalR", identity, g.bytes(16), append(append([]byte{}, e...), make([]byte, 32)...))
	}

	// 8. Add a small-order point T to a real key's signature R and recompute S.
	for _, t := range torsionEncodings {
		for range 4 {
			k := g.key()
			message := g.bytes(24)
			r := g.scalar()
			rBytes := new(edwards25519.Point).Add(new(edwards25519.Point).ScalarBaseMult(r), point(t)).Bytes()
			g.add("torsionR", k.public, message, signWith(r, rBytes, k.public, k.a, message))
		}
	}

	// 9. Sign with A' = [a]B + T, the public key plus a small-order point. Standard verification accepts only when [k]T = 0.
	for _, t := range torsionEncodings {
		for range 4 {
			k := g.key()
			mixed := new(edwards25519.Point).Add(new(edwards25519.Point).ScalarBaseMult(k.a), point(t)).Bytes()
			message := g.bytes(24)
			r := g.scalar()
			g.add("torsionA", mixed, message, signWith(r, new(edwards25519.Point).ScalarBaseMult(r).Bytes(), mixed, k.a, message))
		}
	}

	// 10. A or R off the curve. Replace only that value in a valid signature.
	var offCurve [][]byte
	for len(offCurve) < 4 {
		e := g.bytes(32)
		if _, err := new(edwards25519.Point).SetBytes(e); err != nil {
			offCurve = append(offCurve, e)
		}
	}
	for i, e := range offCurve {
		v := valid[40+i]
		g.add("offCurve", e, v.message, v.signature)
		g.add("offCurve", v.k.public, v.message, append(append([]byte{}, e...), v.signature[32:]...))
	}

	// 11. Inputs of the wrong length.
	for _, n := range []int{0, 63, 65} {
		s := append(append([]byte{}, base.signature...), 0)[:n]
		g.add("length", base.k.public, base.message, s)
	}
	for _, n := range []int{0, 31, 33} {
		p := append(append([]byte{}, base.k.public...), 0)[:n]
		g.add("length", p, base.message, base.signature)
	}

	f := fixture{
		Go:               runtime.Version(),
		Ed25519consensus: moduleVersion("github.com/hdevalence/ed25519consensus"),
		Edwards25519:     moduleVersion("filippo.io/edwards25519"),
		CaseCount:        len(g.cases),
		Cases:            g.cases,
	}
	return encode(f)
}

func moduleVersion(path string) string {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return ""
	}
	for _, m := range info.Deps {
		if m.Path == path {
			return m.Version
		}
	}
	return ""
}

// encode writes one case per line to make diffs easier to read.
func encode(f fixture) ([]byte, error) {
	var b bytes.Buffer
	head, err := json.Marshal(struct {
		Go               string `json:"go"`
		Ed25519consensus string `json:"ed25519consensus"`
		Edwards25519     string `json:"edwards25519"`
		CaseCount        int    `json:"caseCount"`
	}{f.Go, f.Ed25519consensus, f.Edwards25519, f.CaseCount})
	if err != nil {
		return nil, err
	}
	b.Write(head[:len(head)-1])
	b.WriteString(",\"cases\":[\n")
	for i, c := range f.Cases {
		line, err := json.Marshal(c)
		if err != nil {
			return nil, err
		}
		b.Write(line)
		if i < len(f.Cases)-1 {
			b.WriteByte(',')
		}
		b.WriteByte('\n')
	}
	b.WriteString("]}\n")
	return b.Bytes(), nil
}
