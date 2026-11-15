// ed25519fixtures는 Ed25519 검증 입력마다 Go 두 구현의 판정을 JSON으로 쓴다.
//
//   - zip215: github.com/hdevalence/ed25519consensus의 Verify (ZIP-215 규칙)
//   - standard: Go 표준 라이브러리 crypto/ed25519의 Verify
//
// 입력은 고정 씨앗의 ChaCha8에서 만들므로 실행할 때마다 같은 JSON이 나온다. 자료에 든 키는 모두 공개된
// 시험 전용 값이다. 일부러 만든 서명(작은 위수 성분, 비정준 인코딩)은 filippo.io/edwards25519로 점을
// 계산해 만든다.
//
// 인자로 폴더를 주면 그 안에 ed25519-verify.json을 쓰고, 인자가 없으면 같은 JSON을 표준 출력에 쓴다.
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

// zip215Encodings는 ed25519consensus v0.2.0 zip215_test.go의 cases가 쓰는 점 인코딩 14개다(파일에 나오는
// 순서). cases[14·i + j]는 공개 키 zip215Encodings[i], R = zip215Encodings[j], S = 0, 메시지 "Zcash"다.
// main_test.go가 이 구성이 원본 파일의 196개와 같은지 확인한다.
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

// torsionEncodings는 위수가 8을 나누는 점 8개의 정준 인코딩이다. zip215Encodings의 앞 여덟이 그것이고
// (0000…80은 y = 0, x = −√−1인 정준 인코딩이다), 뒤 여섯은 같은 점들의 비정준 인코딩이다.
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
		fmt.Fprintln(os.Stderr, "사용법: ed25519fixtures [폴더]")
		os.Exit(2)
	}
}

// standardVerify는 crypto/ed25519.Verify다. 공개 키 길이가 32가 아니면 Go는 panic하므로 그 경우는
// 거짓으로 적는다(Swift API의 계약과 같다).
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

// key는 시험용 키 쌍과 개인 스칼라 a(RFC 8032 5.1.5의 clamp한 값)다.
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

// challenge는 k = SHA-512(R ‖ A ‖ M) mod L이다.
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

// signWith는 주어진 R 바이트로 S = r + k·a를 만든다. R이 [r]B가 아니어도(작은 위수 점을 더했어도) 된다.
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

// order는 L의 리틀 엔디언 32바이트다.
var order = mustHex("edd3f55c1a631258d69cf7a2def9de1400000000000000000000000000000010")

// addOrder는 32바이트 리틀 엔디언 S에 L을 더한다(S < L이므로 결과는 2^254 미만).
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

	// 1. ZIP-215 벡터 196개.
	for _, a := range zip215Encodings {
		for _, r := range zip215Encodings {
			g.add("zip215", mustHex(a), []byte("Zcash"), append(mustHex(r), make([]byte, 32)...))
		}
	}

	// 2. 정상 서명: 메시지 길이 0~200.
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

	// 3. 한 비트 뒤집기: 서명 512비트, 공개 키 256비트, 메시지 앞 64비트.
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

	// 4. 비정준 S(S + L)와 S = L.
	for _, v := range valid[:16] {
		g.add("nonCanonicalS", v.k.public, v.message, append(append([]byte{}, v.signature[:32]...), addOrder(v.signature[32:])...))
	}
	g.add("nonCanonicalS", base.k.public, base.message, append(append([]byte{}, base.signature[:32]...), order...))

	// 5. sig[63]의 위 세 비트.
	for _, v := range valid[:8] {
		for _, bit := range []byte{0x20, 0x40, 0x80} {
			s := append([]byte{}, v.signature...)
			s[63] |= bit
			g.add("highBits", v.k.public, v.message, s)
		}
	}

	// 6. 작은 위수의 A. R = [r]B + T, S = r이면 [8]([S]B − [k]A − R) = [8](−[k]A − T) = 0.
	for _, a := range torsionEncodings {
		for _, t := range torsionEncodings {
			r := g.scalar()
			rPoint := new(edwards25519.Point).Add(new(edwards25519.Point).ScalarBaseMult(r), point(t))
			g.add("smallOrderA", mustHex(a), g.bytes(16), append(rPoint.Bytes(), r.Bytes()...))
		}
	}
	// 작은 위수의 A와 R, S = 0, 무작위 메시지.
	for _, a := range torsionEncodings {
		for _, r := range torsionEncodings {
			g.add("smallOrderZeroS", mustHex(a), g.bytes(16), append(mustHex(r), make([]byte, 32)...))
		}
	}

	// 7. 비정준 인코딩: y = p + 0…18(2^255 미만이라 모두 표현 가능)에 부호 비트 0·1, 그리고 x = 0에
	// 부호 비트가 선 0100…80·ecff…ff. 곡선 위가 아닌 것도 섞인다(두 규칙 모두 거절).
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
		// A로: R = [r]B, S = r. 표준은 [k]A = 0일 때(A가 항등원일 때)만 받는다.
		r := g.scalar()
		g.add("nonCanonicalA", e, g.bytes(16), append(new(edwards25519.Point).ScalarBaseMult(r).Bytes(), r.Bytes()...))
		// R로: A = 항등원, S = 0. ZIP-215는 R이 작은 위수이면 받는다. 표준은 R 바이트가 정준이 아니라 거절한다.
		g.add("nonCanonicalR", identity, g.bytes(16), append(append([]byte{}, e...), make([]byte, 32)...))
	}

	// 8. 실제 키의 서명 R에 작은 위수 점 T를 더하고 S를 다시 계산한다.
	for _, t := range torsionEncodings {
		for range 4 {
			k := g.key()
			message := g.bytes(24)
			r := g.scalar()
			rBytes := new(edwards25519.Point).Add(new(edwards25519.Point).ScalarBaseMult(r), point(t)).Bytes()
			g.add("torsionR", k.public, message, signWith(r, rBytes, k.public, k.a, message))
		}
	}

	// 9. 공개 키에 작은 위수 점을 더한 A' = [a]B + T로 서명한다. 표준은 [k]T = 0일 때만 받는다.
	for _, t := range torsionEncodings {
		for range 4 {
			k := g.key()
			mixed := new(edwards25519.Point).Add(new(edwards25519.Point).ScalarBaseMult(k.a), point(t)).Bytes()
			message := g.bytes(24)
			r := g.scalar()
			g.add("torsionA", mixed, message, signWith(r, new(edwards25519.Point).ScalarBaseMult(r).Bytes(), mixed, k.a, message))
		}
	}

	// 10. 곡선 위가 아닌 A나 R. 정상 서명에서 그 자리만 바꾼다.
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

	// 11. 길이가 틀린 입력.
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

// encode는 사례 하나를 한 줄에 쓴다(diff를 읽기 쉽게).
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
