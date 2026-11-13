package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	ds "github.com/dchest/blake2s"
	"golang.org/x/crypto/blake2s"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/nacl/box"
	"golang.org/x/crypto/nacl/secretbox"
	"hash"
	"os"
)

type vector struct {
	Kind    string   `json:"kind"`
	Key     string   `json:"key"`
	Input   string   `json:"input"`
	Output  string   `json:"output"`
	Nonce   string   `json:"nonce,omitempty"`
	AAD     string   `json:"aad,omitempty"`
	Public  string   `json:"public,omitempty"`
	Outputs []string `json:"outputs,omitempty"`
}

func hx(b []byte) string { return hex.EncodeToString(b) }
func data(label string, n int) []byte {
	out := make([]byte, 0, n)
	for i := uint32(0); len(out) < n; i++ {
		h := sha256.New()
		h.Write([]byte("Swiftail test vectors v1/" + label))
		var c [4]byte
		binary.BigEndian.PutUint32(c[:], i)
		h.Write(c[:])
		out = append(out, h.Sum(nil)...)
	}
	return out[:n]
}
func mac(key, input []byte) []byte {
	h := hmac.New(func() hash.Hash {
		h, e := blake2s.New256(nil)
		if e != nil {
			panic(e)
		}
		return h
	}, key)
	h.Write(input)
	return h.Sum(nil)
}
func main() {
	var vs []vector
	for _, size := range []int{1, 16, 32} {
		for _, kl := range []int{0, 1, 32} {
			for _, n := range []int{0, 1, 63, 64, 65, 127, 128, 129, 1000} {
				k, m := data(fmt.Sprintf("blake-key-%d", kl), kl), data(fmt.Sprintf("blake-input-%d", n), n)
				h, e := ds.New(&ds.Config{Size: uint8(size), Key: k})
				if e != nil {
					panic(e)
				}
				h.Write(m)
				sum := h.Sum(nil)
				if size == 32 {
					x, _ := blake2s.New256(k)
					x.Write(m)
					if !hmac.Equal(sum, x.Sum(nil)) {
						panic("blake2s mismatch")
					}
				}
				if size == 16 && kl > 0 {
					x, _ := blake2s.New128(k)
					x.Write(m)
					if !hmac.Equal(sum, x.Sum(nil)) {
						panic("blake2s mismatch")
					}
				}
				vs = append(vs, vector{Kind: "blake2s", Key: hx(k), Input: hx(m), Output: hx(sum)})
			}
		}
	}
	for _, kl := range []int{0, 32, 64, 65, 100} {
		for _, n := range []int{0, 1, 64, 65, 1000} {
			k, m := data(fmt.Sprintf("hmac-key-%d", kl), kl), data(fmt.Sprintf("hmac-input-%d", n), n)
			prk := mac(k, m)
			var outs []string
			var prev []byte
			for i := byte(1); i <= 3; i++ {
				prev = mac(prk, append(append([]byte{}, prev...), i))
				outs = append(outs, hx(prev))
			}
			vs = append(vs, vector{Kind: "kdf", Key: hx(k), Input: hx(m), Output: hx(prk), Outputs: outs})
		}
	}
	key := data("secret-key", 32)
	nonce := data("secret-nonce", 24)
	var k [32]byte
	var no [24]byte
	copy(k[:], key)
	copy(no[:], nonce)
	for _, n := range []int{0, 1, 15, 16, 17, 63, 64, 65, 1000} {
		m := data(fmt.Sprintf("secret-input-%d", n), n)
		vs = append(vs, vector{Kind: "secretbox", Key: hx(key), Nonce: hx(nonce), Input: hx(m), Output: hx(secretbox.Seal(nil, m, &no, &k))})
	}
	priv := data("box-private", 32)
	peerPriv := data("box-peer-private", 32)
	pub, e := curve25519.X25519(peerPriv, curve25519.Basepoint)
	if e != nil {
		panic(e)
	}
	var sk, pk, shared [32]byte
	copy(sk[:], priv)
	copy(pk[:], pub)
	box.Precompute(&shared, &pk, &sk)
	vs = append(vs, vector{Kind: "box", Key: hx(priv), Public: hx(pub), Output: hx(shared[:])})
	a, e := chacha20poly1305.NewX(key)
	if e != nil {
		panic(e)
	}
	for _, n := range []int{0, 1, 15, 16, 17, 63, 64, 65, 1000} {
		for _, an := range []int{0, 1, 15, 16, 17, 64} {
			m, ad := data(fmt.Sprintf("x-input-%d", n), n), data(fmt.Sprintf("x-aad-%d", an), an)
			vs = append(vs, vector{Kind: "xchacha", Key: hx(key), Nonce: hx(nonce), Input: hx(m), AAD: hx(ad), Output: hx(a.Seal(nil, nonce, m, ad))})
		}
	}
	b, e := json.MarshalIndent(vs, "", "  ")
	if e != nil {
		panic(e)
	}
	b = append(b, '\n')
	if e = os.WriteFile("../../Tests/SwiftailCryptoTests/Vectors/cross.json", b, 0644); e != nil {
		panic(e)
	}
}
