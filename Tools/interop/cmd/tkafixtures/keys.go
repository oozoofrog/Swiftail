package main

import (
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"fmt"

	"filippo.io/edwards25519"
	"tailscale.com/tka"
	"tailscale.com/types/key"
	"tailscale.com/types/tkatype"
)

// 모든 키는 SHA-256("swiftail-fixtures/tka/<역할>/<번호>")에서 나온다(계약 7절). 공개된 시험 전용 값이다.
// 역할: lock(신뢰 키. 9번은 상태에 넣지 않는 "믿지 않는 키"), nl(노드의 NL 키, 회전 키), credential(감싼
// 인증 키의 개인 키), node(node 키의 X25519 개인 키 입력), disablement(끄기 비밀).
func seed(role string, index int) (string, []byte) {
	label := fmt.Sprintf("swiftail-fixtures/tka/%s/%d", role, index)
	digest := sha256.Sum256([]byte(label))
	return label, digest[:]
}

// edKey는 Ed25519 시험 키다(lock·nl·credential).
type edKey struct {
	role  string
	index int
	label string
	priv  ed25519.PrivateKey
}

func newEdKey(role string, index int) edKey {
	label, s := seed(role, index)
	return edKey{role, index, label, ed25519.NewKeyFromSeed(s)}
}

func (k edKey) pub() []byte { return []byte(k.priv.Public().(ed25519.PublicKey)) }

// nl은 같은 키를 Go의 key.NLPrivate로 읽은 것이다(텍스트 형식 "nlpriv:" ‖ 64바이트 16진).
func (k edKey) nl() key.NLPrivate {
	var out key.NLPrivate
	if err := out.UnmarshalText([]byte("nlpriv:" + hex.EncodeToString(k.priv))); err != nil {
		panic(err)
	}
	return out
}

func (k edKey) tkaKey(votes uint) tka.Key {
	return tka.Key{Kind: tka.Key25519, Votes: votes, Public: k.pub()}
}

// nodeKey는 SHA-256 씨앗을 X25519 개인 키로 읽어 만든 node 공개 키다.
type nodeKey struct {
	index int
	label string
	priv  key.NodePrivate
}

func newNodeKey(index int) nodeKey {
	label, s := seed("node", index)
	var priv key.NodePrivate
	if err := priv.UnmarshalText([]byte("privkey:" + hex.EncodeToString(s))); err != nil {
		panic(err)
	}
	return nodeKey{index, label, priv}
}

func (n nodeKey) public() key.NodePublic { return n.priv.Public() }

func (n nodeKey) raw() []byte {
	r := n.public().Raw32()
	return r[:]
}

// binary는 NKS의 Pubkey에 들어가는 "np" ‖ 32바이트 형식이다.
func (n nodeKey) binary() []byte {
	b, err := n.public().MarshalBinary()
	if err != nil {
		panic(err)
	}
	return b
}

// 시나리오가 쓰는 키들. 번호의 뜻은 각 시나리오의 주석에 적는다.
var (
	lockKeys    = makeEdKeys("lock", 6)
	untrusted   = newEdKey("lock", 9)
	nlKeys      = makeEdKeys("nl", 3)
	credentials = makeEdKeys("credential", 2)
	nodeKeys    = makeNodeKeys(20)
)

func makeEdKeys(role string, n int) []edKey {
	out := make([]edKey, n)
	for i := range out {
		out[i] = newEdKey(role, i)
	}
	return out
}

func makeNodeKeys(n int) []nodeKey {
	out := make([]nodeKey, n)
	for i := range out {
		out[i] = newNodeKey(i)
	}
	return out
}

// disablementSecret은 i번 끄기 비밀(32바이트)이다.
func disablementSecret(i int) []byte {
	_, s := seed("disablement", i)
	return s
}

// nonCanonicalIdentity는 항등원 (0, 1)을 y = p + 1로 쓴 비정준 인코딩이다. 이 공개 키로는 R = [r]B, S = r인
// 서명이 ZIP-215 규칙에서 어떤 메시지에나 통과한다([8]([S]B − R − [k]A) = 0). 신뢰 키 W로 쓴다.
var nonCanonicalIdentity = mustHex("eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f")

// orderTwoPoint는 위수 2인 점 (0, −1)의 인코딩이다.
var orderTwoPoint = mustHex("ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f")

func mustHex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

func hexOf(b []byte) string { return hex.EncodeToString(b) }

// hexOrNull은 nil이면 JSON null, 아니면(길이 0 포함) 16진 문자열이다.
func hexOrNull(b []byte) *string {
	if b == nil {
		return nil
	}
	s := hex.EncodeToString(b)
	return &s
}

// derivedScalar는 결정적인 서명 난스 r이다: SHA-512(label ‖ message) mod L.
func derivedScalar(label string, message []byte) *edwards25519.Scalar {
	h := sha512.New()
	h.Write([]byte(label))
	h.Write(message)
	s, err := edwards25519.NewScalar().SetUniformBytes(h.Sum(nil))
	if err != nil {
		panic(err)
	}
	return s
}

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

// zip215OnlySign은 R = [r]B + T(T는 위수 2인 점), S = r + k·a인 서명을 만든다. ed25519consensus(ZIP-215)는
// 받아들이고 Go 표준 ed25519.Verify는 거절한다(노트 8.1의 "R에 위수 2인 점을 더한 서명").
func zip215OnlySign(k edKey, message []byte) []byte {
	h := sha512.Sum512(k.priv.Seed())
	a, err := edwards25519.NewScalar().SetBytesWithClamping(h[:32])
	if err != nil {
		panic(err)
	}
	r := derivedScalar("swiftail-fixtures/tka/zip215-only", message)
	t, err := new(edwards25519.Point).SetBytes(orderTwoPoint)
	if err != nil {
		panic(err)
	}
	rBytes := new(edwards25519.Point).Add(new(edwards25519.Point).ScalarBaseMult(r), t).Bytes()
	s := edwards25519.NewScalar().MultiplyAdd(challenge(rBytes, k.pub(), message), a, r)
	return append(rBytes, s.Bytes()...)
}

// identitySign은 공개 키가 항등원(비정준 인코딩 포함)일 때 ZIP-215에서 통과하는 서명 R = [r]B, S = r이다.
func identitySign(message []byte) []byte {
	r := derivedScalar("swiftail-fixtures/tka/identity", message)
	return append(new(edwards25519.Point).ScalarBaseMult(r).Bytes(), r.Bytes()...)
}

// signAUM은 서명 키마다 AUM의 SigHash에 Ed25519 서명을 붙인다(tka.AUM.sign25519·NLPrivate.SignAUM과 같은 모양).
func signAUM(a *tka.AUM, signers ...edKey) {
	h := a.SigHash()
	for _, k := range signers {
		a.Signatures = append(a.Signatures, tkatype.Signature{KeyID: k.pub(), Signature: ed25519.Sign(k.priv, h[:])})
	}
}

func flip(b []byte, bit int) []byte {
	c := append([]byte{}, b...)
	c[bit/8] ^= 1 << (bit % 8)
	return c
}
