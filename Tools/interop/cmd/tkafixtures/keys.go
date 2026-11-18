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

// All keys are derived from SHA-256("swiftail-fixtures/tka/<role>/<number>") (contract §7). They are public test-only values.
// Roles: lock (trusted key, with number 9 as the "untrusted key" omitted from state), nl (the node's NL key, the rotation key), credential (private key
// for the wrapped auth key), node (the node key's X25519 private key input), and disablement (disablement secret).
func seed(role string, index int) (string, []byte) {
	label := fmt.Sprintf("swiftail-fixtures/tka/%s/%d", role, index)
	digest := sha256.Sum256([]byte(label))
	return label, digest[:]
}

// edKey is an Ed25519 test key (lock, nl, or credential).
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

// nl is the same key read as Go's key.NLPrivate (text format "nlpriv:" ‖ 64 hexadecimal bytes).
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

// nodeKey is the public node key derived by reading the SHA-256 seed as an X25519 private key.
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

// binary is the "np" ‖ 32-byte format used in an NKS Pubkey.
func (n nodeKey) binary() []byte {
	b, err := n.public().MarshalBinary()
	if err != nil {
		panic(err)
	}
	return b
}

// Keys for scenarios. See each scenario's comments for what the numbers mean.
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

// disablementSecret is disablement secret number i (32 bytes).
func disablementSecret(i int) []byte {
	_, s := seed("disablement", i)
	return s
}

// nonCanonicalIdentity encodes the identity (0, 1) noncanonically as y = p + 1. With this public key, signatures with R = [r]B and S = r
// verify under ZIP-215 for any message ([8]([S]B − R − [k]A) = 0). Use it as trusted key W.
var nonCanonicalIdentity = mustHex("eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f")

// orderTwoPoint encodes the point (0, −1) of order 2.
var orderTwoPoint = mustHex("ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f")

func mustHex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

func hexOf(b []byte) string { return hex.EncodeToString(b) }

// hexOrNull is JSON null for nil and a hexadecimal string otherwise (including length 0).
func hexOrNull(b []byte) *string {
	if b == nil {
		return nil
	}
	s := hex.EncodeToString(b)
	return &s
}

// derivedScalar is the deterministic signature nonce r: SHA-512(label ‖ message) mod L.
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

// zip215OnlySign creates a signature with R = [r]B + T (T is a point of order 2) and S = r + k·a. ed25519consensus (ZIP-215)
// accepts it, and Go's standard ed25519.Verify rejects it (notes §8.1, "Signatures with an order-2 point added to R").
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

// identitySign is the signature R = [r]B, S = r that verifies under ZIP-215 with the identity as public key (including a noncanonical encoding).
func identitySign(message []byte) []byte {
	r := derivedScalar("swiftail-fixtures/tka/identity", message)
	return append(new(edwards25519.Point).ScalarBaseMult(r).Bytes(), r.Bytes()...)
}

// signAUM adds an Ed25519 signature over the AUM's SigHash for each signing key (same format as tka.AUM.sign25519 and NLPrivate.SignAUM).
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
