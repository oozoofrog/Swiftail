package main

// TL-11a 검토(SwiftailTKA 보안 검토)가 더한 시나리오. 기존 chains·signatures가 다루지 않은 모양의 입력이다:
// 서명 목록만 다른 같은 AUM(해시는 서명을 담으므로 서로 다른 형제가 된다), 같은 AUM 집합을 다른 묶음·순서로 들이기,
// 지운 키를 같은 KeyID로 다시 더하기, Votes·Meta의 경계, 갈래 안의 체크포인트, 부모 해시가 32바이트가 아닌 부트스트랩,
// 길이가 틀린 NKS 서명. 출력 모양은 chains(chainCase)·signatures(signatureCase)와 같다.

import (
	"bytes"
	"fmt"
	"strings"

	"tailscale.com/tka"
	"tailscale.com/types/tkatype"
)

// withSignatures는 raw의 본문(서명을 뺀 것)은 그대로 두고 서명 목록만 바꾼 AUM이다. SigHash는 같고 Hash는 다르다.
func withSignatures(raw []byte, edit func([]tkatype.Signature) []tkatype.Signature) []byte {
	var a tka.AUM
	if err := a.Unserialize(raw); err != nil {
		panic(err)
	}
	a.Signatures = edit(append([]tkatype.Signature{}, a.Signatures...))
	return a.Serialize()
}

// repeatSignature는 첫 서명을 n번 되풀이한 서명 목록이다.
func repeatSignature(raw []byte, n int) []byte {
	return withSignatures(raw, func(s []tkatype.Signature) []tkatype.Signature {
		out := make([]tkatype.Signature, n)
		for i := range out {
			out[i] = s[0]
		}
		return out
	})
}

// variantBelow·variantAbove는 서명을 2~64번 되풀이한 변종 가운데 해시가 raw보다 작은(큰) 첫 것이다.
func variantBelow(raw []byte) []byte {
	for n := 2; n <= 64; n++ {
		if v := repeatSignature(raw, n); hashLess(v, raw) {
			return v
		}
	}
	panic("해시가 더 작은 변종을 찾지 못했습니다")
}

func variantAbove(raw []byte) []byte {
	for n := 2; n <= 64; n++ {
		if v := repeatSignature(raw, n); hashLess(raw, v) {
			return v
		}
	}
	panic("해시가 더 큰 변종을 찾지 못했습니다")
}

func keyWithMeta(k edKey, votes uint, meta map[string]string) tka.Key {
	key := k.tkaKey(votes)
	key.Meta = meta
	return key
}

// metaOfSize는 키·값 길이의 합이 n바이트인 Meta 하나다(키 "k").
func metaOfSize(n int) map[string]string { return map[string]string{"k": strings.Repeat("v", n-1)} }

func reviewChainCases() []chainCase {
	L, V := lockKeys, disablementValues
	var out []chainCase
	two := []tka.Key{L[0].tkaKey(1), L[1].tkaKey(1)}

	// 1. 서명을 되풀이한 변종이 원본보다 해시가 작으면 이긴다. 원본에 붙은 자식(lock/1을 지우는 RemoveKey)은
	//    진 갈래에 남아 적용되지 않고, lock/1이 계속 신뢰된다(서명을 만들 수 없는 제어 서버가 고를 수 있다).
	g := genesisAUM(two, V[:1], 1, 2, L[0])
	x := noop(aumHash(g), L[0])
	xLow := variantBelow(x)
	c := newChain("review/duplicate-signature-variant-wins", g)
	c.mustStep("original", x)
	c.mustStep("variant-lower-hash", xLow)
	c.mustStep("remove-key-child-of-original", removeKey(aumHash(x), L[1].pub(), L[0]))
	c.mustStep("removed-key-signs-on-variant", noop(aumHash(xLow), L[1]))
	out = append(out, c.c)

	// 2. 해시가 큰 변종은 진다. 변종에 붙인 자식도 진 갈래에 남는다.
	xHigh := variantAbove(x)
	c = newChain("review/duplicate-signature-variant-loses", g)
	c.mustStep("original", x)
	c.mustStep("variant-higher-hash", xHigh)
	c.mustStep("remove-key-child-of-original", removeKey(aumHash(x), L[1].pub(), L[0]))
	c.mustStep("child-of-variant", noop(aumHash(xHigh), L[0]))
	out = append(out, c.c)

	// 3. 원본과 변종을 한 묶음으로, 순서를 바꿔서.
	c = newChain("review/variant-batch-original-first", g)
	c.mustStep("both", x, xLow, xHigh)
	out = append(out, c.c)
	c = newChain("review/variant-batch-variant-first", g)
	c.mustStep("both", xHigh, xLow, x)
	out = append(out, c.c)

	// 4. 서명 둘의 순서만 바꾼 형제. 가중치·종류가 같아 해시로 갈린다.
	ab := noop(aumHash(g), L[0], L[1])
	ba := withSignatures(ab, func(s []tkatype.Signature) []tkatype.Signature { return []tkatype.Signature{s[1], s[0]} })
	c = newChain("review/signature-order-variant", g)
	c.mustStep("a-then-b", ab)
	c.mustStep("b-then-a", ba)
	out = append(out, c.c)

	// 5. 받아들인 AUM의 서명 목록에 믿지 않는 키의 서명이나 틀린 서명을 덧붙인 것, 빈 목록, 신뢰 키 서명을 1,024번
	//    되풀이한 것.
	untrustedSig := noop(aumHash(g), untrusted)
	c = newChain("review/signature-list-tampering", g)
	c.step("append-untrusted", withSignatures(x, func(s []tkatype.Signature) []tkatype.Signature {
		return append(s, mustSignatures(untrustedSig)[0])
	}))
	c.step("append-corrupt-copy", withSignatures(x, func(s []tkatype.Signature) []tkatype.Signature {
		bad := s[0]
		bad.Signature = flip(bad.Signature, 3)
		return append(s, bad)
	}))
	c.step("prepend-corrupt-copy", withSignatures(x, func(s []tkatype.Signature) []tkatype.Signature {
		bad := s[0]
		bad.Signature = flip(bad.Signature, 3)
		return append([]tkatype.Signature{bad}, s...)
	}))
	c.step("signature-of-other-aum", withSignatures(x, func([]tkatype.Signature) []tkatype.Signature {
		return mustSignatures(noop(aumHash(x), L[1]))
	}))
	c.step("empty-list", withSignatures(x, func([]tkatype.Signature) []tkatype.Signature { return nil }))
	c.mustStep("repeated-1024", repeatSignature(x, 1024))
	out = append(out, c.c)

	// 6. 모르는 필드로 부풀린 사본과 원본이 한 묶음에 온다(정준 바이트가 같아 같은 AUM이다). 그 뒤 원본만 다시.
	inflated := addPairs(x, 1, "18ff"+"5a"+"00000400"+strings.Repeat("00", 1024))
	c = newChain("review/inflated-copy-with-original", g)
	c.mustStep("inflated-then-original", inflated, x)
	c.mustStep("original-again", x)
	c.mustStep("child", noop(aumHash(x), L[1]))
	out = append(out, c.c)

	// 7. 지운 키를 같은 KeyID로 다시 더한다(다른 Votes·Meta). 지운 동안의 서명은 거절, 다시 더한 뒤는 받는다.
	c = newChain("review/remove-then-readd-same-key", genesisAUM([]tka.Key{L[0].tkaKey(2), L[1].tkaKey(1)}, V[:1], 1, 2, L[0]))
	c.mustStep("remove", removeKey(c.head(), L[1].pub(), L[0]))
	c.step("removed-key-signs", noop(c.head(), L[1]))
	c.mustStep("readd", addKey(c.head(), keyWithMeta(L[1], 7, map[string]string{"n": "again"}), L[0]))
	c.mustStep("readded-key-signs", noop(c.head(), L[1]))
	c.step("readd-twice", addKey(c.head(), L[1].tkaKey(1), L[0]))
	c.mustStep("readded-removes-other", removeKey(c.head(), L[0].pub(), L[1]))
	c.step("remove-last", removeKey(c.head(), L[1].pub(), L[1]))
	out = append(out, c.c)

	// 8. Votes와 Meta의 경계(AddKey·UpdateKey). Meta는 키·값 길이 합 512바이트까지.
	c = newChain("review/votes-and-meta-bounds", genesisAUM([]tka.Key{L[0].tkaKey(1)}, V[:1], 1, 2, L[0]))
	c.step("add-votes-0", addKey(c.head(), L[1].tkaKey(0), L[0]))
	c.step("add-votes-4097", addKey(c.head(), L[1].tkaKey(4097), L[0]))
	c.mustStep("add-votes-4096", addKey(c.head(), L[1].tkaKey(4096), L[0]))
	c.step("add-meta-513", addKey(c.head(), keyWithMeta(L[2], 1, metaOfSize(513)), L[0]))
	c.mustStep("add-meta-512", addKey(c.head(), keyWithMeta(L[2], 1, metaOfSize(512)), L[0]))
	c.step("update-meta-513", childAUM(c.head(), tka.AUM{MessageKind: tka.AUMUpdateKey, KeyID: L[2].pub(), Meta: metaOfSize(513)}, L[0]))
	// 빈 Meta(`07a0`)만 있는 UpdateKey: Go의 Serialize는 빈 맵을 빼므로 받은 바이트에만 `07a0`이 있다. 받은 값으로는
	// 정적 검사를 통과하지만, 정준 바이트(서명·해시의 입력)에는 Meta가 없다.
	c.mustStep("update-meta-empty-wire-only", addPairs(childAUM(c.head(), tka.AUM{MessageKind: tka.AUMUpdateKey, KeyID: L[2].pub()}, L[0]), 1, "07a0"))
	c.step("update-no-votes-no-meta", childAUM(c.head(), tka.AUM{MessageKind: tka.AUMUpdateKey, KeyID: L[2].pub()}, L[0]))
	c.mustStep("update-votes-4096-and-meta", childAUM(c.head(), tka.AUM{MessageKind: tka.AUMUpdateKey, KeyID: L[2].pub(), Votes: ptrUint(4096), Meta: metaOfSize(512)}, L[0]))
	c.step("update-votes-4097-with-valid-meta", childAUM(c.head(), tka.AUM{MessageKind: tka.AUMUpdateKey, KeyID: L[2].pub(), Votes: ptrUint(4097), Meta: map[string]string{"a": "b"}}, L[0]))
	c.step("update-votes-max-uint", updateVotes(c.head(), L[2].pub(), ^uint(0), L[0]))
	// 무거운 두 키(4,096표)의 서명 하나와 가벼운 키 서명 하나의 갈래: 무거운 쪽이 이긴다.
	heavy := noop(c.head(), L[1], L[2])
	light := noop(c.head(), L[0])
	c.mustStep("light", light)
	c.mustStep("heavy", heavy)
	out = append(out, c.c)

	// 9. 갈래 안의 체크포인트: 진 갈래의 체크포인트가 키를 바꾸고, 그 아래 AUM은 그 체크포인트의 상태로 검증된다.
	g3 := genesisAUM([]tka.Key{L[0].tkaKey(1), L[1].tkaKey(2)}, V[:1], 1, 2, L[0])
	win := noop(aumHash(g3), L[1])
	loseCP := childAUM(aumHash(g3), tka.AUM{MessageKind: tka.AUMCheckpoint, State: &tka.State{DisablementValues: V[1:2], Keys: []tka.Key{L[0].tkaKey(1), L[3].tkaKey(1)}, StateID1: 1, StateID2: 2}}, L[0])
	c = newChain("review/checkpoint-in-losing-branch", g3)
	c.mustStep("winner", win)
	c.mustStep("losing-checkpoint", loseCP)
	c.mustStep("new-key-signs-below-checkpoint", noop(aumHash(loseCP), L[3]))
	c.step("removed-key-signs-below-checkpoint", noop(aumHash(loseCP), L[1]))
	c.step("new-key-signs-on-winner", noop(aumHash(win), L[3]))
	c.mustStep("winner-child", noop(aumHash(win), L[1]))
	out = append(out, c.c)

	// 10. 같은 AUM 나무를 서로 다른 묶음·순서로 들인다. 머리는 같아야 한다.
	g4 := genesisAUM([]tka.Key{L[0].tkaKey(1), L[1].tkaKey(1), L[2].tkaKey(1)}, V[:1], 1, 2, L[0])
	a1 := noop(aumHash(g4), L[0])
	a2 := addKey(aumHash(a1), L[3].tkaKey(1), L[1])
	b1 := noop(aumHash(g4), L[1])
	b2 := removeKey(aumHash(b1), L[2].pub(), L[0])
	a3 := noop(aumHash(a2), L[3])
	b3 := noop(aumHash(b2), L[1])
	orders := [][][]byte{
		{a1, a2, a3, b1, b2, b3},
		{b1, b2, b3, a1, a2, a3},
		{a1, b1, a2, b2, a3, b3},
	}
	for i, order := range orders {
		c = newChain(fmt.Sprintf("review/same-tree-order-%d", i), g4)
		c.mustStep("one-batch", order...)
		out = append(out, c.c)
	}
	c = newChain("review/same-tree-split", g4)
	c.mustStep("b1", b1)
	c.mustStep("a1-a2", a1, a2)
	c.mustStep("b2-b3", b2, b3)
	c.mustStep("a3", a3)
	out = append(out, c.c)
	c = newChain("review/same-tree-child-before-parent", g4)
	c.step("a2-a1", a2, a1)
	c.mustStep("a1", a1)
	c.mustStep("a3-a2", a2, a3)
	out = append(out, c.c)

	// 11. 지울 키가 더 무거우면, 지워진 키가 옛 부모에서 만든 형제가 RemoveKey를 이긴다(갈래 해소는 표로 한다).
	g5 := genesisAUM([]tka.Key{L[0].tkaKey(1), L[1].tkaKey(2)}, V[:1], 1, 2, L[0])
	rm := removeKey(aumHash(g5), L[1].pub(), L[0])
	c = newChain("review/heavier-removed-key-forks-back", g5)
	c.mustStep("remove-heavy-key", rm)
	c.mustStep("removed-key-sibling", noop(aumHash(g5), L[1]))
	c.mustStep("child-of-removal", noop(aumHash(rm), L[0]))
	out = append(out, c.c)

	// 12. 부모 해시가 31·33바이트·빈 값인 체크포인트로 부트스트랩한다(부트스트랩은 부모를 보지 않는다).
	for _, p := range []struct {
		name string
		prev []byte
	}{{"prev-31", bytes.Repeat([]byte{7}, 31)}, {"prev-33", bytes.Repeat([]byte{7}, 33)}, {"prev-empty", []byte{}}, {"prev-32", bytes.Repeat([]byte{7}, 32)}} {
		b := tka.AUM{MessageKind: tka.AUMCheckpoint, PrevAUMHash: p.prev, State: &tka.State{DisablementValues: V[:1], Keys: two, StateID1: 1, StateID2: 2}}
		signAUM(&b, L[0])
		c = newChain("review/bootstrap-"+p.name, b.Serialize())
		if c.a != nil {
			c.mustStep("child", noop(c.head(), L[1]))
		}
		out = append(out, c.c)
	}

	// 13. 부트스트랩 체크포인트의 서명 목록: 자기 상태 밖의 키, 되풀이, 순서.
	gs := tka.AUM{MessageKind: tka.AUMCheckpoint, State: &tka.State{DisablementValues: V[:1], Keys: two, StateID1: 1, StateID2: 2}}
	signAUM(&gs, L[0], L[1])
	gsRaw := gs.Serialize()
	out = append(out, newChain("review/bootstrap-with-untrusted-signature", withSignatures(gsRaw, func(s []tkatype.Signature) []tkatype.Signature {
		return append(s, mustSignatures(noop(aumHash(g), untrusted))[0])
	})).c)
	out = append(out, newChain("review/bootstrap-repeated-signature", repeatSignature(gsRaw, 3)).c)
	return out
}

func mustSignatures(raw []byte) []tkatype.Signature {
	var a tka.AUM
	if err := a.Unserialize(raw); err != nil {
		panic(err)
	}
	return a.Signatures
}

func ptrUint(v uint) *uint { return &v }

func reviewSignatureCases(all []namedAuthority) []signatureCase {
	L, NL, N := lockKeys, nlKeys, nodeKeys
	var out []signatureCase
	add := func(name, auth string, n nodeKey, nks []byte) {
		c := signatureCase{Name: name, Authority: auth, NodeKey: hexOf(n.raw()), NKS: hexOf(nks)}
		var s tka.NodeKeySignature
		if s.Unserialize(nks) == nil {
			h := s.SigHash()
			c.SigHash = hexOf(h[:])
		}
		c.verdict = authorize(findAuthority(all, auth), n.raw(), nks)
		out = append(out, c)
	}
	base := "nks-base"
	direct := directNKS(L[0], N[0], NL[0].pub())
	resized := func(s tka.NodeKeySignature, n int) []byte {
		sig := append([]byte{}, s.Signature...)
		if n < len(sig) {
			sig = sig[:n]
		} else {
			sig = append(sig, make([]byte, n-len(sig))...)
		}
		s.Signature = sig
		return ser(s)
	}
	add("direct-signature-63", base, N[0], resized(direct, 63))
	add("direct-signature-65", base, N[0], resized(direct, 65))
	add("direct-signature-empty", base, N[0], resized(direct, 0))
	r1 := rotationNKS(NL[0], N[1], direct, nil)
	add("rotation-signature-63", base, N[1], resized(r1, 63))
	add("rotation-signature-65", base, N[1], resized(r1, 65))
	add("rotation-33-byte-rotation-key", base, N[1], ser(rotationNKS(NL[0], N[1], directNKS(L[0], N[0], append(NL[0].pub(), 0)), nil)))
	// 같은 node 키로의 회전: 자기 키가 이전 키 목록에 든다.
	add("rotation-to-same-node-key", base, N[0], ser(rotationNKS(NL[0], N[0], direct, nil)))
	// rotation의 바깥에 KeyID를 넣어도 쓰이지 않는다(허가 키는 안쪽에서 찾는다).
	withKeyID := signNKS(tka.NodeKeySignature{SigKind: tka.SigRotation, Pubkey: N[1].binary(), KeyID: untrusted.pub(), Nested: &direct}, NL[0].priv)
	add("rotation-outer-keyid-ignored", base, N[1], ser(withKeyID))
	// 회전 키로 신뢰 키 자신을 쓰는 사슬, 지워진 키가 만든 credential.
	add("rotation-key-is-lock-key", base, N[1], ser(rotationNKS(L[0], N[1], directNKS(L[0], N[0], L[0].pub()), nil)))
	cred1 := credentialNKS(L[1], credentials[0].pub())
	add("credential-rotation-removed-key", "nks-removed", N[3], ser(rotationNKS(credentials[0], N[3], cred1, nil)))
	add("credential-rotation-before-removal", base, N[3], ser(rotationNKS(credentials[0], N[3], cred1, nil)))
	// 가운데 rotation이 credential을 감싸고 바깥 rotation이 그것을 감싼다(가운데 WrappingPubkey가 회전 키).
	mid := rotationNKS(credentials[0], N[3], credentialNKS(L[0], credentials[0].pub()), NL[1].pub())
	add("rotation-over-credential-rotation-with-wrapping", base, N[4], ser(rotationNKS(NL[1], N[4], mid, nil)))
	add("rotation-over-credential-rotation-wrong-key", base, N[4], ser(rotationNKS(credentials[0], N[4], mid, nil)))
	// 잘린 NKS, 비최단 머리로 쓴 NKS.
	full := ser(direct)
	add("direct-truncated", base, N[0], full[:len(full)-1])
	add("direct-non-shortest-kind", base, N[0], append([]byte{full[0], 0x01, 0x18, 0x01}, full[3:]...))
	return out
}
