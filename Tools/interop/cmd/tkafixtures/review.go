package main

// Scenarios added by the TL-11a review (SwiftailTKA security review). The existing chains and signatures do not cover these input forms:
// The same AUM differing only in its signature list (the hash includes signatures, making them distinct siblings), admitting the same AUM set in different groups and orders,
// re-adding a deleted key under the same KeyID, Votes and Meta boundaries, a checkpoint within a fork, a bootstrap parent hash with a length other than 32 bytes,
// and an NKS signature of the wrong length. Output uses the same shapes as chains (chainCase) and signatures (signatureCase).

import (
	"bytes"
	"fmt"
	"strings"

	"tailscale.com/tka"
	"tailscale.com/types/tkatype"
)

// withSignatures keeps the body of raw unchanged (everything except signatures) and replaces only the AUM's signature list. SigHash matches and Hash differs.
func withSignatures(raw []byte, edit func([]tkatype.Signature) []tkatype.Signature) []byte {
	var a tka.AUM
	if err := a.Unserialize(raw); err != nil {
		panic(err)
	}
	a.Signatures = edit(append([]tkatype.Signature{}, a.Signatures...))
	return a.Serialize()
}

// repeatSignature is a signature list that repeats the first signature n times.
func repeatSignature(raw []byte, n int) []byte {
	return withSignatures(raw, func(s []tkatype.Signature) []tkatype.Signature {
		out := make([]tkatype.Signature, n)
		for i := range out {
			out[i] = s[0]
		}
		return out
	})
}

// variantBelow and variantAbove are the first variants that repeat the signature 2–64 times and have a hash lower or higher than raw, respectively.
func variantBelow(raw []byte) []byte {
	for n := 2; n <= 64; n++ {
		if v := repeatSignature(raw, n); hashLess(v, raw) {
			return v
		}
	}
	panic("could not find a variant with a lower hash")
}

func variantAbove(raw []byte) []byte {
	for n := 2; n <= 64; n++ {
		if v := repeatSignature(raw, n); hashLess(raw, v) {
			return v
		}
	}
	panic("could not find a variant with a higher hash")
}

func keyWithMeta(k edKey, votes uint, meta map[string]string) tka.Key {
	key := k.tkaKey(votes)
	key.Meta = meta
	return key
}

// metaOfSize is one Meta entry (key "k") whose key and value lengths total n bytes.
func metaOfSize(n int) map[string]string { return map[string]string{"k": strings.Repeat("v", n-1)} }

func reviewChainCases() []chainCase {
	L, V := lockKeys, disablementValues
	var out []chainCase
	two := []tka.Key{L[0].tkaKey(1), L[1].tkaKey(1)}

	// 1. The repeated-signature variant wins if its hash is lower than the original's. The original's child (RemoveKey for lock/1)
	//       stays on the losing fork and is never applied, so lock/1 stays trusted (a control server that cannot create signatures can choose this outcome).
	g := genesisAUM(two, V[:1], 1, 2, L[0])
	x := noop(aumHash(g), L[0])
	xLow := variantBelow(x)
	c := newChain("review/duplicate-signature-variant-wins", g)
	c.mustStep("original", x)
	c.mustStep("variant-lower-hash", xLow)
	c.mustStep("remove-key-child-of-original", removeKey(aumHash(x), L[1].pub(), L[0]))
	c.mustStep("removed-key-signs-on-variant", noop(aumHash(xLow), L[1]))
	out = append(out, c.c)

	// 2. The variant with the larger hash loses. Its child also remains on the losing fork.
	xHigh := variantAbove(x)
	c = newChain("review/duplicate-signature-variant-loses", g)
	c.mustStep("original", x)
	c.mustStep("variant-higher-hash", xHigh)
	c.mustStep("remove-key-child-of-original", removeKey(aumHash(x), L[1].pub(), L[0]))
	c.mustStep("child-of-variant", noop(aumHash(xHigh), L[0]))
	out = append(out, c.c)

	// 3. Put the original and variant in one group, with the order reversed.
	c = newChain("review/variant-batch-original-first", g)
	c.mustStep("both", x, xLow, xHigh)
	out = append(out, c.c)
	c = newChain("review/variant-batch-variant-first", g)
	c.mustStep("both", xHigh, xLow, x)
	out = append(out, c.c)

	// 4. Siblings that differ only in the order of two signatures. Weight and kind match, so the hash decides.
	ab := noop(aumHash(g), L[0], L[1])
	ba := withSignatures(ab, func(s []tkatype.Signature) []tkatype.Signature { return []tkatype.Signature{s[1], s[0]} })
	c = newChain("review/signature-order-variant", g)
	c.mustStep("a-then-b", ab)
	c.mustStep("b-then-a", ba)
	out = append(out, c.c)

	// 5. Append a signature from an untrusted key or an invalid signature to an accepted AUM's signature list, use an empty list, or repeat a trusted key's signature
	//       1,024 times.
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

	// 6. The copy inflated with an unknown field arrives in one group with the original (the canonical bytes match, so it is the same AUM). Then retry just the original.
	inflated := addPairs(x, 1, "18ff"+"5a"+"00000400"+strings.Repeat("00", 1024))
	c = newChain("review/inflated-copy-with-original", g)
	c.mustStep("inflated-then-original", inflated, x)
	c.mustStep("original-again", x)
	c.mustStep("child", noop(aumHash(x), L[1]))
	out = append(out, c.c)

	// 7. Re-add a deleted key under the same KeyID (different Votes and Meta). Reject signatures while the key is absent and accept them after re-adding it.
	c = newChain("review/remove-then-readd-same-key", genesisAUM([]tka.Key{L[0].tkaKey(2), L[1].tkaKey(1)}, V[:1], 1, 2, L[0]))
	c.mustStep("remove", removeKey(c.head(), L[1].pub(), L[0]))
	c.step("removed-key-signs", noop(c.head(), L[1]))
	c.mustStep("readd", addKey(c.head(), keyWithMeta(L[1], 7, map[string]string{"n": "again"}), L[0]))
	c.mustStep("readded-key-signs", noop(c.head(), L[1]))
	c.step("readd-twice", addKey(c.head(), L[1].tkaKey(1), L[0]))
	c.mustStep("readded-removes-other", removeKey(c.head(), L[0].pub(), L[1]))
	c.step("remove-last", removeKey(c.head(), L[1].pub(), L[1]))
	out = append(out, c.c)

	// 8. Votes and Meta boundaries (AddKey and UpdateKey). Meta allows a combined key and value length of up to 512 bytes.
	c = newChain("review/votes-and-meta-bounds", genesisAUM([]tka.Key{L[0].tkaKey(1)}, V[:1], 1, 2, L[0]))
	c.step("add-votes-0", addKey(c.head(), L[1].tkaKey(0), L[0]))
	c.step("add-votes-4097", addKey(c.head(), L[1].tkaKey(4097), L[0]))
	c.mustStep("add-votes-4096", addKey(c.head(), L[1].tkaKey(4096), L[0]))
	c.step("add-meta-513", addKey(c.head(), keyWithMeta(L[2], 1, metaOfSize(513)), L[0]))
	c.mustStep("add-meta-512", addKey(c.head(), keyWithMeta(L[2], 1, metaOfSize(512)), L[0]))
	c.step("update-meta-513", childAUM(c.head(), tka.AUM{MessageKind: tka.AUMUpdateKey, KeyID: L[2].pub(), Meta: metaOfSize(513)}, L[0]))
	// An UpdateKey with only empty Meta (`07a0`): Go's Serialize omits the empty map, so `07a0` appears only in the received bytes. The received value
	// passes static validation, but the canonical bytes (signature and hash input) omit Meta.
	c.mustStep("update-meta-empty-wire-only", addPairs(childAUM(c.head(), tka.AUM{MessageKind: tka.AUMUpdateKey, KeyID: L[2].pub()}, L[0]), 1, "07a0"))
	c.step("update-no-votes-no-meta", childAUM(c.head(), tka.AUM{MessageKind: tka.AUMUpdateKey, KeyID: L[2].pub()}, L[0]))
	c.mustStep("update-votes-4096-and-meta", childAUM(c.head(), tka.AUM{MessageKind: tka.AUMUpdateKey, KeyID: L[2].pub(), Votes: ptrUint(4096), Meta: metaOfSize(512)}, L[0]))
	c.step("update-votes-4097-with-valid-meta", childAUM(c.head(), tka.AUM{MessageKind: tka.AUMUpdateKey, KeyID: L[2].pub(), Votes: ptrUint(4097), Meta: map[string]string{"a": "b"}}, L[0]))
	c.step("update-votes-max-uint", updateVotes(c.head(), L[2].pub(), ^uint(0), L[0]))
	// A fork between one signature from the two heavier keys (4,096 votes) and one signature from the lighter key. The heavier side wins.
	heavy := noop(c.head(), L[1], L[2])
	light := noop(c.head(), L[0])
	c.mustStep("light", light)
	c.mustStep("heavy", heavy)
	out = append(out, c.c)

	// 9. Checkpoint within a fork: the losing fork's checkpoint changes the keys, and its descendant AUM is verified against that checkpoint's state.
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

	// 10. Admit the same AUM tree in different groups and orders. The head must match.
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

	// 11. If the key to remove is heavier, the sibling the removed key creates from the old parent beats RemoveKey (votes resolve the fork).
	g5 := genesisAUM([]tka.Key{L[0].tkaKey(1), L[1].tkaKey(2)}, V[:1], 1, 2, L[0])
	rm := removeKey(aumHash(g5), L[1].pub(), L[0])
	c = newChain("review/heavier-removed-key-forks-back", g5)
	c.mustStep("remove-heavy-key", rm)
	c.mustStep("removed-key-sibling", noop(aumHash(g5), L[1]))
	c.mustStep("child-of-removal", noop(aumHash(rm), L[0]))
	out = append(out, c.c)

	// 12. Bootstrap from a checkpoint with a 31-byte, 33-byte, or empty parent hash (bootstrap ignores the parent).
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

	// 13. Bootstrap checkpoint signature lists: keys outside its own state, repetition, and order.
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
	// Rotation to the same node key: its own key appears in the previous-key list.
	add("rotation-to-same-node-key", base, N[0], ser(rotationNKS(NL[0], N[0], direct, nil)))
	// KeyID on the outside of a rotation is ignored (the authorizing key is found inside).
	withKeyID := signNKS(tka.NodeKeySignature{SigKind: tka.SigRotation, Pubkey: N[1].binary(), KeyID: untrusted.pub(), Nested: &direct}, NL[0].priv)
	add("rotation-outer-keyid-ignored", base, N[1], ser(withKeyID))
	// A chain using the trusted key itself as the rotation key, and a credential made by a deleted key.
	add("rotation-key-is-lock-key", base, N[1], ser(rotationNKS(L[0], N[1], directNKS(L[0], N[0], L[0].pub()), nil)))
	cred1 := credentialNKS(L[1], credentials[0].pub())
	add("credential-rotation-removed-key", "nks-removed", N[3], ser(rotationNKS(credentials[0], N[3], cred1, nil)))
	add("credential-rotation-before-removal", base, N[3], ser(rotationNKS(credentials[0], N[3], cred1, nil)))
	// The middle rotation wraps the credential and the outer rotation wraps it (the middle WrappingPubkey is the rotation key).
	mid := rotationNKS(credentials[0], N[3], credentialNKS(L[0], credentials[0].pub()), NL[1].pub())
	add("rotation-over-credential-rotation-with-wrapping", base, N[4], ser(rotationNKS(NL[1], N[4], mid, nil)))
	add("rotation-over-credential-rotation-wrong-key", base, N[4], ser(rotationNKS(credentials[0], N[4], mid, nil)))
	// Truncated NKS and NKS with a non-shortest header.
	full := ser(direct)
	add("direct-truncated", base, N[0], full[:len(full)-1])
	add("direct-non-shortest-kind", base, N[0], append([]byte{full[0], 0x01, 0x18, 0x01}, full[3:]...))
	return out
}
