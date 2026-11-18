package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"fmt"

	"tailscale.com/tka"
	"tailscale.com/types/tkatype"
)

// stateSnapshot is state read through Authority's public API. Keys come from Keys(), StateID from StateIDs(), and the head from Head().
// Disablement values have no public accessor. Walk backward from the head in storage (ChonkMem.AUM) and read
// State.DisablementValues from the first checkpoint. Go's applyVerifiedAUM replaces the whole state only at checkpoints, and other AUM types
// leave DisablementValues alone (tka/state.go:162-254), so these are the state's values.
type stateSnapshot struct {
	Head              string     `json:"head"`
	Keys              []keyValue `json:"keys"`
	DisablementValues []string   `json:"disablementValues"`
	StateID1          uint64     `json:"stateID1,string"`
	StateID2          uint64     `json:"stateID2,string"`
}

type chainStep struct {
	Name  string        `json:"name"`
	AUMs  []string      `json:"aums"`
	OK    bool          `json:"ok"`
	Error string        `json:"error,omitempty"`
	After stateSnapshot `json:"after"`
}

type chainCase struct {
	Name           string         `json:"name"`
	Bootstrap      string         `json:"bootstrap"`
	BootstrapOK    bool           `json:"bootstrapOK"`
	BootstrapError string         `json:"bootstrapError,omitempty"`
	Initial        *stateSnapshot `json:"initial"`
	Steps          []chainStep    `json:"steps"`
}

// authority is the Go Authority over tka.ChonkMem. Each step calls Unserialize on the bytes and passes them to Inform.
type authority struct {
	storage *tka.Mem
	auth    *tka.Authority
	aums    [][]byte // Bootstrap AUM and AUMs from accepted groups (in receipt order)
}

func bootstrapAuthority(genesis []byte) (*authority, error) {
	r := &authority{storage: tka.ChonkMem()}
	err := catch(func() error {
		var a tka.AUM
		if err := a.Unserialize(genesis); err != nil {
			return fmt.Errorf("unserialize: %w", err)
		}
		var err error
		r.auth, err = tka.Bootstrap(r.storage, a)
		return err
	})
	if err != nil {
		return nil, err
	}
	r.aums = [][]byte{genesis}
	return r, nil
}

func mustAuthority(aums ...[]byte) *authority {
	r, err := bootstrapAuthority(aums[0])
	if err != nil {
		panic(err)
	}
	if len(aums) > 1 {
		if err := r.inform(aums[1:]...); err != nil {
			panic(err)
		}
	}
	return r
}

func (r *authority) inform(raws ...[]byte) error {
	return catch(func() error {
		updates := make([]tka.AUM, len(raws))
		for i, raw := range raws {
			if err := updates[i].Unserialize(raw); err != nil {
				return fmt.Errorf("unserialize %d: %w", i, err)
			}
		}
		if err := r.auth.Inform(r.storage, updates); err != nil {
			return err
		}
		r.aums = append(r.aums, raws...)
		return nil
	})
}

func (r *authority) head() []byte {
	h := r.auth.Head()
	return h[:]
}

func (r *authority) snapshot() stateSnapshot {
	s := stateSnapshot{Head: hexOf(r.head()), Keys: []keyValue{}}
	for _, k := range r.auth.Keys() {
		s.Keys = append(s.Keys, viewKey(k))
	}
	s.StateID1, s.StateID2 = r.auth.StateIDs()
	cursor := r.auth.Head()
	for range 10000 {
		a, err := r.storage.AUM(cursor)
		if err != nil {
			panic(err)
		}
		if a.MessageKind == tka.AUMCheckpoint {
			s.DisablementValues = hexList(a.State.DisablementValues)
			return s
		}
		parent, ok := a.Parent()
		if !ok {
			panic("reached the root without a checkpoint")
		}
		cursor = parent
	}
	panic("could not find a checkpoint")
}

// chainRun creates one chainCase.
type chainRun struct {
	c chainCase
	a *authority
}

func newChain(name string, genesis []byte) *chainRun {
	r := &chainRun{c: chainCase{Name: name, Bootstrap: hexOf(genesis), Steps: []chainStep{}}}
	a, err := bootstrapAuthority(genesis)
	if err != nil {
		r.c.BootstrapError = err.Error()
		return r
	}
	r.a = a
	r.c.BootstrapOK = true
	s := a.snapshot()
	r.c.Initial = &s
	return r
}

// step passes one group of AUMs to Inform, records the result, and reports whether it was accepted.
func (r *chainRun) step(name string, raws ...[]byte) bool {
	st := chainStep{Name: name, AUMs: []string{}}
	for _, raw := range raws {
		st.AUMs = append(st.AUMs, hexOf(raw))
	}
	if err := r.a.inform(raws...); err != nil {
		st.Error = err.Error()
	} else {
		st.OK = true
	}
	st.After = r.a.snapshot()
	r.c.Steps = append(r.c.Steps, st)
	return st.OK
}

// mustStep is a step that must be accepted. It catches mistakes in scenario construction.
func (r *chainRun) mustStep(name string, raws ...[]byte) {
	if !r.step(name, raws...) {
		panic(fmt.Sprintf("%s/%s: %s", r.c.Name, name, r.c.Steps[len(r.c.Steps)-1].Error))
	}
}

func (r *chainRun) head() []byte { return r.a.head() }

// AUM construction helpers. All fill in the public tka.AUM type and call Serialize.

func genesisAUM(keys []tka.Key, dis [][]byte, id1, id2 uint64, signers ...edKey) []byte {
	a := tka.AUM{MessageKind: tka.AUMCheckpoint, State: &tka.State{DisablementValues: dis, Keys: keys, StateID1: id1, StateID2: id2}}
	signAUM(&a, signers...)
	return a.Serialize()
}

func childAUM(parent []byte, a tka.AUM, signers ...edKey) []byte {
	a.PrevAUMHash = append([]byte{}, parent...)
	signAUM(&a, signers...)
	return a.Serialize()
}

func noop(parent []byte, signers ...edKey) []byte {
	return childAUM(parent, tka.AUM{MessageKind: tka.AUMNoOp}, signers...)
}

func addKey(parent []byte, k tka.Key, signers ...edKey) []byte {
	return childAUM(parent, tka.AUM{MessageKind: tka.AUMAddKey, Key: &k}, signers...)
}

func removeKey(parent, keyID []byte, signers ...edKey) []byte {
	return childAUM(parent, tka.AUM{MessageKind: tka.AUMRemoveKey, KeyID: keyID}, signers...)
}

func updateVotes(parent, keyID []byte, votes uint, signers ...edKey) []byte {
	return childAUM(parent, tka.AUM{MessageKind: tka.AUMUpdateKey, KeyID: keyID, Votes: &votes}, signers...)
}

func aumHash(raw []byte) []byte {
	var a tka.AUM
	if err := a.Unserialize(raw); err != nil {
		panic(err)
	}
	h := a.Hash()
	return h[:]
}

var disablementValues = func() [][]byte {
	out := make([][]byte, 3)
	for i := range out {
		out[i] = tka.DisablementKDF(disablementSecret(i))
	}
	return out
}()

// forkKey is used only as the contents of AddKey in fork scenarios to change the hash.
func forkKey(i int) tka.Key { return newEdKey("fork", i).tkaKey(1) }

// pickPair selects the first pair of AUMs generated with i = 0, 1, … that satisfies cond. It sets relative hash order
// so an earlier fork rule gives a different outcome from hash comparison (rule 3).
func pickPair(make func(i int) (a, b []byte), cond func(a, b []byte) bool) ([]byte, []byte) {
	for i := range 64 {
		a, b := make(i)
		if cond(a, b) {
			return a, b
		}
	}
	panic("could not find a pair satisfying the condition")
}

func hashLess(a, b []byte) bool { return bytes.Compare(aumHash(a), aumHash(b)) < 0 }

func chainCases() ([]chainCase, []byte) {
	L, V := lockKeys, disablementValues
	var out []chainCase

	// 1. Linear chain. Genesis: lock/0 (2 votes), lock/1 (1 vote), disablement values 0 and 1, StateID 1 and 2, signed by lock/0.
	linear := newChain("linear", genesisAUM([]tka.Key{L[0].tkaKey(2), L[1].tkaKey(1)}, V[:2], 1, 2, L[0]))
	linear.mustStep("add-key", addKey(linear.head(), L[2].tkaKey(1), L[0]))
	linear.mustStep("update-key-votes", updateVotes(linear.head(), L[2].pub(), 3, L[1]))
	linear.mustStep("update-key-meta", childAUM(linear.head(), tka.AUM{MessageKind: tka.AUMUpdateKey, KeyID: L[2].pub(), Meta: map[string]string{"bb": "2", "a": "1", "c": "3"}}, L[2]))
	linear.mustStep("remove-key", removeKey(linear.head(), L[1].pub(), L[0]))
	linear.mustStep("noop", noop(linear.head(), L[2]))
	id1, id2 := linear.a.auth.StateIDs()
	checkpointState := tka.State{DisablementValues: [][]byte{V[2]}, Keys: linear.a.auth.Keys(), StateID1: id1, StateID2: id2}
	laterCheckpoint := childAUM(linear.head(), tka.AUM{MessageKind: tka.AUMCheckpoint, State: &checkpointState}, L[0])
	linear.mustStep("checkpoint", laterCheckpoint)
	linear.mustStep("add-key-after-checkpoint", addKey(linear.head(), L[3].tkaKey(1), L[2]))
	b1 := addKey(linear.head(), L[4].tkaKey(1), L[0])
	b2 := updateVotes(aumHash(b1), L[4].pub(), 2, L[4])
	b3 := noop(aumHash(b2), L[3])
	linear.mustStep("batch", b1, b2, b3)
	out = append(out, linear.c)

	// 2. Bootstrap.
	later := newChain("bootstrap/later-checkpoint", laterCheckpoint)
	later.mustStep("add-key", addKey(later.head(), L[5].tkaKey(1), L[0]))
	out = append(out, later.c)
	out = append(out, newChain("bootstrap/go-test-genesis", mustBase64(goTestGenesis)).c)
	notCheckpoint := tka.AUM{MessageKind: tka.AUMNoOp}
	signAUM(&notCheckpoint, L[0])
	out = append(out, newChain("bootstrap/not-checkpoint", notCheckpoint.Serialize()).c)
	out = append(out, newChain("bootstrap/unsigned", genesisAUM([]tka.Key{L[0].tkaKey(1)}, V[:1], 1, 2)).c)
	out = append(out, newChain("bootstrap/signed-by-untrusted", genesisAUM([]tka.Key{L[0].tkaKey(1)}, V[:1], 1, 2, untrusted)).c)
	last := tka.AUMHash{1}
	withLast := tka.AUM{MessageKind: tka.AUMCheckpoint, State: &tka.State{LastAUMHash: &last, DisablementValues: V[:1], Keys: []tka.Key{L[0].tkaKey(1)}}}
	signAUM(&withLast, L[0])
	out = append(out, newChain("bootstrap/last-aum-hash", withLast.Serialize()).c)
	out = append(out, newChain("bootstrap/wrong-signature", corruptSignature(genesisAUM([]tka.Key{L[0].tkaKey(1)}, V[:1], 1, 2, L[0]))).c)

	// 3. Rejections. Genesis: lock/0 and lock/1 (1 vote each).
	rej := newChain("rejections", genesisAUM([]tka.Key{L[0].tkaKey(1), L[1].tkaKey(1)}, V[:1], 1, 2, L[0]))
	rej.step("empty-batch")
	rej.step("unsigned", noop(rej.head()))
	rej.step("untrusted-signature-mixed", noop(rej.head(), L[0], untrusted))
	rej.step("wrong-signature", corruptSignature(noop(rej.head(), L[0])))
	rej.step("missing-parent", childAUMNoParent(tka.AUM{MessageKind: tka.AUMNoOp}, L[0]))
	rej.step("unknown-parent", noop(bytes.Repeat([]byte{0x5a}, 32), L[0]))
	rej.step("prev-33-bytes", noop(append(append([]byte{}, rej.head()...), 0), L[0]))
	rej.step("prev-31-bytes", noop(rej.head()[:31], L[0]))
	rej.step("duplicate-add-key", addKey(rej.head(), L[1].tkaKey(1), L[0]))
	otherIDs := tka.State{DisablementValues: V[:1], Keys: []tka.Key{L[0].tkaKey(1), L[1].tkaKey(1)}, StateID1: 1, StateID2: 3}
	rej.step("checkpoint-other-stateid", childAUM(rej.head(), tka.AUM{MessageKind: tka.AUMCheckpoint, State: &otherIDs}, L[0]))
	rej.step("remove-unknown-key", removeKey(rej.head(), L[5].pub(), L[0]))
	rej.step("update-unknown-key", updateVotes(rej.head(), L[5].pub(), 2, L[0]))
	rej.step("update-key-votes-zero", updateVotes(rej.head(), L[1].pub(), 0, L[0]))
	rej.step("update-key-votes-4097", updateVotes(rej.head(), L[1].pub(), 4097, L[0]))
	rej.step("static-invalid-signed", childAUM(rej.head(), tka.AUM{MessageKind: tka.AUMRemoveKey, KeyID: L[1].pub(), Votes: new(uint)}, L[0]))
	rej.step("kind-0-unsigned", childAUM(rej.head(), tka.AUM{MessageKind: tka.AUMInvalid}))
	good := noop(rej.head(), L[0])
	rej.step("batch-with-bad", good, noop(aumHash(good)))
	rej.step("batch-with-bad-first", noop(rej.head()), good)
	rej.mustStep("good-alone", good)
	rej.mustStep("already-held", good)
	next1 := noop(rej.head(), L[1])
	next2 := noop(aumHash(next1), L[0])
	rej.step("out-of-order", next2, next1)
	rej.mustStep("in-order", next1, next2)
	rej.mustStep("remove-key", removeKey(rej.head(), L[1].pub(), L[0]))
	rej.step("remove-last-key", removeKey(rej.head(), L[0].pub(), L[0]))
	rej.step("removed-key-signature", noop(rej.head(), L[1]))
	out = append(out, rej.c)

	// 4. Unusual inputs that are accepted. Genesis: lock/0 (1 vote).
	odd := newChain("oddities", genesisAUM([]tka.Key{L[0].tkaKey(1)}, V[:1], 1, 2, L[0]))
	odd.mustStep("kind-0", childAUM(odd.head(), tka.AUM{MessageKind: tka.AUMInvalid}, L[0]))
	odd.mustStep("kind-9", childAUM(odd.head(), tka.AUM{MessageKind: 9}, L[0]))
	odd.mustStep("kind-255", childAUM(odd.head(), tka.AUM{MessageKind: 255}, L[0]))
	three := uint(3)
	odd.mustStep("noop-extra-fields", childAUM(odd.head(), tka.AUM{MessageKind: tka.AUMNoOp, KeyID: L[1].pub(), Votes: &three, Meta: map[string]string{"a": "1"}}, L[0]))
	fk := newEdKey("fork", 0).pub()
	odd.step("add-key-public-null", addKey(odd.head(), tka.Key{Kind: tka.Key25519, Votes: 1}, L[0]))
	odd.step("add-key-public-empty", addKey(odd.head(), tka.Key{Kind: tka.Key25519, Votes: 1, Public: []byte{}}, L[0]))
	odd.step("add-key-public-31", addKey(odd.head(), tka.Key{Kind: tka.Key25519, Votes: 1, Public: fk[:31]}, L[0]))
	odd.step("add-key-public-33", addKey(odd.head(), tka.Key{Kind: tka.Key25519, Votes: 2, Public: append(append([]byte{}, fk...), 0)}, L[0]))
	odd.mustStep("noop-after", noop(odd.head(), L[0]))
	odd.step("remove-key-31", removeKey(odd.head(), fk[:31], L[0]))
	odd.step("update-key-33", updateVotes(odd.head(), append(append([]byte{}, fk...), 0), 4, L[0]))
	// A signature with a 33-byte key as KeyID fails static validation (32-byte KeyID).
	odd.step("signature-by-33-byte-key", signedWith(odd.head(), append(append([]byte{}, fk...), 0), func(m []byte) []byte { return ed25519.Sign(newEdKey("fork", 0).priv, m) }))
	sid1, sid2 := odd.a.auth.StateIDs()
	oddState := tka.State{DisablementValues: V[:1], Keys: odd.a.auth.Keys(), StateID1: sid1, StateID2: sid2}
	odd.step("checkpoint-with-odd-keys", childAUM(odd.head(), tka.AUM{MessageKind: tka.AUMCheckpoint, State: &oddState}, L[0]))
	canonical := noop(odd.head(), L[0])
	// Append an unknown field (8: 1) and extend MessageKind to a one-byte argument (18 03). The signature covers the SigHash of the canonical bytes.
	extended := addPairs(canonical, 1, "0801")
	extended = append([]byte{extended[0], 0x01, 0x18, 0x03}, extended[3:]...)
	odd.mustStep("unknown-field-and-non-shortest", extended)
	odd.mustStep("child-of-canonical-hash", noop(aumHash(canonical), L[0]))
	plain := noop(odd.head(), L[0])
	// Reorder pairs as 2, 1, 23 (canonical order is 1, 2, 23).
	unsorted := append(append(append([]byte{plain[0]}, plain[3:38]...), plain[1:3]...), plain[38:]...)
	odd.mustStep("unsorted-keys", unsorted)
	odd.mustStep("child-after-unsorted", noop(aumHash(plain), L[0]))
	// An integer array in place of a byte string: replace PrevAUMHash (02 58 20 …) with an array of 32 integers.
	plain = noop(odd.head(), L[0])
	asArray := append(append(append([]byte{}, plain[:4]...), mustHex(uintArray(plain[6:38]))...), plain[38:]...)
	odd.step("prev-as-uint-array", asArray)
	odd.step("child-after-prev-as-uint-array", noop(aumHash(plain), L[0]))
	// Replace the signature's KeyID and Signature with integer arrays.
	plain = noop(odd.head(), L[0])
	var parsed tka.AUM
	if err := parsed.Unserialize(plain); err != nil {
		panic(err)
	}
	sigArrays := bytes.Replace(plain, mustHex("01"+bstr(parsed.Signatures[0].KeyID)), mustHex("01"+uintArray(parsed.Signatures[0].KeyID)), 1)
	sigArrays = bytes.Replace(sigArrays, mustHex("02"+bstr(parsed.Signatures[0].Signature)), mustHex("02"+uintArray(parsed.Signatures[0].Signature)), 1)
	odd.step("signature-as-uint-arrays", sigArrays)
	odd.step("child-after-signature-as-uint-arrays", noop(aumHash(plain), L[0]))
	// A null Meta value: the canonical bytes encode {"a": ""} (07 a1 61 61 60). Replace the value with null (f6).
	metaEmpty := childAUM(odd.head(), tka.AUM{MessageKind: tka.AUMUpdateKey, KeyID: L[0].pub(), Meta: map[string]string{"a": ""}}, L[0])
	odd.step("update-key-meta-null-value", bytes.Replace(metaEmpty, mustHex("07a1616160"), mustHex("07a16161f6"), 1))
	odd.step("child-after-meta-null-value", noop(aumHash(metaEmpty), L[0]))
	out = append(out, odd.c)

	// 5. Signature that verifies only under ZIP-215 and a noncanonical public key. Genesis: lock/0, W (noncanonical encoding of the identity).
	w := tka.Key{Kind: tka.Key25519, Votes: 1, Public: nonCanonicalIdentity}
	z := newChain("zip215", genesisAUM([]tka.Key{L[0].tkaKey(1), w}, V[:1], 1, 2, L[0]))
	z.step("torsion-r-signature", signedWith(z.head(), L[0].pub(), func(m []byte) []byte { return zip215OnlySign(L[0], m) }))
	z.step("non-canonical-identity-key", signedWith(z.head(), nonCanonicalIdentity, identitySign))
	// R = W itself (noncanonical identity), S = 0. ZIP-215 accepts because [8]([0]B − R − [k]A) = 0.
	z.step("non-canonical-identity-key-identity-r-zero-s", signedWith(z.head(), nonCanonicalIdentity, func([]byte) []byte { return append(append([]byte{}, nonCanonicalIdentity...), make([]byte, 32)...) }))
	out = append(out, z.c)

	// 6. Duplicate AUM in one group (contract §5 TL-3, added by the TL-5 comparison tests). Go InformIdempotent validates and applies the second copy again
	// because it is not yet in storage (tka/tka.go:605-640). Genesis: lock/0 (1 vote).
	dup := newChain("batch-duplicates", genesisAUM([]tka.Key{L[0].tkaKey(1)}, V[:1], 1, 2, L[0]))
	da := noop(dup.head(), L[0])
	db := noop(aumHash(da), L[0])
	dc := noop(aumHash(db), L[0])
	dup.step("same-aum-twice", da, da)
	dup.step("duplicate-around-child", db, dc, db)
	dup.step("held-twice", dc, dc)
	one := uint(1)
	fork := childAUM(aumHash(da), tka.AUM{MessageKind: tka.AUMNoOp, Votes: &one}, L[0])
	dup.step("fork-twice", fork, fork)
	dup.step("unsigned-twice", noop(dup.head()), noop(dup.head()))
	dup.step("child-then-duplicate-parent", noop(aumHash(fork), L[0]), fork)
	out = append(out, dup.c)

	out = append(out, forkCases()...)
	return out, laterCheckpoint
}

// signedWith is a NoOp whose SigHash is signed with the function sign (KeyID is keyID).
func signedWith(parent, keyID []byte, sign func(message []byte) []byte) []byte {
	a := tka.AUM{MessageKind: tka.AUMNoOp, PrevAUMHash: append([]byte{}, parent...)}
	h := a.SigHash()
	a.Signatures = []tkatype.Signature{{KeyID: keyID, Signature: sign(h[:])}}
	return a.Serialize()
}

func childAUMNoParent(a tka.AUM, signers ...edKey) []byte {
	signAUM(&a, signers...)
	return a.Serialize()
}

// corruptSignature flips the first bit of the first signature.
func corruptSignature(raw []byte) []byte {
	var a tka.AUM
	if err := a.Unserialize(raw); err != nil {
		panic(err)
	}
	a.Signatures[0].Signature = flip(a.Signatures[0].Signature, 0)
	return a.Serialize()
}

func mustBase64(s string) []byte {
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

// forkCases contains chains with multiple children of the same parent (pickNextAUM rules 1–3).
func forkCases() []chainCase {
	L, V := lockKeys, disablementValues
	three := []tka.Key{L[0].tkaKey(1), L[1].tkaKey(1), L[2].tkaKey(1)}
	var out []chainCase

	// Weight: lock/2 has 2 votes. B (2 votes) beats A (1 vote) despite the larger hash.
	g := genesisAUM([]tka.Key{L[0].tkaKey(1), L[1].tkaKey(1), L[2].tkaKey(2)}, V[:1], 1, 2, L[0])
	a, b := pickPair(func(i int) ([]byte, []byte) {
		return addKey(aumHash(g), forkKey(2*i), L[0]), addKey(aumHash(g), forkKey(2*i+1), L[2])
	}, hashLess)
	c := newChain("fork/weight", g)
	c.mustStep("a", a)
	c.mustStep("b-heavier", b)
	out = append(out, c.c)

	// Two signatures (two keys, 2 votes) beat one (1 vote). The heavier side has the larger hash.
	g = genesisAUM(three, V[:1], 1, 2, L[0])
	a, b = pickPair(func(i int) ([]byte, []byte) {
		return addKey(aumHash(g), forkKey(2*i), L[2]), addKey(aumHash(g), forkKey(2*i+1), L[0], L[1])
	}, hashLess)
	c = newChain("fork/two-keys-beat-one", g)
	c.mustStep("a", a)
	c.mustStep("b-two-signatures", b)
	out = append(out, c.c)

	// Two signatures from the same key count once. A = lock/0 twice, B = lock/1 once. The weights tie, so B wins
	// with the smaller hash (A would win if counted twice).
	a, b = pickPair(func(i int) ([]byte, []byte) {
		return addKey(aumHash(g), forkKey(2*i), L[0], L[0]), addKey(aumHash(g), forkKey(2*i+1), L[1])
	}, func(a, b []byte) bool { return hashLess(b, a) })
	c = newChain("fork/same-key-twice", g)
	c.mustStep("a-same-key-twice", a)
	c.mustStep("b", b)
	out = append(out, c.c)

	// RemoveKey wins at equal weight. AddKey has the smaller hash.
	rk := removeKey(aumHash(g), L[2].pub(), L[1])
	a, _ = pickPair(func(i int) ([]byte, []byte) {
		return addKey(aumHash(g), forkKey(i), L[0]), rk
	}, hashLess)
	c = newChain("fork/remove-key-wins", g)
	c.mustStep("add-key", a)
	c.mustStep("remove-key", rk)
	out = append(out, c.c)

	// The smaller hash wins at equal weight and kind.
	c = newChain("fork/hash-tiebreak", g)
	c.mustStep("a", noop(aumHash(g), L[0]))
	c.mustStep("b", noop(aumHash(g), L[1]))
	out = append(out, c.c)

	// Adding descendants to the losing fork leaves the head unchanged. lock/1 has 2 votes.
	g2 := genesisAUM([]tka.Key{L[0].tkaKey(1), L[1].tkaKey(2)}, V[:1], 1, 2, L[0])
	win := addKey(aumHash(g2), forkKey(0), L[1])
	lose := addKey(aumHash(g2), forkKey(1), L[0])
	c = newChain("fork/losing-branch-grows", g2)
	c.mustStep("winner", win)
	c.mustStep("loser", lose)
	l1 := noop(aumHash(lose), L[0])
	c.mustStep("loser-child", l1)
	c.mustStep("loser-grandchild", noop(aumHash(l1), L[0]))
	c.mustStep("winner-child", noop(aumHash(win), L[0]))
	out = append(out, c.c)

	// A winning fork from an older point (recovery AUM): after X1 and X2 signed by lock/1, lock/0 and lock/2 sign
	// the MakeRetroactiveRevocation checkpoint forked from genesis (which removes lock/1).
	c = newChain("fork/retroactive-revocation", g)
	x1 := noop(aumHash(g), L[1])
	c.mustStep("x1", x1)
	x2 := noop(aumHash(x1), L[1])
	c.mustStep("x2", x2)
	var gh tka.AUMHash
	copy(gh[:], aumHash(g))
	revocation, err := c.a.auth.MakeRetroactiveRevocation(c.a.storage, []tkatype.KeyID{L[1].pub()}, L[0].pub(), gh)
	if err != nil {
		panic(err)
	}
	signAUM(revocation, L[0], L[2])
	c.mustStep("revocation", revocation.Serialize())
	c.step("old-branch-child", noop(aumHash(x2), L[1]))
	out = append(out, c.c)

	// Multilevel forks and one group that creates a fork.
	c = newChain("fork/multi-level", g)
	fa := addKey(aumHash(g), forkKey(0), L[0], L[1])
	fb := addKey(aumHash(g), forkKey(1), L[2])
	c.mustStep("batch-a-b", fa, fb)
	c.mustStep("a-children", noop(aumHash(fa), L[0]), noop(aumHash(fa), L[1], L[2]))
	c.mustStep("b-heavy-child", noop(aumHash(fb), L[0], L[1], L[2]))
	out = append(out, c.c)
	return out
}
