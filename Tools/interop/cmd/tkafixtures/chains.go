package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"fmt"

	"tailscale.com/tka"
	"tailscale.com/types/tkatype"
)

// stateSnapshot은 Authority의 공개 API로 읽은 상태다. 키는 Keys(), StateID는 StateIDs(), 머리는 Head()다.
// 끄기 값은 공개 접근자가 없어 저장소(ChonkMem.AUM)에서 머리부터 거꾸로 가 처음 만나는 체크포인트의
// State.DisablementValues를 읽는다. Go의 applyVerifiedAUM은 체크포인트에서만 상태 전체를 바꾸고 다른 종류는
// DisablementValues를 건드리지 않으므로(tka/state.go:162-254) 이것이 상태의 값이다.
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

// authority는 tka.ChonkMem 위의 Go Authority다. 단계마다 바이트를 Unserialize해 Inform에 넣는다.
type authority struct {
	storage *tka.Mem
	auth    *tka.Authority
	aums    [][]byte // 부트스트랩 AUM과 받아들인 묶음의 AUM(받은 순서)
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
			panic("체크포인트 없이 뿌리에 닿았습니다")
		}
		cursor = parent
	}
	panic("체크포인트를 찾지 못했습니다")
}

// chainRun은 chainCase 하나를 만든다.
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

// step은 AUM 묶음 하나를 Inform에 넣고 결과를 적는다. 받아들였는지 돌려준다.
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

// mustStep은 받아들여져야 하는 단계다(시나리오를 만드는 쪽의 실수를 잡는다).
func (r *chainRun) mustStep(name string, raws ...[]byte) {
	if !r.step(name, raws...) {
		panic(fmt.Sprintf("%s/%s: %s", r.c.Name, name, r.c.Steps[len(r.c.Steps)-1].Error))
	}
}

func (r *chainRun) head() []byte { return r.a.head() }

// AUM 만들기 도우미. 모두 공개 타입 tka.AUM에 값을 넣고 Serialize한다.

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

// forkKey는 갈래 시나리오에서 AddKey의 내용(해시를 바꾸는 값)으로만 쓰는 키다.
func forkKey(i int) tka.Key { return newEdKey("fork", i).tkaKey(1) }

// pickPair는 i = 0, 1, …로 만든 두 AUM 가운데 cond를 만족하는 첫 쌍을 고른다. 갈래 규칙의 앞 규칙이 해시
// 비교(규칙 3)와 다른 답을 내도록 해시의 대소를 맞추는 데 쓴다.
func pickPair(make func(i int) (a, b []byte), cond func(a, b []byte) bool) ([]byte, []byte) {
	for i := range 64 {
		a, b := make(i)
		if cond(a, b) {
			return a, b
		}
	}
	panic("조건을 만족하는 쌍을 찾지 못했습니다")
}

func hashLess(a, b []byte) bool { return bytes.Compare(aumHash(a), aumHash(b)) < 0 }

func chainCases() ([]chainCase, []byte) {
	L, V := lockKeys, disablementValues
	var out []chainCase

	// 1. 직선 사슬. genesis: lock/0(2표)·lock/1(1표), 끄기 값 0·1, StateID 1·2, lock/0이 서명.
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

	// 2. 부트스트랩.
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

	// 3. 거절. genesis: lock/0·lock/1(각 1표).
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

	// 4. 받아들여지는 이상한 것. genesis: lock/0(1표).
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
	// 33바이트 키를 KeyID로 단 서명은 정적 검사(KeyID 32바이트)에서 떨어진다.
	odd.step("signature-by-33-byte-key", signedWith(odd.head(), append(append([]byte{}, fk...), 0), func(m []byte) []byte { return ed25519.Sign(newEdKey("fork", 0).priv, m) }))
	sid1, sid2 := odd.a.auth.StateIDs()
	oddState := tka.State{DisablementValues: V[:1], Keys: odd.a.auth.Keys(), StateID1: sid1, StateID2: sid2}
	odd.step("checkpoint-with-odd-keys", childAUM(odd.head(), tka.AUM{MessageKind: tka.AUMCheckpoint, State: &oddState}, L[0]))
	canonical := noop(odd.head(), L[0])
	// 모르는 필드(8: 1)를 덧붙이고 MessageKind를 1바이트 인자(18 03)로 늘렸다. 서명은 정준 바이트의 SigHash 위에 있다.
	extended := addPairs(canonical, 1, "0801")
	extended = append([]byte{extended[0], 0x01, 0x18, 0x03}, extended[3:]...)
	odd.mustStep("unknown-field-and-non-shortest", extended)
	odd.mustStep("child-of-canonical-hash", noop(aumHash(canonical), L[0]))
	plain := noop(odd.head(), L[0])
	// 쌍 순서를 2, 1, 23으로 바꿨다(정준은 1, 2, 23).
	unsorted := append(append(append([]byte{plain[0]}, plain[3:38]...), plain[1:3]...), plain[38:]...)
	odd.mustStep("unsorted-keys", unsorted)
	odd.mustStep("child-after-unsorted", noop(aumHash(plain), L[0]))
	// 바이트열 자리를 정수 배열로 쓴 것: PrevAUMHash(02 58 20 …)를 정수 32개의 배열로 바꿨다.
	plain = noop(odd.head(), L[0])
	asArray := append(append(append([]byte{}, plain[:4]...), mustHex(uintArray(plain[6:38]))...), plain[38:]...)
	odd.step("prev-as-uint-array", asArray)
	odd.step("child-after-prev-as-uint-array", noop(aumHash(plain), L[0]))
	// 서명의 KeyID·Signature를 정수 배열로 바꿨다.
	plain = noop(odd.head(), L[0])
	var parsed tka.AUM
	if err := parsed.Unserialize(plain); err != nil {
		panic(err)
	}
	sigArrays := bytes.Replace(plain, mustHex("01"+bstr(parsed.Signatures[0].KeyID)), mustHex("01"+uintArray(parsed.Signatures[0].KeyID)), 1)
	sigArrays = bytes.Replace(sigArrays, mustHex("02"+bstr(parsed.Signatures[0].Signature)), mustHex("02"+uintArray(parsed.Signatures[0].Signature)), 1)
	odd.step("signature-as-uint-arrays", sigArrays)
	odd.step("child-after-signature-as-uint-arrays", noop(aumHash(plain), L[0]))
	// Meta 값의 null: 정준 바이트는 {"a": ""}(07 a1 61 61 60)이고 값 자리를 null(f6)로 바꿨다.
	metaEmpty := childAUM(odd.head(), tka.AUM{MessageKind: tka.AUMUpdateKey, KeyID: L[0].pub(), Meta: map[string]string{"a": ""}}, L[0])
	odd.step("update-key-meta-null-value", bytes.Replace(metaEmpty, mustHex("07a1616160"), mustHex("07a16161f6"), 1))
	odd.step("child-after-meta-null-value", noop(aumHash(metaEmpty), L[0]))
	out = append(out, odd.c)

	// 5. ZIP-215에서만 통과하는 서명과 비정준 공개 키. genesis: lock/0, W(비정준 인코딩의 항등원).
	w := tka.Key{Kind: tka.Key25519, Votes: 1, Public: nonCanonicalIdentity}
	z := newChain("zip215", genesisAUM([]tka.Key{L[0].tkaKey(1), w}, V[:1], 1, 2, L[0]))
	z.step("torsion-r-signature", signedWith(z.head(), L[0].pub(), func(m []byte) []byte { return zip215OnlySign(L[0], m) }))
	z.step("non-canonical-identity-key", signedWith(z.head(), nonCanonicalIdentity, identitySign))
	// R = W 자신(비정준 항등원), S = 0. ZIP-215에서는 [8]([0]B − R − [k]A) = 0이라 통과한다.
	z.step("non-canonical-identity-key-identity-r-zero-s", signedWith(z.head(), nonCanonicalIdentity, func([]byte) []byte { return append(append([]byte{}, nonCanonicalIdentity...), make([]byte, 32)...) }))
	out = append(out, z.c)

	// 6. 한 묶음 안의 같은 AUM(계약 5절 TL-3. TL-5 대조 시험이 더했다). Go InformIdempotent는 같은 묶음의 두 번째를
	// 저장소에 아직 없어서 다시 검증·적용한다(tka/tka.go:605-640). genesis: lock/0(1표).
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

// signedWith는 서명 함수 sign으로 SigHash에 서명한 NoOp이다(KeyID는 keyID).
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

// corruptSignature는 첫 서명의 첫 비트를 뒤집는다.
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

// forkCases는 같은 부모의 자식이 여럿인 사슬이다(pickNextAUM의 규칙 1~3).
func forkCases() []chainCase {
	L, V := lockKeys, disablementValues
	three := []tka.Key{L[0].tkaKey(1), L[1].tkaKey(1), L[2].tkaKey(1)}
	var out []chainCase

	// 가중치: lock/2가 2표. B(2표)가 해시가 더 큰데도 A(1표)를 이긴다.
	g := genesisAUM([]tka.Key{L[0].tkaKey(1), L[1].tkaKey(1), L[2].tkaKey(2)}, V[:1], 1, 2, L[0])
	a, b := pickPair(func(i int) ([]byte, []byte) {
		return addKey(aumHash(g), forkKey(2*i), L[0]), addKey(aumHash(g), forkKey(2*i+1), L[2])
	}, hashLess)
	c := newChain("fork/weight", g)
	c.mustStep("a", a)
	c.mustStep("b-heavier", b)
	out = append(out, c.c)

	// 서명 둘(키 둘, 2표)이 하나(1표)를 이긴다. 무거운 쪽의 해시가 더 크다.
	g = genesisAUM(three, V[:1], 1, 2, L[0])
	a, b = pickPair(func(i int) ([]byte, []byte) {
		return addKey(aumHash(g), forkKey(2*i), L[2]), addKey(aumHash(g), forkKey(2*i+1), L[0], L[1])
	}, hashLess)
	c = newChain("fork/two-keys-beat-one", g)
	c.mustStep("a", a)
	c.mustStep("b-two-signatures", b)
	out = append(out, c.c)

	// 같은 키의 서명 둘은 한 번만 센다. A = lock/0 두 번, B = lock/1 한 번. 같은 가중치라 해시가 작은 B가
	// 이긴다(두 번 세면 A가 이긴다).
	a, b = pickPair(func(i int) ([]byte, []byte) {
		return addKey(aumHash(g), forkKey(2*i), L[0], L[0]), addKey(aumHash(g), forkKey(2*i+1), L[1])
	}, func(a, b []byte) bool { return hashLess(b, a) })
	c = newChain("fork/same-key-twice", g)
	c.mustStep("a-same-key-twice", a)
	c.mustStep("b", b)
	out = append(out, c.c)

	// 같은 가중치면 RemoveKey가 이긴다. AddKey 쪽의 해시가 더 작다.
	rk := removeKey(aumHash(g), L[2].pub(), L[1])
	a, _ = pickPair(func(i int) ([]byte, []byte) {
		return addKey(aumHash(g), forkKey(i), L[0]), rk
	}, hashLess)
	c = newChain("fork/remove-key-wins", g)
	c.mustStep("add-key", a)
	c.mustStep("remove-key", rk)
	out = append(out, c.c)

	// 같은 가중치·같은 종류면 해시가 작은 쪽.
	c = newChain("fork/hash-tiebreak", g)
	c.mustStep("a", noop(aumHash(g), L[0]))
	c.mustStep("b", noop(aumHash(g), L[1]))
	out = append(out, c.c)

	// 진 갈래에 자손이 붙어도 머리는 그대로다. lock/1이 2표.
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

	// 오래된 지점에서 갈라져 이기는 갈래(복구 AUM): lock/1로 서명된 X1·X2 뒤에, genesis에서 갈라진
	// MakeRetroactiveRevocation의 체크포인트(lock/1 제거)를 lock/0·lock/2가 서명한다.
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

	// 여러 단의 갈래와, 갈래를 만드는 묶음 하나.
	c = newChain("fork/multi-level", g)
	fa := addKey(aumHash(g), forkKey(0), L[0], L[1])
	fb := addKey(aumHash(g), forkKey(1), L[2])
	c.mustStep("batch-a-b", fa, fb)
	c.mustStep("a-children", noop(aumHash(fa), L[0]), noop(aumHash(fa), L[1], L[2]))
	c.mustStep("b-heavy-child", noop(aumHash(fb), L[0], L[1], L[2]))
	out = append(out, c.c)
	return out
}
