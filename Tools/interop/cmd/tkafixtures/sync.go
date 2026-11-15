package main

import (
	"crypto/sha256"

	"tailscale.com/tka"
)

// 동기화 시나리오. 두 Authority(local, remote)를 AUM 모음(pool)의 번호 목록으로 만든다: 첫 번호로
// 부트스트랩하고 나머지를 그 순서대로 한 묶음으로 Inform한다. 각자 SyncOffer를 내고, 상대 제안에 대한
// MissingAUMs(상대가 모를 자기 AUM)를 둘 다 먼저 계산한 뒤, 상대의 목록을 Inform한다(목록이 비었거나
// 계산이 실패하면 하지 않는다).

type offerView struct {
	Head      string   `json:"head"`
	Ancestors []string `json:"ancestors"`
	// HeadText·AncestorsText는 tka.FromSyncOffer의 base32 텍스트(RPC에 실리는 형식)다.
	HeadText      string   `json:"headText"`
	AncestorsText []string `json:"ancestorsText"`
}

// missingView는 MissingAUMs의 결과다. 해시가 100개를 넘으면 목록은 싣지 않고 수와 SHA-256(해시 32바이트를
// 차례로 이은 것)만 싣는다.
type missingView struct {
	OK     bool     `json:"ok"`
	Error  string   `json:"error,omitempty"`
	Count  int      `json:"count"`
	Digest string   `json:"digest"`
	Hashes []string `json:"hashes,omitempty"`
}

type syncSide struct {
	AUMs        []int       `json:"aums"`
	Offer       offerView   `json:"offer"`
	Missing     missingView `json:"missing"`
	InformOK    bool        `json:"informOK"`
	InformError string      `json:"informError,omitempty"`
	HeadAfter   string      `json:"headAfter"`
}

type syncCase struct {
	Name   string   `json:"name"`
	Local  syncSide `json:"local"`
	Remote syncSide `json:"remote"`
}

type syncGroup struct {
	Name  string     `json:"name"`
	Pool  []string   `json:"pool"`
	Cases []syncCase `json:"cases"`
}

func indices(from, to int) []int {
	var out []int
	for i := from; i <= to; i++ {
		out = append(out, i)
	}
	return out
}

func join(parts ...[]int) []int {
	var out []int
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}

func syncSideAuthority(pool [][]byte, idx []int) *authority {
	raws := make([][]byte, len(idx))
	for i, n := range idx {
		raws[i] = pool[n]
	}
	return mustAuthority(raws...)
}

func viewOffer(o tka.SyncOffer) offerView {
	v := offerView{Head: hexOf(o.Head[:]), Ancestors: []string{}}
	for _, a := range o.Ancestors {
		v.Ancestors = append(v.Ancestors, hexOf(a[:]))
	}
	head, ancestors, err := tka.FromSyncOffer(o)
	if err != nil {
		panic(err)
	}
	v.HeadText, v.AncestorsText = head, ancestors
	return v
}

func runSync(name string, pool [][]byte, localIdx, remoteIdx []int) syncCase {
	local, remote := syncSideAuthority(pool, localIdx), syncSideAuthority(pool, remoteIdx)
	c := syncCase{Name: name, Local: syncSide{AUMs: localIdx}, Remote: syncSide{AUMs: remoteIdx}}
	localOffer, err := local.auth.SyncOffer(local.storage)
	if err != nil {
		panic(err)
	}
	remoteOffer, err := remote.auth.SyncOffer(remote.storage)
	if err != nil {
		panic(err)
	}
	c.Local.Offer, c.Remote.Offer = viewOffer(localOffer), viewOffer(remoteOffer)
	missing := func(a *authority, offer tka.SyncOffer) (missingView, [][]byte) {
		var aums []tka.AUM
		err := catch(func() error {
			var err error
			aums, err = a.auth.MissingAUMs(a.storage, offer)
			return err
		})
		v := missingView{OK: err == nil}
		if err != nil {
			v.Error = err.Error()
		}
		digest := sha256.New()
		var raws [][]byte
		for _, m := range aums {
			h := m.Hash()
			digest.Write(h[:])
			v.Hashes = append(v.Hashes, hexOf(h[:]))
			raws = append(raws, m.Serialize())
		}
		v.Count, v.Digest = len(aums), hexOf(digest.Sum(nil))
		if len(v.Hashes) > 100 {
			v.Hashes = nil
		}
		return v, raws
	}
	var localSends, remoteSends [][]byte
	c.Local.Missing, localSends = missing(local, remoteOffer)
	c.Remote.Missing, remoteSends = missing(remote, localOffer)
	receive := func(side *syncSide, a *authority, raws [][]byte, ok bool) {
		side.InformOK = true
		if ok && len(raws) > 0 {
			if err := a.inform(raws...); err != nil {
				side.InformOK, side.InformError = false, err.Error()
			}
		}
		side.HeadAfter = hexOf(a.head())
	}
	receive(&c.Local, local, remoteSends, c.Remote.Missing.OK)
	receive(&c.Remote, remote, localSends, c.Local.Missing.OK)
	return c
}

func syncGroups() []syncGroup {
	L, V := lockKeys, disablementValues
	var groups []syncGroup
	hexPool := func(pool [][]byte) []string {
		out := make([]string, len(pool))
		for i, p := range pool {
			out[i] = hexOf(p)
		}
		return out
	}

	// basic: 0 G(lock/0·lock/1), 1~5 X1~X5(직선, lock/0), 6·7 Y3·Y4(X2에서 갈라짐, lock/1),
	// 8 C1(G에서 갈라진 체크포인트, lock/0·lock/1이 서명해 2표), 9 C2(C1의 자식), 10 G'(다른 genesis), 11 G'의 자식.
	keys := []tka.Key{L[0].tkaKey(1), L[1].tkaKey(1)}
	g := genesisAUM(keys, V[:1], 1, 2, L[0])
	pool := [][]byte{g}
	for range 5 {
		pool = append(pool, noop(aumHash(pool[len(pool)-1]), L[0]))
	}
	y3 := noop(aumHash(pool[2]), L[1])
	pool = append(pool, y3, noop(aumHash(y3), L[1]))
	c1 := childAUM(aumHash(g), tka.AUM{MessageKind: tka.AUMCheckpoint, State: &tka.State{DisablementValues: V[:1], Keys: keys, StateID1: 1, StateID2: 2}}, L[0], L[1])
	pool = append(pool, c1, noop(aumHash(c1), L[0]))
	other := genesisAUM([]tka.Key{L[2].tkaKey(1)}, V[:1], 3, 4, L[2])
	pool = append(pool, other, noop(aumHash(other), L[2]))
	groups = append(groups, syncGroup{"basic", hexPool(pool), []syncCase{
		runSync("same-head", pool, indices(0, 5), indices(0, 5)),
		runSync("behind", pool, indices(0, 2), indices(0, 5)),
		runSync("ahead", pool, indices(0, 5), indices(0, 2)),
		runSync("diverged", pool, indices(0, 5), join(indices(0, 2), []int{6, 7})),
		runSync("diverged-remote-checkpoint", pool, indices(0, 5), []int{0, 8, 9}),
		runSync("remote-genesis-only", pool, indices(0, 5), []int{0}),
		runSync("no-intersection", pool, indices(0, 5), []int{10, 11}),
	}})

	// checkpoint-51: 0 G, 1~49 NoOp, 50 체크포인트(51번째 AUM), 51·52 NoOp.
	pool = [][]byte{genesisAUM(keys, V[:1], 1, 2, L[0])}
	for i := 1; i <= 52; i++ {
		parent := aumHash(pool[i-1])
		if i == 50 {
			pool = append(pool, childAUM(parent, tka.AUM{MessageKind: tka.AUMCheckpoint, State: &tka.State{DisablementValues: V[:1], Keys: keys, StateID1: 1, StateID2: 2}}, L[0]))
		} else {
			pool = append(pool, noop(parent, L[0]))
		}
	}
	groups = append(groups, syncGroup{"checkpoint-51", hexPool(pool), []syncCase{
		runSync("offer-with-checkpoint", pool, indices(0, 52), []int{0}),
		runSync("head-intersection", pool, indices(0, 52), indices(0, 30)),
		runSync("remote-past-checkpoint", pool, indices(0, 30), indices(0, 52)),
	}})

	// long: 0 G(lock/0), 1 C(G 다음의 체크포인트), 2~2000 NoOp. 조상 목록의 1,000회 한도와 앞으로 감기의
	// 2,000회 한도(maxSyncHeadIntersectionIter, maxSyncIter)의 경계.
	one := []tka.Key{L[0].tkaKey(1)}
	pool = [][]byte{genesisAUM(one, V[:1], 1, 2, L[0])}
	pool = append(pool, childAUM(aumHash(pool[0]), tka.AUM{MessageKind: tka.AUMCheckpoint, State: &tka.State{DisablementValues: V[:1], Keys: one, StateID1: 1, StateID2: 2}}, L[0]))
	for i := 2; i <= 2000; i++ {
		pool = append(pool, noop(aumHash(pool[i-1]), L[0]))
	}
	groups = append(groups, syncGroup{"long", hexPool(pool), []syncCase{
		runSync("checkpoint-depth-999", pool, indices(0, 1000), []int{0}),
		runSync("checkpoint-depth-1000", pool, indices(0, 1001), []int{0}),
		runSync("fast-forward-1999", pool, indices(0, 1999), []int{0}),
		runSync("fast-forward-2000", pool, indices(0, 2000), []int{0}),
	}})
	return groups
}
