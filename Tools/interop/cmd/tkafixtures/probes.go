package main

import (
	"encoding/base64"
	"fmt"
	"strings"

	"tailscale.com/tka"
)

// TL-5 대조 시험이 더한 시나리오 가운데 다른 배열의 모양에 맞지 않는 셋이다(계약 5절 "구현하며 정해진 것"의
// "실행으로 확정하지 않은 것", 그리고 Swiftail 한도(동작 M)의 경계).
//
//   - limits: 뿌리에서 2,000개가 넘는 사슬. AUM이 수천 개라 sync의 long 묶음(pool)을 앞부분으로 같이 쓰고 번호로 가리킨다.
//   - padded: Swiftail의 바이트 한도(NKS 8KiB, AUM 512KiB)를 넘기는 입력. 모르는 필드 하나(0으로 채운 바이트열)를
//     정준 바이트의 맵 끝에 덧붙인 것이라 바이트 대신 만드는 법(base, padKey, padLength)을 싣는다.
//   - openedStates: Bootstrap·Inform으로는 만들 수 없는 신뢰 상태(Key25519가 아닌 키). 저장소에 직접 넣고 tka.Open으로 연다.

type limitStep struct {
	Name  string `json:"name"`
	AUMs  []int  `json:"aums"`
	OK    bool   `json:"ok"`
	Error string `json:"error,omitempty"`
	Head  string `json:"head"`
}

type limitCase struct {
	Name string `json:"name"`
	// BaseCount개(pool 번호 0부터)로 시작한다: 첫 것으로 부트스트랩하고 나머지를 한 묶음으로 Inform한다.
	BaseCount int         `json:"baseCount"`
	BaseHead  string      `json:"baseHead"`
	Steps     []limitStep `json:"steps"`
}

type limitGroup struct {
	Name string `json:"name"`
	// Pool은 sync 배열의 묶음 이름이다. 그 pool 뒤에 Extra를 이은 것이 번호의 대상이다.
	Pool  string      `json:"pool"`
	Extra []string    `json:"extra"`
	Cases []limitCase `json:"cases"`
}

// limitGroups는 Go Inform의 반복 한도(maxScanIterations 2,000)가 어디서 걸리는지 본다(계약 5절 TL-3, 동작 F7).
//
// Go InformIdempotent는 묶음이 지금 머리에서 이어지는 사슬이면 상태를 그대로 쓰고(빠른 길), 아니면(갈래, 이미 쥔 AUM)
// 저장소에 커밋한 뒤 computeActiveChain을 2,000회 한도로 다시 돈다(tka/tka.go:651-664). 그 안의
// computeChainCandidates는 저장소의 모든 머리에서 뿌리까지 거꾸로 가므로(tka/tka.go:84-118), 뿌리에서 2,000번째 뒤의
// AUM이 하나라도 있으면 빠른 길이 아닌 Inform은 모두 실패한다. 부모 상태 찾기(computeStateAt)의 한도는 커밋 전에
// 걸린다. 번호: 0 G, 1 C(체크포인트), 2~2000 NoOp(long 묶음), 2001 E0(2000의 자식), 2002 E1(E0의 자식),
// 2003~2006 F(k)(k = 1998, 1999, 2000, 2001(E0)의 갈래 자식. NoOp에 Votes를 실어 형제와 다르다).
func limitGroups() []limitGroup {
	L := lockKeys
	pool := longPool()
	all := append([][]byte{}, pool...)
	all = append(all, noop(aumHash(all[2000]), L[0]))
	all = append(all, noop(aumHash(all[2001]), L[0]))
	one := uint(1)
	for _, k := range []int{1998, 1999, 2000, 2001} {
		all = append(all, childAUM(aumHash(all[k]), tka.AUM{MessageKind: tka.AUMNoOp, Votes: &one}, L[0]))
	}
	run := func(name string, baseCount int, steps ...[]int) limitCase {
		a := mustAuthority(all[:baseCount]...)
		c := limitCase{Name: name, BaseCount: baseCount, BaseHead: hexOf(a.head()), Steps: []limitStep{}}
		for i, idx := range steps {
			raws := make([][]byte, len(idx))
			for j, n := range idx {
				raws[j] = all[n]
			}
			st := limitStep{Name: fmt.Sprintf("step-%d", i+1), AUMs: idx}
			if err := a.inform(raws...); err != nil {
				st.Error = err.Error()
			} else {
				st.OK = true
			}
			st.Head = hexOf(a.head())
			c.Steps = append(c.Steps, st)
		}
		return c
	}
	var extra []string
	for _, raw := range all[len(pool):] {
		extra = append(extra, hexOf(raw))
	}
	return []limitGroup{{Name: "long-chain", Pool: "long", Extra: extra, Cases: []limitCase{
		// 빠른 길: 뿌리에서 2,001·2,002번째 AUM도 받는다.
		run("linear-past-2000", 2001, []int{2001}, []int{2002}),
		// 갈래(부모가 머리가 아니다): 새 AUM이 뿌리에서 1,999번째면 받고, 2,000번째면 커밋 뒤의 재계산에서 실패한다.
		run("fork-at-depth-1999", 2000, []int{2003}),
		run("fork-at-depth-2000", 2001, []int{2004}),
		// 이미 쥔 AUM이 섞여 빠른 길이 아니다. 실패한 묶음의 AUM은 Go 저장소에 남아 다음 묶음도 빠른 길이 아니게 된다.
		run("held-and-new-at-depth-2000", 2000, []int{1999, 2000}, []int{2000}),
		// 부모 상태 찾기: 체크포인트 C부터 부모까지 2,000개는 찾지만 뿌리에서 2,001번째 머리 때문에 재계산에서 실패한다.
		run("fork-parent-path-2000", 2002, []int{2005}),
		// 부모 상태 찾기: C부터 부모까지 2,001개는 커밋 전에 실패한다.
		run("fork-parent-path-2001", 2003, []int{2006}),
	}}}
}

type paddedCase struct {
	Name string `json:"name"`
	// Kind: authorize(NKS 판정), resign(ResignNKS의 옛 서명), inform(AUM 들이기), authKey(감싼 인증 키의 credential).
	Kind string `json:"kind"`
	// Base는 맵 머리가 한 바이트인 정준 바이트다. 입력 = 머리 + 1 ‖ Base[1:] ‖ uint(PadKey) ‖ bstr(0 × PadLength).
	Base      string `json:"base"`
	PadKey    uint64 `json:"padKey"`
	PadLength int    `json:"padLength"`
	Length    int    `json:"length"`
	Authority string `json:"authority,omitempty"`
	NodeKey   string `json:"nodeKey,omitempty"`
	NLKey     string `json:"nlKey,omitempty"`
	// authKey의 나머지: 입력 문자열 = ControlValue ‖ "--TL" ‖ RawStd(입력) ‖ "-" ‖ RawStd(PrivateKey).
	ControlValue string   `json:"controlValue,omitempty"`
	PrivateKey   string   `json:"privateKey,omitempty"`
	OK           bool     `json:"ok"`
	Error        string   `json:"error,omitempty"`
	Head         string   `json:"head,omitempty"`
	SigHash      string   `json:"sigHash,omitempty"`
	Verdict      *verdict `json:"verdict"`
}

// padTo는 정준 바이트 base의 맵 끝에 (padKey: 0으로 채운 바이트열)을 덧붙여 전체가 total바이트가 되게 한다.
func padTo(base []byte, padKey uint64, total int) ([]byte, int) {
	keyLen := len(mustHex(head(0, padKey)))
	for n := max(total-len(base)-keyLen-9, 0); n <= total; n++ {
		if len(base)+keyLen+len(mustHex(head(2, uint64(n))))+n == total {
			return addPairs(base, 1, head(0, padKey)+head(2, uint64(n))+strings.Repeat("00", n)), n
		}
	}
	panic("길이를 맞출 수 없습니다")
}

func paddedCases(all []namedAuthority) []paddedCase {
	L, NL, N := lockKeys, nlKeys, nodeKeys
	var out []paddedCase
	direct := ser(directNKS(L[0], N[0], NL[0].pub()))
	for _, total := range []int{8192, 8193} {
		input, n := padTo(direct, 7, total)
		c := paddedCase{Name: fmt.Sprintf("nks-direct-%d-bytes", total), Kind: "authorize", Base: hexOf(direct), PadKey: 7, PadLength: n, Length: len(input), Authority: "nks-base", NodeKey: hexOf(N[0].raw())}
		v := authorize(findAuthority(all, c.Authority), N[0].raw(), input)
		c.OK, c.Error, c.Verdict = v.Authorized, v.Error, &v
		out = append(out, c)
	}
	{
		input, n := padTo(direct, 7, 8193)
		c := paddedCase{Name: "resign-old-8193-bytes", Kind: "resign", Base: hexOf(direct), PadKey: 7, PadLength: n, Length: len(input), Authority: "nks-base", NodeKey: hexOf(N[1].raw()), NLKey: NL[0].label}
		var result []byte
		err := catch(func() error {
			var err error
			result, err = tka.ResignNKS(NL[0].nl(), N[1].public(), input)
			return err
		})
		if err != nil {
			c.Error = err.Error()
		} else {
			c.OK = true
			s := mustNKS(result)
			h := s.SigHash()
			c.SigHash = hexOf(h[:])
			v := authorize(findAuthority(all, c.Authority), N[1].raw(), result)
			c.Verdict = &v
		}
		out = append(out, c)
	}
	dis := findAuthority(all, "disablement")
	aum := noop(dis.head(), L[0])
	for _, total := range []int{512 * 1024, 512*1024 + 1} {
		input, n := padTo(aum, 8, total)
		c := paddedCase{Name: fmt.Sprintf("aum-noop-%d-bytes", total), Kind: "inform", Base: hexOf(aum), PadKey: 8, PadLength: n, Length: len(input), Authority: "disablement"}
		a := mustAuthority(dis.aums...)
		if err := a.inform(input); err != nil {
			c.Error = err.Error()
		} else {
			c.OK = true
		}
		c.Head = hexOf(a.head())
		out = append(out, c)
	}
	{
		cred := ser(credentialNKS(L[0], credentials[0].pub()))
		input, n := padTo(cred, 7, 8193)
		const control = "tskey-auth-kfixture1CNTRL-test0000"
		c := paddedCase{Name: "auth-key-credential-8193-bytes", Kind: "authKey", Base: hexOf(cred), PadKey: 7, PadLength: n, Length: len(input), Authority: "nks-base", NodeKey: hexOf(N[8].raw()), ControlValue: control, PrivateKey: hexOf(credentials[0].priv)}
		raw := base64RawStd(input)
		authKey, isWrapped, sig, p := tka.DecodeWrappedAuthkey(control+"--TL"+raw+"-"+base64RawStd(credentials[0].priv), func(string, ...any) {})
		switch {
		case !isWrapped:
			c.Error = "not wrapped: " + authKey
		default:
			var nks []byte
			if err := catch(func() error {
				var err error
				nks, err = tka.SignByCredential(p, sig, N[8].public())
				return err
			}); err != nil {
				c.Error = err.Error()
			} else {
				c.OK = authKey == control
				v := authorize(findAuthority(all, c.Authority), N[8].raw(), nks)
				c.Verdict = &v
			}
		}
		out = append(out, c)
	}
	return out
}

type openedCase struct {
	Name       string `json:"name"`
	Checkpoint string `json:"checkpoint"`
	OpenOK     bool   `json:"openOK"`
	OpenError  string `json:"openError,omitempty"`
	NodeKey    string `json:"nodeKey"`
	NKS        string `json:"nks"`
	verdict
}

// openedCases는 Key25519가 아닌 키가 든 신뢰 상태에서 State.GetKey의 판정을 본다(계약 5절 TL-4). 그런 체크포인트는
// 정적 검사에서 떨어지므로 Bootstrap으로는 만들 수 없다. 저장소에 직접 넣고(CommitVerifiedAUMs, SetLastActiveAncestor)
// tka.Open으로 연다. Open은 저장된 AUM을 다시 검증하지 않는다(tka/tka.go:476-498).
func openedCases() []openedCase {
	L, V, N := lockKeys, disablementValues, nodeKeys
	other := tka.Key{Kind: 2, Votes: 1, Public: newEdKey("fork", 0).pub()}
	var out []openedCase
	for _, c := range []struct {
		name string
		keys []tka.Key
	}{
		{"kind-2-key-before-signer", []tka.Key{other, L[0].tkaKey(1)}},
		{"kind-2-key-after-signer", []tka.Key{L[0].tkaKey(1), other}},
	} {
		cp := tka.AUM{MessageKind: tka.AUMCheckpoint, State: &tka.State{DisablementValues: V[:1], Keys: c.keys, StateID1: 1, StateID2: 2}}
		signAUM(&cp, L[0])
		nks := ser(directNKS(L[0], N[0], nil))
		oc := openedCase{Name: c.name, Checkpoint: hexOf(cp.Serialize()), NodeKey: hexOf(N[0].raw()), NKS: hexOf(nks)}
		storage := tka.ChonkMem()
		var opened *tka.Authority
		err := catch(func() error {
			if err := storage.CommitVerifiedAUMs([]tka.AUM{cp}); err != nil {
				return err
			}
			if err := storage.SetLastActiveAncestor(cp.Hash()); err != nil {
				return err
			}
			var err error
			opened, err = tka.Open(storage)
			return err
		})
		if err != nil {
			oc.OpenError = err.Error()
		} else {
			oc.OpenOK = true
			oc.verdict = authorize(&authority{storage: storage, auth: opened}, N[0].raw(), nks)
		}
		out = append(out, oc)
	}
	return out
}

func base64RawStd(b []byte) string { return base64.RawStdEncoding.EncodeToString(b) }
