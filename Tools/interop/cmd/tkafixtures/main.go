// tkafixtures는 Go tailscale.com/tka 패키지의 판정을 JSON으로 쓴다(Tailnet Lock 계약 7절 "Go 기준값 대조").
// Swift 소스는 읽거나 실행하지 않는다. 네트워크·현재 시각·외부 난수를 쓰지 않는다. 키는 모두
// SHA-256("swiftail-fixtures/tka/<역할>/<번호>")에서 나오고 Ed25519 서명은 결정적이라, 다시 뽑아도 같은 바이트가
// 나온다. 판정은 tka의 공개 API가 내고, 피어 거르기만 ipnlocal의 실제 함수를 overlay로 부른다(peersets.go).
//
// 사용법(현재 폴더는 Tools/interop):
//
//	tkafixtures            JSON을 표준 출력에 쓴다
//	tkafixtures <폴더>      <폴더>/tka-fixtures.json을 쓴다
//	tkafixtures verify-nks 표준 입력의 JSON 객체 하나로 NKS를 검증해 JSON 한 줄을 쓴다
package main

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"strings"
)

const tailscaleVersion = "v1.104.6"

type reference struct {
	Go        string `json:"go"`
	Tailscale string `json:"tailscale"`
}

func buildReference() (reference, error) {
	r := reference{Go: runtime.Version()}
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return r, errors.New("Go 빌드 정보가 없습니다")
	}
	for _, dep := range info.Deps {
		if dep.Path == "tailscale.com" && dep.Replace == nil {
			r.Tailscale = dep.Version
		}
	}
	if r.Tailscale != tailscaleVersion {
		return r, errors.New("기준 tailscale 버전이 다릅니다")
	}
	return r, nil
}

// keyCase는 자료에 쓰인 시험 키다. seed는 SHA-256의 입력 문자열, private은 Ed25519 씨앗(32바이트) 또는
// node 키의 X25519 개인 키 입력이다.
type keyCase struct {
	Role    string `json:"role"`
	Index   int    `json:"index"`
	Seed    string `json:"seed"`
	Private string `json:"private"`
	Public  string `json:"public"`
	Text    string `json:"text"`
}

func keyCases() []keyCase {
	var out []keyCase
	ed := func(k edKey) {
		pub := k.nl().Public()
		out = append(out, keyCase{k.role, k.index, k.label, hexOf(k.priv.Seed()), hexOf(k.pub()), pub.CLIString()})
	}
	for _, k := range lockKeys {
		ed(k)
	}
	ed(untrusted)
	for _, k := range nlKeys {
		ed(k)
	}
	for _, k := range credentials {
		ed(k)
	}
	for i := range 10 {
		ed(newEdKey("fork", i))
	}
	for _, n := range nodeKeys {
		_, s := seed("node", n.index)
		out = append(out, keyCase{"node", n.index, n.label, hexOf(s), hexOf(n.raw()), n.public().String()})
	}
	for i := range 4 {
		label, s := seed("disablement", i)
		out = append(out, keyCase{"disablement", i, label, hexOf(s), "", ""})
	}
	return out
}

// section은 출력 JSON의 최상위 멤버 하나다. 배열은 원소 하나를 한 줄에 쓴다(diff를 읽기 쉽게).
type section struct {
	name  string
	value any
	cases int // caseCount에 더할 수
}

func evaluate() ([]byte, error) {
	ref, err := buildReference()
	if err != nil {
		return nil, err
	}
	all := authorities()
	chains, laterCheckpoint := chainCases()
	syncs := syncGroups()
	syncCount := 0
	for _, g := range syncs {
		syncCount += len(g.Cases)
	}
	peers, unordered, err := peerSetCases(all)
	if err != nil {
		return nil, err
	}
	limits := limitGroups()
	limitCount := 0
	for _, g := range limits {
		limitCount += len(g.Cases)
	}
	var auths []authorityCase
	for _, n := range all {
		auths = append(auths, viewAuthority(n))
	}
	cbors, encodings := cborCases(), encodingCases()
	texts := textCases([][]byte{aumHash(laterCheckpoint), make([]byte, 32), bytes.Repeat([]byte{0xff}, 32)})
	sigs, resigns := signatureCases(all), resignCases(all)
	dis, authKeys := disablementCases(all), authKeyCases(all)
	padded, opened := paddedCases(all), openedCases()
	reviewChains, reviewSigs := reviewChainCases(), reviewSignatureCases(all)
	sections := []section{
		{"keys", keyCases(), 0},
		{"authorities", auths, 0},
		{"text", texts, len(texts)},
		{"encodings", encodings, len(encodings)},
		{"cbor", cbors, len(cbors)},
		{"chains", chains, len(chains)},
		{"sync", syncs, syncCount},
		{"signatures", sigs, len(sigs)},
		{"peerSets", peers, len(peers)},
		{"disablement", dis, len(dis)},
		{"authKeys", authKeys, len(authKeys)},
		{"resign", resigns, len(resigns)},
		{"unorderedPeerSets", unordered, len(unordered)},
		{"limits", limits, limitCount},
		{"padded", padded, len(padded)},
		{"openedStates", opened, len(opened)},
		{"reviewChains", reviewChains, len(reviewChains)},
		{"reviewSignatures", reviewSigs, len(reviewSigs)},
	}
	return encode(ref, sections)
}

func encode(ref reference, sections []section) ([]byte, error) {
	var b bytes.Buffer
	count := 0
	for _, s := range sections {
		count += s.cases
	}
	refJSON, err := json.Marshal(ref)
	if err != nil {
		return nil, err
	}
	fmt.Fprintf(&b, "{\"reference\":%s,\n\"caseCount\":%d", refJSON, count)
	for _, s := range sections {
		raw, err := json.Marshal(s.value)
		if err != nil {
			return nil, err
		}
		var items []json.RawMessage
		if err := json.Unmarshal(raw, &items); err != nil {
			return nil, err
		}
		fmt.Fprintf(&b, ",\n%q:[", s.name)
		for i, item := range items {
			if i > 0 {
				b.WriteByte(',')
			}
			b.WriteByte('\n')
			b.Write(item)
		}
		b.WriteString("\n]")
	}
	b.WriteString("}\n")
	return b.Bytes(), nil
}

func main() {
	if len(os.Args) == 2 && os.Args[1] == "verify-nks" {
		os.Exit(verifyCommand(os.Stdin, os.Stdout))
	}
	if os.Getenv("GOCACHE") == "" {
		fmt.Fprintln(os.Stderr, "GOCACHE를 정하세요(Tools/interop/README.md의 환경)")
		os.Exit(1)
	}
	data, err := evaluate()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	switch len(os.Args) {
	case 1:
		os.Stdout.Write(data)
	case 2:
		if err := os.WriteFile(filepath.Join(os.Args[1], "tka-fixtures.json"), data, 0o644); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
	default:
		fmt.Fprintln(os.Stderr, "사용법: tkafixtures [폴더 | verify-nks]")
		os.Exit(2)
	}
}

// verifyInput은 verify-nks의 입력이다. aums의 첫 것으로 부트스트랩하고 나머지를 Inform한 상태에서
// node 키(32바이트 16진)와 NKS(16진)를 NodeKeyAuthorizedWithDetails로 판정한다.
type verifyInput struct {
	AUMs    []string `json:"aums"`
	NodeKey string   `json:"nodeKey"`
	NKS     string   `json:"nks"`
}

type verifyOutput struct {
	OK bool `json:"ok"`
	verdict
}

const maxVerifyInput = 4 << 20

func verifyCommand(stdin io.Reader, stdout io.Writer) int {
	fail := func(message string) int {
		line, _ := json.Marshal(struct {
			OK    bool   `json:"ok"`
			Error string `json:"error"`
		}{false, message})
		fmt.Fprintf(stdout, "%s\n", line)
		return 1
	}
	data, err := io.ReadAll(io.LimitReader(stdin, maxVerifyInput+1))
	if err != nil || len(data) > maxVerifyInput {
		return fail("입력을 읽지 못했거나 4MiB를 넘습니다")
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var in verifyInput
	if err := dec.Decode(&in); err != nil {
		return fail("JSON 객체가 아닙니다: " + err.Error())
	}
	if dec.More() {
		return fail("JSON 뒤에 남은 값이 있습니다")
	}
	if len(in.AUMs) == 0 {
		return fail("aums가 비었습니다")
	}
	raws := make([][]byte, len(in.AUMs))
	for i, h := range in.AUMs {
		if raws[i], err = decodeHex(h); err != nil {
			return fail(fmt.Sprintf("aums[%d]: %v", i, err))
		}
	}
	node, err := decodeHex(in.NodeKey)
	if err != nil || len(node) != 32 {
		return fail("nodeKey는 32바이트 16진이어야 합니다")
	}
	nks, err := decodeHex(in.NKS)
	if err != nil {
		return fail("nks: " + err.Error())
	}
	a, err := bootstrapAuthority(raws[0])
	if err != nil {
		return fail("bootstrap: " + err.Error())
	}
	if len(raws) > 1 {
		if err := a.inform(raws[1:]...); err != nil {
			return fail("inform: " + err.Error())
		}
	}
	line, err := json.Marshal(verifyOutput{true, authorize(a, node, nks)})
	if err != nil {
		return fail(err.Error())
	}
	fmt.Fprintf(stdout, "%s\n", line)
	return 0
}

// decodeHex는 소문자 16진만 받는다.
func decodeHex(s string) ([]byte, error) {
	if s != strings.ToLower(s) {
		return nil, errors.New("16진은 소문자여야 합니다")
	}
	return hex.DecodeString(s)
}
