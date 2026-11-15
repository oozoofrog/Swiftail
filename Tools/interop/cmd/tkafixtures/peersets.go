package main

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"tailscale.com/tka"
)

// 피어 거르기의 낡은 키 판정(rotationTracker)은 ipnlocal의 내보내지 않은 타입이다. mapfixtures와 같은 방식으로
// tailscale.com의 임시 사본에 bridge.go.txt 한 파일을 overlay로 얹고, 그 파일이 실제 tkaFilterNetmapLocked를
// 부른다(거르기 로직을 옮겨 적지 않는다). 모듈 캐시는 고치지 않고, 임시 사본은 끝나면 지운다.

//go:embed bridge.go.txt
var bridge []byte

//go:embed worker.go.txt
var worker []byte

type peerInput struct {
	NodeKey             string `json:"nodeKey"`
	Signature           string `json:"signature"`
	UnsignedPeerAPIOnly bool   `json:"unsignedPeerAPIOnly"`
}

type peerSetCase struct {
	Name      string      `json:"name"`
	Authority string      `json:"authority"`
	Peers     []peerInput `json:"peers"`
	Kept      []string    `json:"kept"`
}

func peerSetInputs() []peerSetCase {
	L, NL, N := lockKeys, nlKeys, nodeKeys
	peer := func(n nodeKey, sig []byte) peerInput {
		return peerInput{NodeKey: hexOf(n.raw()), Signature: hexOf(sig)}
	}
	direct := directNKS(L[0], N[0], NL[0].pub())
	r1 := rotationNKS(NL[0], N[1], direct, nil)
	r2 := rotationNKS(NL[0], N[2], r1, nil)
	r3 := rotationNKS(NL[0], N[3], direct, nil)
	r4 := rotationNKS(NL[0], N[4], direct, nil)
	cred := credentialNKS(L[0], credentials[0].pub())
	byCred := func(n nodeKey) []byte {
		b, err := tka.SignByCredential(credentials[0].priv, &cred, n.public())
		if err != nil {
			panic(err)
		}
		return b
	}
	other := directNKS(L[0], N[9], NL[1].pub())
	apiOnly := func(p peerInput) peerInput { p.UnsignedPeerAPIOnly = true; return p }
	base := "nks-base"
	return []peerSetCase{
		{Name: "unsigned-invalid-and-api-only", Authority: base, Peers: []peerInput{
			peer(N[0], ser(direct)), peer(N[1], nil), peer(N[2], ser(directNKS(L[0], N[3], nil))),
			apiOnly(peer(N[4], nil)), apiOnly(peer(N[5], ser(directNKS(untrusted, N[5], nil)))),
			peer(N[6], ser(directNKS(untrusted, N[6], nil))),
		}},
		{Name: "rotation-obsoletes-previous", Authority: base, Peers: []peerInput{peer(N[0], ser(direct)), peer(N[1], ser(r1))}},
		{Name: "same-wrapping-longest-wins", Authority: base, Peers: []peerInput{peer(N[3], ser(r3)), peer(N[2], ser(r2)), peer(N[7], ser(directNKS(L[0], N[7], NL[0].pub())))}},
		{Name: "same-wrapping-equal-length", Authority: base, Peers: []peerInput{peer(N[3], ser(r3)), peer(N[4], ser(r4))}},
		{Name: "obsolete-member-excluded", Authority: base, Peers: []peerInput{peer(N[1], ser(r1)), peer(N[2], ser(r2))}},
		{Name: "credential-chains-not-grouped", Authority: base, Peers: []peerInput{peer(N[6], byCred(N[6])), peer(N[7], byCred(N[7]))}},
		{Name: "different-wrapping-keys", Authority: base, Peers: []peerInput{peer(N[3], ser(r3)), peer(N[8], ser(rotationNKS(NL[1], N[8], other, nil)))}},
		{Name: "removed-signing-key", Authority: "nks-removed", Peers: []peerInput{peer(N[0], ser(direct)), peer(N[10], ser(directNKS(L[1], N[10], nil)))}},
	}
}

func peerSetCases(all []namedAuthority) ([]peerSetCase, error) {
	cases := peerSetInputs()
	type setInput struct {
		AUMs  []string    `json:"aums"`
		Peers []peerInput `json:"peers"`
	}
	input := make([]setInput, len(cases))
	for i, c := range cases {
		input[i] = setInput{viewAuthority(namedAuthority{c.Authority, findAuthority(all, c.Authority)}).AUMs, c.Peers}
	}
	payload, err := json.Marshal(input)
	if err != nil {
		return nil, err
	}
	output, err := runBridge(payload)
	if err != nil {
		return nil, err
	}
	var kept [][]string
	if err := json.Unmarshal(output, &kept); err != nil {
		return nil, err
	}
	if len(kept) != len(cases) {
		return nil, errors.New("피어 집합 결과의 수가 다릅니다")
	}
	for i := range cases {
		cases[i].Kept = kept[i]
	}
	return cases, nil
}

// runBridge는 tailscale.com 사본 + overlay로 worker를 빌드해 실행한다. 현재 폴더가 Tools/interop(그
// go.mod가 GOMOD)여야 한다. 빌드 임시 파일은 eyebuild dir interop-tools 아래에만 둔다.
func runBridge(payload []byte) ([]byte, error) {
	out, err := exec.Command("go", "list", "-m", "-json", "tailscale.com").Output()
	if err != nil {
		return nil, fmt.Errorf("기준 모듈 조회(현재 폴더가 Tools/interop인지 확인): %w", err)
	}
	var module struct{ Dir, Version string }
	if err := json.Unmarshal(out, &module); err != nil {
		return nil, err
	}
	if module.Version != tailscaleVersion {
		return nil, errors.New("기준 tailscale.com 버전이 다릅니다")
	}
	build, err := exec.Command("eyebuild", "dir", "interop-tools").Output()
	if err != nil {
		return nil, err
	}
	dir, err := os.MkdirTemp(strings.TrimSpace(string(build)), "tkafixtures-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(dir)
	// Go는 모듈 캐시 안의 overlay를 금지한다. 원본의 임시 사본에만 얹는다.
	reference := filepath.Join(dir, "tailscale")
	if err := os.CopyFS(reference, os.DirFS(module.Dir)); err != nil {
		return nil, err
	}
	gomod, err := exec.Command("go", "env", "GOMOD").Output()
	if err != nil {
		return nil, err
	}
	sourceModfile := strings.TrimSpace(string(gomod))
	mod, err := os.ReadFile(sourceModfile)
	if err != nil {
		return nil, err
	}
	sum, err := os.ReadFile(filepath.Join(filepath.Dir(sourceModfile), "go.sum"))
	if err != nil {
		return nil, err
	}
	modfile, overlayPath, bridgePath, workerPath := filepath.Join(dir, "go.mod"), filepath.Join(dir, "overlay.json"), filepath.Join(dir, "bridge.go"), filepath.Join(dir, "main.go")
	mod = append(mod, []byte("\nreplace tailscale.com => "+fmt.Sprintf("%q", reference)+"\n")...)
	overlay, err := json.Marshal(map[string]any{"Replace": map[string]string{filepath.Join(reference, "ipn", "ipnlocal", "swiftail_fixtures.go"): bridgePath}})
	if err != nil {
		return nil, err
	}
	for path, content := range map[string][]byte{modfile: mod, filepath.Join(dir, "go.sum"): sum, overlayPath: overlay, bridgePath: bridge, workerPath: worker} {
		if err := os.WriteFile(path, content, 0o600); err != nil {
			return nil, err
		}
	}
	binary := filepath.Join(dir, "worker")
	cmd := exec.Command("go", "build", "-modfile", modfile, "-overlay", overlayPath, "-o", binary, workerPath)
	cmd.Env = append(os.Environ(), "GOTMPDIR="+dir)
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("ipnlocal 사본 빌드: %w", err)
	}
	run := exec.Command(binary)
	run.Stdin = bytes.NewReader(payload)
	run.Stderr = os.Stderr
	data, err := run.Output()
	if err != nil {
		return nil, fmt.Errorf("tkaFilterNetmapLocked 실행: %w", err)
	}
	return data, nil
}
