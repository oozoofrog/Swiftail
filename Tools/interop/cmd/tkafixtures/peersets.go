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

// Stale-key detection in peer filtering (rotationTracker) is an unexported ipnlocal type. As in mapfixtures,
// overlay the single bridge.go.txt file onto a temporary copy of tailscale.com and let it call the actual tkaFilterNetmapLocked
// without copying the filtering logic. Leave the module cache intact and delete the temporary copy on completion.

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
	// Runs is the number of tkaFilterNetmapLocked runs with the same input. This array includes only cases with identical results on every run.
	Runs int `json:"runs"`
}

// unorderedPeerSetCase is an input whose Go result depends on map iteration order (rotationTracker.obsoleteKeys
// iterates the byWrappingKey map). Outcomes contains the distinct results (lists of remaining node keys) from Runs runs, sorted.
type unorderedPeerSetCase struct {
	Name      string      `json:"name"`
	Authority string      `json:"authority"`
	Peers     []peerInput `json:"peers"`
	Runs      int         `json:"runs"`
	Outcomes  [][]string  `json:"outcomes"`
}

const (
	peerSetRuns          = 64
	unorderedPeerSetRuns = 256
)

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
		// Added by the TL-5 comparison tests (contract §5 TL-4, behavior P1): stale-key detection accepts UnsignedPeerAPIOnly peers as well. It skips their
		// signatures, so their rotations do not make other peers' keys stale.
		{Name: "api-only-obsoleted-by-rotation", Authority: base, Peers: []peerInput{apiOnly(peer(N[0], nil)), peer(N[1], ser(r1))}},
		{Name: "api-only-rotation-not-tracked", Authority: base, Peers: []peerInput{peer(N[0], ser(direct)), apiOnly(peer(N[1], ser(r1)))}},
	}
}

// unorderedPeerSetInputs is input where the same node key belongs to groups with different rotation keys (contract §5 TL-4).
// Group nl/0: node/3 (1 previous key), node/4 (2). Group nl/1: node/3 (2), node/7 (1). If nl/0 comes first, node/3
// becomes stale, leaving only node/7 in nl/1, which survives. If nl/1 comes first, node/7 becomes stale.
func unorderedPeerSetInputs() []unorderedPeerSetCase {
	L, NL, N := lockKeys, nlKeys, nodeKeys
	peer := func(n nodeKey, sig tka.NodeKeySignature) peerInput {
		return peerInput{NodeKey: hexOf(n.raw()), Signature: hexOf(ser(sig))}
	}
	a1 := rotationNKS(NL[0], N[3], directNKS(L[0], N[0], NL[0].pub()), nil)
	a2 := rotationNKS(NL[0], N[4], rotationNKS(NL[0], N[2], directNKS(L[0], N[1], NL[0].pub()), nil), nil)
	b1 := rotationNKS(NL[1], N[3], rotationNKS(NL[1], N[6], directNKS(L[0], N[5], NL[1].pub()), nil), nil)
	b2 := rotationNKS(NL[1], N[7], directNKS(L[0], N[8], NL[1].pub()), nil)
	return []unorderedPeerSetCase{
		{Name: "same-node-key-in-two-wrapping-groups", Authority: "nks-base", Peers: []peerInput{peer(N[3], a1), peer(N[4], a2), peer(N[3], b1), peer(N[7], b2)}},
	}
}

// peerSetCases builds both arrays with one bridge run. For each peer set, it collects the distinct results from Runs runs.
func peerSetCases(all []namedAuthority) ([]peerSetCase, []unorderedPeerSetCase, error) {
	cases, unordered := peerSetInputs(), unorderedPeerSetInputs()
	type setInput struct {
		AUMs  []string    `json:"aums"`
		Peers []peerInput `json:"peers"`
		Runs  int         `json:"runs"`
	}
	var input []setInput
	view := func(name string) []string { return viewAuthority(namedAuthority{name, findAuthority(all, name)}).AUMs }
	for _, c := range cases {
		input = append(input, setInput{view(c.Authority), c.Peers, peerSetRuns})
	}
	for _, c := range unordered {
		input = append(input, setInput{view(c.Authority), c.Peers, unorderedPeerSetRuns})
	}
	payload, err := json.Marshal(input)
	if err != nil {
		return nil, nil, err
	}
	output, err := runBridge(payload)
	if err != nil {
		return nil, nil, err
	}
	var outcomes [][][]string
	if err := json.Unmarshal(output, &outcomes); err != nil {
		return nil, nil, err
	}
	if len(outcomes) != len(input) {
		return nil, nil, errors.New("peer set result count differs")
	}
	for i := range cases {
		if len(outcomes[i]) != 1 {
			return nil, nil, fmt.Errorf("Go results for peer set %s differ across runs: %v", cases[i].Name, outcomes[i])
		}
		cases[i].Kept, cases[i].Runs = outcomes[i][0], peerSetRuns
	}
	for i := range unordered {
		unordered[i].Outcomes, unordered[i].Runs = outcomes[len(cases)+i], unorderedPeerSetRuns
	}
	return cases, unordered, nil
}

// runBridge builds and runs the worker from a copy of tailscale.com with an overlay. The working directory must be Tools/interop
// (its go.mod must be GOMOD). Keep temporary build files under eyebuild dir interop-tools only.
func runBridge(payload []byte) ([]byte, error) {
	out, err := exec.Command("go", "list", "-m", "-json", "tailscale.com").Output()
	if err != nil {
		return nil, fmt.Errorf("look up reference module (check that the working directory is Tools/interop): %w", err)
	}
	var module struct{ Dir, Version string }
	if err := json.Unmarshal(out, &module); err != nil {
		return nil, err
	}
	if module.Version != tailscaleVersion {
		return nil, errors.New("reference tailscale.com version differs")
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
	// Go forbids overlays inside the module cache. Overlay only a temporary copy of the original.
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
		return nil, fmt.Errorf("build ipnlocal copy: %w", err)
	}
	run := exec.Command(binary)
	run.Stdin = bytes.NewReader(payload)
	run.Stderr = os.Stderr
	data, err := run.Output()
	if err != nil {
		return nil, fmt.Errorf("run tkaFilterNetmapLocked: %w", err)
	}
	return data, nil
}
