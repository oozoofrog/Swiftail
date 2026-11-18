// tkafixtures writes verdicts from Go's tailscale.com/tka package as JSON (Tailnet Lock contract §7, "Comparison with Go reference values").
// It neither reads nor executes Swift source. It uses no network, current time, or external randomness. All keys come from
// SHA-256("swiftail-fixtures/tka/<role>/<number>"), and Ed25519 signatures are deterministic, so regeneration yields the same
// bytes. tka's public API produces the verdicts, with only peer filtering calling the actual ipnlocal function through an overlay (peersets.go).
//
// Usage (current directory is Tools/interop):
//
//	tkafixtures            Write JSON to standard output
//	tkafixtures <directory> Write <directory>/tka-fixtures.json
//	tkafixtures verify-nks Verify an NKS from a single JSON object on standard input and write one JSON line
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
		return r, errors.New("Go build information is missing")
	}
	for _, dep := range info.Deps {
		if dep.Path == "tailscale.com" && dep.Replace == nil {
			r.Tailscale = dep.Version
		}
	}
	if r.Tailscale != tailscaleVersion {
		return r, errors.New("reference tailscale version differs")
	}
	return r, nil
}

// keyCase is a test key used in the fixture. seed is the SHA-256 input string, and private is the Ed25519 seed (32 bytes) or
// the X25519 private key input for the node key.
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

// section is one top-level member of the output JSON. Each array element gets its own line to make diffs easier to read.
type section struct {
	name  string
	value any
	cases int // Count to add to caseCount
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
		fmt.Fprintln(os.Stderr, "Set GOCACHE (see the environment in Tools/interop/README.md)")
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
		fmt.Fprintln(os.Stderr, "Usage: tkafixtures [directory | verify-nks]")
		os.Exit(2)
	}
}

// verifyInput is the input to verify-nks. Bootstrap from the first of aums, then call Inform with the rest,
// and check the node key (32 bytes in hexadecimal) and NKS (hexadecimal) with NodeKeyAuthorizedWithDetails.
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
		return fail("could not read input or input exceeds 4MiB")
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var in verifyInput
	if err := dec.Decode(&in); err != nil {
		return fail("expected a JSON object: " + err.Error())
	}
	if dec.More() {
		return fail("trailing value after JSON")
	}
	if len(in.AUMs) == 0 {
		return fail("aums is empty")
	}
	raws := make([][]byte, len(in.AUMs))
	for i, h := range in.AUMs {
		if raws[i], err = decodeHex(h); err != nil {
			return fail(fmt.Sprintf("aums[%d]: %v", i, err))
		}
	}
	node, err := decodeHex(in.NodeKey)
	if err != nil || len(node) != 32 {
		return fail("nodeKey must be 32 bytes in hexadecimal")
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

// decodeHex accepts only lowercase hexadecimal.
func decodeHex(s string) ([]byte, error) {
	if s != strings.ToLower(s) {
		return nil, errors.New("hexadecimal must be lowercase")
	}
	return hex.DecodeString(s)
}
