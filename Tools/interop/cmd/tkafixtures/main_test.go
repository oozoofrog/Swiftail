package main

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

const savedPath = "../../../../Tests/SwiftailTKATests/Fixtures/tka-fixtures.json"

func TestFixtures(t *testing.T) {
	first, err := evaluate()
	if err != nil {
		t.Fatal(err)
	}
	second, err := evaluate()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first, second) {
		t.Fatal("consecutive generations differ")
	}
	saved, err := os.ReadFile(savedPath)
	if err != nil {
		t.Fatal("could not read the stored reference fixtures")
	}
	if !bytes.Equal(first, saved) {
		t.Fatal("stored fixtures differ from regenerated fixtures")
	}
	var f map[string]json.RawMessage
	if err := json.Unmarshal(first, &f); err != nil {
		t.Fatal(err)
	}
	var caseCount int
	if err := json.Unmarshal(f["caseCount"], &caseCount); err != nil || caseCount == 0 {
		t.Fatalf("caseCount is 0 or unreadable: %v", err)
	}
	sum := 0
	for _, name := range []string{"keys", "authorities", "text", "encodings", "cbor", "chains", "sync", "signatures", "peerSets", "disablement", "authKeys", "resign", "unorderedPeerSets", "limits", "padded", "openedStates", "reviewChains", "reviewSignatures"} {
		var items []json.RawMessage
		if err := json.Unmarshal(f[name], &items); err != nil || len(items) == 0 {
			t.Fatalf("array %s is empty or missing", name)
		}
		switch name {
		case "keys", "authorities":
		case "limits":
			var groups []limitGroup
			if err := json.Unmarshal(f[name], &groups); err != nil {
				t.Fatal(err)
			}
			for _, g := range groups {
				sum += len(g.Cases)
			}
		case "sync":
			var groups []syncGroup
			if err := json.Unmarshal(f[name], &groups); err != nil {
				t.Fatal(err)
			}
			for _, g := range groups {
				sum += len(g.Cases)
			}
		default:
			sum += len(items)
		}
	}
	if sum != caseCount {
		t.Fatalf("caseCount %d differs from scenario count %d", caseCount, sum)
	}
	if len(first) > 2<<20 {
		t.Fatalf("fixture exceeds 2MB: %d", len(first))
	}
}

// TestCopiedGoTestData checks that the Go test values copied into genesis.go are present verbatim in the original files.
func TestCopiedGoTestData(t *testing.T) {
	out, err := exec.Command("go", "list", "-m", "-f", "{{.Dir}}", "tailscale.com").Output()
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(strings.TrimSpace(string(out)), "tka")
	for file, value := range map[string]string{"aum_test.go": goTestGenesis, "sig_test.go": goTestWrappedAuthKey} {
		source, err := os.ReadFile(filepath.Join(dir, file))
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Contains(source, []byte(`"`+value+`"`)) {
			t.Fatalf("%s is missing the copied value", file)
		}
	}
}

func TestVerifyCommand(t *testing.T) {
	all := authorities()
	base := viewAuthority(all[0])
	for _, c := range signatureCases(all)[:12] {
		if c.Authority != base.Name {
			continue
		}
		input, err := json.Marshal(verifyInput{AUMs: base.AUMs, NodeKey: c.NodeKey, NKS: c.NKS})
		if err != nil {
			t.Fatal(err)
		}
		var stdout bytes.Buffer
		if code := verifyCommand(bytes.NewReader(input), &stdout); code != 0 {
			t.Fatalf("%s: exit code %d: %s", c.Name, code, stdout.String())
		}
		var got verifyOutput
		if err := json.Unmarshal(stdout.Bytes(), &got); err != nil {
			t.Fatal(err)
		}
		if !got.OK || got.Authorized != c.Authorized || got.Error != c.Error {
			t.Fatalf("%s: verdict differs from fixture: %s", c.Name, stdout.String())
		}
	}
	for _, bad := range []string{
		``,
		`[]`,
		`{"aums":[],"nodeKey":"00","nks":""}`,
		`{"aums":["zz"],"nodeKey":"","nks":""}`,
		`{"aums":["` + base.AUMs[0] + `"],"nodeKey":"00","nks":""}`,
		`{"aums":["` + base.AUMs[0] + `"],"nodeKey":"` + strings.Repeat("AA", 32) + `","nks":""}`,
		`{"aums":["` + base.AUMs[0] + `"],"nodeKey":"` + strings.Repeat("00", 32) + `","nks":"","extra":1}`,
		`{"aums":["` + base.AUMs[0] + `"],"nodeKey":"` + strings.Repeat("00", 32) + `","nks":""} {}`,
		`{"aums":["a0"],"nodeKey":"` + strings.Repeat("00", 32) + `","nks":""}`,
	} {
		var stdout bytes.Buffer
		if code := verifyCommand(strings.NewReader(bad), &stdout); code != 1 || !strings.Contains(stdout.String(), `"ok":false`) {
			t.Fatalf("accepted invalid input %q: %s", bad, stdout.String())
		}
	}
}
