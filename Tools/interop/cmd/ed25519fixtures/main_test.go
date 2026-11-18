package main

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

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
	saved, err := os.ReadFile("../../../../Tests/SwiftailCryptoTests/Vectors/ed25519-verify.json")
	if err != nil {
		t.Fatal("could not read the stored reference fixtures")
	}
	if !bytes.Equal(first, saved) {
		t.Fatal("stored fixtures differ from regenerated fixtures")
	}
	var f fixture
	if err := json.Unmarshal(first, &f); err != nil {
		t.Fatal(err)
	}
	if f.CaseCount != len(f.Cases) {
		t.Fatal("caseCount differs from the number of cases")
	}
}

// TestZIP215Cases checks that the 196 cases built from zip215Encodings match ed25519consensus's zip215_test.go.
func TestZIP215Cases(t *testing.T) {
	out, err := exec.Command("go", "list", "-m", "-f", "{{.Dir}}", "github.com/hdevalence/ed25519consensus").Output()
	if err != nil {
		t.Fatal(err)
	}
	source, err := os.ReadFile(filepath.Join(strings.TrimSpace(string(out)), "zip215_test.go"))
	if err != nil {
		t.Fatal(err)
	}
	hexes := regexp.MustCompile(`"([0-9a-f]+)"`).FindAllStringSubmatch(string(source), -1)
	if len(hexes) != 2*196 {
		t.Fatalf("zip215_test.go contains %d strings", len(hexes))
	}
	data, err := evaluate()
	if err != nil {
		t.Fatal(err)
	}
	var f fixture
	if err := json.Unmarshal(data, &f); err != nil {
		t.Fatal(err)
	}
	for i := range 196 {
		c := f.Cases[i]
		if c.Kind != "zip215" || c.Index != i || c.PublicKey != hexes[2*i][1] || c.Signature != hexes[2*i+1][1] || c.Message != "5a63617368" {
			t.Fatalf("ZIP-215 case %d differs from the original", i)
		}
	}
}
