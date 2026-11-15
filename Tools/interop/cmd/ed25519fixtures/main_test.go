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
		t.Fatal("연속 생성 결과가 다릅니다")
	}
	saved, err := os.ReadFile("../../../../Tests/SwiftailCryptoTests/Vectors/ed25519-verify.json")
	if err != nil {
		t.Fatal("저장된 기준 자료를 읽지 못했습니다")
	}
	if !bytes.Equal(first, saved) {
		t.Fatal("저장 자료와 재생성 결과가 다릅니다")
	}
	var f fixture
	if err := json.Unmarshal(first, &f); err != nil {
		t.Fatal(err)
	}
	if f.CaseCount != len(f.Cases) {
		t.Fatal("caseCount가 사례 수와 다릅니다")
	}
}

// TestZIP215Cases는 zip215Encodings로 만든 196개가 ed25519consensus의 zip215_test.go와 같은지 본다.
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
		t.Fatalf("zip215_test.go의 문자열 수가 %d입니다", len(hexes))
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
			t.Fatalf("ZIP-215 사례 %d가 원본과 다릅니다", i)
		}
	}
}
