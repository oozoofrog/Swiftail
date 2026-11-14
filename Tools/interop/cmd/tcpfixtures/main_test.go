package main

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestFixturesMatchGo(t *testing.T) {
	actual, err := evaluate()
	if err != nil {
		t.Fatal(err)
	}
	second, err := evaluate()
	if err != nil || !bytes.Equal(actual, second) {
		t.Fatal("실행 사이의 자료가 다릅니다", err)
	}
	want, err := os.ReadFile(filepath.Join("..", "..", "..", "..", "Tests", "SwiftailNetstackTests", "Fixtures", "tcp-segments.json"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(actual, want) {
		t.Fatal("저장 자료와 Go 결과가 다릅니다. tcpfixtures로 재생성하세요")
	}
	var doc document
	if err := json.Unmarshal(actual, &doc); err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	differences := 0
	for _, c := range doc.Cases {
		if seen[c.Name] {
			t.Fatal("중복 사례", c.Name)
		}
		seen[c.Name] = true
		b, err := hex.DecodeString(c.Packet)
		if err != nil {
			t.Fatal(err)
		}
		observed, _ := json.Marshal(observe(b))
		saved, _ := json.Marshal(c.Go)
		if !bytes.Equal(observed, saved) {
			t.Fatal("기준 해석이 다릅니다", c.Name)
		}
		if c.SwiftailDiffers != "" {
			differences++
		}
		switch c.Name {
		case "ipv4-options":
			if c.Go.Decoded.IPHeaderLength != 24 || c.Go.Decoded.SourcePort != 42001 {
				t.Fatal("IPv4 옵션 경계를 읽지 못했습니다")
			}
		case "ipv6-no-options":
			if *c.Go.Decoded.MSS != 536 || *c.Swiftail.Decoded.MSS != 1220 {
				t.Fatal("IPv6 기본 MSS 차이를 보존해야 합니다")
			}
		case "small-mss":
			if *c.Go.Decoded.MSS != 48 || *c.Swiftail.Decoded.MSS != 1 {
				t.Fatal("작은 MSS 차이를 보존해야 합니다")
			}
		case "ipv4-mss-zero", "ipv6-mss-zero":
			if *c.Go.Decoded.WindowScale != -1 || *c.Swiftail.Decoded.WindowScale != 3 {
				t.Fatal("MSS 0 뒤 WS 차이를 보존해야 합니다")
			}
		case "nop-unaligned":
			if *c.Go.Decoded.MSS != 1240 || *c.Go.Decoded.WindowScale != 2 {
				t.Fatal("어긋난 옵션을 읽지 못했습니다")
			}
		case "eol-ignores-tail":
			if c.Go.Error != "" || *c.Go.Decoded.WindowScale != -1 {
				t.Fatal("EOL 뒤를 읽었습니다")
			}
		}
	}
	if len(doc.Cases) != 49 || doc.CaseCount != 49 || differences != 11 {
		t.Fatalf("사례/차이 수: %d/%d", len(doc.Cases), differences)
	}
}

func TestObserveArbitraryBytes(t *testing.T) {
	// 결정적인 1만 입력으로 gVisor 접근자 앞의 길이 검사를 검증한다.
	var state uint64 = 1
	for i := 0; i < 10000; i++ {
		state = state*6364136223846793005 + 1442695040888963407
		b := make([]byte, int(state%128))
		for j := range b {
			state = state*6364136223846793005 + 1442695040888963407
			b[j] = byte(state >> 56)
		}
		observe(b)
	}
}
