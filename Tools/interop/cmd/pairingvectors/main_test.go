package main

import (
	"bytes"
	"os"
	"testing"
)

// TestFixtures는 연속 생성이 같고, 저장된 기준 자료가 지금의 도구 출력과 같은지 본다.
func TestFixtures(t *testing.T) {
	first, err := generate()
	if err != nil {
		t.Fatal(err)
	}
	second, err := generate()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first, second) {
		t.Fatal("연속 생성 결과가 다릅니다")
	}
	saved, err := os.ReadFile("../../../../Tests/SwiftailPairingTests/Fixtures/pairing-vectors.json")
	if err != nil {
		t.Fatal("저장된 기준 자료를 읽지 못했습니다")
	}
	if !bytes.Equal(first, saved) {
		t.Fatal("저장 자료와 재생성 결과가 다릅니다")
	}
}
