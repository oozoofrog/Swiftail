package main

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestFixturesMatchGo(t *testing.T) {
	actual, err := evaluate()
	if err != nil {
		t.Fatal(err)
	}
	want, err := os.ReadFile(filepath.Join("..", "..", "..", "..", "Tests", "SwiftailEngineTests", "Fixtures", "magicdns-fixtures.json"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(actual, want) {
		t.Fatal("저장 자료와 Go 기준 구현 결과가 다릅니다. dnsfixtures로 재생성하세요")
	}
}
