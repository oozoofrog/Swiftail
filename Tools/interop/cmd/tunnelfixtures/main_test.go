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
	want, err := os.ReadFile(filepath.Join("..", "..", "..", "..", "Tests", "SwiftailEngineTests", "Fixtures", "tunnel-settings-fixtures.json"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(actual, want) {
		t.Fatal("Stored fixtures differ from the Go reference results. Regenerate them with tunnelfixtures")
	}
}
