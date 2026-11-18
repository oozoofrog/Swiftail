package main

import (
	"bytes"
	"os"
	"testing"
)

// TestFixtures checks that consecutive generations match and that the stored reference fixtures match the tool's current output.
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
		t.Fatal("consecutive generations differ")
	}
	saved, err := os.ReadFile("../../../../Tests/SwiftailPairingTests/Fixtures/pairing-vectors.json")
	if err != nil {
		t.Fatal("could not read the stored reference fixtures")
	}
	if !bytes.Equal(first, saved) {
		t.Fatal("stored fixtures differ from regenerated fixtures")
	}
}
