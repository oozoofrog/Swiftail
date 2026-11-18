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
		t.Fatal("fixtures differ across runs", err)
	}
	want, err := os.ReadFile(filepath.Join("..", "..", "..", "..", "Tests", "SwiftailNetstackTests", "Fixtures", "tcp-segments.json"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(actual, want) {
		t.Fatal("Stored fixtures differ from Go results. Regenerate them with tcpfixtures")
	}
	var doc document
	if err := json.Unmarshal(actual, &doc); err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	differences := 0
	for _, c := range doc.Cases {
		if seen[c.Name] {
			t.Fatal("duplicate case", c.Name)
		}
		seen[c.Name] = true
		b, err := hex.DecodeString(c.Packet)
		if err != nil {
			t.Fatal(err)
		}
		observed, _ := json.Marshal(observe(b))
		saved, _ := json.Marshal(c.Go)
		if !bytes.Equal(observed, saved) {
			t.Fatal("reference parse differs", c.Name)
		}
		if c.SwiftailDiffers != "" {
			differences++
		}
		switch c.Name {
		case "ipv4-options":
			if c.Go.Decoded.IPHeaderLength != 24 || c.Go.Decoded.SourcePort != 42001 {
				t.Fatal("could not read IPv4 option boundary")
			}
		case "ipv6-no-options":
			if *c.Go.Decoded.MSS != 536 || *c.Swiftail.Decoded.MSS != 1220 {
				t.Fatal("must preserve the IPv6 default MSS difference")
			}
		case "small-mss":
			if *c.Go.Decoded.MSS != 48 || *c.Swiftail.Decoded.MSS != 1 {
				t.Fatal("must preserve the small MSS difference")
			}
		case "ipv4-mss-zero", "ipv6-mss-zero":
			if *c.Go.Decoded.WindowScale != -1 || *c.Swiftail.Decoded.WindowScale != 3 {
				t.Fatal("must preserve the WS difference after MSS 0")
			}
		case "nop-unaligned":
			if *c.Go.Decoded.MSS != 1240 || *c.Go.Decoded.WindowScale != 2 {
				t.Fatal("could not read the malformed option")
			}
		case "ipv4-syn-sack-permitted", "ipv6-syn-sack-permitted", "sack-timestamp-options":
			if !*c.Go.Decoded.SACKPermitted || c.Go.Decoded.SACKBlocks != nil {
				t.Fatal("could not read SACK-Permitted in SYN", c.Name)
			}
		case "sack-permitted-length-three":
			if *c.Go.Decoded.SACKPermitted || *c.Go.Decoded.MSS != 1240 {
				t.Fatal("accepted SACK-Permitted with the wrong length")
			}
		case "ipv6-ack-sack-four-blocks":
			if len(c.Go.Decoded.SACKBlocks) != 4 || c.Go.Decoded.SACKBlocks[1] != [2]uint32{0xfffffff0, 0x10} {
				t.Fatal("could not read 4 SACK blocks")
			}
		case "sack-duplicate":
			if len(c.Go.Decoded.SACKBlocks) != 2 || c.Go.Decoded.SACKBlocks[0] != [2]uint32{3, 4} {
				t.Fatal("the later SACK option must remain")
			}
		case "sack-outside", "sack-five-blocks":
			if c.Go.Error != "" || len(c.Go.Decoded.SACKBlocks) != 0 || c.Swiftail.Error != "malformed" {
				t.Fatal("must preserve the difference for SACK extending past the header", c.Name)
			}
		case "eol-ignores-tail":
			if c.Go.Error != "" || *c.Go.Decoded.WindowScale != -1 {
				t.Fatal("read past EOL")
			}
		}
	}
	if len(doc.Cases) != 62 || doc.CaseCount != 62 || differences != 11 {
		t.Fatalf("case/difference count: %d/%d", len(doc.Cases), differences)
	}
}

func TestObserveArbitraryBytes(t *testing.T) {
	// Verify length checks ahead of the gVisor accessors with 10,000 deterministic inputs.
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
