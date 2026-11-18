package main

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"os"
	"strings"

	"golang.org/x/net/http2/hpack"
)

type header struct {
	Name      string `json:"name"`
	Value     string `json:"value"`
	Sensitive bool   `json:"sensitive"`
}
type block struct {
	Hex     string   `json:"hex"`
	Headers []header `json:"headers"`
}
type connection struct {
	Name   string  `json:"name"`
	Blocks []block `json:"blocks"`
}

func hpackFixtures() []connection {
	var buf bytes.Buffer
	encoder := hpack.NewEncoder(&buf)
	c := connection{Name: "허프만·동적 표·크기 갱신"}
	add := func(fields ...header) {
		buf.Reset()
		for _, f := range fields {
			if err := encoder.WriteField(hpack.HeaderField{Name: f.Name, Value: f.Value, Sensitive: f.Sensitive}); err != nil {
				panic(err)
			}
		}
		c.Blocks = append(c.Blocks, block{Hex: hex.EncodeToString(buf.Bytes()), Headers: fields})
	}
	add(header{":status", "200", false}, header{"x-message", "www.example.test", false}, header{"x-empty", "", false})
	add(header{":status", "200", false}, header{"x-message", "www.example.test", false}, header{"x-empty", "", false})
	add(header{"authorization", "Bearer fake-test-value", true}, header{"x-message", "www.example.test", false})
	encoder.SetMaxDynamicTableSize(128)
	add(header{"x-one", "one", false}, header{"x-two", "two", false}, header{"x-three", "three", false})
	add(header{"x-three", "three", false}, header{"x-one", "one", false})
	encoder.SetMaxDynamicTableSize(0)
	add(header{"x-empty", "", false})
	encoder.SetMaxDynamicTableSize(4096)
	add(header{"x-long", strings.Repeat("abcdef0123456789", 256), false})
	add(header{"x-message", "www.example.test", false})
	// Also cover the path that signals both the minimum and final sizes in one block.
	encoder.SetMaxDynamicTableSize(0)
	encoder.SetMaxDynamicTableSize(512)
	add(header{"x-final", "final", false})
	var other bytes.Buffer
	e := hpack.NewEncoder(&other)
	f := header{"x-message", "www.example.test", false}
	_ = e.WriteField(hpack.HeaderField{Name: f.Name, Value: f.Value})
	return []connection{c, {Name: "새 연결은 표를 공유하지 않음", Blocks: []block{{Hex: hex.EncodeToString(other.Bytes()), Headers: []header{f}}}}}
}
func writeHPACK(path string) error {
	b, err := json.MarshalIndent(hpackFixtures(), "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(b, '\n'), 0644)
}
