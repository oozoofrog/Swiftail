package main

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/fxamacker/cbor/v2"
	"tailscale.com/tka"
	"tailscale.com/types/tkatype"
)

// cborCase is the verdict from passing one byte input to Go's tka decoder. AUM uses Unserialize → StaticValidate,
// while NKS uses only Unserialize (NKS has no static validation). Accepted cases include the bytes re-encoded with Serialize
// and the hash.
type cborCase struct {
	Name        string `json:"name"`
	Type        string `json:"type"`
	Input       string `json:"input"`
	Decoded     bool   `json:"decoded"`
	StaticValid *bool  `json:"staticValid"`
	Accepted    bool   `json:"accepted"`
	Error       string `json:"error,omitempty"`
	Reencoded   string `json:"reencoded,omitempty"`
	Canonical   bool   `json:"canonical"`
	Hash        string `json:"hash,omitempty"`
	SigHash     string `json:"sigHash,omitempty"`
}

func evalCBOR(name, typ string, input []byte) cborCase {
	c := cborCase{Name: name, Type: typ, Input: hexOf(input)}
	var reencoded []byte
	switch typ {
	case "aum":
		var a tka.AUM
		if err := catch(func() error { return a.Unserialize(input) }); err != nil {
			c.Error = err.Error()
			return c
		}
		c.Decoded = true
		err := a.StaticValidate()
		valid := err == nil
		c.StaticValid = &valid
		if err != nil {
			c.Error = err.Error()
		}
		c.Accepted = valid
		reencoded = a.Serialize()
		h, sh := a.Hash(), a.SigHash()
		c.Hash, c.SigHash = hexOf(h[:]), hexOf(sh[:])
	case "nks":
		var s tka.NodeKeySignature
		if err := catch(func() error { return s.Unserialize(input) }); err != nil {
			c.Error = err.Error()
			return c
		}
		c.Decoded, c.Accepted = true, true
		reencoded = s.Serialize()
		sh := s.SigHash()
		c.SigHash = hexOf(sh[:])
	default:
		panic(typ)
	}
	c.Reencoded = hexOf(reencoded)
	c.Canonical = bytes.Equal(reencoded, input)
	return c
}

// catch converts panics from Go code to errors. The verdict fixture records them as "panic: …".
func catch(f func() error) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("panic: %v", r)
		}
	}()
	return f()
}

// Write the CBOR header in hexadecimal (shortest encoding).
func head(major byte, n uint64) string {
	m := major << 5
	switch {
	case n < 24:
		return hex.EncodeToString([]byte{m | byte(n)})
	case n < 1<<8:
		return hex.EncodeToString([]byte{m | 24, byte(n)})
	case n < 1<<16:
		return hex.EncodeToString([]byte{m | 25, byte(n >> 8), byte(n)})
	case n < 1<<32:
		return hex.EncodeToString([]byte{m | 26, byte(n >> 24), byte(n >> 16), byte(n >> 8), byte(n)})
	default:
		b := []byte{m | 27, 0, 0, 0, 0, 0, 0, 0, 0}
		for i := range 8 {
			b[8-i] = byte(n >> (8 * i))
		}
		return hex.EncodeToString(b)
	}
}

// uintArray writes a byte sequence as an array of unsigned integers (an input that substitutes an array for a byte string).
func uintArray(b []byte) string {
	var s strings.Builder
	s.WriteString(head(4, uint64(len(b))))
	for _, v := range b {
		s.WriteString(head(0, uint64(v)))
	}
	return s.String()
}

func cmap(pairs ...string) string { return head(5, uint64(len(pairs))) + strings.Join(pairs, "") }
func bstr(b []byte) string        { return head(2, uint64(len(b))) + hexOf(b) }
func tstr(s string) string        { return head(3, uint64(len(s))) + hexOf([]byte(s)) }
func repeat(s string, n int) string {
	return strings.Repeat(s, n)
}

// addPairs appends pairs to a canonically encoded map (at most 23 pairs, one-byte header). It constructs deliberately malformed inputs
// from valid signed AUMs and NKSs.
func addPairs(canonical []byte, count int, pairs string) []byte {
	if canonical[0] < 0xa0 || canonical[0]+byte(count) > 0xb7 {
		panic("addPairs: expected a one-byte map header")
	}
	out := append([]byte{canonical[0] + byte(count)}, canonical[1:]...)
	return append(out, mustHex(pairs)...)
}

const (
	kindNoOp = "0103"
	prevNull = "02f6"
)

var zero32 = make([]byte, 32)

// rawAUMCases contains manually assembled AUM bytes. Name prefixes state what each case probes: accept for cases the notes or contract expect Go
// to accept, reject for cases they expect it to reject, and probe for cases where they have not established Go's verdict.
// The fixture includes Go's actual verdict unchanged.
func rawAUMCases() [][2]string {
	unknown := func(value string) string { return cmap(kindNoOp, prevNull, "08"+value) }
	updateKey := func(meta string) string { return cmap("0104", prevNull, "044101", "07"+meta) }
	nested := func(depth int) string { // The outermost map is level 1. Nest depth−1 array levels in the value of an unknown field
		return unknown(repeat("81", depth-2) + "80")
	}
	nestedMaps := func(depth int) string {
		return unknown(repeat("a101", depth-2) + "a0")
	}
	array := func(n int) string { return unknown(head(4, uint64(n)) + repeat("00", n)) }
	valueMap := func(n int) string {
		var b strings.Builder
		b.WriteString(head(5, uint64(n)))
		for i := range n {
			b.WriteString(head(0, uint64(i)) + "00")
		}
		return unknown(b.String())
	}
	topMap := func(n int) string { // n pairs: 1, 2, and unknown keys 24, 25, … (skip known key 23)
		var b strings.Builder
		b.WriteString(head(5, uint64(n)) + kindNoOp + prevNull)
		for i := range n - 2 {
			b.WriteString(head(0, uint64(24+i)) + "00")
		}
		return b.String()
	}
	pub := lockKeys[0].pub()
	key := func(pairs ...string) string { return cmap("0101", prevNull, "03"+cmap(pairs...)) }
	checkpoint := func(state string) string { return cmap("0105", prevNull, "05"+state) }
	validState := func(extra ...string) string {
		return cmap(append([]string{"01f6", "02" + head(4, 1) + bstr(zero32), "03" + head(4, 1) + cmap("0101", "0201", "03"+bstr(pub))}, extra...)...)
	}
	return [][2]string{
		{"accept/base-noop", cmap(kindNoOp, prevNull)},
		{"accept/unknown-int-key-int", unknown("01")},
		{"accept/unknown-int-key-negative", unknown("20")},
		{"accept/unknown-int-key-float16", unknown("f93c00")},
		{"accept/unknown-int-key-float32", unknown("fa3f800000")},
		{"accept/unknown-int-key-float64", unknown("fb3ff0000000000000")},
		{"accept/unknown-int-key-true", unknown("f5")},
		{"accept/unknown-int-key-false", unknown("f4")},
		{"accept/unknown-int-key-null", unknown("f6")},
		{"accept/unknown-int-key-undefined", unknown("f7")},
		{"accept/unknown-int-key-simple-99", unknown("f863")},
		{"probe/unknown-int-key-simple-0", unknown("e0")},
		{"probe/unknown-int-key-simple-19", unknown("f3")},
		{"probe/unknown-int-key-simple-255", unknown("f8ff")},
		{"probe/two-byte-simple-0", unknown("f800")},
		{"probe/two-byte-simple-23", unknown("f817")},
		{"probe/two-byte-simple-24", unknown("f818")},
		{"probe/two-byte-simple-31", unknown("f81f")},
		{"probe/two-byte-simple-32", unknown("f820")},
		{"accept/unknown-int-key-invalid-utf8-text", unknown("61ff")},
		{"accept/unknown-int-key-nested-map", unknown("a10101")},
		{"accept/unknown-value-nested-duplicate", unknown("a201010102")},
		{"accept/unknown-int-key-array", unknown("83010203")},
		{"accept/unknown-int-key-bstr", unknown("420102")},
		{"accept/unknown-negative-key", cmap(kindNoOp, prevNull, "2001")},
		{"probe/negative-key-min-int64", cmap(kindNoOp, prevNull, "3b7fffffffffffffff01")},
		{"probe/negative-key-below-min-int64", cmap(kindNoOp, prevNull, "3b800000000000000001")},
		{"probe/negative-key-min-uint64", cmap(kindNoOp, prevNull, "3bffffffffffffffff01")},
		{"accept/int-key-max-int64", cmap(kindNoOp, prevNull, "1b7fffffffffffffff01")},
		{"reject/int-key-two-pow-63", cmap(kindNoOp, prevNull, "1b800000000000000001")},
		{"reject/int-key-max-uint64", cmap(kindNoOp, prevNull, "1bffffffffffffffff01")},
		{"accept/text-key-MessageKind", cmap(kindNoOp, prevNull, tstr("MessageKind")+"05")},
		{"accept/text-key-messagekind", cmap(kindNoOp, prevNull, tstr("messagekind")+"05")},
		{"accept/text-key-1", cmap(kindNoOp, prevNull, tstr("1")+"05")},
		{"accept/non-shortest-value-1byte", cmap("011803", prevNull)},
		{"accept/non-shortest-value-2byte", cmap("01190003", prevNull)},
		{"accept/non-shortest-value-4byte", cmap("011a00000003", prevNull)},
		{"accept/non-shortest-value-8byte", cmap("011b0000000000000003", prevNull)},
		{"accept/non-shortest-key", cmap("180103", prevNull)},
		{"accept/non-shortest-key-2byte", cmap("19000103", prevNull)},
		{"probe/non-shortest-map-head", "b802" + kindNoOp + prevNull},
		{"probe/non-shortest-bstr-length", cmap(kindNoOp, "02590020"+hexOf(zero32))},
		{"accept/unsorted-keys", cmap(prevNull, kindNoOp)},
		{"accept/prev-omitted", cmap(kindNoOp)},
		{"accept/kind-0", cmap("0100", prevNull)},
		{"accept/kind-9", cmap("0109", prevNull)},
		{"accept/kind-255", cmap("0118ff", prevNull)},
		{"reject/kind-256", cmap("01190100", prevNull)},
		{"accept/kind-null", cmap("01f6", prevNull)},
		{"probe/key-null", cmap(kindNoOp, prevNull, "03f6")},
		{"probe/keyid-null", cmap(kindNoOp, prevNull, "04f6")},
		{"probe/state-null", cmap(kindNoOp, prevNull, "05f6")},
		{"probe/votes-null", cmap(kindNoOp, prevNull, "06f6")},
		{"probe/meta-null", cmap(kindNoOp, prevNull, "07f6")},
		{"probe/signatures-null", cmap(kindNoOp, prevNull, "17f6")},
		{"probe/signatures-empty-array", cmap(kindNoOp, prevNull, "1780")},
		{"probe/signatures-null-element", cmap(kindNoOp, prevNull, "1781f6")},
		{"probe/signature-fields-null", cmap(kindNoOp, prevNull, "1781"+cmap("01f6", "02f6"))},
		{"probe/updatekey-votes-null-only", cmap("0104", prevNull, "044101", "06f6")},
		{"probe/updatekey-meta-value-null", updateKey(cmap(tstr("a") + "f6"))},
		{"probe/updatekey-meta-key-null", updateKey(cmap("f6" + tstr("a")))},
		{"probe/addkey-public-null", key("0101", "0201", "03f6")},
		{"probe/addkey-public-absent", key("0101", "0201")},
		{"probe/addkey-public-empty", key("0101", "0201", "0340")},
		{"probe/addkey-kind-null", key("01f6", "0201", "03"+bstr(pub))},
		{"probe/addkey-votes-null", key("0101", "02f6", "03"+bstr(pub))},
		{"probe/addkey-key-meta-null", key("0101", "0201", "03"+bstr(pub), "0cf6")},
		{"probe/checkpoint-state-arrays-null", checkpoint(cmap("01f6", "02f6", "03f6"))},
		{"probe/checkpoint-stateid-null", checkpoint(validState("04f6"))},
		{"accept/checkpoint-valid-state", checkpoint(validState())},
		{"accept/checkpoint-last-aum-hash-2-bytes", checkpoint(cmap("01420102", "02"+head(4, 1)+bstr(zero32), "03"+head(4, 1)+cmap("0101", "0201", "03"+bstr(pub))))},
		{"reject/checkpoint-last-aum-hash-text", checkpoint(cmap("016161", "02"+head(4, 1)+bstr(zero32), "03"+head(4, 1)+cmap("0101", "0201", "03"+bstr(pub))))},
		{"accept/updatekey-empty-meta", updateKey("a0")},
		{"accept/updatekey-votes-zero-empty-meta", cmap("0104", prevNull, "044101", "0600", "07a0")},
		{"reject/dup-known-key", cmap(kindNoOp, prevNull, "0103")},
		{"probe/dup-known-key-non-shortest", cmap(kindNoOp, prevNull, "180103")},
		{"reject/dup-unknown-int-key", cmap(kindNoOp, prevNull, "0800", "0800")},
		{"probe/dup-unknown-int-key-non-shortest", cmap(kindNoOp, prevNull, "0800", "180800")},
		{"reject/dup-text-key", cmap(kindNoOp, prevNull, "617800", "617800")},
		{"reject/dup-negative-key", cmap(kindNoOp, prevNull, "2000", "2000")},
		{"probe/dup-negative-key-non-shortest", cmap(kindNoOp, prevNull, "2000", "380000")},
		{"reject/dup-meta-key", updateKey(cmap(tstr("a")+tstr("1"), tstr("a")+tstr("2")))},
		{"probe/dup-key-map-key", key("0101", "0201", "03"+bstr(pub), "0102")},
		{"probe/dup-state-map-key", checkpoint(validState("01f6"))},
		{"probe/dup-signature-map-key", cmap(kindNoOp, prevNull, "1781"+cmap("01"+bstr(pub), "02"+bstr(make([]byte, 64)), "01"+bstr(pub)))},
		{"reject/empty-input", ""},
		{"reject/top-level-array", "820102"},
		{"reject/top-level-int", "03"},
		{"reject/top-level-bstr", "4100"},
		{"probe/top-level-null", "f6"},
		{"probe/top-level-undefined", "f7"},
		{"probe/top-level-empty-map", "a0"},
		{"reject/trailing-byte", cmap(kindNoOp, prevNull) + "00"},
		{"reject/truncated-map", "a20103"},
		{"reject/truncated-bstr", cmap(kindNoOp, "025820"+"00")},
		{"reject/indefinite-map", "bf" + kindNoOp + prevNull + "ff"},
		{"reject/indefinite-bstr-prev", cmap(kindNoOp, "025f4100ff")},
		{"reject/indefinite-bstr-in-unknown", unknown("5f4100ff")},
		{"reject/indefinite-array-in-unknown", unknown("9f01ff")},
		{"reject/indefinite-text-in-unknown", unknown("7f6161ff")},
		{"reject/tag-in-unknown-bignum", unknown("c24101")},
		{"reject/tag-in-unknown-datetime", unknown("c0" + tstr("x"))},
		{"reject/tag-self-describe-top", "d9d9f7" + cmap(kindNoOp, prevNull)},
		{"reject/tag-on-prev", cmap(kindNoOp, "02c0"+bstr(zero32))},
		{"probe/reserved-ai-28-uint", unknown("1c")},
		{"probe/reserved-ai-29-uint", unknown("1d")},
		{"probe/reserved-ai-30-uint", unknown("1e")},
		{"probe/reserved-ai-28-negative", unknown("3c")},
		{"probe/reserved-ai-28-bstr", unknown("5c")},
		{"probe/reserved-ai-28-text", unknown("7c")},
		{"probe/reserved-ai-28-array", unknown("9c")},
		{"probe/reserved-ai-28-map", unknown("bc")},
		{"probe/reserved-ai-28-tag", unknown("dc")},
		{"probe/reserved-ai-28-simple", unknown("fc")},
		{"probe/reserved-ai-29-simple", unknown("fd")},
		{"probe/reserved-ai-30-simple", unknown("fe")},
		{"probe/break-outside-indefinite", unknown("ff")},
		{"probe/reserved-ai-top", "1c"},
		{"probe/indefinite-uint-ai-31", unknown("1f")},
		{"reject/kind-negative", cmap("0120", prevNull)},
		{"reject/kind-float", cmap("01f93c00", prevNull)},
		{"reject/kind-text", cmap("016133", prevNull)},
		{"probe/kind-bstr", cmap("014103", prevNull)},
		{"probe/kind-true", cmap("01f5", prevNull)},
		{"reject/prev-text", cmap(kindNoOp, "026161")},
		{"probe/prev-int", cmap(kindNoOp, "0201")},
		{"probe/prev-array", cmap(kindNoOp, "0280")},
		{"probe/prev-uint-array-32", cmap(kindNoOp, "02"+uintArray(zero32))},
		{"probe/prev-uint-array-element-256", cmap(kindNoOp, "0281190100")},
		{"probe/prev-uint-array-negative-element", cmap(kindNoOp, "028120")},
		{"probe/prev-undefined", cmap(kindNoOp, "02f7")},
		{"probe/kind-undefined", cmap("01f7", prevNull)},
		{"probe/addkey-public-uint-array", key("0101", "0201", "03"+uintArray(pub))},
		{"probe/signature-uint-arrays", cmap(kindNoOp, prevNull, "1781"+cmap("01"+uintArray(pub), "02"+uintArray(make([]byte, 64))))},
		{"probe/checkpoint-disablement-uint-array", checkpoint(cmap("01f6", "02"+head(4, 1)+uintArray(zero32), "03"+head(4, 1)+cmap("0101", "0201", "03"+bstr(pub))))},
		{"probe/updatekey-meta-value-undefined", updateKey(cmap(tstr("a") + "f7"))},
		{"probe/updatekey-meta-value-true", updateKey(cmap(tstr("a") + "f5"))},
		{"probe/updatekey-meta-value-text-array", updateKey(cmap(tstr("a") + "8161" + "61"))},
		{"accept/unknown-empty-text-key", cmap(kindNoOp, prevNull, "6000")},
		{"reject/meta-bstr-key", updateKey(cmap("4161" + tstr("1")))},
		{"reject/meta-int-key", updateKey(cmap("01" + tstr("1")))},
		{"reject/meta-bstr-value", updateKey(cmap(tstr("a") + "4131"))},
		{"reject/meta-int-value", updateKey(cmap(tstr("a") + "01"))},
		{"reject/meta-invalid-utf8-value", updateKey(cmap(tstr("a") + "61ff"))},
		{"probe/meta-invalid-utf8-key", updateKey(cmap("61ff" + tstr("1")))},
		{"probe/meta-not-map", updateKey("80")},
		{"reject/bstr-key", cmap(kindNoOp, prevNull, "410100")},
		{"reject/float-key", cmap(kindNoOp, prevNull, "f93c0000")},
		{"reject/true-key", cmap(kindNoOp, prevNull, "f500")},
		{"probe/false-key", cmap(kindNoOp, prevNull, "f400")},
		{"reject/null-key", cmap(kindNoOp, prevNull, "f600")},
		{"probe/undefined-key", cmap(kindNoOp, prevNull, "f700")},
		{"reject/array-key", cmap(kindNoOp, prevNull, "8000")},
		{"probe/map-key", cmap(kindNoOp, prevNull, "a000")},
		{"reject/invalid-utf8-text-key", cmap(kindNoOp, prevNull, "61ff00")},
		{"reject/signatures-element-not-map", cmap(kindNoOp, prevNull, "178101")},
		{"probe/signatures-not-array", cmap(kindNoOp, prevNull, "1701")},
		{"probe/key-not-map", cmap("0101", prevNull, "0301")},
		{"probe/state-not-map", cmap("0105", prevNull, "0501")},
		{"accept/nesting-16-arrays", nested(16)},
		{"reject/nesting-17-arrays", nested(17)},
		{"probe/nesting-16-maps", nestedMaps(16)},
		{"probe/nesting-17-maps", nestedMaps(17)},
		{"accept/array-4096", array(4096)},
		{"reject/array-4097", array(4097)},
		{"accept/map-1024-in-value", valueMap(1024)},
		{"reject/map-1025-in-value", valueMap(1025)},
		{"probe/top-map-1024", topMap(1024)},
		{"probe/top-map-1025", topMap(1025)},
		// Added by the TL-5 comparison tests (contract §5 TL-2, "Unverified by execution"): simple values in integer fields and
		// simple values, null, and other integer array elements, simple values, undefined, and false as Meta keys, simple-value keys in struct maps, and a duplicate null and empty key.
		{"probe/kind-simple-3", cmap("01e3", prevNull)},
		{"probe/kind-simple-19", cmap("01f3", prevNull)},
		{"probe/kind-simple-99", cmap("01f863", prevNull)},
		{"probe/kind-simple-255", cmap("01f8ff", prevNull)},
		{"probe/kind-false", cmap("01f4", prevNull)},
		{"probe/updatekey-votes-simple-32", cmap("0104", prevNull, "044101", "06f820")},
		{"probe/addkey-kind-simple-1", key("01e1", "0201", "03"+bstr(pub))},
		{"probe/addkey-votes-simple-1", key("0101", "02e1", "03"+bstr(pub))},
		{"probe/checkpoint-stateid-simple-7", checkpoint(validState("04e7"))},
		{"probe/prev-uint-array-simple-and-null", cmap(kindNoOp, "028401e5f618ff")},
		{"probe/prev-uint-array-undefined-element", cmap(kindNoOp, "0281f7")},
		{"probe/prev-uint-array-true-element", cmap(kindNoOp, "0281f5")},
		{"probe/prev-uint-array-float-element", cmap(kindNoOp, "0281f93c00")},
		{"probe/prev-uint-array-array-element", cmap(kindNoOp, "028180")},
		{"probe/addkey-public-uint-array-simple-and-null", key("0101", "0201", "038401e5f618ff")},
		{"probe/updatekey-meta-key-simple", updateKey(cmap("e0" + tstr("1")))},
		{"probe/updatekey-meta-key-undefined", updateKey(cmap("f7" + tstr("1")))},
		{"probe/updatekey-meta-key-false", updateKey(cmap("f4" + tstr("1")))},
		{"probe/updatekey-meta-value-simple", updateKey(cmap(tstr("a") + "e0"))},
		{"probe/updatekey-meta-null-key-and-empty-key", updateKey(cmap("f6"+tstr("1"), tstr("")+tstr("2")))},
		{"probe/simple-key-0", cmap(kindNoOp, prevNull, "e000")},
		{"probe/simple-key-99", cmap(kindNoOp, prevNull, "f86300")},
	}
}

// valueAUMCases contains tka.AUM values encoded with Serialize (static validation boundaries). The signatures contain
// dummy bytes of the correct length only (static validation does not verify signatures).
func valueAUMCases() []struct {
	name string
	aum  tka.AUM
} {
	pub := lockKeys[0].pub()
	parent := bytes.Repeat([]byte{0x11}, 32)
	sig := func(keyLen, sigLen int) []tkatype.Signature {
		return []tkatype.Signature{{KeyID: bytes.Repeat([]byte{0x22}, keyLen), Signature: bytes.Repeat([]byte{0x33}, sigLen)}}
	}
	k := func(votes uint, meta map[string]string) *tka.Key {
		return &tka.Key{Kind: tka.Key25519, Votes: votes, Public: pub, Meta: meta}
	}
	votes := func(v uint) *uint { return &v }
	meta := func(n int) map[string]string { // key "k" (1 byte) + n−1 value bytes = n bytes
		return map[string]string{"k": strings.Repeat("v", n-1)}
	}
	values := func(n, length int) [][]byte {
		out := make([][]byte, n)
		for i := range out {
			out[i] = bytes.Repeat([]byte{byte(i + 1)}, length)
		}
		return out
	}
	keys := func(n int) []tka.Key {
		out := make([]tka.Key, n)
		for i := range out {
			public := make([]byte, 32)
			public[0], public[1] = byte(i>>8), byte(i)
			out[i] = tka.Key{Kind: tka.Key25519, Votes: 1, Public: public}
		}
		return out
	}
	state := func(dv [][]byte, ks []tka.Key) *tka.State {
		return &tka.State{DisablementValues: dv, Keys: ks, StateID1: 1, StateID2: 2}
	}
	okState := state(values(1, 32), []tka.Key{*k(1, nil)})
	last := tka.AUMHash{1}
	type c = struct {
		name string
		aum  tka.AUM
	}
	return []c{
		{"value/addkey-votes-0", tka.AUM{MessageKind: tka.AUMAddKey, PrevAUMHash: parent, Key: k(0, nil)}},
		{"value/addkey-votes-1", tka.AUM{MessageKind: tka.AUMAddKey, PrevAUMHash: parent, Key: k(1, nil)}},
		{"value/addkey-votes-4096", tka.AUM{MessageKind: tka.AUMAddKey, PrevAUMHash: parent, Key: k(4096, nil)}},
		{"value/addkey-votes-4097", tka.AUM{MessageKind: tka.AUMAddKey, PrevAUMHash: parent, Key: k(4097, nil)}},
		{"value/addkey-meta-512", tka.AUM{MessageKind: tka.AUMAddKey, PrevAUMHash: parent, Key: k(1, meta(512))}},
		{"value/addkey-meta-513", tka.AUM{MessageKind: tka.AUMAddKey, PrevAUMHash: parent, Key: k(1, meta(513))}},
		{"value/addkey-meta-order", tka.AUM{MessageKind: tka.AUMAddKey, PrevAUMHash: parent, Key: k(1, map[string]string{"bb": "2", "a": "1", "c": "3"})}},
		{"value/addkey-kind-0", tka.AUM{MessageKind: tka.AUMAddKey, PrevAUMHash: parent, Key: &tka.Key{Kind: 0, Votes: 1, Public: pub}}},
		{"value/addkey-kind-2", tka.AUM{MessageKind: tka.AUMAddKey, PrevAUMHash: parent, Key: &tka.Key{Kind: 2, Votes: 1, Public: pub}}},
		{"value/addkey-public-31", tka.AUM{MessageKind: tka.AUMAddKey, PrevAUMHash: parent, Key: &tka.Key{Kind: 1, Votes: 1, Public: pub[:31]}}},
		{"value/addkey-public-33", tka.AUM{MessageKind: tka.AUMAddKey, PrevAUMHash: parent, Key: &tka.Key{Kind: 1, Votes: 1, Public: append(append([]byte{}, pub...), 0)}}},
		{"value/addkey-missing-key", tka.AUM{MessageKind: tka.AUMAddKey, PrevAUMHash: parent}},
		{"value/addkey-with-keyid", tka.AUM{MessageKind: tka.AUMAddKey, PrevAUMHash: parent, Key: k(1, nil), KeyID: pub}},
		{"value/addkey-with-votes", tka.AUM{MessageKind: tka.AUMAddKey, PrevAUMHash: parent, Key: k(1, nil), Votes: votes(1)}},
		{"value/addkey-with-meta", tka.AUM{MessageKind: tka.AUMAddKey, PrevAUMHash: parent, Key: k(1, nil), Meta: map[string]string{"a": "1"}}},
		{"value/addkey-with-state", tka.AUM{MessageKind: tka.AUMAddKey, PrevAUMHash: parent, Key: k(1, nil), State: okState}},
		{"value/removekey-valid", tka.AUM{MessageKind: tka.AUMRemoveKey, PrevAUMHash: parent, KeyID: pub}},
		{"value/removekey-short-keyid", tka.AUM{MessageKind: tka.AUMRemoveKey, PrevAUMHash: parent, KeyID: []byte{1}}},
		{"value/removekey-missing-keyid", tka.AUM{MessageKind: tka.AUMRemoveKey, PrevAUMHash: parent}},
		{"value/removekey-with-key", tka.AUM{MessageKind: tka.AUMRemoveKey, PrevAUMHash: parent, KeyID: pub, Key: k(1, nil)}},
		{"value/removekey-with-votes", tka.AUM{MessageKind: tka.AUMRemoveKey, PrevAUMHash: parent, KeyID: pub, Votes: votes(1)}},
		{"value/removekey-with-meta", tka.AUM{MessageKind: tka.AUMRemoveKey, PrevAUMHash: parent, KeyID: pub, Meta: map[string]string{"a": "1"}}},
		{"value/removekey-with-state", tka.AUM{MessageKind: tka.AUMRemoveKey, PrevAUMHash: parent, KeyID: pub, State: okState}},
		{"value/updatekey-votes", tka.AUM{MessageKind: tka.AUMUpdateKey, PrevAUMHash: parent, KeyID: pub, Votes: votes(2)}},
		{"value/updatekey-votes-zero", tka.AUM{MessageKind: tka.AUMUpdateKey, PrevAUMHash: parent, KeyID: pub, Votes: votes(0)}},
		{"value/updatekey-votes-zero-keyid-1", tka.AUM{MessageKind: tka.AUMUpdateKey, PrevAUMHash: nil, KeyID: []byte{1}, Votes: votes(0), Meta: map[string]string{}}},
		{"value/updatekey-meta", tka.AUM{MessageKind: tka.AUMUpdateKey, PrevAUMHash: parent, KeyID: pub, Meta: map[string]string{"a": "1"}}},
		{"value/updatekey-no-change", tka.AUM{MessageKind: tka.AUMUpdateKey, PrevAUMHash: parent, KeyID: pub}},
		{"value/updatekey-missing-keyid", tka.AUM{MessageKind: tka.AUMUpdateKey, PrevAUMHash: parent, Votes: votes(2)}},
		{"value/updatekey-with-key", tka.AUM{MessageKind: tka.AUMUpdateKey, PrevAUMHash: parent, KeyID: pub, Votes: votes(2), Key: k(1, nil)}},
		{"value/updatekey-with-state", tka.AUM{MessageKind: tka.AUMUpdateKey, PrevAUMHash: parent, KeyID: pub, Votes: votes(2), State: okState}},
		{"value/checkpoint-valid", tka.AUM{MessageKind: tka.AUMCheckpoint, State: okState}},
		{"value/checkpoint-missing-state", tka.AUM{MessageKind: tka.AUMCheckpoint}},
		{"value/checkpoint-with-keyid", tka.AUM{MessageKind: tka.AUMCheckpoint, State: okState, KeyID: pub}},
		{"value/checkpoint-with-key", tka.AUM{MessageKind: tka.AUMCheckpoint, State: okState, Key: k(1, nil)}},
		{"value/checkpoint-with-votes", tka.AUM{MessageKind: tka.AUMCheckpoint, State: okState, Votes: votes(1)}},
		{"value/checkpoint-with-meta", tka.AUM{MessageKind: tka.AUMCheckpoint, State: okState, Meta: map[string]string{"a": "1"}}},
		{"value/checkpoint-last-aum-hash", tka.AUM{MessageKind: tka.AUMCheckpoint, State: &tka.State{LastAUMHash: &last, DisablementValues: values(1, 32), Keys: []tka.Key{*k(1, nil)}}}},
		{"value/checkpoint-disablement-0", tka.AUM{MessageKind: tka.AUMCheckpoint, State: state(values(0, 32), []tka.Key{*k(1, nil)})}},
		{"value/checkpoint-disablement-null", tka.AUM{MessageKind: tka.AUMCheckpoint, State: state(nil, []tka.Key{*k(1, nil)})}},
		{"value/checkpoint-disablement-1", tka.AUM{MessageKind: tka.AUMCheckpoint, State: state(values(1, 32), []tka.Key{*k(1, nil)})}},
		{"value/checkpoint-disablement-32", tka.AUM{MessageKind: tka.AUMCheckpoint, State: state(values(32, 32), []tka.Key{*k(1, nil)})}},
		{"value/checkpoint-disablement-33", tka.AUM{MessageKind: tka.AUMCheckpoint, State: state(values(33, 32), []tka.Key{*k(1, nil)})}},
		{"value/checkpoint-disablement-31-bytes", tka.AUM{MessageKind: tka.AUMCheckpoint, State: state(values(1, 31), []tka.Key{*k(1, nil)})}},
		{"value/checkpoint-disablement-33-bytes", tka.AUM{MessageKind: tka.AUMCheckpoint, State: state(values(1, 33), []tka.Key{*k(1, nil)})}},
		{"value/checkpoint-disablement-duplicate", tka.AUM{MessageKind: tka.AUMCheckpoint, State: state(append(values(1, 32), values(1, 32)...), []tka.Key{*k(1, nil)})}},
		{"value/checkpoint-keys-0", tka.AUM{MessageKind: tka.AUMCheckpoint, State: state(values(1, 32), keys(0))}},
		{"value/checkpoint-keys-null", tka.AUM{MessageKind: tka.AUMCheckpoint, State: state(values(1, 32), nil)}},
		{"value/checkpoint-keys-1", tka.AUM{MessageKind: tka.AUMCheckpoint, State: state(values(1, 32), keys(1))}},
		{"value/checkpoint-keys-512", tka.AUM{MessageKind: tka.AUMCheckpoint, State: state(values(1, 32), keys(512))}},
		{"value/checkpoint-keys-513", tka.AUM{MessageKind: tka.AUMCheckpoint, State: state(values(1, 32), keys(513))}},
		{"value/checkpoint-keys-duplicate", tka.AUM{MessageKind: tka.AUMCheckpoint, State: state(values(1, 32), append(keys(1), keys(1)...))}},
		{"value/checkpoint-key-votes-0", tka.AUM{MessageKind: tka.AUMCheckpoint, State: state(values(1, 32), []tka.Key{*k(0, nil)})}},
		{"value/checkpoint-stateid-two-pow-40", tka.AUM{MessageKind: tka.AUMCheckpoint, State: &tka.State{DisablementValues: values(1, 32), Keys: keys(1), StateID1: 1 << 40}}},
		{"value/checkpoint-stateid-max", tka.AUM{MessageKind: tka.AUMCheckpoint, State: &tka.State{DisablementValues: values(1, 32), Keys: keys(1), StateID1: ^uint64(0), StateID2: ^uint64(0)}}},
		{"value/noop-prev-empty", tka.AUM{MessageKind: tka.AUMNoOp, PrevAUMHash: []byte{}}},
		{"value/noop-prev-1-byte", tka.AUM{MessageKind: tka.AUMNoOp, PrevAUMHash: []byte{1}}},
		{"value/noop-prev-33-bytes", tka.AUM{MessageKind: tka.AUMNoOp, PrevAUMHash: append(append([]byte{}, parent...), 0)}},
		{"value/noop-extra-fields", tka.AUM{MessageKind: tka.AUMNoOp, PrevAUMHash: parent, Key: k(1, nil), KeyID: pub, Votes: votes(3), Meta: map[string]string{"a": "1"}, State: okState}},
		{"value/noop-extra-invalid-key", tka.AUM{MessageKind: tka.AUMNoOp, PrevAUMHash: parent, Key: k(0, nil)}},
		{"value/kind-0-extra-fields", tka.AUM{MessageKind: tka.AUMInvalid, PrevAUMHash: parent, KeyID: pub}},
		{"value/kind-6", tka.AUM{MessageKind: 6, PrevAUMHash: parent}},
		{"value/signature-keyid-31", tka.AUM{MessageKind: tka.AUMNoOp, PrevAUMHash: parent, Signatures: sig(31, 64)}},
		{"value/signature-keyid-32", tka.AUM{MessageKind: tka.AUMNoOp, PrevAUMHash: parent, Signatures: sig(32, 64)}},
		{"value/signature-keyid-33", tka.AUM{MessageKind: tka.AUMNoOp, PrevAUMHash: parent, Signatures: sig(33, 64)}},
		{"value/signature-63", tka.AUM{MessageKind: tka.AUMNoOp, PrevAUMHash: parent, Signatures: sig(32, 63)}},
		{"value/signature-65", tka.AUM{MessageKind: tka.AUMNoOp, PrevAUMHash: parent, Signatures: sig(32, 65)}},
	}
}

// rawNKSCases contains bytes modified by hand from a valid direct NKS (lock/0 signs node/0, WrappingPubkey is nl/0).
func rawNKSCases() [][2]string {
	base := directNKS(lockKeys[0], nodeKeys[0], nlKeys[0].pub())
	b := base.Serialize()
	baseHex := hexOf(b)
	// The first pair in a canonical direct NKS is 01 01 (SigKind=1).
	if !strings.HasPrefix(baseHex[2:], "0101") {
		panic("unexpected first pair in direct NKS")
	}
	withFirst := func(pair string) string { return baseHex[:2] + pair + baseHex[6:] }
	noWrapping := directNKS(lockKeys[0], nodeKeys[0], nil)
	nb := noWrapping.Serialize()
	credential := credentialNKS(lockKeys[0], credentials[0].pub())
	cb := credential.Serialize()
	return [][2]string{
		{"accept/nks-direct", baseHex},
		{"accept/nks-direct-no-wrapping", hexOf(nb)},
		{"accept/nks-unknown-int-key", hexOf(addPairs(b, 1, "0701"))},
		{"accept/nks-unknown-text-key", hexOf(addPairs(b, 1, tstr("SigKind")+"03"))},
		{"accept/nks-non-shortest-sigkind", withFirst("011801")},
		{"probe/nks-sigkind-null", withFirst("01f6")},
		{"reject/nks-sigkind-256", withFirst("01190100")},
		{"reject/nks-dup-key", hexOf(addPairs(b, 1, "0101"))},
		{"probe/nks-pubkey-null", hexOf(addPairs(cb, 1, "02f6"))},
		{"probe/nks-nested-null", hexOf(addPairs(b, 1, "05f6"))},
		{"probe/nks-wrapping-null", hexOf(addPairs(nb, 1, "06f6"))},
		{"probe/nks-nested-not-map", hexOf(addPairs(b, 1, "0501"))},
		{"reject/nks-wrapping-text", hexOf(addPairs(nb, 1, "06"+tstr("x")))},
		{"reject/nks-trailing-byte", baseHex + "00"},
		{"reject/nks-top-level-array", "8101"},
		{"reject/nks-empty", ""},
		{"reject/nks-tag", "c0" + baseHex},
		{"probe/nks-top-level-null", "f6"},
		{"probe/nks-pubkey-uint-array", hexOf(addPairs(cb, 1, "02"+uintArray(nodeKeys[0].binary())))},
		// Added by the TL-5 comparison tests: a simple value in SigKind.
		{"probe/nks-sigkind-simple-1", withFirst("01e1")},
		{"probe/nks-sigkind-simple-200", withFirst("01f8c8")},
	}
}

// keyView and stateView are the JSON representations of Key and State. Bytes are in hexadecimal, and nil is null.
type keyValue struct {
	Kind   uint8             `json:"kind"`
	Votes  uint              `json:"votes"`
	Public *string           `json:"public"`
	Meta   map[string]string `json:"meta"`
}

func viewKey(k tka.Key) keyValue {
	return keyValue{uint8(k.Kind), k.Votes, hexOrNull(k.Public), k.Meta}
}

type stateValue struct {
	LastAUMHash       *string    `json:"lastAUMHash"`
	DisablementValues []string   `json:"disablementValues"`
	Keys              []keyValue `json:"keys"`
	StateID1          uint64     `json:"stateID1,string"`
	StateID2          uint64     `json:"stateID2,string"`
}

func hexList(values [][]byte) []string {
	if values == nil {
		return nil
	}
	out := make([]string, len(values))
	for i, v := range values {
		out[i] = hexOf(v)
	}
	return out
}

func viewState(s tka.State) stateValue {
	v := stateValue{DisablementValues: hexList(s.DisablementValues), StateID1: s.StateID1, StateID2: s.StateID2}
	if s.LastAUMHash != nil {
		v.LastAUMHash = hexOrNull(s.LastAUMHash[:])
	}
	if s.Keys != nil {
		v.Keys = make([]keyValue, len(s.Keys))
		for i, k := range s.Keys {
			v.Keys[i] = viewKey(k)
		}
	}
	return v
}

// encodingCase is the canonical CBOR for one Key or State value. tka does not Serialize Key or State separately, so encode them
// directly with tka's encoder settings (cbor.CTAP2EncOptions, aum.go:249-260). This yields the same
// bytes as when they are embedded in an AUM or NKS.
type encodingCase struct {
	Name    string `json:"name"`
	Type    string `json:"type"`
	Value   any    `json:"value"`
	Encoded string `json:"encoded"`
}

func encodingCases() []encodingCase {
	enc, err := cbor.CTAP2EncOptions().EncMode()
	if err != nil {
		panic(err)
	}
	marshal := func(v any) string {
		b, err := enc.Marshal(v)
		if err != nil {
			panic(err)
		}
		return hexOf(b)
	}
	pub := lockKeys[0].pub()
	var out []encodingCase
	for _, c := range []struct {
		name string
		key  tka.Key
	}{
		{"key/basic", tka.Key{Kind: 1, Votes: 1, Public: pub}},
		{"key/votes-4096", tka.Key{Kind: 1, Votes: 4096, Public: pub}},
		{"key/public-null", tka.Key{Kind: 1, Votes: 1}},
		{"key/public-empty", tka.Key{Kind: 1, Votes: 1, Public: []byte{}}},
		{"key/meta-order", tka.Key{Kind: 1, Votes: 2, Public: pub, Meta: map[string]string{"bb": "2", "a": "1", "c": "3"}}},
		{"key/meta-empty", tka.Key{Kind: 1, Votes: 1, Public: pub, Meta: map[string]string{}}},
		{"key/meta-utf8", tka.Key{Kind: 1, Votes: 1, Public: pub, Meta: map[string]string{"이름": "값", "b": ""}}},
	} {
		out = append(out, encodingCase{c.name, "key", viewKey(c.key), marshal(c.key)})
	}
	last := tka.AUMHash{0xaa}
	for _, c := range []struct {
		name  string
		state tka.State
	}{
		{"state/checkpoint", tka.State{DisablementValues: [][]byte{zero32}, Keys: []tka.Key{{Kind: 1, Votes: 1, Public: pub}}, StateID1: 1, StateID2: 2}},
		{"state/last-aum-hash", tka.State{LastAUMHash: &last, DisablementValues: [][]byte{zero32}, Keys: []tka.Key{{Kind: 1, Votes: 1, Public: pub}}}},
		{"state/arrays-null", tka.State{}},
		{"state/arrays-empty", tka.State{DisablementValues: [][]byte{}, Keys: []tka.Key{}}},
		{"state/stateid1-two-pow-40", tka.State{StateID1: 1 << 40}},
		{"state/stateid-max", tka.State{StateID1: ^uint64(0), StateID2: ^uint64(0)}},
	} {
		out = append(out, encodingCase{c.name, "state", viewState(c.state), marshal(c.state)})
	}
	return out
}

func cborCases() []cborCase {
	var out []cborCase
	for _, c := range rawAUMCases() {
		out = append(out, evalCBOR(c[0], "aum", mustHex(c[1])))
	}
	for _, c := range valueAUMCases() {
		out = append(out, evalCBOR(c.name, "aum", c.aum.Serialize()))
	}
	for _, c := range rawNKSCases() {
		out = append(out, evalCBOR(c[0], "nks", mustHex(c[1])))
	}
	return out
}
