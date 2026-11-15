package main

import (
	"strings"

	"tailscale.com/tka"
	"tailscale.com/types/key"
)

// textCase는 텍스트 표기 하나의 Go 판정이다. encode는 16진 입력의 Go 텍스트, decode는 텍스트를 Go가 읽은
// 결과(16진, 또는 nlpriv는 다시 쓴 텍스트)다.
type textCase struct {
	Name   string `json:"name"`
	Kind   string `json:"kind"`
	Input  string `json:"input"`
	OK     bool   `json:"ok"`
	Output string `json:"output,omitempty"`
	Error  string `json:"error,omitempty"`
}

func textCases(hashes [][]byte) []textCase {
	var out []textCase
	result := func(name, kind, input string, output string, err error) {
		c := textCase{Name: name, Kind: kind, Input: input, OK: err == nil}
		if err != nil {
			c.Error = err.Error()
		} else {
			c.Output = output
		}
		out = append(out, c)
	}
	for i, h := range hashes {
		var a tka.AUMHash
		copy(a[:], h)
		result("aum-hash-encode-"+string(rune('a'+i)), "aumHash.encode", hexOf(h), a.String(), nil)
	}
	decode := func(name, text string) {
		var a tka.AUMHash
		err := a.UnmarshalText([]byte(text))
		result(name, "aumHash.decode", text, hexOf(a[:]), err)
	}
	var sample tka.AUMHash
	copy(sample[:], hashes[0])
	s := sample.String()
	zero := strings.Repeat("A", 51)
	decode("aum-hash-valid", s)
	decode("aum-hash-lowercase", strings.ToLower(s))
	decode("aum-hash-51-chars", s[:51])
	decode("aum-hash-53-chars", s+"A")
	decode("aum-hash-padded", s+"====")
	decode("aum-hash-empty", "")
	decode("aum-hash-invalid-char", "1"+s[1:])
	for _, last := range []string{"A", "B", "P", "Q", "7"} {
		decode("aum-hash-zero-last-"+last, zero+last)
	}

	pub := key.NLPublicFromEd25519Unsafe(lockKeys[0].pub())
	text, _ := pub.MarshalText()
	result("nlpub-encode", "nlPublic.encode", hexOf(lockKeys[0].pub()), string(text), nil)
	result("tlpub-encode", "nlPublic.encodeCLI", hexOf(lockKeys[0].pub()), pub.CLIString(), nil)
	h := hexOf(lockKeys[0].pub())
	for _, c := range []struct{ name, input string }{
		{"nlpub-decode", "nlpub:" + h},
		{"tlpub-decode", "tlpub:" + h},
		{"nlpub-decode-uppercase", "nlpub:" + strings.ToUpper(h)},
		{"nlpub-decode-no-prefix", h},
		{"nlpub-decode-short", "nlpub:" + h[:62]},
		{"nlpub-decode-long", "nlpub:" + h + "00"},
		{"nlpub-decode-nlpriv-prefix", "nlpriv:" + h},
	} {
		var p key.NLPublic
		err := p.UnmarshalText([]byte(c.input))
		result(c.name, "nlPublic.decode", c.input, hexOf(p.Verifier()), err)
	}

	nl := nlKeys[0].nl()
	privText, _ := nl.MarshalText()
	result("nlpriv-encode", "nlPrivate.encode", hexOf(nlKeys[0].priv.Seed()), string(privText), nil)
	ph := strings.TrimPrefix(string(privText), "nlpriv:")
	for _, c := range []struct{ name, input string }{
		{"nlpriv-decode", string(privText)},
		{"nlpriv-decode-seed-only", "nlpriv:" + ph[:64]},
		{"nlpriv-decode-nlpub-prefix", "nlpub:" + ph},
		{"nlpriv-decode-wrong-public-half", "nlpriv:" + ph[:64] + strings.Repeat("00", 32)},
	} {
		var p key.NLPrivate
		err := p.UnmarshalText([]byte(c.input))
		var outText []byte
		if err == nil {
			outText, _ = p.MarshalText()
		}
		result(c.name, "nlPrivate.decode", c.input, string(outText), err)
	}

	n := nodeKeys[0]
	result("nodekey-encode", "nodePublic.encode", hexOf(n.raw()), n.public().String(), nil)
	result("nodekey-binary", "nodePublic.binary", hexOf(n.raw()), hexOf(n.binary()), nil)
	return out
}
