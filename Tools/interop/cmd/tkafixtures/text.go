package main

import (
	"strings"

	"tailscale.com/tka"
	"tailscale.com/types/key"
)

// textCase is Go's verdict for one text encoding. encode is Go's text for hexadecimal input. decode is Go's result from reading the text
// (hexadecimal, or re-encoded text for nlpriv).
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
	// Added by the TL-5 comparison tests (contract §5 TL-2): base32.Decode removes \r and \n, but the length check (DecodedLen) uses
	// the character count before removal (tka/aum.go:33-41). With two line breaks in 52 characters, it reads 50 characters and fills only 31 bytes.
	decode("aum-hash-50-chars-crlf", s[:50]+"\r\n")
	decode("aum-hash-50-chars-lf-lf", s[:50]+"\n\n")
	decode("aum-hash-50-chars-cr-cr", s[:50]+"\r\r")
	decode("aum-hash-crlf-inside", s[:20]+"\r\n"+s[20:50])
	decode("aum-hash-leading-lf-lf", "\n\n"+s[:50])
	decode("aum-hash-48-chars-4-lf", s[:48]+"\n\n\n\n")
	decode("aum-hash-51-chars-lf", s[:51]+"\n")
	decode("aum-hash-52-chars-lf", s+"\n")
	decode("aum-hash-52-chars-lf-inside", s[:26]+"\n"+s[26:])

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
