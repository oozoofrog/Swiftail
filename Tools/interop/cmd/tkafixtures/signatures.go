package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"

	"tailscale.com/tka"
	"tailscale.com/types/key"
)

// authorityCase is the trust state used for verdicts on signatures, peer sets, disablement secrets, and re-signing. Bootstrap from the first of aums
// and pass the rest to Inform as one group.
type authorityCase struct {
	Name  string        `json:"name"`
	AUMs  []string      `json:"aums"`
	Head  string        `json:"head"`
	State stateSnapshot `json:"state"`
}

type namedAuthority struct {
	name string
	a    *authority
}

func viewAuthority(n namedAuthority) authorityCase {
	c := authorityCase{Name: n.name, Head: hexOf(n.a.head()), State: n.a.snapshot()}
	for _, raw := range n.a.aums {
		c.AUMs = append(c.AUMs, hexOf(raw))
	}
	return c
}

// k31 is a trusted key with a 31-byte public key (static validation does not check its length).
var k31 = newEdKey("fork", 9).pub()[:31]

func authorities() []namedAuthority {
	L, V := lockKeys, disablementValues
	base := genesisAUM([]tka.Key{L[0].tkaKey(1), L[1].tkaKey(1), {Kind: tka.Key25519, Votes: 1, Public: nonCanonicalIdentity}, {Kind: tka.Key25519, Votes: 1, Public: k31}}, V[:1], 1, 2, L[0])
	removed := removeKey(aumHash(base), L[1].pub(), L[0])
	reference := tka.DisablementKDF(referenceSecret)
	dis := genesisAUM([]tka.Key{L[0].tkaKey(1)}, [][]byte{V[0], V[1], reference}, 5, 6, L[0])
	cp := childAUM(aumHash(dis), tka.AUM{MessageKind: tka.AUMCheckpoint, State: &tka.State{DisablementValues: [][]byte{V[2]}, Keys: []tka.Key{L[0].tkaKey(1)}, StateID1: 5, StateID2: 6}}, L[0])
	return []namedAuthority{
		{"nks-base", mustAuthority(base)},
		{"nks-removed", mustAuthority(base, removed)},
		{"disablement", mustAuthority(dis)},
		{"disablement-after-checkpoint", mustAuthority(dis, cp)},
	}
}

func findAuthority(all []namedAuthority, name string) *authority {
	for _, n := range all {
		if n.name == name {
			return n.a
		}
	}
	panic(name)
}

// referenceSecret is the disablement secret 0xa5 × 32 used by Go's tests (tka/state.go:325, notes §4.5).
var referenceSecret = []byte(strings.Repeat("\xa5", 32))

// NKS construction helpers. Fill in the public tka.NodeKeySignature type and sign SigHash with Ed25519.

func signNKS(s tka.NodeKeySignature, priv ed25519.PrivateKey) tka.NodeKeySignature {
	h := s.SigHash()
	s.Signature = ed25519.Sign(priv, h[:])
	return s
}

func directNKS(k edKey, n nodeKey, wrapping []byte) tka.NodeKeySignature {
	return signNKS(tka.NodeKeySignature{SigKind: tka.SigDirect, Pubkey: n.binary(), KeyID: k.pub(), WrappingPubkey: wrapping}, k.priv)
}

func credentialNKS(k edKey, wrapping []byte) tka.NodeKeySignature {
	return signNKS(tka.NodeKeySignature{SigKind: tka.SigCredential, KeyID: k.pub(), WrappingPubkey: wrapping}, k.priv)
}

func rotationNKS(signer edKey, n nodeKey, nested tka.NodeKeySignature, wrapping []byte) tka.NodeKeySignature {
	return signNKS(tka.NodeKeySignature{SigKind: tka.SigRotation, Pubkey: n.binary(), Nested: &nested, WrappingPubkey: wrapping}, signer.priv)
}

func ser(s tka.NodeKeySignature) []byte { return s.Serialize() }

type rotationView struct {
	PrevNodeKeys          []string `json:"prevNodeKeys"`
	InitialKind           uint8    `json:"initialKind"`
	InitialWrappingPubkey *string  `json:"initialWrappingPubkey"`
}

type verdict struct {
	Authorized bool          `json:"authorized"`
	Error      string        `json:"error,omitempty"`
	Rotation   *rotationView `json:"rotation"`
}

func nodePublic(raw []byte) (key.NodePublic, error) {
	var n key.NodePublic
	err := n.UnmarshalText([]byte("nodekey:" + hex.EncodeToString(raw)))
	return n, err
}

// authorize is Go's NodeKeyAuthorizedWithDetails verdict.
func authorize(a *authority, node []byte, nks []byte) verdict {
	n, err := nodePublic(node)
	if err != nil {
		return verdict{Error: err.Error()}
	}
	var details *tka.RotationDetails
	err = catch(func() error {
		var err error
		details, err = a.auth.NodeKeyAuthorizedWithDetails(n, nks)
		return err
	})
	if err != nil {
		return verdict{Error: err.Error()}
	}
	v := verdict{Authorized: true}
	if details != nil {
		r := &rotationView{PrevNodeKeys: []string{}, InitialKind: uint8(details.InitialSig.SigKind), InitialWrappingPubkey: hexOrNull(details.InitialSig.WrappingPubkey)}
		for _, p := range details.PrevNodeKeys {
			raw := p.Raw32()
			r.PrevNodeKeys = append(r.PrevNodeKeys, hexOf(raw[:]))
		}
		v.Rotation = r
	}
	return v
}

type signatureCase struct {
	Name      string `json:"name"`
	Authority string `json:"authority"`
	NodeKey   string `json:"nodeKey"`
	NKS       string `json:"nks"`
	SigHash   string `json:"sigHash,omitempty"`
	verdict
}

func signatureCases(all []namedAuthority) []signatureCase {
	L, NL, N := lockKeys, nlKeys, nodeKeys
	var out []signatureCase
	add := func(name, auth string, n nodeKey, nks []byte) {
		c := signatureCase{Name: name, Authority: auth, NodeKey: hexOf(n.raw()), NKS: hexOf(nks)}
		var s tka.NodeKeySignature
		if s.Unserialize(nks) == nil {
			h := s.SigHash()
			c.SigHash = hexOf(h[:])
		}
		c.verdict = authorize(findAuthority(all, auth), n.raw(), nks)
		out = append(out, c)
	}
	base := "nks-base"
	direct := directNKS(L[0], N[0], NL[0].pub())
	add("direct", base, N[0], ser(direct))
	add("direct-no-wrapping", base, N[0], ser(directNKS(L[0], N[0], nil)))
	add("direct-other-node-key", base, N[1], ser(direct))
	add("direct-untrusted-key", base, N[0], ser(directNKS(untrusted, N[0], nil)))
	add("direct-key-before-removal", base, N[2], ser(directNKS(L[1], N[2], nil)))
	add("direct-key-after-removal", "nks-removed", N[2], ser(directNKS(L[1], N[2], nil)))
	add("direct-with-nested", base, N[0], ser(signNKS(tka.NodeKeySignature{SigKind: tka.SigDirect, Pubkey: N[0].binary(), KeyID: L[0].pub(), Nested: &direct}, L[0].priv)))
	add("direct-31-byte-trusted-key", base, N[0], ser(signNKS(tka.NodeKeySignature{SigKind: tka.SigDirect, Pubkey: N[0].binary(), KeyID: k31}, L[0].priv)))
	bad := direct
	bad.Signature = flip(direct.Signature, 0)
	add("direct-bad-signature", base, N[0], ser(bad))
	torsion := tka.NodeKeySignature{SigKind: tka.SigDirect, Pubkey: N[0].binary(), KeyID: L[0].pub()}
	th := torsion.SigHash()
	torsion.Signature = zip215OnlySign(L[0], th[:])
	add("direct-zip215-only-signature", base, N[0], ser(torsion))
	identity := tka.NodeKeySignature{SigKind: tka.SigDirect, Pubkey: N[0].binary(), KeyID: nonCanonicalIdentity}
	ih := identity.SigHash()
	identity.Signature = identitySign(ih[:])
	add("direct-non-canonical-identity-key", base, N[0], ser(identity))
	add("direct-missing-keyid", base, N[0], ser(signNKS(tka.NodeKeySignature{SigKind: tka.SigDirect, Pubkey: N[0].binary()}, L[0].priv)))
	add("direct-missing-pubkey", base, N[0], ser(signNKS(tka.NodeKeySignature{SigKind: tka.SigDirect, KeyID: L[0].pub()}, L[0].priv)))
	add("kind-0", base, N[0], ser(signNKS(tka.NodeKeySignature{SigKind: tka.SigInvalid, Pubkey: N[0].binary(), KeyID: L[0].pub()}, L[0].priv)))
	add("kind-4", base, N[0], ser(signNKS(tka.NodeKeySignature{SigKind: 4, Pubkey: N[0].binary(), KeyID: L[0].pub()}, L[0].priv)))
	add("credential-alone", base, N[0], ser(credentialNKS(L[0], NL[0].pub())))
	add("direct-trailing-byte", base, N[0], append(ser(direct), 0))
	add("direct-unknown-field", base, N[0], addPairs(ser(direct), 1, "0701"))

	// Rotation chain: wrap direct (lock/0 → node/0, rotation key nl/0) in k rotations, with nl/0 signing node/k.
	// Verification succeeds through 15 wrappers (16 CBOR levels). Decoding rejects 16 wrappers (17 levels).
	chain := direct
	for k := 1; k <= 16; k++ {
		chain = rotationNKS(NL[0], N[k], chain, nil)
		add(fmt.Sprintf("rotation-depth-%d", k), base, N[k], ser(chain))
	}
	r1 := rotationNKS(NL[0], N[1], direct, nil)
	add("rotation-wrong-node-key", base, N[0], ser(r1))
	add("rotation-after-removal-of-other-key", "nks-removed", N[1], ser(r1))
	m1 := rotationNKS(NL[0], N[1], direct, NL[1].pub())
	add("rotation-middle-wrapping-used", base, N[2], ser(rotationNKS(NL[1], N[2], m1, nil)))
	add("rotation-middle-wrapping-outer-signed-by-inner-key", base, N[2], ser(rotationNKS(NL[0], N[2], m1, nil)))
	add("rotation-no-rotation-key", base, N[1], ser(rotationNKS(NL[0], N[1], directNKS(L[0], N[0], nil), nil)))
	add("rotation-31-byte-rotation-key", base, N[1], ser(rotationNKS(NL[0], N[1], directNKS(L[0], N[0], NL[0].pub()[:31]), nil)))
	innerBad := signNKS(tka.NodeKeySignature{SigKind: tka.SigDirect, Pubkey: append(N[0].binary(), 0), KeyID: L[0].pub(), WrappingPubkey: NL[0].pub()}, L[0].priv)
	add("rotation-inner-pubkey-not-np", base, N[1], ser(rotationNKS(NL[0], N[1], innerBad, nil)))
	outer := tka.NodeKeySignature{SigKind: tka.SigRotation, Pubkey: N[1].binary(), Nested: &direct}
	oh := outer.SigHash()
	outer.Signature = zip215OnlySign(NL[0], oh[:])
	add("rotation-outer-zip215-only-signature", base, N[1], ser(outer))
	add("rotation-missing-nested", base, N[1], ser(signNKS(tka.NodeKeySignature{SigKind: tka.SigRotation, Pubkey: N[1].binary()}, NL[0].priv)))
	add("rotation-outer-wrong-signer", base, N[1], ser(rotationNKS(NL[2], N[1], direct, nil)))
	// Added by the TL-5 comparison tests (contract §5 TL-4): empty Pubkey in the direct signature inside a rotation and empty Pubkey in the middle rotation.
	emptyInner := signNKS(tka.NodeKeySignature{SigKind: tka.SigDirect, KeyID: L[0].pub(), WrappingPubkey: NL[0].pub()}, L[0].priv)
	add("rotation-inner-direct-empty-pubkey", base, N[1], ser(rotationNKS(NL[0], N[1], emptyInner, nil)))
	emptyMiddle := rotationNKS(NL[0], N[1], direct, nil)
	emptyMiddle.Pubkey = nil
	emptyMiddle = signNKS(emptyMiddle, NL[0].priv)
	add("rotation-middle-rotation-empty-pubkey", base, N[2], ser(rotationNKS(NL[0], N[2], emptyMiddle, nil)))

	// credential → rotation: credential/0 wraps credential (lock/0, rotation key credential/0) for node/3.
	cred := credentialNKS(L[0], credentials[0].pub())
	byCred, err := tka.SignByCredential(credentials[0].priv, &cred, N[3].public())
	if err != nil {
		panic(err)
	}
	add("credential-rotation", base, N[3], byCred)
	add("credential-rotation-other-node-key", base, N[4], byCred)
	add("credential-rotation-untrusted-credential", base, N[3], ser(rotationNKS(credentials[0], N[3], credentialNKS(untrusted, credentials[0].pub()), nil)))
	add("credential-rotation-wrong-signer", base, N[3], ser(rotationNKS(credentials[1], N[3], cred, nil)))
	credNP := signNKS(tka.NodeKeySignature{SigKind: tka.SigCredential, Pubkey: N[4].binary(), KeyID: L[0].pub(), WrappingPubkey: credentials[0].pub()}, L[0].priv)
	add("credential-with-np-pubkey", base, N[3], ser(rotationNKS(credentials[0], N[3], credNP, nil)))
	credGarbage := signNKS(tka.NodeKeySignature{SigKind: tka.SigCredential, Pubkey: []byte{1, 2, 3, 4, 5}, KeyID: L[0].pub(), WrappingPubkey: credentials[0].pub()}, L[0].priv)
	add("credential-with-garbage-pubkey", base, N[3], ser(rotationNKS(credentials[0], N[3], credGarbage, nil)))
	add("credential-rotation-twice", base, N[5], ser(rotationNKS(NL[0], N[5], mustNKS(byCred), nil)))
	return out
}

func mustNKS(b []byte) tka.NodeKeySignature {
	var s tka.NodeKeySignature
	if err := s.Unserialize(b); err != nil {
		panic(err)
	}
	return s
}

// resignCase contains the result of tka.ResignNKS(NL private key, new node key, old signature) and its verdict. ResignNKS signs with Ed25519,
// so its output bytes are deterministic.
type resignCase struct {
	Name      string   `json:"name"`
	Authority string   `json:"authority"`
	NLKey     string   `json:"nlKey"`
	OldNKS    string   `json:"oldNKS"`
	NodeKey   string   `json:"nodeKey"`
	OK        bool     `json:"ok"`
	Error     string   `json:"error,omitempty"`
	Result    string   `json:"result,omitempty"`
	SigHash   string   `json:"sigHash,omitempty"`
	SameAsOld bool     `json:"sameAsOld"`
	Depth     int      `json:"depth"`
	Verdict   *verdict `json:"verdict"`
}

// nksDepth counts signatures from the outside in by following Nested.
func nksDepth(s tka.NodeKeySignature) int {
	n := 1
	for p := s.Nested; p != nil; p = p.Nested {
		n++
	}
	return n
}

func resignCases(all []namedAuthority) []resignCase {
	L, NL, N := lockKeys, nlKeys, nodeKeys
	var out []resignCase
	add := func(name string, nl edKey, old []byte, n nodeKey) {
		c := resignCase{Name: name, Authority: "nks-base", NLKey: nl.label, OldNKS: hexOf(old), NodeKey: hexOf(n.raw())}
		var result []byte
		err := catch(func() error {
			var err error
			result, err = tka.ResignNKS(nl.nl(), n.public(), old)
			return err
		})
		if err != nil {
			c.Error = err.Error()
			out = append(out, c)
			return
		}
		c.OK, c.Result, c.SameAsOld = true, hexOf(result), hexOf(result) == hexOf(old)
		s := mustNKS(result)
		h := s.SigHash()
		c.SigHash, c.Depth = hexOf(h[:]), nksDepth(s)
		v := authorize(findAuthority(all, "nks-base"), n.raw(), result)
		c.Verdict = &v
		out = append(out, c)
	}
	direct := ser(directNKS(L[0], N[0], NL[0].pub()))
	add("same-node-key", NL[0], direct, N[0])
	add("direct-wrapping-is-nl-key", NL[0], direct, N[1])
	add("direct-wrapping-is-other-key", NL[1], direct, N[1])
	add("direct-no-wrapping", NL[0], ser(directNKS(L[0], N[0], nil)), N[1])
	cred := credentialNKS(L[0], credentials[0].pub())
	byCred, err := tka.SignByCredential(credentials[0].priv, &cred, N[3].public())
	if err != nil {
		panic(err)
	}
	add("credential-chain", NL[0], byCred, N[4])
	// Shortening boundary: k rotation wrappers mean k+1 Pubkey values. Wrap them unchanged through 15 and shorten starting at 16.
	chain := directNKS(L[0], N[0], NL[0].pub())
	for k := 1; k <= 16; k++ {
		chain = rotationNKS(NL[0], N[k], chain, nil)
		if k >= 13 {
			add(fmt.Sprintf("rotation-%d-keys", k+1), NL[0], ser(chain), N[17])
		}
	}
	add("garbage", NL[0], []byte{0xa0, 0x00}, N[1])
	return out
}

// withTrailingBits sets the lowest unused bit of the last unpadded base64 character (the decoded value stays the same).
func withTrailingBits(s string) string {
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
	if len(s)%4 == 0 {
		panic("input length has no unused bits")
	}
	v := strings.IndexByte(alphabet, s[len(s)-1])
	if v < 0 || v&1 != 0 {
		panic("unused bits in the last character are already set")
	}
	return s[:len(s)-1] + string(alphabet[v|1])
}

func insertAt(s string, i int, insert string) string { return s[:i] + insert + s[i:] }

type disablementCase struct {
	Name      string `json:"name"`
	Authority string `json:"authority"`
	Secret    string `json:"secret"`
	KDF       string `json:"kdf"`
	Valid     bool   `json:"valid"`
}

func disablementCases(all []namedAuthority) []disablementCase {
	var out []disablementCase
	add := func(name, auth string, secret []byte) {
		out = append(out, disablementCase{name, auth, hexOf(secret), hexOf(tka.DisablementKDF(secret)), findAuthority(all, auth).auth.ValidDisablement(secret)})
	}
	add("reference-secret", "disablement", referenceSecret)
	add("secret-0", "disablement", disablementSecret(0))
	add("secret-1", "disablement", disablementSecret(1))
	add("secret-2-before-checkpoint", "disablement", disablementSecret(2))
	add("wrong-secret", "disablement", disablementSecret(3))
	add("empty-secret", "disablement", []byte{})
	add("secret-0-after-checkpoint", "disablement-after-checkpoint", disablementSecret(0))
	add("secret-2-after-checkpoint", "disablement-after-checkpoint", disablementSecret(2))
	add("short-secret", "disablement", disablementSecret(0)[:31])
	return out
}

// authKeyCase contains the tka.DecodeWrappedAuthkey result and, for a wrapped key, the signature tka.SignByCredential creates for node/8
// and its verdict. The input string includes test-only private keys (such as credential/0).
type authKeyCase struct {
	Name             string   `json:"name"`
	Input            string   `json:"input"`
	AuthKey          string   `json:"authKey"`
	IsWrapped        bool     `json:"isWrapped"`
	ReturnedInput    bool     `json:"returnedInput"`
	Credential       string   `json:"credential,omitempty"`
	PrivateKeyLength int      `json:"privateKeyLength"`
	NodeKey          string   `json:"nodeKey,omitempty"`
	Sign             string   `json:"sign,omitempty"`
	SignError        string   `json:"signError,omitempty"`
	NKS              string   `json:"nks,omitempty"`
	Authority        string   `json:"authority,omitempty"`
	Verdict          *verdict `json:"verdict"`
}

func authKeyCases(all []namedAuthority) []authKeyCase {
	L := lockKeys
	raw := base64.RawStdEncoding.EncodeToString
	cred := ser(credentialNKS(L[0], credentials[0].pub()))
	priv := []byte(credentials[0].priv)
	const plain = "tskey-auth-kfixture1CNTRL-test0000"
	wrap := func(a, b string) string { return plain + "--TL" + a + "-" + b }
	urlPriv := base64.RawURLEncoding.EncodeToString(priv)
	if urlPriv == raw(priv) {
		panic("URL alphabet variant matches the standard alphabet")
	}
	mismatched := append(append([]byte{}, priv[:32]...), credentials[1].pub()...)
	inputs := []struct{ name, input, authority string }{
		{"go-test-string", goTestWrappedAuthKey, ""},
		{"valid", wrap(raw(cred), raw(priv)), "nks-base"},
		{"not-wrapped", plain, ""},
		{"missing-dash", plain + "--TL" + raw(cred) + raw(priv), ""},
		{"padded-base64", wrap(base64.StdEncoding.EncodeToString(cred)+"=", raw(priv)), ""},
		{"url-alphabet-key", wrap(raw(cred), urlPriv), ""},
		{"extra-dash", wrap(raw(cred), raw(priv)) + "-x", ""},
		{"credential-not-cbor", wrap(raw([]byte("not cbor")), raw(priv)), ""},
		{"credential-direct-kind", wrap(raw(ser(directNKS(L[0], nodeKeys[0], credentials[0].pub()))), raw(priv)), "nks-base"},
		{"key-63-bytes", wrap(raw(cred), raw(priv[:63])), "nks-base"},
		{"key-65-bytes", wrap(raw(cred), raw(append(append([]byte{}, priv...), 0))), "nks-base"},
		{"key-32-bytes", wrap(raw(cred), raw(priv[:32])), "nks-base"},
		{"key-public-half-mismatch", wrap(raw(cred), raw(mismatched)), "nks-base"},
		{"credential-wrapping-other-key", wrap(raw(ser(credentialNKS(L[0], credentials[1].pub()))), raw(priv)), "nks-base"},
		{"credential-untrusted", wrap(raw(ser(credentialNKS(untrusted, credentials[0].pub()))), raw(priv)), "nks-base"},
		{"empty-parts", plain + "--TL-", ""},
		// Added by the TL-5 comparison tests (contract §5 TL-4): RawStdEncoding ignores unused bits and skips \r and \n.
		{"credential-trailing-bits", wrap(withTrailingBits(raw(cred)), raw(priv)), "nks-base"},
		{"key-trailing-bits", wrap(raw(cred), withTrailingBits(raw(priv))), "nks-base"},
		{"credential-lf", wrap(insertAt(raw(cred), 40, "\n"), raw(priv)), "nks-base"},
		{"key-crlf", wrap(raw(cred), insertAt(raw(priv), 40, "\r\n")), "nks-base"},
		{"key-trailing-lf", wrap(raw(cred), raw(priv)+"\n"), "nks-base"},
	}
	var out []authKeyCase
	n := nodeKeys[8]
	for _, in := range inputs {
		c := authKeyCase{Name: in.name, Input: in.input}
		authKey, isWrapped, sig, p := tka.DecodeWrappedAuthkey(in.input, func(string, ...any) {})
		c.AuthKey, c.IsWrapped, c.ReturnedInput = authKey, isWrapped, authKey == in.input
		if isWrapped {
			c.Credential, c.PrivateKeyLength, c.NodeKey = hexOf(sig.Serialize()), len(p), hexOf(n.raw())
			var nks []byte
			err := catch(func() error {
				var err error
				nks, err = tka.SignByCredential(p, sig, n.public())
				return err
			})
			switch {
			case err == nil:
				c.Sign, c.NKS = "ok", hexOf(nks)
			case strings.HasPrefix(err.Error(), "panic: "):
				c.Sign, c.SignError = "panic", strings.TrimPrefix(err.Error(), "panic: ")
			default:
				c.Sign, c.SignError = "error", err.Error()
			}
			if err == nil && in.authority != "" {
				c.Authority = in.authority
				v := authorize(findAuthority(all, in.authority), n.raw(), nks)
				c.Verdict = &v
			}
		}
		out = append(out, c)
	}
	return out
}
