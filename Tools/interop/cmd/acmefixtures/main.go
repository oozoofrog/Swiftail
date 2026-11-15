// acmefixtures는 Swift 구현을 참조하지 않는 ACME 기준 자료와 검증 명령이다.
// CSR 템플릿의 출처: tailscale.com v1.104.6 feature/acme/certstore.go:305-320,
// Copyright (c) Tailscale Inc & contributors, BSD-3-Clause.
// 모든 개인 키는 공개된 고정 씨앗에서 만든 시험 전용 값이며 운영에 쓰면 안 된다.
package main

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"runtime/debug"
	"strings"
	"unicode/utf8"

	"tailscale.com/tempfork/acme"
)

const (
	maxInput = 256 << 10
	maxDER   = 64 << 10
	baseURL  = "https://acme.invalid"
	nonce    = "AAECAwQFBgcICQoLDA0ODw"
	kid      = baseURL + "/account/1"
)

var b64 = base64.RawURLEncoding.Strict()

type jwk struct {
	Curve string `json:"crv"`
	Type  string `json:"kty"`
	X     string `json:"x"`
	Y     string `json:"y"`
}

type jws struct {
	Protected string `json:"protected"`
	Payload   string `json:"payload"`
	Signature string `json:"signature"`
}

type protectedHeader struct {
	Algorithm string          `json:"alg"`
	KID       string          `json:"kid,omitempty"`
	JWK       json.RawMessage `json:"jwk,omitempty"`
	Nonce     string          `json:"nonce"`
	URL       string          `json:"url"`
}

// deterministicSigner는 Go의 RFC 6979 구현을 써 자료를 재현한다.
// acme가 넘기는 rand.Reader는 읽지 않는다. 실제 클라이언트의 서명 난수 정책과는 다르다.
type deterministicSigner struct{ key *ecdsa.PrivateKey }

func (s deterministicSigner) Public() crypto.PublicKey { return &s.key.PublicKey }
func (s deterministicSigner) Sign(_ io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	return s.key.Sign(nil, digest, opts)
}

type keyCase struct {
	ID         string `json:"id"`
	TestOnly   bool   `json:"testOnly"`
	Seed       string `json:"seed"`
	ScalarHex  string `json:"scalarHex"`
	PublicKey  jwk    `json:"publicKey"`
	JWKJSON    string `json:"jwkJSON"`
	Thumbprint string `json:"thumbprint"`
	SEC1PEM    string `json:"sec1PEM"`
	PKCS8PEM   string `json:"pkcs8PEM"`
}

type challengeCase struct {
	KeyID            string `json:"keyID"`
	Token            string `json:"token"`
	KeyAuthorization string `json:"keyAuthorization"`
	DNS01TXT         string `json:"dns01TXT"`
}

type jwsCase struct {
	KeyID           string `json:"keyID"`
	Mode            string `json:"mode"`
	ProtectedJSON   string `json:"protectedJSON"`
	PayloadJSON     string `json:"payloadJSON"`
	SigningInput    string `json:"signingInput"`
	VerifiedExample jws    `json:"verifiedExample"`
}

type csrCase struct {
	Name        string `json:"name"`
	KeyID       string `json:"keyID"`
	Domain      string `json:"domain"`
	DERHex      string `json:"derHex"`
	InfoHex     string `json:"certificationRequestInfoHex"`
	CNStringTag int    `json:"cnStringTag"`
}

type fixture struct {
	Reference struct {
		Go        string `json:"go"`
		Tailscale string `json:"tailscale"`
	} `json:"reference"`
	CaseCount  int             `json:"caseCount"`
	Keys       []keyCase       `json:"keys"`
	Challenges []challengeCase `json:"challenges"`
	JWS        []jwsCase       `json:"jws"`
	CSRs       []csrCase       `json:"csrs"`
}

// captureTransport는 소켓 없이 acme.Client의 실제 요청 본문을 포착한다.
type captureTransport struct{ requests []jws }

func (t *captureTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	status, body := http.StatusOK, ""
	switch r.Method + " " + r.URL.String() {
	case "GET " + baseURL + "/directory":
		body = `{"newAccount":"` + baseURL + `/new-account","newOrder":"` + baseURL + `/new-order","newNonce":"` + baseURL + `/nonce"}`
	case "POST " + baseURL + "/new-account", "POST " + baseURL + "/authz/1":
		data, err := readLimited(r.Body)
		if err != nil {
			return nil, err
		}
		var message jws
		if err := strictJSON(data, &message); err != nil {
			return nil, err
		}
		t.requests = append(t.requests, message)
		if r.URL.Path == "/new-account" {
			status, body = http.StatusCreated, `{"status":"valid","orders":"`+baseURL+`/orders"}`
		} else {
			body = `{"status":"valid","identifier":{"type":"dns","value":"a.ts.net"},"challenges":[]}`
		}
	default:
		return nil, errors.New("예상하지 않은 메모리 전송 요청")
	}
	h := make(http.Header)
	h.Set("Replay-Nonce", nonce)
	h.Set("Location", kid)
	return &http.Response{StatusCode: status, Header: h, Body: io.NopCloser(strings.NewReader(body)), Request: r}, nil
}

func capture(key *ecdsa.PrivateKey) ([]jws, error) {
	t := &captureTransport{}
	c := &acme.Client{Key: deterministicSigner{key}, DirectoryURL: baseURL + "/directory", HTTPClient: &http.Client{Transport: t}}
	if _, err := c.Register(context.Background(), &acme.Account{}, nil); err != nil {
		return nil, err
	}
	if _, err := c.GetAuthorization(context.Background(), baseURL+"/authz/1"); err != nil {
		return nil, err
	}
	if len(t.requests) != 2 {
		return nil, errors.New("포착한 JWS 수가 다릅니다")
	}
	return t.requests, nil
}

func publicJWK(p *ecdsa.PublicKey) jwk {
	return jwk{"P-256", "EC", b64.EncodeToString(p.X.FillBytes(make([]byte, 32))), b64.EncodeToString(p.Y.FillBytes(make([]byte, 32)))}
}

func testKey(index int) (*ecdsa.PrivateKey, string, error) {
	seed := fmt.Sprintf("swiftail-fixtures/acme/%d", index)
	digest := sha256.Sum256([]byte(seed))
	key, err := ecdsa.ParseRawPrivateKey(elliptic.P256(), digest[:])
	return key, seed, err
}

func evaluate() ([]byte, error) {
	var f fixture
	f.Reference.Go = runtime.Version()
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return nil, errors.New("Go 빌드 정보가 없습니다")
	}
	for _, dep := range info.Deps {
		if dep.Path == "tailscale.com" && dep.Replace == nil {
			f.Reference.Tailscale = dep.Version
		}
	}
	if f.Reference.Tailscale != "v1.104.6" {
		return nil, errors.New("기준 tailscale 버전이 다릅니다")
	}
	var keys []*ecdsa.PrivateKey
	for i := 0; i < 4096 && len(keys) < 3; i++ {
		key, seed, err := testKey(i)
		if err != nil {
			return nil, err
		}
		x, y := key.X.FillBytes(make([]byte, 32)), key.Y.FillBytes(make([]byte, 32))
		if len(keys) == 1 && x[0] != 0 || len(keys) == 2 && y[0] != 0 {
			continue
		}
		id := []string{"account", "leading-zero-x", "leading-zero-y"}[len(keys)]
		messages, err := capture(key)
		if err != nil {
			return nil, err
		}
		headerJSON, err := decodeBase64(messages[0].Protected)
		if err != nil {
			return nil, err
		}
		var header protectedHeader
		if err := strictJSON(headerJSON, &header); err != nil {
			return nil, err
		}
		thumb, err := acme.JWKThumbprint(key.Public())
		if err != nil {
			return nil, err
		}
		sec1, err := x509.MarshalECPrivateKey(key)
		if err != nil {
			return nil, err
		}
		pkcs8, err := x509.MarshalPKCS8PrivateKey(key)
		if err != nil {
			return nil, err
		}
		f.Keys = append(f.Keys, keyCase{id, true, seed, hex.EncodeToString(key.D.FillBytes(make([]byte, 32))), publicJWK(&key.PublicKey), string(header.JWK), thumb,
			string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: sec1})), string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8}))})
		c := &acme.Client{Key: key}
		for _, token := range []string{nonce, b64.EncodeToString(bytes.Repeat([]byte{0xff}, 16)), b64.EncodeToString(bytes.Repeat([]byte{0xfb}, 32))} {
			auth, err := c.HTTP01ChallengeResponse(token)
			if err != nil {
				return nil, err
			}
			txt, err := c.DNS01ChallengeRecord(token)
			if err != nil {
				return nil, err
			}
			f.Challenges = append(f.Challenges, challengeCase{id, token, auth, txt})
		}
		for j, message := range messages {
			h, err := decodeBase64(message.Protected)
			if err != nil {
				return nil, err
			}
			payload, err := decodeBase64(message.Payload)
			if err != nil {
				return nil, err
			}
			mode, expectedURL, expectedKID := "jwk", baseURL+"/new-account", ""
			if j == 1 {
				mode, expectedURL, expectedKID = "kid", baseURL+"/authz/1", kid
			}
			if _, err := verifyJWS(jwsInput{message, publicJWK(&key.PublicKey), nonce, expectedURL, expectedKID}); err != nil {
				return nil, err
			}
			f.JWS = append(f.JWS, jwsCase{id, mode, string(h), string(payload), message.Protected + "." + message.Payload, message})
		}
		keys = append(keys, key)
	}
	if len(keys) != 3 {
		return nil, errors.New("선행 0 좌표 시험 키를 찾지 못했습니다")
	}
	domains := []struct{ name, domain string }{
		{"short", "a.ts.net"},
		{"ordinary", "rd-mac-1a2b3c4d.tail0001.ts.net"},
		{"label-63", strings.Repeat("a", 63) + ".tail0001.ts.net"},
		{"name-253", strings.Repeat("a", 63) + "." + strings.Repeat("b", 63) + "." + strings.Repeat("c", 63) + "." + strings.Repeat("d", 45) + ".tail0001.ts.net"},
	}
	for _, d := range domains {
		// certRequest(key, domain, nil)의 일반 이름 경로와 같은 템플릿이다.
		template := &x509.CertificateRequest{Subject: pkix.Name{CommonName: d.domain}, DNSNames: []string{d.domain}, ExtraExtensions: nil}
		der, err := x509.CreateCertificateRequest(nil, template, deterministicSigner{keys[0]})
		if err != nil {
			return nil, err
		}
		parsed, err := parseCSR(der)
		if err != nil {
			return nil, err
		}
		f.CSRs = append(f.CSRs, csrCase{d.name, f.Keys[0].ID, d.domain, hex.EncodeToString(der), parsed.InfoHex, parsed.CNStringTag})
	}
	f.CaseCount = len(f.Keys) + len(f.Challenges) + len(f.JWS) + len(f.CSRs)
	data, err := json.MarshalIndent(f, "", "  ")
	return append(data, '\n'), err
}

func decodeBase64(s string) ([]byte, error) {
	data, err := b64.DecodeString(s)
	if err != nil || b64.EncodeToString(data) != s {
		return nil, errors.New("채움 없는 base64url 형식이 아닙니다")
	}
	return data, nil
}

func parseJWK(j jwk) (*ecdsa.PublicKey, error) {
	x, ex := decodeBase64(j.X)
	y, ey := decodeBase64(j.Y)
	if j.Curve != "P-256" || j.Type != "EC" || ex != nil || ey != nil || len(x) != 32 || len(y) != 32 {
		return nil, errors.New("P-256 공개 JWK 형식이 잘못되었습니다")
	}
	p := &ecdsa.PublicKey{Curve: elliptic.P256(), X: new(big.Int).SetBytes(x), Y: new(big.Int).SetBytes(y)}
	if !p.Curve.IsOnCurve(p.X, p.Y) {
		return nil, errors.New("JWK 좌표가 P-256 곡선 위에 없습니다")
	}
	return p, nil
}

type jwsInput struct {
	JWS           jws    `json:"jws"`
	JWK           jwk    `json:"jwk"`
	ExpectedNonce string `json:"expectedNonce"`
	ExpectedURL   string `json:"expectedURL"`
	ExpectedKID   string `json:"expectedKID,omitempty"`
}

type jwsResult struct {
	OK           bool            `json:"ok"`
	Protected    json.RawMessage `json:"protected"`
	PayloadHex   string          `json:"payloadHex"`
	SigningInput string          `json:"signingInput"`
}

func validURL(s string) bool {
	u, err := url.Parse(s)
	return err == nil && len(s) <= 2048 && u.Scheme == "https" && u.Hostname() != "" && u.User == nil && !strings.Contains(s, "#")
}

func verifyJWS(in jwsInput) (jwsResult, error) {
	fail := func() (jwsResult, error) {
		return jwsResult{}, errors.New("JWS 보호 머리 또는 서명이 올바르지 않습니다")
	}
	pub, err := parseJWK(in.JWK)
	if err != nil {
		return jwsResult{}, err
	}
	h, err := decodeBase64(in.JWS.Protected)
	if err != nil || len(h) > 8192 {
		return fail()
	}
	var header protectedHeader
	if strictJSON(h, &header) != nil {
		return fail()
	}
	if header.Algorithm != "ES256" || header.Nonce == "" || header.Nonce != in.ExpectedNonce || !validURL(header.URL) || header.URL != in.ExpectedURL {
		return fail()
	}
	if _, err := decodeBase64(header.Nonce); err != nil {
		return fail()
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(h, &fields); err != nil {
		return fail()
	}
	_, hasJWK := fields["jwk"]
	_, hasKID := fields["kid"]
	if hasJWK == hasKID {
		return fail()
	}
	if hasJWK {
		var embedded jwk
		if in.ExpectedKID != "" || strictJSON(header.JWK, &embedded) != nil || embedded != in.JWK {
			return fail()
		}
	} else if !validURL(header.KID) || header.KID != in.ExpectedKID {
		return fail()
	}
	payload, err := decodeBase64(in.JWS.Payload)
	if err != nil {
		return fail()
	}
	signature, err := decodeBase64(in.JWS.Signature)
	if err != nil || len(signature) != 64 {
		return fail()
	}
	input := in.JWS.Protected + "." + in.JWS.Payload
	digest := sha256.Sum256([]byte(input))
	if !ecdsa.Verify(pub, digest[:], new(big.Int).SetBytes(signature[:32]), new(big.Int).SetBytes(signature[32:])) {
		return fail()
	}
	return jwsResult{true, h, hex.EncodeToString(payload), input}, nil
}

type csrResult struct {
	OK                 bool     `json:"ok"`
	CommonName         string   `json:"commonName"`
	DNSNames           []string `json:"dnsNames"`
	PublicKey          jwk      `json:"publicKey"`
	SignatureAlgorithm string   `json:"signatureAlgorithm"`
	InfoHex            string   `json:"certificationRequestInfoHex"`
	CNStringTag        int      `json:"cnStringTag"`
}

func parseCSR(der []byte) (csrResult, error) {
	if len(der) == 0 || len(der) > maxDER {
		return csrResult{}, errors.New("CSR DER 크기 한도를 벗어났습니다")
	}
	request, err := x509.ParseCertificateRequest(der)
	if err != nil {
		return csrResult{}, errors.New("Go가 CSR DER를 읽지 못했습니다")
	}
	if err := request.CheckSignature(); err != nil {
		return csrResult{}, errors.New("Go가 CSR 서명을 거절했습니다")
	}
	pub, ok := request.PublicKey.(*ecdsa.PublicKey)
	if !ok || pub.Curve != elliptic.P256() {
		return csrResult{}, errors.New("CSR 공개 키가 P-256이 아닙니다")
	}
	type rawRDNSET []struct {
		OID   asn1.ObjectIdentifier
		Value asn1.RawValue
	}
	var subject []rawRDNSET
	rest, err := asn1.Unmarshal(request.RawSubject, &subject)
	if err != nil || len(rest) != 0 {
		return csrResult{}, errors.New("CSR 주체를 읽지 못했습니다")
	}
	tag := 0
	for _, set := range subject {
		for _, attr := range set {
			if attr.OID.Equal(asn1.ObjectIdentifier{2, 5, 4, 3}) {
				tag = attr.Value.Tag
			}
		}
	}
	names := request.DNSNames
	if names == nil {
		names = []string{}
	}
	return csrResult{true, request.Subject.CommonName, names, publicJWK(pub), request.SignatureAlgorithm.String(), hex.EncodeToString(request.RawTBSCertificateRequest), tag}, nil
}

type keyResult struct {
	OK        bool   `json:"ok"`
	Format    string `json:"format"`
	PublicKey jwk    `json:"publicKey"`
}

func parseKey(text string) (keyResult, error) {
	data := bytes.TrimSpace([]byte(text))
	if len(data) > maxDER || !bytes.HasPrefix(data, []byte("-----BEGIN ")) {
		return keyResult{}, errors.New("PEM 입력 형식 또는 크기가 잘못되었습니다")
	}
	block, rest := pem.Decode(data)
	if block == nil || len(bytes.TrimSpace(rest)) != 0 || len(block.Headers) != 0 || bytes.Count(data, []byte("-----BEGIN ")) != 1 || bytes.Count(data, []byte("-----END ")) != 1 {
		return keyResult{}, errors.New("PEM 블록 하나가 필요합니다")
	}
	var parsed any
	var err error
	switch block.Type {
	case "EC PRIVATE KEY":
		parsed, err = x509.ParseECPrivateKey(block.Bytes)
	case "PRIVATE KEY":
		parsed, err = x509.ParsePKCS8PrivateKey(block.Bytes)
	default:
		return keyResult{}, errors.New("지원하지 않는 PEM 종류입니다")
	}
	key, ok := parsed.(*ecdsa.PrivateKey)
	if err != nil || !ok || key.Curve != elliptic.P256() {
		return keyResult{}, errors.New("Go가 P-256 개인 키를 읽지 못했습니다")
	}
	return keyResult{true, block.Type, publicJWK(&key.PublicKey)}, nil
}

func readLimited(r io.Reader) ([]byte, error) {
	data, err := io.ReadAll(io.LimitReader(r, maxInput+1))
	if err != nil {
		return nil, errors.New("입력을 읽지 못했습니다")
	}
	if len(data) > maxInput {
		return nil, errors.New("입력은 256KiB 이하여야 합니다")
	}
	return data, nil
}

// strictJSON은 중복 멤버·과도한 중첩·알 수 없는 필드·뒤따르는 값을 거절한다.
func strictJSON(data []byte, out any) error {
	bad := errors.New("JSON 입력 형식이 잘못되었습니다")
	if !utf8.Valid(data) {
		return bad
	}
	d := json.NewDecoder(bytes.NewReader(data))
	var walk func(int, reflect.Type) error
	walk = func(depth int, schema reflect.Type) error {
		if depth > 32 {
			return bad
		}
		t, err := d.Token()
		if err != nil {
			return bad
		}
		switch t {
		case json.Delim('{'):
			// encoding/json의 대소문자 무시 매칭을 프로토콜 경계에서 허용하지 않는다.
			var fields map[string]reflect.Type
			if schema != nil && schema.Kind() == reflect.Struct {
				fields = make(map[string]reflect.Type)
				for field := range schema.Fields() {
					name := strings.Split(field.Tag.Get("json"), ",")[0]
					fields[name] = field.Type
				}
			}
			seen := map[string]bool{}
			for d.More() {
				key, err := d.Token()
				s, ok := key.(string)
				if err != nil || !ok || seen[s] {
					return bad
				}
				seen[s] = true
				var child reflect.Type
				if fields != nil {
					var exists bool
					child, exists = fields[s]
					if !exists {
						return bad
					}
				}
				if err := walk(depth+1, child); err != nil {
					return err
				}
			}
			if end, err := d.Token(); err != nil || end != json.Delim('}') {
				return bad
			}
		case json.Delim('['):
			for d.More() {
				if err := walk(depth+1, nil); err != nil {
					return err
				}
			}
			if end, err := d.Token(); err != nil || end != json.Delim(']') {
				return bad
			}
		}
		return nil
	}
	if err := walk(0, reflect.TypeOf(out).Elem()); err != nil {
		return err
	}
	if _, err := d.Token(); err != io.EOF {
		return bad
	}
	if !bytes.HasPrefix(bytes.TrimSpace(data), []byte("{")) {
		return bad
	}
	d = json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	if err := d.Decode(out); err != nil {
		return bad
	}
	return nil
}

func execute(args []string, in io.Reader, out io.Writer) error {
	if len(args) == 0 || len(args) == 1 && args[0] != "verify-jws" && args[0] != "verify-csr" && args[0] != "parse-key" {
		data, err := evaluate()
		if err != nil {
			return err
		}
		if len(args) == 0 {
			_, err = out.Write(data)
			return err
		}
		if err := os.MkdirAll(args[0], 0755); err != nil {
			return errors.New("자료 폴더를 만들지 못했습니다")
		}
		if err := os.WriteFile(filepath.Join(args[0], "acme-fixtures.json"), data, 0644); err != nil {
			return errors.New("자료를 쓰지 못했습니다")
		}
		return nil
	}
	if len(args) != 1 {
		return errors.New("사용법: acmefixtures [자료 폴더 | verify-jws | verify-csr | parse-key]")
	}
	data, err := readLimited(in)
	if err != nil {
		return err
	}
	var result any
	switch args[0] {
	case "verify-jws":
		var input jwsInput
		if err := strictJSON(data, &input); err != nil {
			return err
		}
		result, err = verifyJWS(input)
	case "verify-csr":
		var input struct {
			DERHex string `json:"derHex"`
		}
		if err := strictJSON(data, &input); err != nil {
			return err
		}
		der, decodeErr := hex.DecodeString(input.DERHex)
		if decodeErr != nil {
			return errors.New("DER hex 형식이 잘못되었습니다")
		}
		result, err = parseCSR(der)
	case "parse-key":
		var input struct {
			PEM string `json:"pem"`
		}
		if err := strictJSON(data, &input); err != nil {
			return err
		}
		result, err = parseKey(input.PEM)
	}
	if err != nil {
		return err
	}
	return json.NewEncoder(out).Encode(result)
}

func run(args []string, in io.Reader, out io.Writer) int {
	if err := execute(args, in, out); err != nil {
		_ = json.NewEncoder(out).Encode(struct {
			OK    bool   `json:"ok"`
			Error string `json:"error"`
		}{false, err.Error()})
		return 1
	}
	return 0
}

func main() { os.Exit(run(os.Args[1:], os.Stdin, os.Stdout)) }
