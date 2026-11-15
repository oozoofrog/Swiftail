package main

import (
	"bytes"
	"crypto"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"encoding/json"
	"math/big"
	"os"
	"strings"
	"testing"
)

func generated(t *testing.T) ([]byte, fixture) {
	t.Helper()
	data, err := evaluate()
	if err != nil {
		t.Fatal(err)
	}
	var f fixture
	if err := json.Unmarshal(data, &f); err != nil {
		t.Fatal(err)
	}
	return data, f
}

func TestFixtures(t *testing.T) {
	first, f := generated(t)
	second, _ := generated(t)
	if !bytes.Equal(first, second) {
		t.Fatal("연속 생성 결과가 다릅니다")
	}
	saved, err := os.ReadFile("../../../../Tests/SwiftailCertificatesTests/Fixtures/acme-fixtures.json")
	if err != nil {
		t.Fatal("저장된 기준 자료를 읽지 못했습니다")
	}
	if !bytes.Equal(first, saved) {
		t.Fatal("저장 자료와 재생성 결과가 다릅니다")
	}
	if f.CaseCount != 22 || len(f.Keys) != 3 || len(f.Challenges) != 9 || len(f.JWS) != 6 || len(f.CSRs) != 4 {
		t.Fatal("사례 수가 다릅니다")
	}
	for _, key := range f.Keys {
		x, _ := decodeBase64(key.PublicKey.X)
		y, _ := decodeBase64(key.PublicKey.Y)
		if len(x) != 32 || len(y) != 32 || key.ID == "leading-zero-x" && x[0] != 0 || key.ID == "leading-zero-y" && y[0] != 0 {
			t.Fatal("좌표 채움 사례가 잘못되었습니다")
		}
		digest := sha256.Sum256([]byte(key.JWKJSON))
		if b64.EncodeToString(digest[:]) != key.Thumbprint {
			t.Fatal("지문 입력 바이트가 다릅니다")
		}
		for _, text := range []string{key.SEC1PEM, key.PKCS8PEM} {
			result, err := parseKey(text)
			if err != nil || result.PublicKey != key.PublicKey {
				t.Fatal("PEM 공개 키가 다릅니다")
			}
			checkCommand(t, "parse-key", map[string]string{"pem": text}, true)
		}
	}
	for _, c := range f.Challenges {
		digest := sha256.Sum256([]byte(c.KeyAuthorization))
		if b64.EncodeToString(digest[:]) != c.DNS01TXT || len(c.DNS01TXT) != 43 {
			t.Fatal("DNS-01 값이 다릅니다")
		}
	}
	for _, c := range f.CSRs {
		der, _ := hex.DecodeString(c.DERHex)
		request, err := x509.ParseCertificateRequest(der)
		if err != nil {
			t.Fatal(err)
		}
		if err := request.CheckSignature(); err != nil {
			t.Fatal(err)
		}
		if c.CNStringTag != asn1.TagPrintableString || request.Subject.CommonName != c.Domain || len(request.DNSNames) != 1 || request.DNSNames[0] != c.Domain || hex.EncodeToString(request.RawTBSCertificateRequest) != c.InfoHex {
			t.Fatal("CSR 주체·SAN·Info가 다릅니다")
		}
		if len(request.Extensions) != 1 || !request.Extensions[0].Id.Equal(asn1.ObjectIdentifier{2, 5, 29, 17}) || request.Extensions[0].Critical || len(request.Attributes) != 1 || !request.Attributes[0].Type.Equal(asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 14}) {
			t.Fatal("CSR은 extensionRequest의 SAN 하나여야 합니다")
		}
		if request.SignatureAlgorithm != x509.ECDSAWithSHA256 {
			t.Fatal("CSR 서명 알고리즘이 다릅니다")
		}
		if c.Name == "name-253" && len(c.Domain) != 253 {
			t.Fatal("253자 이름이 아닙니다")
		}
		checkCommand(t, "verify-csr", map[string]string{"derHex": c.DERHex}, true)
	}
}

func checkCommand(t *testing.T, command string, input any, wantOK bool) []byte {
	t.Helper()
	data, err := json.Marshal(input)
	if err != nil {
		t.Fatal(err)
	}
	return checkRaw(t, command, data, wantOK)
}

func checkRaw(t *testing.T, command string, input []byte, wantOK bool) []byte {
	t.Helper()
	var out bytes.Buffer
	status := run([]string{command}, bytes.NewReader(input), &out)
	var result struct {
		OK    bool   `json:"ok"`
		Error string `json:"error"`
	}
	if err := json.Unmarshal(out.Bytes(), &result); err != nil {
		t.Fatal("명령이 JSON 한 값을 반환하지 않았습니다")
	}
	if result.OK != wantOK || (status == 0) != wantOK || !wantOK && result.Error == "" {
		t.Fatalf("명령 %s의 성공·오류 응답이 다릅니다: %s", command, out.String())
	}
	return out.Bytes()
}

func inputFor(f fixture, c jwsCase) jwsInput {
	var pub jwk
	for _, k := range f.Keys {
		if k.ID == c.KeyID {
			pub = k.PublicKey
		}
	}
	expectedURL, expectedKID := baseURL+"/new-account", ""
	if c.Mode == "kid" {
		expectedURL, expectedKID = baseURL+"/authz/1", kid
	}
	return jwsInput{c.VerifiedExample, pub, nonce, expectedURL, expectedKID}
}

// 시험 머리를 다시 서명해 서명 오류에 가려지지 않은 머리 검사를 확인한다.
func resign(t *testing.T, in jwsInput, header string) jwsInput {
	t.Helper()
	key, _, err := testKey(0)
	if err != nil {
		t.Fatal(err)
	}
	in.JWS.Protected = b64.EncodeToString([]byte(header))
	digest := sha256.Sum256([]byte(in.JWS.Protected + "." + in.JWS.Payload))
	der, err := key.Sign(nil, digest[:], crypto.SHA256)
	if err != nil {
		t.Fatal(err)
	}
	var rs struct{ R, S *big.Int }
	if _, err := asn1.Unmarshal(der, &rs); err != nil {
		t.Fatal(err)
	}
	signature := append(rs.R.FillBytes(make([]byte, 32)), rs.S.FillBytes(make([]byte, 32))...)
	in.JWS.Signature = b64.EncodeToString(signature)
	return in
}

func TestVerifyJWS(t *testing.T) {
	_, f := generated(t)
	for _, c := range f.JWS {
		checkCommand(t, "verify-jws", inputFor(f, c), true)
	}
	in := inputFor(f, f.JWS[0])
	// JSON 순서와 공백이 달라도 실제 직렬화한 바이트를 서명했다면 유효하다.
	reordered := `{"url":"` + in.ExpectedURL + `", "nonce":"` + nonce + `", "jwk":` + f.Keys[0].JWKJSON + `, "alg":"ES256"}`
	checkCommand(t, "verify-jws", resign(t, in, reordered), true)
	mutations := []struct {
		name   string
		change func(*jwsInput)
	}{
		{"payload", func(v *jwsInput) { v.JWS.Payload = b64.EncodeToString([]byte(`{"changed":true}`)) }},
		{"signature", func(v *jwsInput) {
			s, _ := decodeBase64(v.JWS.Signature)
			s[0] ^= 1
			v.JWS.Signature = b64.EncodeToString(s)
		}},
		{"short-signature", func(v *jwsInput) { v.JWS.Signature = "AA" }},
		{"wrong-key", func(v *jwsInput) { v.JWK = f.Keys[1].PublicKey }},
		{"off-curve", func(v *jwsInput) { v.JWK.X = b64.EncodeToString(make([]byte, 32)); v.JWK.Y = v.JWK.X }},
		{"short-coordinate", func(v *jwsInput) { v.JWK.X = "AA" }},
		{"nonce", func(v *jwsInput) { v.ExpectedNonce = "AQIDBA" }},
		{"url", func(v *jwsInput) { v.ExpectedURL = baseURL + "/different" }},
		{"kid", func(v *jwsInput) { v.ExpectedKID = kid }},
		{"padding", func(v *jwsInput) { v.JWS.Protected += "=" }},
		{"newline", func(v *jwsInput) { v.JWS.Protected += "\n" }},
	}
	for _, m := range mutations {
		t.Run(m.name, func(t *testing.T) { v := in; m.change(&v); checkCommand(t, "verify-jws", v, false) })
	}
	for _, header := range []string{
		strings.Replace(reordered, `"ES256"`, `"HS256"`, 1),
		strings.Replace(reordered, `"jwk":`, `"kid":"`+kid+`","jwk":`, 1),
		strings.Replace(reordered, `"alg":"ES256"`, `"alg":"ES256","alg":"ES256"`, 1),
		strings.Replace(reordered, `"alg":"ES256"`, `"alg":"ES256","crit":["extra"]`, 1),
		strings.Replace(reordered, `"alg"`, `"ALG"`, 1),
		strings.Replace(reordered, `"crv"`, `"CRV"`, 1),
		strings.Replace(reordered, `https://`, `http://`, 1),
		strings.Replace(reordered, nonce, "", 1),
		strings.Replace(reordered, `"jwk":`+f.Keys[0].JWKJSON+`, `, "", 1),
	} {
		checkCommand(t, "verify-jws", resign(t, in, header), false)
	}
	kidInput := inputFor(f, f.JWS[1])
	kidInput.ExpectedKID = baseURL + "/account/2"
	checkCommand(t, "verify-jws", kidInput, false)
	data, err := json.Marshal(in)
	if err != nil {
		t.Fatal(err)
	}
	checkRaw(t, "verify-jws", bytes.Replace(data, []byte(`"expectedNonce"`), []byte(`"expectednonce"`), 1), false)
	checkRaw(t, "verify-jws", bytes.Replace(data, []byte(`"crv"`), []byte(`"CRV"`), 1), false)
}

func TestVerifyCSRRejectsTampering(t *testing.T) {
	_, f := generated(t)
	der, _ := hex.DecodeString(f.CSRs[1].DERHex)
	signatureChanged := bytes.Clone(der)
	signatureChanged[len(signatureChanged)-1] ^= 1
	infoChanged := bytes.Clone(der)
	position := bytes.Index(infoChanged, []byte(f.CSRs[1].Domain))
	if position < 0 {
		t.Fatal("CSR에서 시험 이름을 찾지 못했습니다")
	}
	infoChanged[position] = 's'
	for _, bad := range [][]byte{signatureChanged, infoChanged, der[:len(der)-1], append(bytes.Clone(der), 0), nil, make([]byte, maxDER+1)} {
		checkCommand(t, "verify-csr", map[string]string{"derHex": hex.EncodeToString(bad)}, false)
	}
	checkCommand(t, "verify-csr", map[string]string{"derHex": "zz"}, false)
	// UTF8String CSR은 유효하지만 Go 기준 Info와 바이트가 다름을 결과로 드러낸다.
	key, _, _ := testKey(0)
	name := f.CSRs[1].Domain
	subject := pkix.Name{CommonName: name}.ToRDNSequence()
	subject[0][0].Value = asn1.RawValue{Tag: asn1.TagUTF8String, Bytes: []byte(name)}
	raw, err := asn1.Marshal(subject)
	if err != nil {
		t.Fatal(err)
	}
	utf8DER, err := x509.CreateCertificateRequest(nil, &x509.CertificateRequest{RawSubject: raw, DNSNames: []string{name}}, deterministicSigner{key})
	if err != nil {
		t.Fatal(err)
	}
	result, err := parseCSR(utf8DER)
	if err != nil || result.CNStringTag != asn1.TagUTF8String || result.InfoHex == f.CSRs[1].InfoHex {
		t.Fatal("UTF8String과 바이트 동일성의 구별이 잘못되었습니다")
	}
}

func TestUntrustedInput(t *testing.T) {
	var raw struct {
		PEM json.RawMessage `json:"pem"`
	}
	if strictJSON([]byte("{\"pem\":\"\xff\"}"), &raw) == nil {
		t.Fatal("잘못된 UTF-8을 받아들였습니다")
	}
	if strictJSON([]byte(`{"pem":`+strings.Repeat("[", 40)+"0"+strings.Repeat("]", 40)+"}"), &raw) == nil {
		t.Fatal("과도한 JSON 중첩을 받아들였습니다")
	}
	for _, command := range []string{"verify-jws", "verify-csr", "parse-key"} {
		for _, input := range []string{"", "null", "[]", "{} {}", `{"unknown":1}`, `{"pem":"a","pem":"b"}`, strings.Repeat(" ", maxInput+1), `{"a":` + strings.Repeat("[", 40) + "0" + strings.Repeat("]", 40) + "}"} {
			checkRaw(t, command, []byte(input), false)
		}
	}
	_, f := generated(t)
	key := f.Keys[0].SEC1PEM
	for _, input := range []string{key + key, "garbage\n" + key, key + "garbage", "-----BEGIN BROKEN-----\n???\n-----END BROKEN-----\n" + key, strings.ReplaceAll(key, "EC PRIVATE KEY", "CERTIFICATE"), "-----BEGIN PRIVATE KEY-----\nAA==\n-----END PRIVATE KEY-----", strings.Repeat("a", maxDER+1)} {
		checkCommand(t, "parse-key", map[string]string{"pem": input}, false)
	}
	var out bytes.Buffer
	if run([]string{"verify-csr", "extra"}, strings.NewReader("{}"), &out) == 0 {
		t.Fatal("명령 인자 초과를 받아들였습니다")
	}
}
