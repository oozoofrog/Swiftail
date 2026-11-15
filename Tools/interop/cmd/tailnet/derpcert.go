// selfSignedIPCert의 인증서 모양은 tailscale.com v1.104.6 `cmd/derper/cert.go`의 `createSelfSignedIPCert`(derper의 수동 인증서
// 모드가 IP 주소용으로 만드는 자체 서명 인증서)를 옮겼다. Copyright (c) Tailscale Inc & contributors. BSD-3-Clause.

package main

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"time"

	"tailscale.com/derp/derpserver"
	"tailscale.com/types/key"
)

// selfSignedIPCert는 derper의 수동 인증서 모드가 IP 주소 hostname에 만드는 인증서와 같은 모양의 인증서를 만든다.
// derper는 지금부터 1년을 쓴다. 고정값(certificateFixtures)은 날짜를 정해 넣는다.
func selfSignedIPCert(ip net.IP, notBefore, notAfter time.Time) (tls.Certificate, error) {
	template, priv, err := selfSignedTemplate(ip.String(), notBefore, notAfter)
	if err != nil {
		return tls.Certificate{}, err
	}
	template.IPAddresses = []net.IP{ip}
	return createCertificate(template, template, &priv.PublicKey, priv, priv)
}

// selfSignedTemplate은 createSelfSignedIPCert의 template에서 SAN만 뺀 것이다.
func selfSignedTemplate(commonName string, notBefore, notAfter time.Time) (*x509.Certificate, *ecdsa.PrivateKey, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, nil, err
	}
	return &x509.Certificate{
		SerialNumber:          serialNumber,
		Subject:               pkix.Name{CommonName: commonName},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}, priv, nil
}

func createCertificate(template, parent *x509.Certificate, pub, signer any, priv *ecdsa.PrivateKey) (tls.Certificate, error) {
	der, err := x509.CreateCertificate(rand.Reader, template, parent, pub, signer)
	if err != nil {
		return tls.Certificate{}, err
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: priv, Leaf: leaf}, nil
}

// certSHA256는 DERPNode `CertName`의 `sha256-raw:` 뒤에 쓰는 값이다(derper와 같은 `%02x`, 소문자 64자리).
func certSHA256(der []byte) string {
	return fmt.Sprintf("%02x", sha256.Sum256(der))
}

// derpCertificateMode는 `setDERPCertificate`가 바꾸는 DERP 서버의 인증서다.
type derpCertificateMode struct {
	// config의 GetCertificate는 derper처럼 `ModifyTLSConfigToAddMetaCert`로 meta 인증서를 덧붙인다.
	config    *tls.Config
	certName  string
	presented int
}

// newPinnedDERPCertificate는 derper의 IP 주소 수동 인증서 모드와 같은 서버 인증서와, DERPMap에 알릴 `CertName`을 만든다.
// wrong이면 그 서버가 실제로 내는 meta 인증서의 해시를 알린다(meta가 아닌 인증서와는 맞지 않는다).
func newPinnedDERPCertificate(server *derpserver.Server, ip net.IP, wrong bool) (*derpCertificateMode, error) {
	now := time.Now()
	cert, err := selfSignedIPCert(ip, now, now.AddDate(1, 0, 0))
	if err != nil {
		return nil, err
	}
	config := &tls.Config{
		NextProtos:     []string{"http/1.1"},
		GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) { return &cert, nil },
	}
	server.ModifyTLSConfigToAddMetaCert(config)
	presented, err := config.GetCertificate(&tls.ClientHelloInfo{})
	if err != nil {
		return nil, err
	}
	pinned := cert.Certificate[0]
	if wrong {
		pinned = server.MetaCert()
	}
	return &derpCertificateMode{
		config:    config,
		certName:  "sha256-raw:" + certSHA256(pinned),
		presented: len(presented.Certificate),
	}, nil
}

// derpTLSConfig는 DERP TLS 서버의 GetConfigForClient다. ClientHello마다 불리므로 여기서 세고 SNI를 적는다. 고정 모드가
// 아니면 nil을 돌려 httptest의 기본 인증서를 쓴다. (`GetCertificate`는 `Certificates`가 있고 SNI가 없으면 불리지 않는다.
// httptest가 `Certificates`를 채우므로 그 자리에서는 IP로 붙는 클라이언트를 놓친다.)
func (n *network) derpTLSConfig(hi *tls.ClientHelloInfo) (*tls.Config, error) {
	n.mu.Lock()
	n.derpTLSHandshakes++
	n.derpServerNames[hi.ServerName] = true
	mode := n.derpCertMode
	n.mu.Unlock()
	if mode == nil {
		return nil, nil
	}
	return mode.config, nil
}

// setDERPCertificate는 첫 제어 요청 전에 DERP 노드를 `InsecureForTests` 대신 `CertName: sha256-raw:<해시>`로 알리게 한다.
func (n *network) setDERPCertificate(c command) (map[string]any, error) {
	if c.Mode != "pinned" && c.Mode != "wrongPin" {
		return nil, errors.New("mode는 pinned 또는 wrongPin이어야 합니다")
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.started {
		return nil, errors.New("DERP 인증서는 첫 제어 요청 전에만 바꿀 수 있습니다")
	}
	mode, err := newPinnedDERPCertificate(n.derp, net.IPv4(127, 0, 0, 1), c.Mode == "wrongPin")
	if err != nil {
		return nil, err
	}
	n.derpCertMode = mode
	node := n.control.DERPMap.Regions[1].Nodes[0]
	node.InsecureForTests = false
	node.CertName = mode.certName
	return map[string]any{"event": "derpCertificate", "mode": c.Mode, "certName": mode.certName, "presented": mode.presented}, nil
}

// certificateFixtures는 `Tests/SwiftailIOTests/ServerCertificateFixtures.swift`의 인증서를 만든다(README "인증서 고정값").
// 서명과 키가 난수라 실행마다 바이트가 다르다. 날짜는 고정한다.
func certificateFixtures(out io.Writer) error {
	notBefore := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	notAfter := time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC)
	ip := net.ParseIP("100.64.0.1")
	ipLeaf, err := selfSignedIPCert(ip, notBefore, notAfter)
	if err != nil {
		return err
	}
	otherIPLeaf, err := selfSignedIPCert(ip, notBefore, notAfter)
	if err != nil {
		return err
	}
	dnsTemplate, dnsKey, err := selfSignedTemplate("derp1a.example.test", notBefore, notAfter)
	if err != nil {
		return err
	}
	dnsTemplate.DNSNames = []string{"derp1a.example.test"}
	dnsLeaf, err := createCertificate(dnsTemplate, dnsTemplate, &dnsKey.PublicKey, dnsKey, dnsKey)
	if err != nil {
		return err
	}
	rootTemplate, rootKey, err := selfSignedTemplate("Swiftail Test Root", notBefore, notAfter)
	if err != nil {
		return err
	}
	rootTemplate.IsCA = true
	rootTemplate.KeyUsage = x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature
	rootTemplate.ExtKeyUsage = nil
	root, err := createCertificate(rootTemplate, rootTemplate, &rootKey.PublicKey, rootKey, rootKey)
	if err != nil {
		return err
	}
	namedTemplate, namedKey, err := selfSignedTemplate("derp-cert.example.test", notBefore, notAfter)
	if err != nil {
		return err
	}
	namedTemplate.DNSNames = []string{"derp-cert.example.test"}
	named, err := createCertificate(namedTemplate, root.Leaf, &namedKey.PublicKey, rootKey, namedKey)
	if err != nil {
		return err
	}
	// 실제 derpserver가 만드는 meta 인증서. 유효 기간은 만든 시각 ±30일이다(고정 검사는 meta 인증서를 보지 않는다).
	meta := derpserver.New(key.NewNode(), log.Printf).MetaCert()
	fixtures := map[string]string{}
	for name, der := range map[string][]byte{
		"ipLeaf": ipLeaf.Certificate[0], "otherIPLeaf": otherIPLeaf.Certificate[0], "dnsLeaf": dnsLeaf.Certificate[0],
		"root": root.Certificate[0], "namedLeaf": named.Certificate[0], "meta": meta,
	} {
		fixtures[name] = base64.StdEncoding.EncodeToString(der)
	}
	fixtures["ipLeafSHA256"] = certSHA256(ipLeaf.Certificate[0])
	fixtures["dnsLeafSHA256"] = certSHA256(dnsLeaf.Certificate[0])
	fixtures["metaSHA256"] = certSHA256(meta)
	review, err := reviewFixtures(notBefore, notAfter)
	if err != nil {
		return err
	}
	for name, der := range review {
		fixtures[name] = base64.StdEncoding.EncodeToString(der)
		fixtures[name+"SHA256"] = certSHA256(der)
	}
	encoder := json.NewEncoder(out)
	encoder.SetIndent("", "  ")
	return encoder.Encode(fixtures)
}

// reviewFixtures는 `Tests/SwiftailIOTests/ServerCertificateReviewTests.swift`의 인증서를 만든다: Go 클라이언트
// (`tlsdial.SetConfigExpectedCertHash`)와 Swiftail의 판정이 갈리는 모양들이다. 모두 `derp1a.example.test`의 자체 서명
// 인증서이고, 적은 것만 `selfSignedTemplate`과 다르다.
func reviewFixtures(notBefore, notAfter time.Time) (map[string][]byte, error) {
	_, edKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	// 주체 CN을 VisibleString(태그 26)으로 쓴 `derpkey00`. Go의 x509는 이 문자열 형을 CN으로 읽지 않아 CommonName이 비고
	// (meta 인증서가 아니다), Security 프레임워크는 `derpkey00`으로 읽는다.
	visibleCN, err := asn1.Marshal(pkix.RDNSequence{{{
		Type: asn1.ObjectIdentifier{2, 5, 4, 3}, Value: asn1.RawValue{Tag: 26, Bytes: []byte("derpkey00")},
	}}})
	if err != nil {
		return nil, err
	}
	out := map[string][]byte{}
	for name, shape := range map[string]struct {
		mutate func(*x509.Certificate)
		key    crypto.Signer // nil이면 P-256
	}{
		"longValidityLeaf":  {mutate: func(t *x509.Certificate) { t.NotAfter = notBefore.AddDate(10, 0, 0) }},
		"noEKULeaf":         {mutate: func(t *x509.Certificate) { t.ExtKeyUsage = nil }},
		"ed25519Leaf":       {mutate: func(t *x509.Certificate) { t.KeyUsage = x509.KeyUsageDigitalSignature }, key: edKey},
		"visibleStringMeta": {mutate: func(t *x509.Certificate) { t.RawSubject = visibleCN }},
	} {
		template, key, err := selfSignedTemplate("derp1a.example.test", notBefore, notAfter)
		if err != nil {
			return nil, err
		}
		template.DNSNames = []string{"derp1a.example.test"}
		shape.mutate(template)
		signer := crypto.Signer(key)
		if shape.key != nil {
			signer = shape.key
		}
		der, err := x509.CreateCertificate(rand.Reader, template, template, signer.Public(), signer)
		if err != nil {
			return nil, err
		}
		if _, err := x509.ParseCertificate(der); err != nil {
			return nil, err
		}
		out[name] = der
	}
	return out, nil
}
