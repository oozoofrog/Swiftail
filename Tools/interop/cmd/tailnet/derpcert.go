// The certificate format used by selfSignedIPCert comes from `createSelfSignedIPCert` in tailscale.com v1.104.6 `cmd/derper/cert.go` (the self-signed certificate that derper's manual certificate
// mode creates for IP addresses). Copyright (c) Tailscale Inc & contributors. BSD-3-Clause.

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

	"tailscale.com/derp/derpconst"
	"tailscale.com/derp/derpserver"
	"tailscale.com/types/key"
)

// selfSignedIPCert creates a certificate with the same format that derper's manual certificate mode uses for an IP address hostname.
// derper sets its validity to 1 year from now. The fixtures (certificateFixtures) set fixed dates.
func selfSignedIPCert(ip net.IP, notBefore, notAfter time.Time) (tls.Certificate, error) {
	template, priv, err := selfSignedTemplate(ip.String(), notBefore, notAfter)
	if err != nil {
		return tls.Certificate{}, err
	}
	template.IPAddresses = []net.IP{ip}
	return createCertificate(template, template, &priv.PublicKey, priv, priv)
}

// selfSignedTemplate is the createSelfSignedIPCert template with only the SAN removed.
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

// certSHA256 is the value after `sha256-raw:` in a DERPNode `CertName` (same `%02x` as derper, 64 lowercase digits).
func certSHA256(der []byte) string {
	return fmt.Sprintf("%02x", sha256.Sum256(der))
}

// derpCertificateMode holds the DERP server certificate changed by `setDERPCertificate`.
type derpCertificateMode struct {
	// The config's GetCertificate appends the meta certificate with `ModifyTLSConfigToAddMetaCert`, as derper does.
	config    *tls.Config
	certName  string
	presented int
}

// newPinnedDERPCertificate creates a server certificate matching derper's IP address manual certificate mode and the `CertName` to advertise in the DERPMap.
// If wrong is set, it advertises the hash of the meta certificate that the server actually serves (which does not match the non-meta certificate).
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

// newLeafNotFirstDERPCertificate builds a list that impersonates the pinned server without its certificate's key. It serves a certificate with CN `derpkey…`
// made with its own key first (where TLS proves key possession), then appends the publicly available pinned certificate. `CertName` is the hash
// of that pinned certificate. The Go client accepts this list (`tlsdial.SetConfigExpectedCertHash` ignores position).
func newLeafNotFirstDERPCertificate(ip net.IP) (*derpCertificateMode, error) {
	now := time.Now()
	pinned, err := selfSignedIPCert(ip, now, now.AddDate(1, 0, 0))
	if err != nil {
		return nil, err
	}
	template, priv, err := selfSignedTemplate(derpconst.MetaCertCommonNamePrefix+"00", now, now.AddDate(1, 0, 0))
	if err != nil {
		return nil, err
	}
	front, err := createCertificate(template, template, &priv.PublicKey, priv, priv)
	if err != nil {
		return nil, err
	}
	front.Certificate = append(front.Certificate, pinned.Certificate[0])
	return &derpCertificateMode{
		config:    &tls.Config{NextProtos: []string{"http/1.1"}, Certificates: []tls.Certificate{front}},
		certName:  "sha256-raw:" + certSHA256(pinned.Certificate[0]),
		presented: len(front.Certificate),
	}, nil
}

// derpTLSConfig is GetConfigForClient for the DERP TLS server. It is called for every ClientHello, so count them and record SNI here. Outside pinned mode,
// return nil to use httptest's default certificate. (`GetCertificate` is skipped when `Certificates` is populated and SNI is absent.
// httptest populates `Certificates`, so that hook would miss clients connecting by IP.)
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

// setDERPCertificate makes the DERP node advertise `CertName: sha256-raw:<hash>` instead of `InsecureForTests` before the first control request.
func (n *network) setDERPCertificate(c command) (map[string]any, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.started {
		return nil, errors.New("the DERP certificate can only be changed before the first control request")
	}
	node := n.control.DERPMap.Regions[1].Nodes[0]
	var mode *derpCertificateMode
	var err error
	switch c.Mode {
	case "pinned", "wrongPin":
		mode, err = newPinnedDERPCertificate(n.derp, net.IPv4(127, 0, 0, 1), c.Mode == "wrongPin")
	case "leafNotFirst":
		mode, err = newLeafNotFirstDERPCertificate(net.IPv4(127, 0, 0, 1))
	case "named":
		// The server still uses httptest's default self-signed certificate. If `CertName` differs from `HostName`, even with `InsecureForTests`
		// the client verifies that name using the system trust store (Go `tlsClient`), so the connection must fail.
		node.CertName = "derp-cert.example.test"
		return map[string]any{"event": "derpCertificate", "mode": c.Mode, "certName": node.CertName, "presented": 1}, nil
	case "dottedHostName":
		// A name with a trailing dot. Go strips the dot for SNI (`crypto/tls` `hostnameInSNI`). It dials the address in `IPv4`.
		node.HostName = "localhost."
		return map[string]any{"event": "derpCertificate", "mode": c.Mode, "certName": "", "presented": 1}, nil
	default:
		return nil, errors.New("mode must be one of pinned, wrongPin, leafNotFirst, named, or dottedHostName")
	}
	if err != nil {
		return nil, err
	}
	n.derpCertMode = mode
	node.InsecureForTests = false
	node.CertName = mode.certName
	return map[string]any{"event": "derpCertificate", "mode": c.Mode, "certName": mode.certName, "presented": mode.presented}, nil
}

// certificateFixtures generates the certificates in `Tests/SwiftailIOTests/ServerCertificateFixtures.swift` (README "Certificate fixtures").
// Random signatures and keys make the bytes differ on each run. The dates are fixed.
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
	// A meta certificate from the actual derpserver. Valid for ±30 days from creation (pin verification ignores meta certificates).
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

// reviewFixtures generates the certificates in `Tests/SwiftailIOTests/ServerCertificateReviewTests.swift`, where the Go client
// (`tlsdial.SetConfigExpectedCertHash`) and Swiftail reach different verdicts. All are self-signed for `derp1a.example.test`
// and differ from `selfSignedTemplate` only as noted.
func reviewFixtures(notBefore, notAfter time.Time) (map[string][]byte, error) {
	_, edKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	// `derpkey00` with the subject CN encoded as VisibleString (tag 26). Go's x509 does not read a CN of this string type, so CommonName is empty
	// (it is not a meta certificate). The Security framework reads it as `derpkey00`.
	visibleCN, err := asn1.Marshal(pkix.RDNSequence{{{
		Type: asn1.ObjectIdentifier{2, 5, 4, 3}, Value: asn1.RawValue{Tag: 26, Bytes: []byte("derpkey00")},
	}}})
	if err != nil {
		return nil, err
	}
	out := map[string][]byte{}
	for name, shape := range map[string]struct {
		mutate func(*x509.Certificate)
		key    crypto.Signer // P-256 if nil
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
