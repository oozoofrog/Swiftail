package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"io"
	"log"
	"math/big"
	"net"
	"net/http/httptest"
	"os"
	"strconv"
	"time"

	"github.com/letsencrypt/challtestsrv"
	"github.com/letsencrypt/pebble/v2/ca"
	"github.com/letsencrypt/pebble/v2/db"
	"github.com/letsencrypt/pebble/v2/va"
	"github.com/letsencrypt/pebble/v2/wfe"
	"github.com/miekg/dns"
)

type acmeServer struct {
	http       *httptest.Server
	challenge  *challtestsrv.ChallSrv
	rootPEM    string
	dnsAddress string
}

func (a *acmeServer) close() { a.http.Close(); a.challenge.Shutdown() }

func (n *network) startACME(c command) (map[string]any, error) {
	nonce, reuse := 0, 0
	if c.NonceReject != nil {
		nonce = *c.NonceReject
	}
	if c.AuthzReuse != nil {
		reuse = *c.AuthzReuse
	}
	if nonce < 0 || nonce > 100 || reuse < 0 || reuse > 100 || c.ValidationDelaySec < 0 || c.ValidationDelaySec > 60 {
		return nil, errors.New("nonceReject·authzReuse는 0…100, validationDelaySec는 0…60입니다")
	}
	n.mu.Lock()
	exists := n.host.acme != nil
	n.mu.Unlock()
	if exists {
		return nil, errors.New("ACME 서버는 한 번만 시작합니다")
	}
	// pebble 생성자가 읽는 설정만 잠시 바꾸고 복원한다. 도구의 명령 처리는 직렬이다.
	env := map[string]string{"PEBBLE_WFE_NONCEREJECT": strconv.Itoa(nonce), "PEBBLE_AUTHZREUSE": strconv.Itoa(reuse), "PEBBLE_VA_ALWAYS_VALID": "0", "PEBBLE_VA_NOSLEEP": "1", "PEBBLE_VA_SLEEPTIME": strconv.Itoa(c.ValidationDelaySec)}
	if c.ValidationDelaySec > 0 {
		env["PEBBLE_VA_NOSLEEP"] = "0"
	}
	for k, v := range env {
		old, ok := os.LookupEnv(k)
		os.Setenv(k, v)
		defer func() {
			if ok {
				os.Setenv(k, old)
			} else {
				os.Unsetenv(k)
			}
		}()
	}
	quiet := log.New(io.Discard, "", 0)
	// challtestsrv는 미리 연 소켓을 받지 않으므로 TCP·UDP 모두 빈 같은 포트를 골라 시작 후 확인한다. OS가 고른 TCP 포트의
	// UDP 쪽을 다른 시험(STUN, 노드의 UDP 소켓)이 쓰고 있을 수 있으므로 그때는 다른 포트를 고른다.
	var listener net.Listener
	var udp net.PacketConn
	var address string
	var err error
	for attempt := 0; ; attempt++ {
		if listener, err = net.Listen("tcp4", "127.0.0.1:0"); err != nil {
			return nil, err
		}
		address = listener.Addr().String()
		if udp, err = net.ListenPacket("udp4", address); err == nil {
			break
		}
		listener.Close()
		if attempt == 19 {
			return nil, err
		}
	}
	challenge, err := challtestsrv.New(challtestsrv.Config{Log: quiet, DNSAddrs: []string{address}})
	if err != nil {
		udp.Close()
		listener.Close()
		return nil, err
	}
	udp.Close()
	listener.Close()
	challenge.Run()
	ok := false
	defer func() {
		if !ok {
			challenge.Shutdown()
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	probe := "_swiftail-ready.tail0001.test."
	challenge.AddDNSTXTRecord(probe, "ready")
	for _, protocol := range []string{"udp", "tcp"} {
		client := &dns.Client{Net: protocol, Timeout: 100 * time.Millisecond}
		for {
			msg := new(dns.Msg)
			msg.SetQuestion(probe, dns.TypeTXT)
			response, _, e := client.ExchangeContext(ctx, msg, address)
			if e == nil && len(response.Answer) == 1 {
				break
			}
			select {
			case <-ctx.Done():
				return nil, errors.New("challtestsrv DNS 시작 실패")
			case <-time.After(10 * time.Millisecond):
			}
		}
	}
	challenge.DeleteDNSTXTRecord(probe)
	store := db.NewMemoryStore()
	authority := ca.New(quiet, store, "", "rsa", 0, 1, map[string]ca.Profile{"default": {Description: "Swiftail 시험"}})
	validator := va.New(quiet, 0, 0, false, address, store)
	frontend := wfe.New(quiet, store, validator, authority, nil, false, false, 0, 0)
	root := authority.GetRootCert(0)
	// 디렉터리 HTTPS와 발급 사슬을 같은 시험 루트로 검증할 수 있게 한다. 키는 메모리에만 둔다.
	serverKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Swiftail 시험 ACME"}, IPAddresses: []net.IP{net.IPv4(127, 0, 0, 1)}, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(24 * time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, template, root.Cert, &serverKey.PublicKey, authority.GetRootKey(0))
	if err != nil {
		return nil, err
	}
	server := httptest.NewUnstartedServer(frontend.Handler())
	server.TLS = &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: serverKey}}}
	server.Config.ErrorLog = quiet
	server.StartTLS()
	a := &acmeServer{server, challenge, string(root.PEM()), address}
	n.mu.Lock()
	n.host.acme = a
	n.host.configured = true
	n.mu.Unlock()
	ok = true
	return map[string]any{"event": "acmeStart", "directoryURL": server.URL + wfe.DirectoryPath, "rootPEM": a.rootPEM, "dnsAddress": address, "nonceReject": nonce, "authzReuse": reuse, "validationDelaySec": c.ValidationDelaySec}, nil
}
