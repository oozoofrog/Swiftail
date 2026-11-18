package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"net/netip"
	"os"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/acme"
	"tailscale.com/ipn/ipnstate"
	"tailscale.com/tailcfg"
	"tailscale.com/tsnet"
)

func TestHostTools(t *testing.T) {
	n, err := newNetwork()
	if err != nil {
		t.Fatal(err)
	}
	defer n.close()
	execute := func(c command) map[string]any {
		t.Helper()
		r, e := n.execute(c)
		if e != nil {
			t.Fatalf("%s: %v", c.Cmd, e)
		}
		return r
	}
	initial, latest := false, true
	execute(command{Cmd: "setDNSConfig", Enabled: &initial})
	execute(command{Cmd: "setMagicDNS", Enabled: &latest})
	nonce, reuse := 35, 100
	started := execute(command{Cmd: "acmeStart", NonceReject: &nonce, AuthzReuse: &reuse})
	if _, err := n.execute(command{Cmd: "acmeStart"}); err == nil {
		t.Fatal("duplicate ACME startup must be rejected")
	}
	a := execute(command{Cmd: "addPeer", Name: "peer-a"})
	b := execute(command{Cmd: "addPeer", Name: "peer-b"})
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	lc, err := n.peers["peer-b"].server.LocalClient()
	if err != nil {
		t.Fatal(err)
	}
	waitStatus := func(check func(*ipnstate.Status) bool) {
		t.Helper()
		deadline := time.Now().Add(10 * time.Second)
		for {
			st, e := lc.Status(ctx)
			if e == nil && check(st) {
				return
			}
			if time.Now().After(deadline) {
				t.Fatal("updated map did not arrive within 10 seconds")
			}
			time.Sleep(20 * time.Millisecond)
		}
	}
	domain := strings.TrimSuffix(b["fqdn"].(string), ".")
	waitStatus(func(s *ipnstate.Status) bool {
		return slices.Contains(s.CertDomains, domain) && s.CurrentTailnet.MagicDNSEnabled && len(s.Peer) == 1
	})
	for _, entry := range []map[string]any{a, b} {
		for _, ip := range entry["addresses"].([]netip.Addr) {
			who := execute(command{Cmd: "peerWhoIs", Name: "peer-b", To: ip.String()})
			original, e := lc.WhoIs(ctx, ip.String())
			if e != nil || who["stableID"] != original.Node.StableID || who["nodeName"] != strings.TrimSuffix(original.Node.Name, ".") || who["computedName"] != original.Node.ComputedName || who["loginName"] != original.UserProfile.LoginName {
				t.Fatal("WhoIs reference value mismatch")
			}
		}
	}
	empty := []string{}
	execute(command{Cmd: "setCertDomains", Domains: &empty})
	waitStatus(func(s *ipnstate.Status) bool { return len(s.CertDomains) == 0 })
	enabled := false
	execute(command{Cmd: "setDNSConfig", Enabled: &enabled})
	waitStatus(func(s *ipnstate.Status) bool { return !s.CurrentTailnet.MagicDNSEnabled })
	// Verify the priority of arbitrary per-node and global domains, and that an empty array clears even the automatic FQDN.
	custom := []string{"rd-mac-1a2b3c4d.tail0001.test"}
	execute(command{Cmd: "setCertDomains", NodeKey: b["nodeKey"].(string), Domains: &custom})
	waitStatus(func(s *ipnstate.Status) bool { return slices.Equal(s.CertDomains, custom) })
	if err := lc.SetDNS(ctx, "_acme-challenge."+custom[0], "custom-value"); err != nil {
		t.Fatal("set-dns for a per-node domain failed")
	}
	if err := lc.SetDNS(ctx, "_acme-challenge."+domain, "not-allowed"); err == nil {
		t.Fatal("allowed a domain outside the configuration")
	}
	domains := []string{domain}
	execute(command{Cmd: "setCertDomains", Domains: &domains})
	enabled = true
	execute(command{Cmd: "setDNSConfig", Enabled: &enabled})
	waitStatus(func(s *ipnstate.Status) bool {
		return slices.Equal(s.CertDomains, domains) && s.CurrentTailnet.MagicDNSEnabled
	})
	one := 1
	for _, fault := range []command{
		{Cmd: "setDNSFault", Count: &one, Status: 403},
		{Cmd: "setDNSFault", Count: &one, Body: "large"},
		{Cmd: "setDNSFault", Count: &one, Body: "null"},
		{Cmd: "setDNSFault", Count: &one, Body: "array"},
		{Cmd: "setDNSFault", Count: &one, Body: "scalar"},
		{Cmd: "setDNSFault", Count: &one, Body: "empty"},
	} {
		execute(fault)
		e := lc.SetDNS(ctx, "_acme-challenge."+domain, "fault-value")
		// Go accepts null and unknown object fields. Swift tests check Swift's object and 4KiB restrictions.
		wantError := fault.Status != 0 || fault.Body == "array" || fault.Body == "scalar" || fault.Body == "empty"
		if (e != nil) != wantError {
			t.Fatalf("unexpected result for set-dns fault %q with status %d", fault.Body, fault.Status)
		}
		if e := lc.SetDNS(ctx, "_acme-challenge."+domain, "after-fault"); e != nil {
			t.Fatal("normal operation did not resume after the fault count was exhausted")
		}
	}
	execute(command{Cmd: "setDNSFault", Count: &one, DelayMs: 500})
	short, shortCancel := context.WithTimeout(ctx, 50*time.Millisecond)
	if e := lc.SetDNS(short, "_acme-challenge."+domain, "delay-value"); e == nil {
		t.Fatal("delayed request did not exceed the deadline")
	}
	shortCancel()
	execute(command{Cmd: "setDNSFault", Count: &one, WrongTXT: true})
	if err := lc.SetDNS(ctx, "_acme-challenge."+domain, "original-value"); err != nil {
		t.Fatal(err)
	}
	if got := n.host.acme.challenge.GetDNSTXTRecords("_acme-challenge." + domain + "."); !slices.Equal(got, []string{"swiftail-invalid-txt"}) {
		t.Fatal("incorrect TXT fault was not reflected in DNS")
	}
	records := execute(command{Cmd: "setDNSLog"})["requests"].([]dnsRecord)
	if records[len(records)-1].Value != "original-value" || records[len(records)-1].Type != "TXT" || records[len(records)-1].NodeKeySummary == "" {
		t.Fatal("setDNSLog did not record the original request")
	}
	for i := 1; i < len(records); i++ {
		if records[i].Time.Before(records[i-1].Time) {
			t.Fatal("request log order changed")
		}
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM([]byte(started["rootPEM"].(string))) {
		t.Fatal("invalid root PEM")
	}
	transport := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}}
	defer transport.CloseIdleConnections()
	accountKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	client := &acme.Client{Key: accountKey, DirectoryURL: started["directoryURL"].(string), HTTPClient: &http.Client{Transport: transport}}
	if _, err := client.Register(ctx, &acme.Account{}, acme.AcceptTOS); err != nil {
		t.Fatal(err)
	}
	issue := func(failValidation bool) ([][]byte, *ecdsa.PrivateKey) {
		t.Helper()
		order, e := client.AuthorizeOrder(ctx, acme.DomainIDs(domain))
		if e != nil {
			t.Fatal(e)
		}
		for _, authURL := range order.AuthzURLs {
			auth, e := client.GetAuthorization(ctx, authURL)
			if e != nil {
				t.Fatal(e)
			}
			if auth.Status == acme.StatusValid {
				continue
			}
			var challenge *acme.Challenge
			for _, c := range auth.Challenges {
				if c.Type == "dns-01" {
					challenge = c
					break
				}
			}
			if challenge == nil {
				t.Fatal("dns-01 is missing")
			}
			value, e := client.DNS01ChallengeRecord(challenge.Token)
			if e != nil {
				t.Fatal(e)
			}
			if failValidation {
				execute(command{Cmd: "setDNSFault", Count: &one, WrongTXT: true})
			}
			if e = lc.SetDNS(ctx, "_acme-challenge."+domain, value); e != nil {
				t.Fatal(e)
			}
			if _, e = client.Accept(ctx, challenge); e != nil {
				t.Fatal(e)
			}
		}
		order, e = client.WaitOrder(ctx, order.URI)
		if failValidation {
			var orderError *acme.OrderError
			if !errors.As(e, &orderError) {
				t.Fatalf("order with incorrect TXT must end as invalid: %v", e)
			}
			return nil, nil
		}
		if e != nil {
			t.Fatal(e)
		}
		certKey, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if e != nil {
			t.Fatal(e)
		}
		csr, e := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: domain}, DNSNames: []string{domain}}, certKey)
		if e != nil {
			t.Fatal(e)
		}
		chain, _, e := client.CreateCertFromOrder(ctx, order, csr, true)
		if e != nil {
			t.Fatal(e)
		}
		leaf, e := x509.ParseCertificate(chain[0])
		if e != nil {
			t.Fatal(e)
		}
		intermediates := x509.NewCertPool()
		for _, der := range chain[1:] {
			cert, e := x509.ParseCertificate(der)
			if e != nil {
				t.Fatal(e)
			}
			intermediates.AddCert(cert)
		}
		if _, e = leaf.Verify(x509.VerifyOptions{Roots: roots, Intermediates: intermediates, DNSName: domain}); e != nil {
			t.Fatal(e)
		}
		return chain, certKey
	}
	issue(true)
	chain, certKey := issue(false)
	before := len(execute(command{Cmd: "setDNSLog"})["requests"].([]dnsRecord))
	issue(false)
	if after := len(execute(command{Cmd: "setDNSLog"})["requests"].([]dnsRecord)); before != after {
		t.Fatal("authorization reuse sent a new TXT request")
	}
	listener, err := n.peers["peer-b"].server.Listen("tcp", ":9443")
	if err != nil {
		t.Fatal(err)
	}
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "POST" {
			h := sha256.New()
			size, e := io.Copy(h, r.Body)
			if e != nil {
				return
			}
			w.Header().Set("X-Request-Length", strconv.FormatInt(size, 10))
			w.Header().Set("X-Request-SHA256", hex.EncodeToString(h.Sum(nil)))
			return
		}
		size := int64(100 << 20)
		if r.Header.Get("Range") == "bytes=0-52428799" {
			size = 50 << 20
			w.Header().Set("Content-Range", "bytes 0-52428799/104857600")
			w.WriteHeader(206)
		}
		io.CopyN(w, newStream(1), size)
	})
	server := &http.Server{Handler: handler, ErrorLog: log.New(io.Discard, "", 0)}
	defer server.Close()
	done := make(chan struct{})
	go func() {
		defer close(done)
		server.Serve(tls.NewListener(listener, &tls.Config{Certificates: []tls.Certificate{{Certificate: chain, PrivateKey: certKey}}, MinVersion: tls.VersionTLS12}))
	}()
	defer func() { server.Close(); <-done }()
	timeout := 60
	result := execute(command{Cmd: "peerHTTP", Name: "peer-a", URL: "https://" + domain + ":9443/ipa", Range: "bytes=0-52428799", TimeoutSec: &timeout})
	expected := sha256.New()
	io.CopyN(expected, newStream(1), 50<<20)
	if result["status"] != 206 || result["bodyLength"] != int64(50<<20) || result["bodySHA256"] != hex.EncodeToString(expected.Sum(nil)) {
		t.Fatal("HTTPS Range body mismatch")
	}
	send, seed := uint64(100<<20), uint64(1)
	result = execute(command{Cmd: "peerHTTP", Name: "peer-a", URL: "https://" + domain + ":9443/upload", Method: "POST", Send: &send, Seed: &seed, TimeoutSec: &timeout})
	expected.Reset()
	io.CopyN(expected, newStream(1), int64(send))
	headers := result["headers"].(http.Header)
	if headers.Get("X-Request-Length") != strconv.FormatInt(int64(send), 10) || headers.Get("X-Request-SHA256") != hex.EncodeToString(expected.Sum(nil)) {
		t.Fatal("HTTPS request body mismatch")
	}
	if _, e := n.execute(command{Cmd: "peerHTTP", Name: "peer-a", URL: "https://wrong.tail0001.test:9443/", To: b["addresses"].([]netip.Addr)[0].String()}); e == nil {
		t.Fatal("TLS server name mismatches must be rejected")
	}
	if _, e := n.execute(command{Cmd: "peerHTTP", Name: "peer-a", URL: "https://" + domain + ":9443/", RootPEM: "invalid"}); e == nil {
		t.Fatal("an incorrect trust root must be rejected")
	}
	plain, err := n.peers["peer-b"].server.Listen("tcp", ":9080")
	if err != nil {
		t.Fatal(err)
	}
	plainServer := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", "https://outside.invalid/")
		w.WriteHeader(302)
	})}
	plainDone := make(chan struct{})
	go func() { defer close(plainDone); plainServer.Serve(plain) }()
	defer func() { plainServer.Close(); <-plainDone }()
	result = execute(command{Cmd: "peerHTTP", Name: "peer-a", URL: "http://" + domain + ":9080/"})
	if result["status"] != 302 {
		t.Fatal("failed to block cleartext HTTP or redirects")
	}
	// M7 map updates must also stay out after manual injection to preserve the existing injectMapResponse contract.
	injected, err := json.Marshal(&tailcfg.MapResponse{DNSConfig: &tailcfg.DNSConfig{Proxied: true, CertDomains: custom}})
	if err != nil {
		t.Fatal(err)
	}
	execute(command{Cmd: "injectMapResponse", NodeKey: b["nodeKey"].(string), Response: injected})
	waitStatus(func(s *ipnstate.Status) bool { return slices.Equal(s.CertDomains, custom) })
	execute(command{Cmd: "setCertDomains", Domains: &empty})
	time.Sleep(150 * time.Millisecond)
	st, err := lc.Status(ctx)
	if err != nil || !slices.Equal(st.CertDomains, custom) {
		t.Fatal("M7 update overwrote the manually injected map")
	}
	state := execute(command{Cmd: "goState", Name: "peer-a"})
	directory := state["directory"].(string)
	if state["stopped"] != false {
		t.Fatal("peer stopped early")
	}
	execute(command{Cmd: "peerClose", Name: "peer-a", Stop: true})
	state = execute(command{Cmd: "goState", Name: "peer-a"})
	if state["stopped"] != true || state["directory"] != directory {
		t.Fatal("state directory changed after stopping")
	}
	if info, e := os.Stat(directory + "/tailscaled.state"); e != nil || info.Size() == 0 {
		t.Fatal("Go state file is missing")
	}
	restored := &tsnet.Server{Dir: directory, Hostname: "peer-a", ControlURL: n.control.ExplicitBaseURL, UserLogf: func(string, ...any) {}}
	restarted, e := restored.Up(ctx)
	if e != nil {
		restored.Close()
		t.Fatal("could not reconnect with saved state")
	}
	if restarted.Self.PublicKey.String() != a["nodeKey"] || !slices.Equal(restarted.TailscaleIPs, a["addresses"].([]netip.Addr)) || n.control.NumNodes() != 2 {
		restored.Close()
		t.Fatal("Go identity changed after reconnecting")
	}
	if e = restored.Close(); e != nil {
		t.Fatal(e)
	}
	execute(command{Cmd: "removePeer", Name: "peer-a"})
	if _, e := os.Stat(directory); !os.IsNotExist(e) {
		t.Fatal("removePeer did not delete state")
	}
}

func TestHostCommandValidation(t *testing.T) {
	n, err := newNetwork()
	if err != nil {
		t.Fatal(err)
	}
	defer n.close()
	invalid := []string{
		`{"cmd":"setCertDomains"}`, `{"cmd":"setCertDomains","domains":null}`, `{"cmd":"setCertDomains","domains":["bad..test"]}`, `{"cmd":"setCertDomains","domains":["-bad.test"]}`, `{"cmd":"setCertDomains","domains":[],"nodeKey":"bad"}`,
		`{"cmd":"setDNSConfig"}`, `{"cmd":"setDNSFault"}`, `{"cmd":"setDNSFault","count":-1}`, `{"cmd":"setDNSFault","count":1,"status":199}`, `{"cmd":"setDNSFault","count":1,"body":"unknown"}`, `{"cmd":"setDNSFault","count":1,"status":403,"wrongTXT":true}`,
		`{"cmd":"acmeStart","nonceReject":101}`, `{"cmd":"acmeStart","authzReuse":-1}`, `{"cmd":"acmeStart","validationDelaySec":61}`, `{"cmd":"peerWhoIs","name":"missing","to":"100.64.0.1"}`, `{"cmd":"peerHTTP","name":"missing","url":"https://outside.invalid/"}`, `{"cmd":"goState","name":"missing"}`,
	}
	for _, line := range invalid {
		var c command
		if err := json.Unmarshal([]byte(line), &c); err != nil {
			t.Fatal(err)
		}
		if _, err := n.execute(c); err == nil {
			t.Fatalf("received an invalid command: %s", line)
		}
	}
	zero := 0
	if _, err := n.execute(command{Cmd: "setDNSFault", Count: &zero}); err != nil {
		t.Fatal(err)
	}
}

func TestHostJSON(t *testing.T) {
	var out bytes.Buffer
	err := run(strings.NewReader(`{"id":{"step":1},"cmd":"setCertDomains","domains":[]}
{"id":2,"cmd":"setDNSConfig","enabled":false}
{"id":3,"cmd":"setDNSLog"}
{"id":4,"cmd":"setDNSFault","count":1,"wrongTXT":true}
{"id":5,"cmd":"quit"}
`), &out)
	if err != nil {
		t.Fatal(err)
	}
	decoder := json.NewDecoder(&out)
	for _, event := range []string{"ready", "certDomains", "dnsConfig", "setDNSLog", "setDNSFault", "quit"} {
		var value map[string]json.RawMessage
		if err := decoder.Decode(&value); err != nil {
			t.Fatal(err)
		}
		if string(value["event"]) != `"`+event+`"` {
			t.Fatal("JSON event mismatch")
		}
		if event == "certDomains" && (string(value["id"]) != `{"step":1}` || string(value["domains"]) != "[]") {
			t.Fatal("id or empty array format mismatch")
		}
		if event == "setDNSLog" && string(value["requests"]) != "[]" {
			t.Fatal("empty log array format mismatch")
		}
	}
}

func TestPeerHTTPConcurrentRemove(t *testing.T) {
	input, writeInput := io.Pipe()
	output, writeOutput := io.Pipe()
	runDone := make(chan error, 1)
	go func() { runDone <- run(input, writeOutput); writeOutput.Close() }()
	defer func() { writeInput.Close(); output.Close(); <-runDone }()
	decoder := json.NewDecoder(output)
	read := func() map[string]any {
		t.Helper()
		var r map[string]any
		if err := decoder.Decode(&r); err != nil {
			t.Fatal(err)
		}
		return r
	}
	ready := read()
	server := &tsnet.Server{Dir: t.TempDir(), Hostname: "peer-b", ControlURL: ready["controlURL"].(string), UserLogf: func(string, ...any) {}}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	state, err := server.Up(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	listener, err := server.Listen("tcp", ":9080")
	if err != nil {
		t.Fatal(err)
	}
	accepted := make(chan struct{})
	httpServer := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { close(accepted); <-r.Context().Done() })}
	serverDone := make(chan struct{})
	go func() { defer close(serverDone); httpServer.Serve(listener) }()
	defer func() { httpServer.Close(); <-serverDone }()
	encoder := json.NewEncoder(writeInput)
	send := func(value map[string]any) {
		t.Helper()
		if err := encoder.Encode(value); err != nil {
			t.Fatal(err)
		}
	}
	send(map[string]any{"id": 1, "cmd": "addPeer", "name": "peer-a"})
	if read()["event"] != "peer" {
		t.Fatal("peer failed to start")
	}
	send(map[string]any{"id": 2, "cmd": "peerHTTP", "name": "peer-a", "url": "http://" + state.TailscaleIPs[0].String() + ":9080/", "timeoutSec": 15})
	select {
	case <-accepted:
	case <-ctx.Done():
		t.Fatal("HTTP request did not reach the server")
	}
	send(map[string]any{"id": 3, "cmd": "removePeer", "name": "peer-a"})
	events := map[float64]string{}
	for len(events) < 2 {
		r := read()
		events[r["id"].(float64)] = r["event"].(string)
	}
	if events[2] != "error" || events[3] != "removed" {
		t.Fatal("unexpected responses for the in-flight HTTP request and peer removal")
	}
	send(map[string]any{"id": 4, "cmd": "quit"})
	if read()["event"] != "quit" {
		t.Fatal("quit response failed")
	}
}
