package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/netip"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"tailscale.com/envknob"
	"tailscale.com/ipn/ipnstate"
)

func TestTailnet(t *testing.T) {
	t.Setenv("TS_NO_LOGS_NO_SUPPORT", "true")
	n, err := newNetwork()
	if err != nil {
		t.Fatal(err)
	}
	defer n.close()
	a, err := n.execute(command{Cmd: "addPeer", Name: "peer-a"})
	if err != nil {
		t.Fatal(err)
	}
	b, err := n.execute(command{Cmd: "addPeer", Name: "peer-b"})
	if err != nil {
		t.Fatal(err)
	}
	nodes, err := n.execute(command{Cmd: "nodes"})
	if err != nil || len(nodes["nodes"].([]any)) != 2 {
		t.Fatalf("nodes: %v %v", nodes, err)
	}
	deadline := time.Now().Add(30 * time.Second)
	for {
		s, e := n.execute(command{Cmd: "peerStatus", Name: "peer-a"})
		if e == nil && len(s["peers"].([]any)) == 1 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("peerStatus: %v %v", s, e)
		}
		time.Sleep(100 * time.Millisecond)
	}
	for _, name := range []string{"peer-a", "peer-b"} {
		s, e := n.execute(command{Cmd: "peerStatus", Name: name})
		if e != nil || len(s["peers"].([]any)) != 1 {
			t.Fatalf("peerStatus: %v %v", s, e)
		}
	}
	addr := b["addresses"].([]netip.Addr)[0].String()
	ping, err := n.execute(command{Cmd: "peerPing", Name: "peer-a", To: addr, Type: "TSMP"})
	if err != nil {
		t.Fatal(err)
	}
	if ping["result"].(*ipnstate.PingResult).Err != "" {
		t.Fatalf("ping: %v", ping)
	}
	for _, ip := range b["addresses"].([]netip.Addr) {
		for _, proto := range []string{"udp", "tcp"} {
			r, e := n.execute(command{Cmd: "peerSend", Name: "peer-a", To: ip.String(), Port: 7, Proto: proto, Payload: "010203"})
			if e != nil || r["sent"] != true || r["error"] != "" || r["attempted"] != true {
				t.Fatalf("peerSend %s %s: %v %v", ip, proto, r, e)
			}
		}
	}
	refused, err := n.execute(command{Cmd: "peerSend", Name: "peer-a", To: addr, Port: 42099, Proto: "tcp"})
	if err != nil || refused["sent"] != false || refused["error"] == "" {
		t.Fatalf("closed TCP port: %v %v", refused, err)
	}
	deadline = time.Now().Add(30 * time.Second)
	for {
		status, err := n.execute(command{Cmd: "peerStatus", Name: "peer-a"})
		if err != nil {
			t.Fatal(err)
		}
		p := status["peers"].([]any)[0].(map[string]any)
		if active, ok := p["active"].(bool); !ok || !active {
			t.Fatal("sending peer's active is not true")
		}
		if lastWrite, ok := p["lastWrite"].(time.Time); !ok || lastWrite.IsZero() || lastWrite.After(time.Now()) {
			t.Fatal("sending peer's lastWrite is not a valid time in the past")
		}
		selfAddrs := status["selfAddrs"].([]string)
		nodes, err := n.execute(command{Cmd: "nodes"})
		if err != nil {
			t.Fatal(err)
		}
		found := false
		for _, value := range nodes["nodes"].([]any) {
			node := value.(map[string]any)
			if node["nodeKey"] != a["nodeKey"] {
				continue
			}
			for _, endpoint := range node["endpoints"].([]netip.AddrPort) {
				if endpoint.Addr().IsLoopback() && endpoint.Port() != 0 && slices.Contains(selfAddrs, endpoint.String()) {
					found = true
				}
			}
		}
		if found {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("could not find a common loopback endpoint in selfAddrs and the control server endpoints")
		}
		time.Sleep(100 * time.Millisecond)
	}
	dir := n.peers["peer-a"].dir
	_, err = n.execute(command{Cmd: "removePeer", Name: "peer-a"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = os.Stat(dir); !os.IsNotExist(err) {
		t.Fatalf("temporary directory was left behind: %v", err)
	}
	if n.peers["peer-a"] != nil {
		t.Fatal("peers were left behind")
	}
}

func TestSetNeverDirectUDP(t *testing.T) {
	envknob.SetenvForTest(t, "TS_DEBUG_NEVER_DIRECT_UDP", "false")
	read := envknob.RegisterBool("TS_DEBUG_NEVER_DIRECT_UDP")
	n := &network{}
	for _, enabled := range []bool{true, false, true, false} {
		result, err := n.execute(command{Cmd: "setNeverDirectUDP", Enabled: &enabled})
		if err != nil {
			t.Fatal(err)
		}
		if result["event"] != "neverDirectUDP" || result["enabled"] != enabled || read() != enabled {
			t.Fatalf("knob toggle: response %v, cached value %v", result, read())
		}
	}
	if _, err := n.execute(command{Cmd: "setNeverDirectUDP"}); err == nil || read() {
		t.Fatal("missing enabled must be rejected without changing state")
	}
}

func TestSetNeverDirectUDPJSON(t *testing.T) {
	envknob.SetenvForTest(t, "TS_DEBUG_NEVER_DIRECT_UDP", "false")
	input := strings.NewReader(`{"id":{"step":1},"cmd":"setNeverDirectUDP","enabled":true}
{"id":"off","cmd":"setNeverDirectUDP","enabled":false}
{"id":3,"cmd":"setNeverDirectUDP"}
{"id":4,"cmd":"setNeverDirectUDP","enabled":null}
{"id":5,"cmd":"setNeverDirectUDP","enabled":"true"}
{"id":6,"cmd":"setNeverDirectUDP","enabled":1}
{"cmd":"setNeverDirectUDP","enabled":true}
{"id":null,"cmd":"setNeverDirectUDP","enabled":true}
{"id":9,"cmd":"quit"}
`)
	var output bytes.Buffer
	if err := run(input, &output); err != nil {
		t.Fatal(err)
	}
	decoder := json.NewDecoder(&output)
	for i, want := range []struct {
		event string
		id    string
	}{
		{"ready", ""},
		{"neverDirectUDP", `{"step":1}`},
		{"neverDirectUDP", `"off"`},
		{"error", "3"},
		{"error", "4"},
		{"error", "5"},
		{"error", "6"},
		{"error", ""},
		{"error", "null"},
		{"quit", "9"},
	} {
		var result struct {
			Event   string          `json:"event"`
			ID      json.RawMessage `json:"id"`
			Enabled *bool           `json:"enabled"`
			Message string          `json:"message"`
		}
		if err := decoder.Decode(&result); err != nil {
			t.Fatal(err)
		}
		if result.Event != want.event || string(result.ID) != want.id {
			t.Fatalf("response %d: event=%s id=%s", i, result.Event, result.ID)
		}
		if want.event == "neverDirectUDP" && (result.Enabled == nil || *result.Enabled != (i == 1)) {
			t.Fatalf("response %d: enabled differs from the request", i)
		}
		if want.event == "error" && result.Message == "" {
			t.Fatalf("response %d: no error description", i)
		}
	}
	if envknob.RegisterBool("TS_DEBUG_NEVER_DIRECT_UDP")() {
		t.Fatal("an invalid request changed the knob")
	}
}

func TestNeverDirectUDPLeavesUDPData(t *testing.T) {
	envknob.SetenvForTest(t, "TS_DEBUG_NEVER_DIRECT_UDP", "false")
	n, err := newNetwork()
	if err != nil {
		t.Fatal(err)
	}
	defer n.close()
	for _, name := range []string{"peer-a", "peer-b"} {
		if _, err := n.execute(command{Cmd: "addPeer", Name: name}); err != nil {
			t.Fatal(err)
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	lc, err := n.peers["peer-b"].server.LocalClient()
	if err != nil {
		t.Fatal(err)
	}
	status, err := lc.Status(ctx)
	if err != nil {
		t.Fatal(err)
	}
	to := netip.AddrPortFrom(status.TailscaleIPs[0], 7).String()
	conn, err := n.peers["peer-a"].server.Dial(ctx, "udp", to)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	echo := func() {
		t.Helper()
		if err := conn.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
			t.Fatal(err)
		}
		payload := []byte{1, 2, 3}
		if _, err := conn.Write(payload); err != nil {
			t.Fatal(err)
		}
		var got [3]byte
		if _, err := io.ReadFull(conn, got[:]); err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(payload, got[:]) {
			t.Fatal("UDP echo differs from the original")
		}
	}
	waitPath := func(direct bool) {
		t.Helper()
		deadline := time.Now().Add(15 * time.Second)
		for {
			echo()
			matched := true
			for _, name := range []string{"peer-a", "peer-b"} {
				r, err := n.execute(command{Cmd: "peerStatus", Name: name})
				if err != nil {
					t.Fatal(err)
				}
				peers := r["peers"].([]any)
				if len(peers) != 1 || (peers[0].(map[string]any)["curAddr"] != "") != direct {
					matched = false
				}
			}
			if matched {
				return
			}
			if time.Now().After(deadline) {
				t.Fatalf("both peers did not reach direct=%v within 15 seconds", direct)
			}
			time.Sleep(100 * time.Millisecond)
		}
	}
	waitPath(true)
	enabled := true
	if _, err := n.execute(command{Cmd: "setNeverDirectUDP", Enabled: &enabled}); err != nil {
		t.Fatal(err)
	}
	waitPath(false)
	// Close the DERP server and listener so the UDP echo cannot succeed through a relay.
	n.derp.Close()
	n.derpHTTP.Close()
	for range 3 {
		echo()
	}
}

func TestPeerSendRejectsInvalidInput(t *testing.T) {
	n := &network{peers: map[string]*peer{"peer-a": {}}}
	for _, change := range []func(*command){
		func(c *command) { c.Name = "missing" },
		func(c *command) { c.To = "invalid" },
		func(c *command) { c.To = "fe80::1%lo0" },
		func(c *command) { c.Port = 0 },
		func(c *command) { c.Port = 65536 },
		func(c *command) { c.Proto = "icmp" },
		func(c *command) { c.Payload = "0" },
		func(c *command) { c.Payload = "xx" },
		func(c *command) { c.Payload = strings.Repeat("00", 65508) },
	} {
		c := command{Cmd: "peerSend", Name: "peer-a", To: "100.64.0.2", Port: 7, Proto: "udp", Payload: "00"}
		change(&c)
		if _, err := n.execute(c); err == nil {
			t.Fatal("invalid peerSend input was not rejected")
		}
	}
}

func TestInspectCapturedPacket(t *testing.T) {
	ipv4 := make([]byte, 28)
	ipv4[0], ipv4[9] = 0x45, 17
	copy(ipv4[16:20], []byte{100, 100, 100, 100})
	ipv4[20], ipv4[21] = 0xa8, 0x02
	ipv6 := make([]byte, 48)
	ipv6[0], ipv6[6] = 0x60, 17
	copy(ipv6[24:40], netip.MustParseAddr("fd7a:115c:a1e0::53").AsSlice())
	ipv6[40], ipv6[41] = 0xa8, 0x02
	for _, ip := range [][]byte{ipv4, ipv6} {
		service, port, err := inspectCapturedPacket(append([]byte{1, 0, 0, 0}, ip...))
		if err != nil || !service || port != 43010 {
			t.Fatal("failed to parse the service packet or UDP port")
		}
	}
	normal := append([]byte(nil), ipv4...)
	copy(normal[16:20], []byte{100, 64, 0, 2})
	service, port, err := inspectCapturedPacket(append([]byte{1, 0, 0, 0}, normal...))
	if err != nil || service || port != 43010 {
		t.Fatal("ordinary UDP positive control failed")
	}
	for _, data := range [][]byte{nil, {1, 0, 0}, {1, 0, 16, 0}, {1, 0, 1, 0}, {1, 0, 0, 0, 0x45}} {
		if _, _, err := inspectCapturedPacket(data); err == nil {
			t.Fatal("accepted a short or invalid boundary")
		}
	}
}

func TestMagicDNSAndNetworkCounters(t *testing.T) {
	n, err := newNetwork()
	if err != nil {
		t.Fatal(err)
	}
	defer n.close()
	enabled := true
	result, err := n.execute(command{Cmd: "setMagicDNS", Enabled: &enabled})
	if err != nil || result["enabled"] != true || n.control.DNSConfig == nil || !n.control.DNSConfig.Proxied {
		t.Fatal("MagicDNS configuration failed")
	}
	if _, err := n.execute(command{Cmd: "setMagicDNS"}); err == nil {
		t.Fatal("allowed a missing bool")
	}
	n.started = true
	enabled = false
	if _, err := n.execute(command{Cmd: "setMagicDNS", Enabled: &enabled}); err == nil || !n.control.DNSConfig.Proxied {
		t.Fatal("allowed a DNS change after registration")
	}
	result, err = n.execute(command{Cmd: "networkStatus"})
	if err != nil || result["controlConnections"] != 0 || result["derpConnections"] != 0 || result["stunRequests"] != 0 {
		t.Fatal("invalid initial connection count")
	}
}
