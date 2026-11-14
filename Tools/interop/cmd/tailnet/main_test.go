package main

import (
	"net/netip"
	"os"
	"strings"
	"tailscale.com/ipn/ipnstate"
	"testing"
	"time"
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
		t.Fatalf("닫힌 TCP 포트: %v %v", refused, err)
	}
	dir := n.peers["peer-a"].dir
	_, err = n.execute(command{Cmd: "removePeer", Name: "peer-a"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = os.Stat(dir); !os.IsNotExist(err) {
		t.Fatalf("임시 디렉터리가 남았습니다: %v", err)
	}
	if n.peers["peer-a"] != nil {
		t.Fatal("피어가 남았습니다")
	}
	_ = a
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
			t.Fatal("잘못된 peerSend 입력을 거절하지 않았습니다")
		}
	}
}
