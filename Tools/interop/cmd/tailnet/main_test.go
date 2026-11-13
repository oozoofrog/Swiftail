package main

import (
	"net/netip"
	"os"
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
