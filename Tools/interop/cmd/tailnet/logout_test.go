package main

import (
	"context"
	"testing"
	"time"

	"tailscale.com/tsnet"
)

// TestPeerLogout checks what request a Go peer's logout (lc.Logout) sends to testcontrol and what it changes:
// The request's Expiry is Unix 123 seconds and its node key stays the same. The node's KeyExpiry on the server becomes that timestamp,
// and the node remains in the other peer's netmap with KeyExpiry set to that timestamp. Restarting with the same state directory creates a new node with a new node key.
func TestPeerLogout(t *testing.T) {
	t.Setenv("TS_NO_LOGS_NO_SUPPORT", "true")
	n, err := newNetwork()
	if err != nil {
		t.Fatal(err)
	}
	defer n.close()
	if _, err := n.execute(command{Cmd: "addPeer", Name: "peer-a"}); err != nil {
		t.Fatal(err)
	}
	b, err := n.execute(command{Cmd: "addPeer", Name: "peer-b"})
	if err != nil {
		t.Fatal(err)
	}
	nodeKey := b["nodeKey"].(string)

	out, err := n.execute(command{Cmd: "peerLogout", Name: "peer-b"})
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("peer-b BackendState after logout: %v", out["backendState"])

	var logout map[string]any
	for _, r := range n.lockRegistrations()["registrations"].([]any) {
		if r := r.(map[string]any); r["nodeKey"] == nodeKey && r["expiryUnix"] != int64(0) {
			logout = r
		}
	}
	if logout == nil || logout["expiryUnix"] != int64(123) {
		t.Fatalf("missing logout request or Expiry is not Unix 123 seconds: %v", logout)
	}
	t.Logf("Go logout request: expiry=%q auth=%v oldNodeKey=%q nlKey present=%v signature=%v",
		logout["expiry"], logout["auth"], logout["oldNodeKey"], logout["nlKey"] != "", logout["signature"])

	nodes, err := n.execute(command{Cmd: "nodes"})
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, v := range nodes["nodes"].([]any) {
		if v := v.(map[string]any); v["nodeKey"] == nodeKey {
			found = true
			if v["keyExpiry"] != "1970-01-01T00:02:03Z" {
				t.Fatalf("server keyExpiry: %v", v["keyExpiry"])
			}
		}
	}
	if !found {
		t.Fatal("logged-out node disappeared from the server list")
	}

	deadline := time.Now().Add(30 * time.Second)
	for {
		s, err := n.execute(command{Cmd: "peerStatus", Name: "peer-a"})
		if err != nil {
			t.Fatal(err)
		}
		var seen map[string]any
		for _, p := range s["peers"].([]any) {
			if p := p.(map[string]any); p["nodeKey"] == nodeKey && p["keyExpiry"] == "1970-01-01T00:02:03Z" {
				seen = p
			}
		}
		if seen != nil {
			// Go receives the KeyExpiry change as a delta and computes Expired only in a full netmap (ipnlocal/local.go flagExpiredPeers).
			t.Logf("peer-b as seen by peer-a: keyExpiry=%v expired=%v online=%v", seen["keyExpiry"], seen["expired"], seen["online"])
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("peer-b's KeyExpiry did not change in peer-a's netmap: %v", s)
		}
		time.Sleep(100 * time.Millisecond)
	}

	// Restart with the same state directory (Go deleted the profile at logout).
	p := n.peers["peer-b"]
	if err := p.server.Close(); err != nil {
		t.Fatal(err)
	}
	p.stopped = true
	again := &tsnet.Server{Dir: p.dir, Hostname: "peer-b", ControlURL: n.control.ExplicitBaseURL, AuthKey: n.authKey, UserLogf: func(string, ...any) {}}
	defer again.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	st, err := again.Up(ctx)
	if err != nil {
		t.Fatalf("could not restart with the same directory: %v", err)
	}
	if st.Self.PublicKey.String() == nodeKey {
		t.Fatal("restarted Go peer reused the logged-out node key")
	}
	nodes, err = n.execute(command{Cmd: "nodes"})
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("after restart, server has %d nodes, new name %q", len(nodes["nodes"].([]any)), st.Self.DNSName)
}
