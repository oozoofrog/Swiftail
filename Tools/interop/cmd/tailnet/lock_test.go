package main

import (
	"context"
	"slices"
	"testing"
	"time"

	"tailscale.com/tailcfg"
	"tailscale.com/tailcfg/nodecap"
	"tailscale.com/tsnet"
	"tailscale.com/types/key"
)

// TestTailnetLock checks that the gate (a) flow works with Go tsnet peers alone
// (docs/contracts/SwiftailTailnetLock.md §7). This must pass before a failure with a Swift node
// can be attributed to the Swift side.
func TestTailnetLock(t *testing.T) {
	t.Setenv("TS_NO_LOGS_NO_SUPPORT", "true")
	n, err := newNetwork()
	if err != nil {
		t.Fatal(err)
	}
	defer n.close()
	run := func(c command) map[string]any {
		t.Helper()
		r, err := n.execute(c)
		if err != nil {
			t.Fatalf("%s: %v", c.Cmd, err)
		}
		return r
	}
	status := func(name string) map[string]any {
		t.Helper()
		return run(command{Cmd: "lockStatus", Name: name})
	}
	waitFor := func(what string, ok func() bool) {
		t.Helper()
		deadline := time.Now().Add(45 * time.Second)
		for !ok() {
			if time.Now().After(deadline) {
				t.Fatalf("timed out waiting for: %s", what)
			}
			time.Sleep(100 * time.Millisecond)
		}
	}
	has := func(r map[string]any, field, nodeKey string) bool {
		return slices.Contains(r[field].([]string), nodeKey)
	}
	tkaRequests := func(path, nodeKey string) int {
		count := 0
		for _, v := range run(command{Cmd: "lockRequests"})["requests"].([]any) {
			r := v.(map[string]any)
			if r["path"] == path && r["nodeKey"] == nodeKey {
				count++
			}
		}
		return count
	}
	registration := func(nodeKey string) map[string]any {
		for _, v := range run(command{Cmd: "lockRegistrations"})["registrations"].([]any) {
			if r := v.(map[string]any); r["nodeKey"] == nodeKey {
				return r
			}
		}
		return nil
	}
	enabled := true
	run(command{Cmd: "setLockCapability", Enabled: &enabled})

	// Enable lock: a is the signing device, and b, which was present at enablement, is signed as well.
	a := run(command{Cmd: "addPeer", Name: "peer-a"})["nodeKey"].(string)
	b := run(command{Cmd: "addPeer", Name: "peer-b"})["nodeKey"].(string)
	if tkaRequests("/machine/tka/bootstrap", a) != 0 {
		t.Fatal("a TKA request was sent before lock was enabled")
	}
	started := run(command{Cmd: "lockInit", Name: "peer-a"})
	if started["enabled"] != true || started["head"] != started["controlHead"] || started["nodeKeySigned"] != true {
		t.Fatalf("lockInit: %v", started)
	}
	waitFor("b bootstraps and sees a", func() bool {
		s := status("peer-b")
		return s["enabled"] == true && s["head"] == s["controlHead"] && s["nodeKeySigned"] == true && has(s, "visiblePeers", a)
	})

	// An unsigned peer disappears from other peers' netmaps and is itself locked.
	c := run(command{Cmd: "addPeer", Name: "peer-c"})["nodeKey"].(string)
	waitFor("a filters c", func() bool {
		s := status("peer-a")
		return has(s, "filteredPeers", c) && !has(s, "visiblePeers", c)
	})
	cs := status("peer-c")
	if cs["enabled"] != true || cs["nodeKeySigned"] != false || !has(cs, "visiblePeers", a) {
		t.Fatalf("c before signing: %v", cs)
	}

	// The peer appears after signing. Include c's lock key as the rotation key so subsequent re-signing can be verified.
	run(command{Cmd: "lockSign", Name: "peer-a", NodeKey: c, LockKey: cs["lockKey"].(string)})
	waitFor("a and b see signed c", func() bool {
		return has(status("peer-a"), "visiblePeers", c) && has(status("peer-b"), "visiblePeers", c) && status("peer-c")["nodeKeySigned"] == true
	})

	// Signed auth key (the chain grows by one via sync/send). A peer registered with it is visible from the start.
	before := status("peer-a")["head"]
	wrapped := run(command{Cmd: "lockWrapAuthKey", Name: "peer-a"})["authKey"].(string)
	if after := status("peer-a")["head"]; after == before || after != status("peer-a")["controlHead"] {
		t.Fatalf("adding the trusted key for the wrapped auth key did not move the head: %v → %v", before, after)
	}
	d := run(command{Cmd: "addPeer", Name: "peer-d", AuthKey: &wrapped})["nodeKey"].(string)
	if r := registration(d); r == nil || r["signature"] != "accepted" || r["wrappedKeyTrace"] != false || r["nlKey"] == "" {
		t.Fatalf("d registration: %v", r)
	}
	waitFor("a sees d without filtering it", func() bool {
		s := status("peer-a")
		return has(s, "visiblePeers", d) && !has(s, "filteredPeers", d)
	})
	// Late joiner d bootstraps from genesis and then catches up to the head with sync (offer, then send).
	waitFor("d reaches the server head and sees itself as signed", func() bool {
		s := status("peer-d")
		return s["head"] == s["controlHead"] && s["nodeKeySigned"] == true
	})
	if tkaRequests("/machine/tka/sync/offer", d) == 0 || tkaRequests("/machine/tka/sync/send", d) == 0 {
		t.Fatal("d did not send sync/offer and sync/send")
	}

	// Extend the chain: trust b's key, have b sign e, then remove b's key, which removes e as well.
	bs := status("peer-b")
	run(command{Cmd: "lockModify", Name: "peer-a", AddKeys: []string{bs["lockKey"].(string)}})
	waitFor("b reaches the head that trusts its own key", func() bool {
		s := status("peer-b")
		return s["head"] == s["controlHead"] && slices.Contains(s["trustedKeys"].([]string), bs["lockKey"].(string))
	})
	e := run(command{Cmd: "addPeer", Name: "peer-e"})["nodeKey"].(string)
	waitFor("a filters e", func() bool { return has(status("peer-a"), "filteredPeers", e) })
	run(command{Cmd: "lockSign", Name: "peer-b", NodeKey: e})
	waitFor("a and d see e with b's signature", func() bool {
		return has(status("peer-a"), "visiblePeers", e) && has(status("peer-d"), "visiblePeers", e)
	})
	run(command{Cmd: "lockModify", Name: "peer-a", RemoveKeys: []string{bs["lockKey"].(string)}})
	waitFor("a and d filter e after removing b's key", func() bool {
		sa, sd := status("peer-a"), status("peer-d")
		return sd["head"] == sd["controlHead"] && has(sa, "filteredPeers", e) && has(sd, "filteredPeers", e)
	})

	// Server re-signing request: after restarting, c re-signs and registers with a new node key, and the old key disappears.
	run(command{Cmd: "lockRequestResign", NodeKey: c})
	restartPeer(t, n, "peer-c")
	var c2 string
	waitFor("c registers with its new re-signed key", func() bool {
		for _, v := range run(command{Cmd: "lockRegistrations"})["registrations"].([]any) {
			if r := v.(map[string]any); r["oldNodeKey"] == c && r["signature"] == "accepted" {
				c2 = r["nodeKey"].(string)
				return true
			}
		}
		return false
	})
	waitFor("a sees c's new key and no longer sees its old key", func() bool {
		s := status("peer-a")
		return has(s, "visiblePeers", c2) && !has(s, "visiblePeers", c)
	})

	// Broken bootstrap: the new peer cannot enable lock (Go does not filter in this case). It enables lock after restoration.
	run(command{Cmd: "setLockBootstrapFault", Enabled: &enabled})
	f := run(command{Cmd: "addPeer", Name: "peer-f"})["nodeKey"].(string)
	waitFor("f attempts bootstrap", func() bool { return tkaRequests("/machine/tka/bootstrap", f) > 0 })
	if s := status("peer-f"); s["enabled"] != false {
		t.Fatalf("f after broken bootstrap: %v", s)
	}
	disabled := false
	run(command{Cmd: "setLockBootstrapFault", Enabled: &disabled})
	waitFor("f bootstraps again", func() bool { s := status("peer-f"); return s["enabled"] == true && s["head"] == s["controlHead"] })

	// Incorrect disablement secret: the server disables lock, but the peers keep it enabled.
	run(command{Cmd: "lockDisable", Name: "peer-a", WrongSecret: true})
	waitFor("peers receive the incorrect secret", func() bool { return tkaRequests("/machine/tka/bootstrap", b) > 1 })
	for _, name := range []string{"peer-a", "peer-b", "peer-d"} {
		if s := status(name); s["enabled"] != true || s["controlDisabled"] != true {
			t.Fatalf("%s after the incorrect secret: %v", name, s)
		}
	}
	if !has(status("peer-a"), "filteredPeers", e) {
		t.Fatal("a did not filter e after receiving the incorrect secret")
	}

	// Correct secret: all peers disable lock and see unsigned e again. After disablement, lockStatus does not populate the peer list
	// (ipn/ipnlocal/tailnet-lock.go:606-612), so check peerStatus.
	run(command{Cmd: "lockDisable", Name: "peer-a"})
	waitFor("all peers disable lock and see e", func() bool {
		for _, name := range []string{"peer-a", "peer-b", "peer-c", "peer-d", "peer-f"} {
			if status(name)["enabled"] != false {
				return false
			}
			seen := false
			for _, v := range run(command{Cmd: "peerStatus", Name: name})["peers"].([]any) {
				seen = seen || v.(map[string]any)["nodeKey"] == e
			}
			if !seen {
				return false
			}
		}
		return true
	})

	// Map response after disablement: TKAInfo{Disabled: true} by default, no TKAInfo with omitTKAInfo. The capability stays the same.
	mapFor := func() *tailcfg.MapResponse {
		t.Helper()
		var k key.NodePublic
		if err := k.UnmarshalText([]byte(a)); err != nil {
			t.Fatal(err)
		}
		m, err := n.control.MapResponse(&tailcfg.MapRequest{NodeKey: k})
		if err != nil || m == nil {
			t.Fatalf("MapResponse: %v", err)
		}
		if _, ok := m.Node.CapMap[nodecap.TailnetLock]; !ok {
			t.Fatal("the self node CapMap is missing tailnet-lock")
		}
		return m
	}
	if m := mapFor(); m.TKAInfo == nil || !m.TKAInfo.Disabled {
		t.Fatalf("TKAInfo after disablement: %+v", m.TKAInfo)
	}
	if r := run(command{Cmd: "lockDisable", Name: "peer-a", OmitTKAInfo: true}); r["alreadyDisabled"] != true {
		t.Fatalf("lockDisable: %v", r)
	}
	if m := mapFor(); m.TKAInfo != nil {
		t.Fatalf("TKAInfo after omitTKAInfo: %+v", m.TKAInfo)
	}
}

// restartPeer relaunches a Go peer with the same state directory.
func restartPeer(t *testing.T, n *network, name string) {
	t.Helper()
	if _, err := n.execute(command{Cmd: "peerClose", Name: name, Stop: true}); err != nil {
		t.Fatal(err)
	}
	p := n.peers[name]
	s := &tsnet.Server{Dir: p.dir, Hostname: name, ControlURL: n.control.ExplicitBaseURL, AuthKey: n.authKey, UserLogf: func(string, ...any) {}}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if _, err := s.Up(ctx); err != nil {
		t.Fatal(err)
	}
	p.server = s
	p.stopped = false
}
