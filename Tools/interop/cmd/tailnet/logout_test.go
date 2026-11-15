package main

import (
	"context"
	"testing"
	"time"

	"tailscale.com/tsnet"
)

// TestPeerLogout는 Go 피어의 로그아웃(lc.Logout)이 testcontrol에 어떤 요청으로 닿고 무엇을 바꾸는지 본다:
// 요청의 Expiry가 Unix 123초이고 node 키가 그대로이며, 서버의 그 노드는 KeyExpiry가 그 시각이 되고,
// 다른 피어의 netmap에 남되 KeyExpiry가 그 시각이 된다. 같은 상태 디렉터리로 다시 띄우면 새 node 키로 새 노드가 된다.
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
	t.Logf("로그아웃 뒤 peer-b의 BackendState: %v", out["backendState"])

	var logout map[string]any
	for _, r := range n.lockRegistrations()["registrations"].([]any) {
		if r := r.(map[string]any); r["nodeKey"] == nodeKey && r["expiryUnix"] != int64(0) {
			logout = r
		}
	}
	if logout == nil || logout["expiryUnix"] != int64(123) {
		t.Fatalf("로그아웃 요청이 없거나 Expiry가 Unix 123초가 아니다: %v", logout)
	}
	t.Logf("Go 로그아웃 요청: expiry=%q auth=%v oldNodeKey=%q nlKey 있음=%v signature=%v",
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
				t.Fatalf("서버의 keyExpiry: %v", v["keyExpiry"])
			}
		}
	}
	if !found {
		t.Fatal("로그아웃한 노드가 서버 목록에서 사라졌다")
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
			// Go는 KeyExpiry의 바뀜을 델타로 받고, Expired는 전체 netmap에서만 계산한다(ipnlocal/local.go flagExpiredPeers).
			t.Logf("peer-a가 본 peer-b: keyExpiry=%v expired=%v online=%v", seen["keyExpiry"], seen["expired"], seen["online"])
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("peer-a의 netmap에서 peer-b의 KeyExpiry가 바뀌지 않았다: %v", s)
		}
		time.Sleep(100 * time.Millisecond)
	}

	// 같은 상태 디렉터리로 다시 띄운다(Go는 로그아웃 때 프로필을 지웠다).
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
		t.Fatalf("같은 디렉터리로 다시 띄우지 못했다: %v", err)
	}
	if st.Self.PublicKey.String() == nodeKey {
		t.Fatal("다시 띄운 Go 피어가 로그아웃한 node 키를 그대로 쓴다")
	}
	nodes, err = n.execute(command{Cmd: "nodes"})
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("다시 띄운 뒤 서버의 노드 %d개, 새 이름 %q", len(nodes["nodes"].([]any)), st.Self.DNSName)
}
