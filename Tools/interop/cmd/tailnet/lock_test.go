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

// TestTailnetLock은 Go tsnet 피어끼리만으로 관문 (가)의 흐름이 도는지 본다
// (docs/contracts/SwiftailTailnetLock.md 7절). 이것이 통과해야 Swift 노드를 붙였을 때의
// 실패를 Swift 쪽 문제라고 말할 수 있다.
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
				t.Fatalf("기다리다 시한을 넘겼습니다: %s", what)
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

	// lock 켜기: a가 서명 기기이고, 켤 때 있던 b도 함께 서명된다.
	a := run(command{Cmd: "addPeer", Name: "peer-a"})["nodeKey"].(string)
	b := run(command{Cmd: "addPeer", Name: "peer-b"})["nodeKey"].(string)
	if tkaRequests("/machine/tka/bootstrap", a) != 0 {
		t.Fatal("lock을 켜기 전에 TKA 요청이 나갔습니다")
	}
	started := run(command{Cmd: "lockInit", Name: "peer-a"})
	if started["enabled"] != true || started["head"] != started["controlHead"] || started["nodeKeySigned"] != true {
		t.Fatalf("lockInit: %v", started)
	}
	waitFor("b가 부트스트랩하고 a를 본다", func() bool {
		s := status("peer-b")
		return s["enabled"] == true && s["head"] == s["controlHead"] && s["nodeKeySigned"] == true && has(s, "visiblePeers", a)
	})

	// 서명 없는 피어는 다른 피어의 netmap에서 빠지고, 자기는 잠긴다.
	c := run(command{Cmd: "addPeer", Name: "peer-c"})["nodeKey"].(string)
	waitFor("a가 c를 거른다", func() bool {
		s := status("peer-a")
		return has(s, "filteredPeers", c) && !has(s, "visiblePeers", c)
	})
	cs := status("peer-c")
	if cs["enabled"] != true || cs["nodeKeySigned"] != false || !has(cs, "visiblePeers", a) {
		t.Fatalf("서명 전의 c: %v", cs)
	}

	// 서명 뒤 나타난다. c의 lock 키를 회전 키로 넣어 뒤의 재서명이 검증되게 한다.
	run(command{Cmd: "lockSign", Name: "peer-a", NodeKey: c, LockKey: cs["lockKey"].(string)})
	waitFor("a와 b가 서명된 c를 본다", func() bool {
		return has(status("peer-a"), "visiblePeers", c) && has(status("peer-b"), "visiblePeers", c) && status("peer-c")["nodeKeySigned"] == true
	})

	// 서명된 인증 키(사슬이 한 칸 자란다: sync/send). 그것으로 등록한 피어는 처음부터 보인다.
	before := status("peer-a")["head"]
	wrapped := run(command{Cmd: "lockWrapAuthKey", Name: "peer-a"})["authKey"].(string)
	if after := status("peer-a")["head"]; after == before || after != status("peer-a")["controlHead"] {
		t.Fatalf("감싼 인증 키의 신뢰 키 추가가 머리를 옮기지 않았습니다: %v → %v", before, after)
	}
	d := run(command{Cmd: "addPeer", Name: "peer-d", AuthKey: &wrapped})["nodeKey"].(string)
	if r := registration(d); r == nil || r["signature"] != "accepted" || r["wrappedKeyTrace"] != false || r["nlKey"] == "" {
		t.Fatalf("d의 등록: %v", r)
	}
	waitFor("a가 d를 거르지 않고 본다", func() bool {
		s := status("peer-a")
		return has(s, "visiblePeers", d) && !has(s, "filteredPeers", d)
	})
	// 늦게 온 d는 genesis에서 부트스트랩한 뒤 sync로 머리를 따라잡는다(offer 뒤 send).
	waitFor("d가 서버 머리에 닿고 서명된 자기를 본다", func() bool {
		s := status("peer-d")
		return s["head"] == s["controlHead"] && s["nodeKeySigned"] == true
	})
	if tkaRequests("/machine/tka/sync/offer", d) == 0 || tkaRequests("/machine/tka/sync/send", d) == 0 {
		t.Fatal("d가 sync/offer·sync/send를 보내지 않았습니다")
	}

	// 사슬이 자란다: b의 키를 신뢰하고, b가 e에 서명하고, b의 키를 빼면 e가 함께 빠진다.
	bs := status("peer-b")
	run(command{Cmd: "lockModify", Name: "peer-a", AddKeys: []string{bs["lockKey"].(string)}})
	waitFor("b가 자기 키를 신뢰하는 머리에 닿는다", func() bool {
		s := status("peer-b")
		return s["head"] == s["controlHead"] && slices.Contains(s["trustedKeys"].([]string), bs["lockKey"].(string))
	})
	e := run(command{Cmd: "addPeer", Name: "peer-e"})["nodeKey"].(string)
	waitFor("a가 e를 거른다", func() bool { return has(status("peer-a"), "filteredPeers", e) })
	run(command{Cmd: "lockSign", Name: "peer-b", NodeKey: e})
	waitFor("a와 d가 b의 서명으로 e를 본다", func() bool {
		return has(status("peer-a"), "visiblePeers", e) && has(status("peer-d"), "visiblePeers", e)
	})
	run(command{Cmd: "lockModify", Name: "peer-a", RemoveKeys: []string{bs["lockKey"].(string)}})
	waitFor("b의 키를 뺀 뒤 a와 d가 e를 거른다", func() bool {
		sa, sd := status("peer-a"), status("peer-d")
		return sd["head"] == sd["controlHead"] && has(sa, "filteredPeers", e) && has(sd, "filteredPeers", e)
	})

	// 서버의 재서명 요청: 다시 시작한 c가 새 node 키로 재서명해 등록하고, 옛 키는 사라진다.
	run(command{Cmd: "lockRequestResign", NodeKey: c})
	restartPeer(t, n, "peer-c")
	var c2 string
	waitFor("c가 재서명한 새 키로 등록한다", func() bool {
		for _, v := range run(command{Cmd: "lockRegistrations"})["registrations"].([]any) {
			if r := v.(map[string]any); r["oldNodeKey"] == c && r["signature"] == "accepted" {
				c2 = r["nodeKey"].(string)
				return true
			}
		}
		return false
	})
	waitFor("a가 c의 새 키를 보고 옛 키를 보지 않는다", func() bool {
		s := status("peer-a")
		return has(s, "visiblePeers", c2) && !has(s, "visiblePeers", c)
	})

	// 깨진 부트스트랩: 새 피어는 lock을 켜지 못한다(Go는 이때 거르지 않는다). 되돌리면 켠다.
	run(command{Cmd: "setLockBootstrapFault", Enabled: &enabled})
	f := run(command{Cmd: "addPeer", Name: "peer-f"})["nodeKey"].(string)
	waitFor("f가 부트스트랩을 시도한다", func() bool { return tkaRequests("/machine/tka/bootstrap", f) > 0 })
	if s := status("peer-f"); s["enabled"] != false {
		t.Fatalf("깨진 부트스트랩 뒤의 f: %v", s)
	}
	disabled := false
	run(command{Cmd: "setLockBootstrapFault", Enabled: &disabled})
	waitFor("f가 다시 부트스트랩한다", func() bool { s := status("peer-f"); return s["enabled"] == true && s["head"] == s["controlHead"] })

	// 틀린 끄기 비밀: 서버는 껐지만 피어는 lock을 유지한다.
	run(command{Cmd: "lockDisable", Name: "peer-a", WrongSecret: true})
	waitFor("피어들이 틀린 비밀을 받는다", func() bool { return tkaRequests("/machine/tka/bootstrap", b) > 1 })
	for _, name := range []string{"peer-a", "peer-b", "peer-d"} {
		if s := status(name); s["enabled"] != true || s["controlDisabled"] != true {
			t.Fatalf("틀린 비밀 뒤의 %s: %v", name, s)
		}
	}
	if !has(status("peer-a"), "filteredPeers", e) {
		t.Fatal("틀린 비밀 뒤에 a가 e를 거르지 않습니다")
	}

	// 맞는 비밀: 모두 lock을 끄고 서명 없는 e가 다시 보인다. 끈 뒤의 lockStatus는 피어 목록을
	// 채우지 않으므로(ipn/ipnlocal/tailnet-lock.go:606-612) peerStatus로 본다.
	run(command{Cmd: "lockDisable", Name: "peer-a"})
	waitFor("모든 피어가 lock을 끄고 e를 본다", func() bool {
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

	// 끈 뒤의 맵 응답: 기본은 TKAInfo{Disabled: true}, omitTKAInfo면 TKAInfo가 없다. capability는 그대로다.
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
			t.Fatal("자기 노드 CapMap에 tailnet-lock이 없습니다")
		}
		return m
	}
	if m := mapFor(); m.TKAInfo == nil || !m.TKAInfo.Disabled {
		t.Fatalf("끈 뒤의 TKAInfo: %+v", m.TKAInfo)
	}
	if r := run(command{Cmd: "lockDisable", Name: "peer-a", OmitTKAInfo: true}); r["alreadyDisabled"] != true {
		t.Fatalf("lockDisable: %v", r)
	}
	if m := mapFor(); m.TKAInfo != nil {
		t.Fatalf("omitTKAInfo 뒤의 TKAInfo: %+v", m.TKAInfo)
	}
}

// restartPeer는 같은 상태 디렉터리로 Go 피어를 다시 띄운다.
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
