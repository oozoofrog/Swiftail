package main

import (
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/netip"
	"time"

	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
	"tailscale.com/types/opt"
)

// All public keys are derived with SHA-256 from public test seeds. They are not for production use.
func publicBytes(label string) []byte {
	seed := sha256.Sum256([]byte("swiftail-fixtures/" + label))
	private, err := ecdh.X25519().NewPrivateKey(seed[:])
	if err != nil {
		panic(err)
	}
	return private.PublicKey().Bytes()
}
func nodeKey(id int) key.NodePublic {
	var k key.NodePublic
	if err := k.UnmarshalText([]byte("nodekey:" + hex.EncodeToString(publicBytes(fmt.Sprintf("node/%d", id))))); err != nil {
		panic(err)
	}
	return k
}
func discoKey(id int) key.DiscoPublic {
	var k key.DiscoPublic
	if err := k.UnmarshalText([]byte("discokey:" + hex.EncodeToString(publicBytes(fmt.Sprintf("disco/%d", id))))); err != nil {
		panic(err)
	}
	return k
}
func lockKey() key.NLPublic {
	seed := sha256.Sum256([]byte("swiftail-fixtures/lock"))
	raw := ed25519.NewKeyFromSeed(seed[:]).Public().(ed25519.PublicKey)
	var k key.NLPublic
	if err := k.UnmarshalText([]byte("nlpub:" + hex.EncodeToString(raw))); err != nil {
		panic(err)
	}
	return k
}
func node(id int) map[string]any {
	return map[string]any{
		"ID": id, "StableID": fmt.Sprintf("node-%d", id), "Name": fmt.Sprintf("rd-mac-%08x.tail0001.test.", id),
		"User": 1 + (id % 2), "Key": nodeKey(id), "DiscoKey": discoKey(id),
		"Addresses":  []string{fmt.Sprintf("100.64.0.%d/32", id), fmt.Sprintf("fd7a:115c:a1e0::%x/128", id)},
		"AllowedIPs": []string{fmt.Sprintf("100.64.0.%d/32", id), fmt.Sprintf("fd7a:115c:a1e0::%x/128", id)},
		"Endpoints":  []string{fmt.Sprintf("100.64.0.%d:41641", id)}, "HomeDERP": 1,
		"Online": true, "LastSeen": "2026-01-01T00:00:00Z", "KeyExpiry": "2027-01-01T00:00:00Z",
		"Expired": false, "Cap": 148, "MachineAuthorized": true,
	}
}
func region(id int) any {
	return map[string]any{"RegionID": id, "RegionCode": fmt.Sprintf("test%d", id), "RegionName": fmt.Sprintf("시험 지역 %d", id), "Nodes": []any{
		map[string]any{"Name": fmt.Sprintf("%da", id), "RegionID": id, "HostName": fmt.Sprintf("derp%d.tail0001.test", id), "IPv4": fmt.Sprintf("100.64.0.%d", id), "IPv6": fmt.Sprintf("fd7a:115c:a1e0::%x", id), "STUNPort": 3478, "DERPPort": 443},
	}}
}
func rule(port int) any {
	return map[string]any{"SrcIPs": []string{"100.64.0.0/10"}, "DstPorts": []any{map[string]any{"IP": "*", "Ports": map[string]int{"First": port, "Last": port}}}, "IPProto": []int{6}}
}
func full() map[string]any {
	return map[string]any{
		"Node": node(1), "Peers": []any{node(4), node(2), node(3)},
		"DERPMap":      map[string]any{"Regions": map[string]any{"1": region(1), "2": region(2)}, "omitDefaultRegions": true, "HomeParams": map[string]any{"RegionScore": map[string]float64{"1": 0.5, "2": 1.5}}},
		"DNSConfig":    map[string]any{"Domains": []string{"tail0001.test"}, "Proxied": true, "Nameservers": []string{"100.64.0.1"}},
		"PacketFilter": []any{rule(80)}, "UserProfiles": []any{
			map[string]any{"ID": 1, "LoginName": "user1@tail0001.test", "DisplayName": "시험 사용자 1"},
			map[string]any{"ID": 2, "LoginName": "user2@tail0001.test", "DisplayName": "시험 사용자 2"},
		}, "Domain": "tail0001.test",
	}
}
func makeStep(name string, value any) step {
	raw, err := json.Marshal(value)
	if err != nil {
		panic(err)
	}
	return step{Name: name, Response: string(raw)}
}
func session(name string, steps ...step) scenario {
	return scenario{Name: name, Steps: append([]step{makeStep("첫 전체 맵", full())}, steps...)}
}
func patch(name string, fields map[string]any) step {
	fields["NodeID"] = 2
	return makeStep(name, map[string]any{"PeersChangedPatch": []any{fields}})
}
func scenarios() []scenario {
	updated := node(5)
	updated["Name"] = "rd-mac-00000005-updated.tail0001.test."
	reintroduced := node(6)
	reintroduced["User"] = 3
	detailed := node(2)
	detailed["LastSeen"] = "2026-01-02T03:04:05.123456789+09:00"
	detailed["KeyExpiry"] = "2027-01-02T03:04:05.120000000+09:00"
	detailed["CapMap"] = map[string]any{"cap/test": nil, "cap/empty": []any{}, "cap/value": []any{map[string]any{"enabled": true}}}
	detailed["FutureNodeField"] = map[string]any{"unknown": 42}
	// Preserve IDs above 2^53 without going through a numeric string.
	detailed["ID"] = int64(9007199254740993)
	return []scenario{
		session("full-keepalive", makeStep("KeepAlive", map[string]any{"KeepAlive": true}), makeStep("빈 응답", map[string]any{})),
		session("peer-upsert-remove",
			makeStep("피어 추가", map[string]any{"PeersChanged": []any{node(5)}}),
			makeStep("같은 ID 갱신", map[string]any{"PeersChanged": []any{updated}}),
			makeStep("제거 뒤 upsert가 우선", map[string]any{"PeersRemoved": []int{2}, "PeersChanged": []any{node(2)}}),
			makeStep("일부 제거", map[string]any{"PeersRemoved": []int{2, 5, 999}}),
			makeStep("마지막까지 제거", map[string]any{"PeersRemoved": []int{3, 4}})),
		session("peer-patches",
			patch("DERPRegion", map[string]any{"DERPRegion": 2}),
			patch("Endpoints", map[string]any{"Endpoints": []string{"100.64.0.2:1234", "[fd7a:115c:a1e0::2]:1234"}}),
			patch("Key", map[string]any{"Key": nodeKey(22)}),
			patch("DiscoKey", map[string]any{"DiscoKey": discoKey(22)}),
			patch("Online false", map[string]any{"Online": false}),
			patch("LastSeen", map[string]any{"LastSeen": "2026-01-02T03:04:05.123456789+09:00"}),
			patch("KeyExpiry", map[string]any{"KeyExpiry": "2025-01-01T00:00:00Z"}),
			patch("Cap", map[string]any{"Cap": 149}),
			patch("동시 갱신", map[string]any{"DERPRegion": 3, "Endpoints": []string{}, "Key": nodeKey(23), "DiscoKey": discoKey(23), "Online": true, "LastSeen": "2026-02-01T00:00:00Z", "KeyExpiry": "2028-01-01T00:00:00Z", "Cap": 150}),
			makeStep("seen·online 뒤 patch가 우선", map[string]any{"PeerSeenChange": map[string]bool{"2": true}, "OnlineChange": map[string]bool{"2": false}, "PeersChangedPatch": []any{map[string]any{"NodeID": 2, "Online": true, "LastSeen": "2026-03-01T00:00:00Z"}}}),
			patch("0·null은 유지", map[string]any{"DERPRegion": 0, "Cap": 0, "Endpoints": nil, "Online": nil, "LastSeen": nil, "KeyExpiry": nil}),
			makeStep("없는 ID patch", map[string]any{"PeersChangedPatch": []any{map[string]any{"NodeID": 999, "DERPRegion": 5}}})),
		session("online-seen",
			makeStep("online true·false", map[string]any{"OnlineChange": map[string]bool{"2": false, "3": true, "999": false}}),
			makeStep("seen true·false", map[string]any{"PeerSeenChange": map[string]bool{"2": true, "3": false, "999": true}}),
			makeStep("반대 online·seen", map[string]any{"OnlineChange": map[string]bool{"2": true, "3": false}, "PeerSeenChange": map[string]bool{"2": false, "3": true}})),
		session("peer-full-empty-omitted",
			makeStep("전체 교체는 delta보다 우선", map[string]any{"Peers": []any{node(5)}, "PeersRemoved": []int{5}, "PeersChanged": []any{node(6)}}),
			makeStep("Peers 빈 배열", map[string]any{"Peers": []any{}}),
			makeStep("Peers 키 생략", map[string]any{}),
			makeStep("Peers null", map[string]any{"Peers": nil}),
			makeStep("빈 배열과 delta", map[string]any{"Peers": []any{}, "PeersChanged": []any{node(6)}}),
			makeStep("명시적으로 모두 제거", map[string]any{"PeersRemoved": []int{5, 6}})),
		session("derp-replacement-and-preservation",
			makeStep("전체 교체", map[string]any{"DERPMap": map[string]any{"Regions": map[string]any{"3": region(3)}, "omitDefaultRegions": false}}),
			makeStep("지역 일부만 보내도 전체 교체", map[string]any{"DERPMap": map[string]any{"Regions": map[string]any{"1": region(1), "2": nil}, "omitDefaultRegions": true}}),
			makeStep("Regions null이면 omitDefaultRegions도 유지", map[string]any{"DERPMap": map[string]any{"Regions": nil, "omitDefaultRegions": false, "HomeParams": map[string]any{}}}),
			makeStep("Regions 생략·점수 교체", map[string]any{"DERPMap": map[string]any{"HomeParams": map[string]any{"RegionScore": map[string]float64{"1": 0.75}}}}),
			makeStep("빈 점수 초기화", map[string]any{"DERPMap": map[string]any{"HomeParams": map[string]any{"RegionScore": map[string]float64{}}}}),
			makeStep("빈 지역 객체", map[string]any{"DERPMap": map[string]any{"Regions": map[string]any{}, "omitDefaultRegions": false}}),
			makeStep("DERPMap null", map[string]any{"DERPMap": nil})),
		session("dns-replacement",
			makeStep("객체 교체", map[string]any{"DNSConfig": map[string]any{"Domains": []string{"changed.tail0001.test"}}}),
			makeStep("생략 유지", map[string]any{}), makeStep("null 유지", map[string]any{"DNSConfig": nil}),
			makeStep("빈 객체 교체", map[string]any{"DNSConfig": map[string]any{}})),
		session("packet-filters",
			makeStep("전체 base 교체", map[string]any{"PacketFilter": []any{rule(443)}}),
			makeStep("빈 배열로 base 모두 차단", map[string]any{"PacketFilter": []any{}}),
			makeStep("생략은 차단 유지", map[string]any{}),
			makeStep("base 복원", map[string]any{"PacketFilter": []any{rule(443)}}),
			makeStep("null은 base 유지", map[string]any{"PacketFilter": nil}),
			makeStep("이름 추가·이름 순 정렬", map[string]any{"PacketFilters": map[string]any{"z-last": []any{rule(22)}, "a-first": []any{rule(53)}}}),
			makeStep("이름 교체", map[string]any{"PacketFilters": map[string]any{"a-first": []any{rule(8080)}}}),
			makeStep("null로 이름 삭제", map[string]any{"PacketFilters": map[string]any{"z-last": nil}}),
			makeStep("빈 base는 다른 이름을 유지", map[string]any{"PacketFilter": []any{}}),
			makeStep("base 처리 뒤 별 초기화", map[string]any{"PacketFilter": []any{rule(9000)}, "PacketFilters": map[string]any{"*": nil, "b": []any{rule(8443)}}}),
			makeStep("모두 초기화", map[string]any{"PacketFilters": map[string]any{"*": nil}}),
			makeStep("빈 배열 모두 차단", map[string]any{"PacketFilter": []any{}}),
			makeStep("생략 유지", map[string]any{}), makeStep("PacketFilter null 유지", map[string]any{"PacketFilter": nil})),
		session("profiles-domain-tka",
			makeStep("사용자 누적·기존 사용자 교체", map[string]any{"UserProfiles": []any{map[string]any{"ID": 3, "LoginName": "user3@tail0001.test", "DisplayName": "시험 사용자 3"}, map[string]any{"ID": 1, "LoginName": "user1@tail0001.test", "DisplayName": "시험 사용자 1 갱신"}}}),
			makeStep("새 사용자 피어 추가", map[string]any{"PeersChanged": []any{reintroduced}}),
			makeStep("사용자 피어 제거", map[string]any{"PeersRemoved": []int{6}}),
			makeStep("프로필 재전송 없이 재등장", map[string]any{"PeersChanged": []any{reintroduced}}),
			makeStep("Domain 변경·TKA 활성화", map[string]any{"Domain": "changed.tail0001.test", "TKAInfo": map[string]any{"Disabled": false}}),
			makeStep("빈 Domain·TKA null 유지", map[string]any{"Domain": "", "TKAInfo": nil}),
			makeStep("TKA 비활성화", map[string]any{"TKAInfo": map[string]any{"Disabled": true}})),
		session("json-time-capmap-unknown",
			makeStep("소수 초·오프셋·CapMap null·모르는 키·큰 ID", map[string]any{"PeersChanged": []any{detailed}, "FutureMapField": []any{1, "unknown", nil}}),
			makeStep("생략 AllowedIPs는 Addresses를 사용", map[string]any{"PeersChanged": []any{map[string]any{"ID": 8, "StableID": "node-8", "Name": "rd-mac-00000008.tail0001.test.", "User": 1, "Key": nodeKey(8), "Addresses": []string{"100.64.0.8/32"}, "DERP": "127.3.3.40:2"}}}),
			makeStep("명시적 빈 AllowedIPs는 유지", map[string]any{"PeersChanged": []any{map[string]any{"ID": 9, "StableID": "node-9", "Name": "rd-mac-00000009.tail0001.test.", "User": 1, "Key": nodeKey(9), "Addresses": []string{"100.64.0.9/32"}, "AllowedIPs": []string{}, "Expired": true}}})),
	}
}

type requestFixture struct {
	Name  string `json:"name"`
	Type  string `json:"type"`
	Input any    `json:"input"`
	JSON  string `json:"json"`
}

func requestFixtures() []requestFixture {
	var out []requestFixture
	add := func(name, typ string, input, request any) {
		raw, err := json.Marshal(request)
		if err != nil {
			panic(err)
		}
		out = append(out, requestFixture{Name: name, Type: typ, Input: input, JSON: string(raw)})
	}
	host := &tailcfg.Hostinfo{Hostname: "rd-mac-1a2b3c4d", IPNVersion: "swiftail-test", OS: "darwin", BackendLogID: "fake-log-id", Userspace: opt.NewBool(true)}
	base := tailcfg.RegisterRequest{Version: 148, NodeKey: nodeKey(1), NLKey: lockKey(), Hostinfo: host}
	r := base
	r.Auth = &tailcfg.RegisterResponseAuth{AuthKey: "tskey-auth-fake"}
	add("인증 키 등록", "RegisterRequest", map[string]any{"Version": 148, "NodeKey": nodeKey(1), "NLKey": lockKey(), "Auth": map[string]string{"AuthKey": "tskey-auth-fake"}, "Hostinfo": host}, r)
	r = base
	r.Followup = "https://control.tail0001.test/auth/fake"
	add("Followup 등록", "RegisterRequest", map[string]any{"Version": 148, "NodeKey": nodeKey(1), "NLKey": lockKey(), "Followup": r.Followup, "Hostinfo": host}, r)
	r = base
	r.NodeKey = nodeKey(2)
	r.OldNodeKey = nodeKey(1)
	add("키 교체", "RegisterRequest", map[string]any{"Version": 148, "NodeKey": r.NodeKey, "OldNodeKey": r.OldNodeKey, "NLKey": lockKey(), "Hostinfo": host}, r)
	r = base
	r.Expiry = time.Unix(123, 0).UTC()
	add("로그아웃", "RegisterRequest", map[string]any{"Version": 148, "NodeKey": r.NodeKey, "NLKey": lockKey(), "Expiry": r.Expiry, "Hostinfo": host}, r)
	m := tailcfg.MapRequest{Version: 148, NodeKey: nodeKey(1), DiscoKey: discoKey(1), Stream: true, KeepAlive: true}
	add("스트림 맵", "MapRequest", map[string]any{"Version": 148, "NodeKey": m.NodeKey, "DiscoKey": m.DiscoKey, "Stream": true, "KeepAlive": true}, m)
	m.Stream = false
	m.KeepAlive = false
	m.OmitPeers = true
	m.Hostinfo = host
	m.Endpoints = []netip.AddrPort{netip.MustParseAddrPort("100.64.0.1:41641"), netip.MustParseAddrPort("[fd7a:115c:a1e0::1]:41641")}
	m.EndpointTypes = []tailcfg.EndpointType{1, 2}
	add("상태 갱신", "MapRequest", map[string]any{"Version": 148, "NodeKey": m.NodeKey, "DiscoKey": m.DiscoKey, "Stream": false, "OmitPeers": true, "Hostinfo": host, "Endpoints": m.Endpoints, "EndpointTypes": m.EndpointTypes}, m)
	add("zero 등록", "RegisterRequest", map[string]any{}, tailcfg.RegisterRequest{})
	add("zero 맵", "MapRequest", map[string]any{}, tailcfg.MapRequest{})
	minimal := &tailcfg.Hostinfo{Hostname: "rd-mac-1a2b3c4d"}
	add("최소 Hostinfo", "RegisterRequest", map[string]any{"Hostinfo": map[string]any{"Hostname": minimal.Hostname}}, tailcfg.RegisterRequest{Hostinfo: minimal})
	info := &tailcfg.NetInfo{WorkingIPv6: opt.NewBool(false), WorkingUDP: opt.NewBool(true), PreferredDERP: 1, DERPLatency: map[string]float64{"1-v4": 0.001}}
	add("최소 NetInfo", "MapRequest", map[string]any{"Hostinfo": map[string]any{"NetInfo": map[string]any{"WorkingIPv6": false, "WorkingUDP": true, "PreferredDERP": 1, "DERPLatency": map[string]float64{"1-v4": 0.001}}}}, tailcfg.MapRequest{Hostinfo: &tailcfg.Hostinfo{NetInfo: info}})
	return out
}
