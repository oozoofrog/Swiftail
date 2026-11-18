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
	return map[string]any{"RegionID": id, "RegionCode": fmt.Sprintf("test%d", id), "RegionName": fmt.Sprintf("Test Region %d", id), "Nodes": []any{
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
			map[string]any{"ID": 1, "LoginName": "user1@tail0001.test", "DisplayName": "Test User 1"},
			map[string]any{"ID": 2, "LoginName": "user2@tail0001.test", "DisplayName": "Test User 2"},
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
	return scenario{Name: name, Steps: append([]step{makeStep("Initial full map", full())}, steps...)}
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
		session("full-keepalive", makeStep("KeepAlive", map[string]any{"KeepAlive": true}), makeStep("Empty response", map[string]any{})),
		session("peer-upsert-remove",
			makeStep("Add peer", map[string]any{"PeersChanged": []any{node(5)}}),
			makeStep("Update the same ID", map[string]any{"PeersChanged": []any{updated}}),
			makeStep("Upsert takes precedence after removal", map[string]any{"PeersRemoved": []int{2}, "PeersChanged": []any{node(2)}}),
			makeStep("Remove some peers", map[string]any{"PeersRemoved": []int{2, 5, 999}}),
			makeStep("Remove the last peer too", map[string]any{"PeersRemoved": []int{3, 4}})),
		session("peer-patches",
			patch("DERPRegion", map[string]any{"DERPRegion": 2}),
			patch("Endpoints", map[string]any{"Endpoints": []string{"100.64.0.2:1234", "[fd7a:115c:a1e0::2]:1234"}}),
			patch("Key", map[string]any{"Key": nodeKey(22)}),
			patch("DiscoKey", map[string]any{"DiscoKey": discoKey(22)}),
			patch("Online false", map[string]any{"Online": false}),
			patch("LastSeen", map[string]any{"LastSeen": "2026-01-02T03:04:05.123456789+09:00"}),
			patch("KeyExpiry", map[string]any{"KeyExpiry": "2025-01-01T00:00:00Z"}),
			patch("Cap", map[string]any{"Cap": 149}),
			patch("Update together", map[string]any{"DERPRegion": 3, "Endpoints": []string{}, "Key": nodeKey(23), "DiscoKey": discoKey(23), "Online": true, "LastSeen": "2026-02-01T00:00:00Z", "KeyExpiry": "2028-01-01T00:00:00Z", "Cap": 150}),
			makeStep("Patch takes precedence after seen and online changes", map[string]any{"PeerSeenChange": map[string]bool{"2": true}, "OnlineChange": map[string]bool{"2": false}, "PeersChangedPatch": []any{map[string]any{"NodeID": 2, "Online": true, "LastSeen": "2026-03-01T00:00:00Z"}}}),
			patch("Zero and null preserve values", map[string]any{"DERPRegion": 0, "Cap": 0, "Endpoints": nil, "Online": nil, "LastSeen": nil, "KeyExpiry": nil}),
			makeStep("Patch an unknown ID", map[string]any{"PeersChangedPatch": []any{map[string]any{"NodeID": 999, "DERPRegion": 5}}})),
		session("online-seen",
			makeStep("online true·false", map[string]any{"OnlineChange": map[string]bool{"2": false, "3": true, "999": false}}),
			makeStep("seen true·false", map[string]any{"PeerSeenChange": map[string]bool{"2": true, "3": false, "999": true}}),
			makeStep("Opposite online and seen changes", map[string]any{"OnlineChange": map[string]bool{"2": true, "3": false}, "PeerSeenChange": map[string]bool{"2": false, "3": true}})),
		session("peer-full-empty-omitted",
			makeStep("Full replacement takes precedence over deltas", map[string]any{"Peers": []any{node(5)}, "PeersRemoved": []int{5}, "PeersChanged": []any{node(6)}}),
			makeStep("Empty Peers array", map[string]any{"Peers": []any{}}),
			makeStep("Peers key omitted", map[string]any{}),
			makeStep("Peers null", map[string]any{"Peers": nil}),
			makeStep("Empty array with delta", map[string]any{"Peers": []any{}, "PeersChanged": []any{node(6)}}),
			makeStep("Explicitly remove all peers", map[string]any{"PeersRemoved": []int{5, 6}})),
		session("derp-replacement-and-preservation",
			makeStep("Full replacement", map[string]any{"DERPMap": map[string]any{"Regions": map[string]any{"3": region(3)}, "omitDefaultRegions": false}}),
			makeStep("Partial region list still replaces all regions", map[string]any{"DERPMap": map[string]any{"Regions": map[string]any{"1": region(1), "2": nil}, "omitDefaultRegions": true}}),
			makeStep("Null Regions also preserves omitDefaultRegions", map[string]any{"DERPMap": map[string]any{"Regions": nil, "omitDefaultRegions": false, "HomeParams": map[string]any{}}}),
			makeStep("Omit Regions and replace scores", map[string]any{"DERPMap": map[string]any{"HomeParams": map[string]any{"RegionScore": map[string]float64{"1": 0.75}}}}),
			makeStep("Reset scores with an empty object", map[string]any{"DERPMap": map[string]any{"HomeParams": map[string]any{"RegionScore": map[string]float64{}}}}),
			makeStep("Empty regions object", map[string]any{"DERPMap": map[string]any{"Regions": map[string]any{}, "omitDefaultRegions": false}}),
			makeStep("DERPMap null", map[string]any{"DERPMap": nil})),
		session("dns-replacement",
			makeStep("Replace object", map[string]any{"DNSConfig": map[string]any{"Domains": []string{"changed.tail0001.test"}}}),
			makeStep("Omission preserves value", map[string]any{}), makeStep("Null preserves value", map[string]any{"DNSConfig": nil}),
			makeStep("Replace with an empty object", map[string]any{"DNSConfig": map[string]any{}})),
		session("packet-filters",
			makeStep("Replace the entire base", map[string]any{"PacketFilter": []any{rule(443)}}),
			makeStep("An empty array denies all traffic in the base", map[string]any{"PacketFilter": []any{}}),
			makeStep("Omission preserves the deny-all base", map[string]any{}),
			makeStep("Restore base", map[string]any{"PacketFilter": []any{rule(443)}}),
			makeStep("Null preserves the base", map[string]any{"PacketFilter": nil}),
			makeStep("Add name and sort by name", map[string]any{"PacketFilters": map[string]any{"z-last": []any{rule(22)}, "a-first": []any{rule(53)}}}),
			makeStep("Replace named filter", map[string]any{"PacketFilters": map[string]any{"a-first": []any{rule(8080)}}}),
			makeStep("Delete named filter with null", map[string]any{"PacketFilters": map[string]any{"z-last": nil}}),
			makeStep("Empty base preserves the other names", map[string]any{"PacketFilter": []any{}}),
			makeStep("Reset with wildcard after processing the base", map[string]any{"PacketFilter": []any{rule(9000)}, "PacketFilters": map[string]any{"*": nil, "b": []any{rule(8443)}}}),
			makeStep("Reset all", map[string]any{"PacketFilters": map[string]any{"*": nil}}),
			makeStep("Empty array denies all", map[string]any{"PacketFilter": []any{}}),
			makeStep("Omission preserves value", map[string]any{}), makeStep("Null PacketFilter preserves value", map[string]any{"PacketFilter": nil})),
		session("profiles-domain-tka",
			makeStep("Accumulate users and replace an existing user", map[string]any{"UserProfiles": []any{map[string]any{"ID": 3, "LoginName": "user3@tail0001.test", "DisplayName": "Test User 3"}, map[string]any{"ID": 1, "LoginName": "user1@tail0001.test", "DisplayName": "Test User 1 Updated"}}}),
			makeStep("Add a peer with a new user", map[string]any{"PeersChanged": []any{reintroduced}}),
			makeStep("Remove the user's peer", map[string]any{"PeersRemoved": []int{6}}),
			makeStep("Peer returns without resending the profile", map[string]any{"PeersChanged": []any{reintroduced}}),
			makeStep("Change Domain and enable TKA", map[string]any{"Domain": "changed.tail0001.test", "TKAInfo": map[string]any{"Disabled": false}}),
			makeStep("Empty Domain and null TKA preserve values", map[string]any{"Domain": "", "TKAInfo": nil}),
			makeStep("Disable TKA", map[string]any{"TKAInfo": map[string]any{"Disabled": true}})),
		session("json-time-capmap-unknown",
			makeStep("Fractional seconds, offset, null CapMap, unknown key, and large ID", map[string]any{"PeersChanged": []any{detailed}, "FutureMapField": []any{1, "unknown", nil}}),
			makeStep("Omitted AllowedIPs uses Addresses", map[string]any{"PeersChanged": []any{map[string]any{"ID": 8, "StableID": "node-8", "Name": "rd-mac-00000008.tail0001.test.", "User": 1, "Key": nodeKey(8), "Addresses": []string{"100.64.0.8/32"}, "DERP": "127.3.3.40:2"}}}),
			makeStep("Preserve explicitly empty AllowedIPs", map[string]any{"PeersChanged": []any{map[string]any{"ID": 9, "StableID": "node-9", "Name": "rd-mac-00000009.tail0001.test.", "User": 1, "Key": nodeKey(9), "Addresses": []string{"100.64.0.9/32"}, "AllowedIPs": []string{}, "Expired": true}}})),
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
	add("Auth key registration", "RegisterRequest", map[string]any{"Version": 148, "NodeKey": nodeKey(1), "NLKey": lockKey(), "Auth": map[string]string{"AuthKey": "tskey-auth-fake"}, "Hostinfo": host}, r)
	r = base
	r.Followup = "https://control.tail0001.test/auth/fake"
	add("Followup registration", "RegisterRequest", map[string]any{"Version": 148, "NodeKey": nodeKey(1), "NLKey": lockKey(), "Followup": r.Followup, "Hostinfo": host}, r)
	r = base
	r.NodeKey = nodeKey(2)
	r.OldNodeKey = nodeKey(1)
	add("Key rotation", "RegisterRequest", map[string]any{"Version": 148, "NodeKey": r.NodeKey, "OldNodeKey": r.OldNodeKey, "NLKey": lockKey(), "Hostinfo": host}, r)
	r = base
	r.Expiry = time.Unix(123, 0).UTC()
	add("Logout", "RegisterRequest", map[string]any{"Version": 148, "NodeKey": r.NodeKey, "NLKey": lockKey(), "Expiry": r.Expiry, "Hostinfo": host}, r)
	m := tailcfg.MapRequest{Version: 148, NodeKey: nodeKey(1), DiscoKey: discoKey(1), Stream: true, KeepAlive: true}
	add("Streaming map", "MapRequest", map[string]any{"Version": 148, "NodeKey": m.NodeKey, "DiscoKey": m.DiscoKey, "Stream": true, "KeepAlive": true}, m)
	m.Stream = false
	m.KeepAlive = false
	m.OmitPeers = true
	m.Hostinfo = host
	m.Endpoints = []netip.AddrPort{netip.MustParseAddrPort("100.64.0.1:41641"), netip.MustParseAddrPort("[fd7a:115c:a1e0::1]:41641")}
	m.EndpointTypes = []tailcfg.EndpointType{1, 2}
	add("Status update", "MapRequest", map[string]any{"Version": 148, "NodeKey": m.NodeKey, "DiscoKey": m.DiscoKey, "Stream": false, "OmitPeers": true, "Hostinfo": host, "Endpoints": m.Endpoints, "EndpointTypes": m.EndpointTypes}, m)
	add("Zero-value registration", "RegisterRequest", map[string]any{}, tailcfg.RegisterRequest{})
	add("Zero-value map", "MapRequest", map[string]any{}, tailcfg.MapRequest{})
	minimal := &tailcfg.Hostinfo{Hostname: "rd-mac-1a2b3c4d"}
	add("Minimal Hostinfo", "RegisterRequest", map[string]any{"Hostinfo": map[string]any{"Hostname": minimal.Hostname}}, tailcfg.RegisterRequest{Hostinfo: minimal})
	info := &tailcfg.NetInfo{WorkingIPv6: opt.NewBool(false), WorkingUDP: opt.NewBool(true), PreferredDERP: 1, DERPLatency: map[string]float64{"1-v4": 0.001}}
	add("Minimal NetInfo", "MapRequest", map[string]any{"Hostinfo": map[string]any{"NetInfo": map[string]any{"WorkingIPv6": false, "WorkingUDP": true, "PreferredDERP": 1, "DERPLatency": map[string]float64{"1-v4": 0.001}}}}, tailcfg.MapRequest{Hostinfo: &tailcfg.Hostinfo{NetInfo: info}})
	return out
}
