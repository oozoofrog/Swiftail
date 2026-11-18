// JSON rules for the tailcfg models. Examples come from the tables in docs/protocol-notes/control-map.md §3.1 (checked with Go 1.27.3 encoding/json)
// and goMarshaledMapResponse below (Go's marshal output for fake values).

import Foundation
import SwiftailBase
import Testing

@testable import SwiftailControl

@Suite("tailcfg JSON")
struct TailcfgJSONTests {
    private let nodeKey = keyText("nodekey:", byte: 0xAB)
    private let discoKey = keyText("discokey:", byte: 0xCD)
    private let nlKey = keyText("nlpub:", byte: 0xEF)

    // MARK: Request encoding

    @Test("Initial auth-key registration sends fields without omitempty even when they are empty")
    func registerRequest() throws {
        let request = RegisterRequest(
            nodeKey: try #require(NodePublicKey(nodeKey)),
            nlKey: try #require(NLPublicKey(nlKey)),
            auth: RegisterResponseAuth(authKey: "tskey-auth-fake"),
            hostinfo: Hostinfo(backendLogID: "fake-log-id", hostname: "rd-mac-1a2b3c4d")
        )
        let expected = #"{"Version":148,"NodeKey":"\#(nodeKey)","OldNodeKey":"nodekey:\#(String(repeating: "0", count: 64))","NLKey":"\#(nlKey)","Auth":{"AuthKey":"tskey-auth-fake"},"Expiry":"0001-01-01T00:00:00Z","Followup":"","Hostinfo":{"BackendLogID":"fake-log-id","Hostname":"rd-mac-1a2b3c4d"},"NodeKeySignature":null}"#
        #expect(try jsonObject(JSONEncoder().encode(request)) == jsonObject(expected))
    }

    @Test("Logout registration uses a past Expiry, omits Auth, and encodes the signature in base64")
    func logoutRequest() throws {
        let request = RegisterRequest(
            nodeKey: try #require(NodePublicKey(nodeKey)),
            expiry: Date(timeIntervalSince1970: 123),
            hostinfo: nil,
            ephemeral: true,
            nodeKeySignature: [1, 2, 3]
        )
        let encoded = try jsonObject(JSONEncoder().encode(request))
        #expect(encoded["Expiry"] as? String == "1970-01-01T00:02:03Z")
        #expect(encoded["Auth"] == nil)
        #expect(encoded["Hostinfo"] is NSNull)
        #expect(encoded["Ephemeral"] as? Bool == true)
        #expect(encoded["NodeKeySignature"] as? String == "AQID")
    }

    @Test("The auth key is absent from description, debugDescription, and dump, including output of the request that holds it")
    func authKeyRedacted() throws {
        let secret = "tskey-auth-fake0000-SECRET"
        let auth = RegisterResponseAuth(authKey: secret)
        let request = RegisterRequest(nodeKey: try #require(NodePublicKey(nodeKey)), auth: auth, hostinfo: nil)
        let optional: RegisterResponseAuth? = auth
        func dumped(_ value: some Any) -> String {
            var text = ""
            dump(value, to: &text)
            return text
        }
        let outputs = [
            String(describing: auth), String(reflecting: auth), dumped(auth),
            String(describing: request), String(reflecting: request), dumped(request),
            String(describing: optional), String(reflecting: optional), dumped(optional),
            String(describing: [request]), dumped([request]),
        ]
        for output in outputs {
            #expect(!output.contains("SECRET"), "\(output)")
            #expect(!output.contains("tskey"), "\(output)")
        }
        #expect(dumped(request).contains("authKey: \"<\(secret.count)자>\""))
        // Encoding must send the original text unchanged.
        #expect(try JSONSerialization.jsonObject(with: JSONEncoder().encode(auth)) as? [String: String] == ["AuthKey": secret])
    }

    @Test("Streaming map request")
    func streamMapRequest() throws {
        let request = MapRequest(
            compress: "zstd",
            keepAlive: true,
            nodeKey: try #require(NodePublicKey(nodeKey)),
            discoKey: try #require(DiscoPublicKey(discoKey)),
            stream: true,
            hostinfo: nil,
            endpoints: [try #require(IPEndpoint("[2001:db8::1]:41641")), try #require(IPEndpoint("192.0.2.1:41641"))],
            endpointTypes: [.local, .stun]
        )
        let expected = #"{"Version":148,"Compress":"zstd","KeepAlive":true,"NodeKey":"\#(nodeKey)","DiscoKey":"\#(discoKey)","Stream":true,"Hostinfo":null,"Endpoints":["[2001:db8::1]:41641","192.0.2.1:41641"],"EndpointTypes":[1,2]}"#
        #expect(try jsonObject(JSONEncoder().encode(request)) == jsonObject(expected))
    }

    @Test("A state update map request omits values of 0 and sends opt.Bool only when it has a value")
    func liteMapRequest() throws {
        let hostinfo = Hostinfo(backendLogID: "fake-log-id", os: "iOS", hostname: "rd-mac-1a2b3c4d", userspace: false,
                                netInfo: NetInfo(workingUDP: true, preferredDERP: 1, derpLatency: ["1-v4": 0.025]))
        let request = MapRequest(
            nodeKey: try #require(NodePublicKey(nodeKey)),
            discoKey: try #require(DiscoPublicKey(discoKey)),
            hostinfo: hostinfo,
            omitPeers: true
        )
        let expected = #"{"Version":148,"NodeKey":"\#(nodeKey)","DiscoKey":"\#(discoKey)","Hostinfo":{"BackendLogID":"fake-log-id","OS":"iOS","Hostname":"rd-mac-1a2b3c4d","Userspace":false,"NetInfo":{"WorkingUDP":true,"PreferredDERP":1,"DERPLatency":{"1-v4":0.025}}},"OmitPeers":true}"#
        #expect(try jsonObject(JSONEncoder().encode(request)) == jsonObject(expected))
        // Hostinfo can return as the node's Hostinfo, so it must decode to the same value.
        #expect(try JSONDecoder().decode(Hostinfo.self, from: JSONEncoder().encode(hostinfo)) == hostinfo)
    }

    // MARK: Response decoding

    @Test("Registration response with values of 0")
    func zeroRegisterResponse() throws {
        let json = #"{"User":{"ID":0,"DisplayName":""},"Login":{"ID":0,"Provider":"","LoginName":"","DisplayName":""},"NodeKeyExpired":false,"MachineAuthorized":false,"AuthURL":"","NodeKeySignature":null,"Error":""}"#
        let response = try JSONDecoder().decode(RegisterResponse.self, from: Data(json.utf8))
        #expect(response.user.id == 0)
        #expect(response.nodeKeySignature.isEmpty)
        #expect(response.error.isEmpty && response.authURL.isEmpty)
        #expect(!response.machineAuthorized && !response.nodeKeyExpired)
    }

    @Test("Registration response with values")
    func registerResponse() throws {
        let json = #"{"User":{"ID":100,"DisplayName":"User","Created":"2026-01-02T03:04:05.5+09:00"},"Login":{"ID":7,"Provider":"github","LoginName":"user@example.com","DisplayName":"User"},"MachineAuthorized":true,"AuthURL":"https://login.example/a/1","NodeKeySignature":"AQID","Error":""}"#
        let response = try JSONDecoder().decode(RegisterResponse.self, from: Data(json.utf8))
        #expect(response.user.id == 100)
        #expect(response.user.created == Date(timeIntervalSince1970: 1_767_290_645.5))
        #expect(response.login.provider == "github")
        #expect(response.authURL == "https://login.example/a/1")
        #expect(response.nodeKeySignature == [1, 2, 3])
        #expect(response.machineAuthorized)
    }

    @Test("Keepalive payload")
    func keepAlive() throws {
        let response = try mapResponse(#"{"KeepAlive":true}"#)
        #expect(response.keepAlive)
        #expect(response.node == nil && response.peers == nil && response.packetFilter == nil)
    }

    /// Result of Go 1.27.3 calling `json.Marshal` on `tailcfg.MapResponse` from tailscale.com v1.104.6 with fake values.
    /// Generation: Temporary Go module under `eyebuild dir m2-map`. Copy the go.mod in Tools/interop and use `go run`.
    static let goMarshaledMapResponse = #"{"Node":{"ID":1,"StableID":"nSELF","Name":"rd-mac-1a2b3c4d.tail0001.ts.net.","User":100,"Key":"nodekey:0000000000000000000000000000000000000000000000000000000000000000","Addresses":["100.64.0.1/32","fd7a:115c:a1e0::1/128"],"HomeDERP":1,"Hostinfo":{"OS":"macOS","Hostname":"rd-mac-1a2b3c4d"},"MachineAuthorized":true,"Capabilities":["cap/old"],"CapMap":{"cap/x":null,"cap/y":[{"a":1}]}},"DERPMap":{"Regions":{"1":{"RegionID":1,"RegionCode":"r1","RegionName":"","Nodes":[{"Name":"1a","RegionID":1,"HostName":"derp.example","STUNPort":-1}]}}},"Peers":[{"ID":2,"StableID":"nPEER","Name":"peer.tail0001.ts.net.","User":101,"Key":"nodekey:0000000000000000000000000000000000000000000000000000000000000000","KeyExpiry":"2026-01-02T03:04:05.123456789+09:00","Addresses":["100.64.0.2/32"],"Endpoints":["192.0.2.1:41641","[2001:db8::1]:41641"],"DERP":"127.3.3.40:2","LastSeen":"2026-01-02T03:04:05.123456789+09:00","Online":true}],"OnlineChange":{"2":true},"DNSConfig":{"Domains":["tail0001.ts.net"],"Proxied":true},"Domain":"tail0001.ts.net","PacketFilter":[{"SrcIPs":["*"],"DstPorts":[{"IP":"*","Ports":{"First":0,"Last":65535}}]}],"UserProfiles":[{"ID":100,"LoginName":"user@example.com","DisplayName":"User"}],"ControlTime":"2026-01-02T03:04:05.123456789+09:00"}"#

    @Test("Reads a Go-generated map response")
    func goMarshaled() throws {
        let response = try mapResponse(Self.goMarshaledMapResponse)
        let node = try #require(response.node)
        #expect(node.addresses.map(\.description) == ["100.64.0.1/32", "fd7a:115c:a1e0::1/128"])
        #expect(node.allowedIPs == node.addresses)
        #expect(node.key == .zero)
        #expect(node.hostinfo.hostname == "rd-mac-1a2b3c4d")
        #expect(node.capMap == ["cap/x": [], "cap/y": [.object(["a": .integer(1)])]])
        #expect(node.capabilities == ["cap/old"])

        let peer = try #require(response.peers?.first)
        #expect(peer.homeDERP == 2)                     // from the legacy "DERP" string
        #expect(peer.endpoints.map(\.description) == ["192.0.2.1:41641", "[2001:db8::1]:41641"])
        #expect(peer.online == true)
        // 2026-01-01T18:04:05.123456789Z. Date uses Double, so compare only to microsecond precision.
        let expected = 1_767_290_645.123456789
        #expect(abs(try #require(peer.keyExpiry).timeIntervalSince1970 - expected) < 1e-6)
        #expect(abs(try #require(peer.lastSeen).timeIntervalSince1970 - expected) < 1e-6)

        #expect(response.onlineChange == [2: true])
        #expect(response.derpMap?.regions?[1]?.nodes.first?.stunPort == -1)
        #expect(response.dnsConfig?.proxied == true)
        #expect(response.packetFilter?.first?.dstPorts.first?.ports == PortRange(first: 0, last: 65535))
        #expect(response.userProfiles?.first?.loginName == "user@example.com")
        #expect(response.controlTime != nil)
    }

    @Test("Node normalization uses Addresses if AllowedIPs is omitted, preserves an empty array, and limits unsigned nodes to their own addresses")
    func nodeNormalization() throws {
        func node(_ json: String) throws -> Node { try JSONDecoder().decode(Node.self, from: Data(json.utf8)) }
        let address = try #require(IPPrefix("100.64.0.2/32"))
        let route = try #require(IPPrefix("10.0.0.0/8"))

        #expect(try node(#"{"Addresses":["100.64.0.2/32"]}"#).allowedIPs == [address])
        #expect(try node(#"{"Addresses":["100.64.0.2/32"],"AllowedIPs":null}"#).allowedIPs == [address])
        #expect(try node(#"{"Addresses":["100.64.0.2/32"],"AllowedIPs":[]}"#).allowedIPs == [])
        #expect(try node(#"{"Addresses":["100.64.0.2/32"],"AllowedIPs":["100.64.0.2/32","10.0.0.0/8"]}"#).allowedIPs == [address, route])
        #expect(try node(#"{"Addresses":["100.64.0.2/32"],"AllowedIPs":["10.0.0.0/8"],"UnsignedPeerAPIOnly":true}"#).allowedIPs == [address])
        // When the current HomeDERP is present, ignore the legacy string. Ignore the string if it lacks the magic address.
        #expect(try node(#"{"HomeDERP":5,"DERP":"127.3.3.40:2"}"#).homeDERP == 5)
        #expect(try node(#"{"DERP":"192.0.2.1:2"}"#).homeDERP == 0)
        #expect(try node(#"{"DERP":"127.3.3.40:x"}"#).homeDERP == 0)
        // A KeyExpiry time of 0 means no expiration.
        #expect(try node(#"{"KeyExpiry":"0001-01-01T00:00:00Z"}"#).keyExpiry == nil)
    }

    // MARK: JSON details

    @Test("Map with integer IDs as base-10 string keys")
    func integerKeyedMaps() throws {
        let response = try mapResponse(#"{"PeerSeenChange":{"5":true,"-1":false,"9007199254740993":true}}"#)
        #expect(response.peerSeenChange == [5: true, -1: false, 9_007_199_254_740_993: true])
        #expect(throws: DecodingError.self) { try mapResponse(#"{"OnlineChange":{"abc":true}}"#) }
        #expect(throws: DecodingError.self) { try mapResponse(#"{"OnlineChange":{"99999999999999999999":true}}"#) }
        #expect(throws: DecodingError.self) { try mapResponse(#"{"OnlineChange":{"":true}}"#) }
    }

    @Test("CapMap arguments preserve 64-bit integers and represent other numbers as Double")
    func capMapNumbers() throws {
        let response = try mapResponse(#"""
            {"Node":{"CapMap":{"cap/n":[9007199254740992,9007199254740993,-9223372036854775808,
              9223372036854775808,18446744073709551615,18446744073709551616,1.5,-0,1e2]}}}
            """#)
        #expect(response.node?.capMap["cap/n"] == [
            .integer(9_007_199_254_740_992), .integer(9_007_199_254_740_993), .integer(.min),
            .unsignedInteger(9_223_372_036_854_775_808), .unsignedInteger(.max), .number(18_446_744_073_709_551_616),
            .number(1.5), .integer(0), .integer(100),
        ])
    }

    @Test("Reads IDs beyond 2^53 exactly")
    func largeIDs() throws {
        let response = try mapResponse(#"{"PeersRemoved":[9007199254740993,-9223372036854775808]}"#)
        #expect(response.peersRemoved == [9_007_199_254_740_993, .min])
        #expect(throws: DecodingError.self) { try mapResponse(#"{"PeersRemoved":[9223372036854775808]}"#) }
    }

    @Test("Both null and [] as a CapMap value mean no arguments")
    func capMapNull() throws {
        let response = try mapResponse(#"{"PeersChangedPatch":[{"NodeID":1,"CapMap":{"cap/x":null,"cap/y":[],"cap/z":[true,"s",null,[1]]}}]}"#)
        #expect(response.peersChangedPatch?.first?.capMap == ["cap/x": [], "cap/y": [], "cap/z": [.bool(true), .string("s"), .null, .array([.integer(1)])]])
    }

    @Test("opt.Bool accepts only true, false, and null")
    func optBool() throws {
        func netInfo(_ json: String) throws -> NetInfo { try JSONDecoder().decode(NetInfo.self, from: Data(json.utf8)) }
        #expect(try netInfo(#"{"WorkingUDP":true}"#).workingUDP == true)
        #expect(try netInfo(#"{"WorkingUDP":false}"#).workingUDP == false)
        #expect(try netInfo(#"{"WorkingUDP":null}"#).workingUDP == nil)
        #expect(try netInfo(#"{}"#).workingUDP == nil)
        #expect(throws: DecodingError.self) { try netInfo(#"{"WorkingUDP":"true"}"#) }
    }

    @Test("Ignores unknown keys")
    func unknownKeys() throws {
        let json = #"{"FutureField":{"x":[1,2,{"y":null}]},"Seq":7,"Health":[],"SSHPolicy":{"rules":[]},"Node":{"ID":1,"NewThing":true,"Hostinfo":{"Brand":"new"}},"DERPMap":{"Regions":{"1":{"RegionID":1,"Latitude":1.5,"Nodes":[{"Name":"a","Future":1}]}}}}"#
        let response = try mapResponse(json)
        #expect(response.node?.id == 1)
        #expect(response.derpMap?.regions?[1]?.nodes.first?.name == "a")
    }

    @Test("Rejects a known key with the wrong type", arguments: [
        #"{"KeepAlive":"true"}"#,
        #"{"Node":"x"}"#,
        #"{"Node":{"ID":"1"}}"#,
        #"{"Node":{"ID":1.5}}"#,
        #"{"Node":{"Addresses":["100.64.0.256/32"]}}"#,
        #"{"Node":{"Addresses":["100.64.0.1"]}}"#,
        #"{"Node":{"Key":"mkey:0000000000000000000000000000000000000000000000000000000000000000"}}"#,
        #"{"Node":{"Key":""}}"#,
        #"{"Node":{"Endpoints":["2001:db8::1:41641"]}}"#,
        #"{"Node":{"KeySignature":"!!"}}"#,
        #"{"Node":{"KeyExpiry":"2026-01-02"}}"#,
        #"{"Node":{"Online":1}}"#,
        #"{"Peers":{}}"#,
        #"{"Peers":[null]}"#,
        #"{"PeersRemoved":["1"]}"#,
        #"{"PacketFilter":[{"DstPorts":[{"IP":"*","Ports":{"First":70000,"Last":1}}]}]}"#,
        #"{"PacketFilters":{"x":{}}}"#,
        #"{"DERPMap":{"Regions":[]}}"#,
        #"{"ControlTime":12345}"#,
        #"[]"#,
        #"null"#,
    ])
    func typeMismatch(_ json: String) {
        #expect(throws: (any Error).self) { try mapResponse(json) }
    }

    // MARK: Value types

    @Test("Time parsing accepts fractional seconds and offsets")
    func timeParsing() throws {
        let base = 1_767_323_045.0  // 2026-01-02T03:04:05Z
        #expect(GoTime.parse("2026-01-02T03:04:05Z") == Date(timeIntervalSince1970: base))
        #expect(GoTime.parse("2026-01-02T03:04:05.5Z") == Date(timeIntervalSince1970: base + 0.5))
        #expect(GoTime.parse("2026-01-02T12:04:05+09:00") == Date(timeIntervalSince1970: base))
        #expect(GoTime.parse("2026-01-01T21:34:05-05:30") == Date(timeIntervalSince1970: base))
        // Truncates fractional digits beyond 9.
        #expect(GoTime.parse("2026-01-02T03:04:05.1234567899Z") == GoTime.parse("2026-01-02T03:04:05.123456789Z"))
        #expect(GoTime.parse("0001-01-01T00:00:00Z") == GoTime.zero)
        #expect(GoTime.parse("1969-12-31T23:59:59Z") == Date(timeIntervalSince1970: -1))
        #expect(GoTime.parse("2024-02-29T00:00:00Z") != nil)
    }

    @Test("Time parsing rejects invalid formats and out-of-range values", arguments: [
        "", "2026-01-02", "2026-01-02T03:04:05", "2026-01-02 03:04:05Z", "2026-01-02t03:04:05Z",
        "2026-13-01T00:00:00Z", "2026-00-01T00:00:00Z", "2026-02-29T00:00:00Z", "2026-04-31T00:00:00Z",
        "2026-01-02T24:00:00Z", "2026-01-02T03:60:00Z", "2026-01-02T03:04:60Z",
        "2026-01-02T03:04:05.Z", "2026-01-02T03:04:05+0900", "2026-01-02T03:04:05+24:00",
        "2026-01-02T03:04:05Zjunk", "+2026-01-02T03:04:05Z", "２０２６-01-02T03:04:05Z",
    ])
    func timeRejected(_ text: String) {
        #expect(GoTime.parse(text) == nil)
    }

    @Test("Time formatting uses UTC, drops trailing zeros from fractional seconds, and supports years 0~9999")
    func timeFormatting() {
        #expect(GoTime.format(GoTime.zero) == "0001-01-01T00:00:00Z")
        #expect(GoTime.format(Date(timeIntervalSince1970: 123)) == "1970-01-01T00:02:03Z")
        #expect(GoTime.format(Date(timeIntervalSince1970: 1_767_323_045.5)) == "2026-01-02T03:04:05.5Z")
        #expect(GoTime.format(Date(timeIntervalSince1970: -1)) == "1969-12-31T23:59:59Z")
        #expect(GoTime.format(Date(timeIntervalSince1970: 253_402_300_800)) == nil)  // Year 10000
        #expect(GoTime.format(Date(timeIntervalSince1970: .infinity)) == nil)
        for seconds in stride(from: -62_135_596_800.0, to: 253_402_300_799, by: 9_876_543_210.25) {
            let date = Date(timeIntervalSince1970: seconds)
            #expect(GoTime.format(date).flatMap(GoTime.parse) == date)
        }
    }
}
