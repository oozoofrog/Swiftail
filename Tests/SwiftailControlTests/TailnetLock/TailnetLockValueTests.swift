// tailnet lock의 입출력 없는 부분: 할 일의 판정, 거르기, RPC의 JSON.
// 계약 `docs/contracts/SwiftailTailnetLock.md` 동작 N2·P·Y7, 단위 시험 18·19·21.

import CryptoKit
import Foundation
import Testing

import SwiftailBase
@testable import SwiftailControl
@testable import SwiftailTKA

@Suite("tailnet lock: 할 일의 판정")
struct TailnetLockPlanTests {
    private static func hash(_ byte: UInt8) -> AUMHash? { AUMHash([UInt8](repeating: byte, count: 32)) }

    /// 서버가 알린 것: 꺼짐, 켜짐(머리 없음), 켜짐(로컬과 같은 머리), 켜짐(다른 머리).
    private static let servers: [(name: String, state: ServerLockState)] = [
        ("꺼짐", ServerLockState()),
        ("꺼짐·머리 있음", ServerLockState(isEnabled: false, head: hash(1))),
        ("켜짐·머리 없음", ServerLockState(isEnabled: true)),
        ("켜짐·같은 머리", ServerLockState(isEnabled: true, head: hash(1))),
        ("켜짐·다른 머리", ServerLockState(isEnabled: true, head: hash(2))),
    ]

    @Test("표의 모든 칸: 로컬 상태 × capability × 서버가 알린 것")
    func table() {
        // (로컬 상태가 있는가, capability) → 서버 다섯 가지의 할 일.
        let expected: [(hasLocal: Bool, hasCapability: Bool, plans: [TailnetLockPlan])] = [
            (false, false, [.nothing, .nothing, .nothing, .nothing, .nothing]),
            (false, true, [.nothing, .nothing, .bootstrap, .bootstrap, .bootstrap]),
            (true, false, [.verifyDisablement, .verifyDisablement, .synchronize, .nothing, .synchronize]),
            (true, true, [.verifyDisablement, .verifyDisablement, .synchronize, .nothing, .synchronize]),
        ]
        for row in expected {
            for (server, plan) in zip(Self.servers, row.plans) {
                let actual = TailnetLockPlan(
                    localHead: row.hasLocal ? Self.hash(1) : nil, hasCapability: row.hasCapability, server: server.state
                )
                #expect(actual == plan, "로컬 \(row.hasLocal), capability \(row.hasCapability), 서버 \(server.name)")
            }
        }
    }

    /// 계약 동작 N2의 표를 서버가 실은 `TKAInfo`에서부터 다시 본다. 읽히지 않는 머리는 "켜짐, 머리 모름"이라 로컬 상태가 없으면
    /// 부트스트랩(그동안과 실패하면 `.unverified`), 있으면 동기화(그동안 예전 상태로 거른다)로 간다. 어느 칸도 "거르지 않고
    /// 통과"가 되지 않는다: 할 일이 `.nothing`인 칸은 로컬 상태가 없고 capability가 없거나(Go와 같다) 서버가 꺼졌다고 한 것,
    /// 또는 로컬 머리와 서버 머리가 같은 것뿐이다(5절 TL-11b 항목 3).
    @Test("TKAInfo에서 할 일까지: 읽히지 않는 머리는 켜짐·머리 모름이다")
    func tableFromTKAInfo() throws {
        let local = try #require(Self.hash(1)), other = try #require(Self.hash(2))
        // (서버가 실은 TKAInfo, [로컬 없음·capability 없음, 로컬 없음·capability 있음, 로컬 있음])
        let rows: [(json: String?, plans: [TailnetLockPlan])] = [
            (nil, [.nothing, .nothing, .verifyDisablement]),
            (#"{"Disabled":true}"#, [.nothing, .nothing, .verifyDisablement]),
            (#"{"Disabled":true,"Head":"not-a-hash"}"#, [.nothing, .nothing, .verifyDisablement]),
            ("{}", [.nothing, .bootstrap, .synchronize]),
            (#"{"Head":"not-a-hash"}"#, [.nothing, .bootstrap, .synchronize]),
            // Go는 줄바꿈을 지우고 읽고 Swiftail은 거절하는 텍스트(동작 D10).
            (#"{"Head":"\#(local.text.prefix(50))\r\n"}"#, [.nothing, .bootstrap, .synchronize]),
            (#"{"Head":"\#(local.text)"}"#, [.nothing, .bootstrap, .nothing]),
            (#"{"Head":"\#(other.text)"}"#, [.nothing, .bootstrap, .synchronize]),
        ]
        for row in rows {
            let info = try row.json.map { try JSONDecoder().decode(TKAInfo.self, from: Data($0.utf8)) }
            let server = ServerLockState(info)
            let actual = [
                TailnetLockPlan(localHead: nil, hasCapability: false, server: server),
                TailnetLockPlan(localHead: nil, hasCapability: true, server: server),
                TailnetLockPlan(localHead: local, hasCapability: true, server: server),
            ]
            #expect(actual == row.plans, "\(row.json ?? "TKAInfo 없음")")
        }
    }

    @Test("머리는 텍스트가 아니라 32바이트로 견준다")
    func headComparison() throws {
        let local = try #require(Self.hash(2))
        // 끝 글자의 남는 비트만 다른 텍스트는 같은 해시로 읽힌다(마지막 비트가 0인 해시의 끝 글자 `A`와 `B`).
        let sameBytes = try #require(AUMHash(text: String(local.text.dropLast()) + "B"))
        #expect(String(local.text.dropLast()) + "B" != local.text)
        let plan = TailnetLockPlan(localHead: local, hasCapability: false, server: ServerLockState(isEnabled: true, head: sameBytes))
        #expect(plan == .nothing)
    }

    @Test("capability는 CapMap의 키와 옛 Capabilities 목록을 합쳐 본다")
    func capability() throws {
        let node = { (extra: String) in
            try JSONDecoder().decode(Node.self, from: Data(#"{"ID":1\#(extra)}"#.utf8))
        }
        #expect(try node("").hasTailnetLockCapability == false)
        #expect(try node(#","CapMap":{"https://tailscale.com/cap/tailnet-lock":null}"#).hasTailnetLockCapability)
        #expect(try node(#","Capabilities":["https://tailscale.com/cap/tailnet-lock"]"#).hasTailnetLockCapability)
        #expect(try node(#","CapMap":{"https://tailscale.com/cap/tailnet-lock-alpha":null}"#).hasTailnetLockCapability == false)
    }

    @Test(".unverified의 재시도 간격: 5초에서 두 배씩, 5분까지")
    func retryDelay() {
        let range = Duration.seconds(5)...Duration.seconds(300)
        let delays = (1...9).map { ControlClient.lockRetryDelay(failures: $0, within: range) }
        #expect(delays == [5, 10, 20, 40, 80, 160, 300, 300, 300].map { Duration.seconds($0) })
        #expect(ControlClient.lockRetryDelay(failures: 0, within: range) == .seconds(5))
        #expect(ControlClient.lockRetryDelay(failures: .max, within: range) == .seconds(300))
        #expect(ControlClient.Timeouts().lockRetry == range)
        #expect(ControlClient.Timeouts().tkaRequest == .seconds(60))
    }
}

@Suite("tailnet lock: netmap 거르기")
struct NetmapLockFilterTests {
    private let signer = LockTesting.Signer()
    private let lockKey = NLPublicKey(Curve25519.Signing.PrivateKey().publicKey)

    private func authority() throws -> Authority {
        try Authority(bootstrappingWith: LockTesting.checkpoint(trusting: [signer], signedBy: signer))
    }

    private func netmap(selfNode: String, peers: [String]) throws -> Netmap {
        var session = MapSession()
        let update = try session.apply(mapResponse(LockTesting.mapJSON(selfNode: selfNode, peers: peers)), receivedAt: receivedAt)
        return try #require(update.netmap)
    }

    @Test(".enforcing: 서명된 피어와 UnsignedPeerAPIOnly 피어가 남고, 서명 없는 피어와 틀린 서명의 피어가 순서를 지키며 빠진다")
    func enforcing() throws {
        let authority = try authority()
        let stranger = LockTesting.Signer()
        let keys = (0..<5).map { _ in LockTesting.newNodeKey() }
        let selfKey = LockTesting.newNodeKey()
        let raw = try netmap(
            selfNode: LockTesting.selfJSON(key: selfKey, signature: signer.signature(for: selfKey)),
            peers: [
                LockTesting.peerJSON(2, key: keys[0], signature: try signer.signature(for: keys[0])),
                LockTesting.peerJSON(3, key: keys[1]),
                // 다른 node 키에 대한 서명과, 신뢰 키가 아닌 키의 서명.
                LockTesting.peerJSON(4, key: keys[2], signature: try signer.signature(for: keys[0])),
                LockTesting.peerJSON(5, key: keys[3], signature: try stranger.signature(for: keys[3])),
                LockTesting.peerJSON(6, key: keys[4], apiOnly: true),
            ]
        )
        let filtered = raw.filtered(by: authority, lockKey: lockKey)
        #expect(filtered.peers.map(\.id) == [2, 6])
        #expect(filtered.tailnetLock == TailnetLockStatus(mode: .enforcing, head: authority.head.text, filteredPeerCount: 3))
        #expect(!filtered.tailnetLock.isLockedOut)
        // 피어 말고는 그대로다.
        var expected = raw
        expected.peers = filtered.peers
        expected.tailnetLock = filtered.tailnetLock
        #expect(filtered == expected)
    }

    @Test("회전으로 낡은 키는 UnsignedPeerAPIOnly 피어여도 빠진다")
    func obsoleteKeyOfAPIOnlyPeer() throws {
        let authority = try authority()
        let rotationKey = Curve25519.Signing.PrivateKey()
        let (oldKey, newKey, bystander) = (LockTesting.newNodeKey(), LockTesting.newNodeKey(), LockTesting.newNodeKey())
        let rotated = try LockTesting.rotation(
            to: newKey, nesting: signer.signature(for: oldKey, rotationKey: rotationKey.publicKey), by: rotationKey
        )
        let raw = try netmap(
            selfNode: LockTesting.selfJSON(key: LockTesting.newNodeKey()),
            peers: [
                LockTesting.peerJSON(2, key: newKey, signature: rotated),
                // 서명 검사를 받지 않는 피어 둘: 하나는 회전으로 낡은 키를 쓰고, 하나는 무관한 키다.
                LockTesting.peerJSON(3, key: oldKey, apiOnly: true),
                LockTesting.peerJSON(4, key: bystander, apiOnly: true),
            ]
        )
        let filtered = raw.filtered(by: authority, lockKey: lockKey)
        #expect(filtered.peers.map(\.id) == [2, 4])
        #expect(filtered.tailnetLock.filteredPeerCount == 1)
    }

    @Test("자기 노드: 서명이 없거나 검증되지 않으면 빠지지 않고 signingRequest에 nodekey:·tlpub: 두 값이 실린다")
    func lockedOut() throws {
        let authority = try authority()
        let selfKey = LockTesting.newNodeKey()
        let peerKey = LockTesting.newNodeKey()
        let peers = [LockTesting.peerJSON(2, key: peerKey, signature: try signer.signature(for: peerKey))]
        let request = TailnetLockStatus.SigningRequest(
            nodeKey: "nodekey:" + selfKey.rawValue.hex, lockKey: "tlpub:" + lockKey.rawValue.hex
        )
        for signature in [[], try LockTesting.Signer().signature(for: selfKey), try signer.signature(for: peerKey)] {
            let filtered = try netmap(selfNode: LockTesting.selfJSON(key: selfKey, signature: signature), peers: peers)
                .filtered(by: authority, lockKey: lockKey)
            #expect(filtered.selfNode.key == selfKey)
            #expect(filtered.tailnetLock.signingRequest == request)
            #expect(filtered.tailnetLock.isLockedOut)
            // 서명된 피어는 남는다(그 피어가 이 노드를 빼므로 통신은 되지 않는다).
            #expect(filtered.peers.map(\.id) == [2])
        }
        let signed = try netmap(selfNode: LockTesting.selfJSON(key: selfKey, signature: signer.signature(for: selfKey)), peers: peers)
            .filtered(by: authority, lockKey: lockKey)
        #expect(signed.tailnetLock.signingRequest == nil)
    }

    @Test(".unverified: 피어를 모두 뺀다(UnsignedPeerAPIOnly와 서명된 피어 포함). 거르기 전의 netmap은 .disabled다")
    func unverified() throws {
        let key = LockTesting.newNodeKey()
        let raw = try netmap(
            selfNode: LockTesting.selfJSON(key: LockTesting.newNodeKey()),
            peers: [
                LockTesting.peerJSON(2, key: key, signature: try signer.signature(for: key)),
                LockTesting.peerJSON(3, key: LockTesting.newNodeKey(), apiOnly: true),
            ]
        )
        #expect(raw.tailnetLock == TailnetLockStatus(mode: .disabled, head: nil, filteredPeerCount: 0, signingRequest: nil))
        let withheld = raw.withholdingPeers()
        #expect(withheld.peers.isEmpty)
        #expect(withheld.tailnetLock == TailnetLockStatus(mode: .unverified, filteredPeerCount: 2))
        #expect(withheld.selfNode == raw.selfNode)
    }
}

@Suite("tailnet lock: RPC와 맵 요청의 JSON")
struct TKARequestJSONTests {
    private let nodeKey = NodePublicKey(rawValue: [UInt8](repeating: 0x11, count: 32)) ?? .zero

    private func json(_ value: some Encodable) throws -> String {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        return String(decoding: try encoder.encode(value), as: UTF8.self)
    }

    @Test("요청 셋: Go 필드 이름, Version 148, 빈 Head도 \"\"로, 빈 MissingAUMs도 []로")
    func requests() throws {
        let key = keyText("nodekey:", byte: 0x11)
        #expect(try json(TKABootstrapRequest(nodeKey: nodeKey, head: "")) == #"{"Head":"","NodeKey":"\#(key)","Version":148}"#)
        #expect(try json(TKASyncOfferRequest(nodeKey: nodeKey, head: "H", ancestors: [])) ==
            #"{"Ancestors":[],"Head":"H","NodeKey":"\#(key)","Version":148}"#)
        #expect(try json(TKASyncOfferRequest(nodeKey: nodeKey, head: "H", ancestors: ["A", "B"])) ==
            #"{"Ancestors":["A","B"],"Head":"H","NodeKey":"\#(key)","Version":148}"#)
        #expect(try json(TKASyncSendRequest(nodeKey: nodeKey, head: "H", missingAUMs: [])) ==
            #"{"Head":"H","Interactive":false,"MissingAUMs":[],"NodeKey":"\#(key)","Version":148}"#)
        // AUM은 패딩 있는 표준 base64다.
        #expect(try json(TKASyncSendRequest(nodeKey: nodeKey, head: "H", missingAUMs: [[0xfb, 0xff], [1]])) ==
            #"{"Head":"H","Interactive":false,"MissingAUMs":["+/8=","AQ=="],"NodeKey":"\#(key)","Version":148}"#)
    }

    @Test("응답: base64를 바이트로, 없는 필드와 null은 빈 값으로, base64가 아니면 실패")
    func responses() throws {
        let decode = { (json: String) in try JSONDecoder().decode(TKABootstrapResponse.self, from: Data(json.utf8)) }
        let bootstrap = try decode(#"{"GenesisAUM":"+/8=","DisablementSecret":"AQID"}"#)
        #expect(bootstrap.genesisAUM == [0xfb, 0xff])
        #expect(bootstrap.disablementSecret == [1, 2, 3])
        #expect(try decode("{}").genesisAUM.isEmpty)
        #expect(try decode(#"{"GenesisAUM":null}"#).disablementSecret.isEmpty)
        #expect(throws: (any Error).self) { try decode(#"{"GenesisAUM":"*"}"#) }
        #expect(throws: (any Error).self) { try decode("null") }

        let offer = { (json: String) in try JSONDecoder().decode(TKASyncOfferResponse.self, from: Data(json.utf8)) }
        let full = try offer(#"{"Head":"H","Ancestors":["A"],"MissingAUMs":["AQ==","+/8="]}"#)
        #expect(full.head == "H")
        #expect(full.ancestors == ["A"])
        #expect(full.missingAUMs == [[1], [0xfb, 0xff]])
        let empty = try offer(#"{"Head":"H","Ancestors":null,"MissingAUMs":null}"#)
        #expect(empty.ancestors.isEmpty && empty.missingAUMs.isEmpty)
        #expect(throws: (any Error).self) { try offer(#"{"Head":"H","MissingAUMs":["*"]}"#) }
        #expect(throws: (any Error).self) { try offer(#"{"Head":"H","MissingAUMs":"AQ=="}"#) }

        #expect(try JSONDecoder().decode(TKASyncSendResponse.self, from: Data(#"{"Head":"H"}"#.utf8)).head == "H")
    }

    /// 5절 TL-11b 항목 5: 개수는 항목을 base64로 디코딩하기 전에 본다. 4,097개째에서 첫 항목이 base64가 아니어도 그 오류가
    /// 아니라 개수 한도로 떨어진다.
    @Test("sync/offer 응답의 MissingAUMs: 4,096개까지 받고 4,097개는 디코딩 전에 거절한다")
    func missingAUMCountLimit() throws {
        let limit = TKASyncOfferResponse.maximumMissingAUMCount
        #expect(limit == 4_096)
        let body = { (items: [String]) in
            Data(#"{"Head":"H","MissingAUMs":[\#(items.map { #""\#($0)""# }.joined(separator: ","))]}"#.utf8)
        }
        let accepted = try JSONDecoder().decode(TKASyncOfferResponse.self, from: body(Array(repeating: "AQ==", count: limit)))
        #expect(accepted.missingAUMs.count == limit && accepted.missingAUMs.allSatisfy { $0 == [1] })

        for first in ["AQ==", "*"] {
            let items = [first] + Array(repeating: "AQ==", count: limit)
            do {
                _ = try JSONDecoder().decode(TKASyncOfferResponse.self, from: body(items))
                Issue.record("4,097개를 받았다")
            } catch DecodingError.dataCorrupted(let context) {
                #expect(context.debugDescription.contains("개수 한도"), "\(first): \(context.debugDescription)")
            }
        }
        // 한도 안에서 base64가 아닌 항목은 그대로 실패한다.
        #expect(throws: DecodingError.self) {
            try JSONDecoder().decode(TKASyncOfferResponse.self, from: body(["*"] + Array(repeating: "AQ==", count: limit - 1)))
        }
    }

    @Test("MapRequest.TKAHead: 머리가 있으면 싣고, 없으면 키가 빠진다")
    func mapRequestHead() throws {
        let without = try json(MapRequest(nodeKey: nodeKey, discoKey: .zero, hostinfo: nil))
        #expect(!without.contains("TKAHead"))
        let with = try json(MapRequest(nodeKey: nodeKey, discoKey: .zero, hostinfo: nil, tkaHead: "HEAD"))
        #expect(with.contains(#""TKAHead":"HEAD""#))
    }
}
