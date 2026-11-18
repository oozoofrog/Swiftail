// Tailnet lock without I/O: deciding what to do, filtering, and RPC JSON.
// Contract `docs/contracts/SwiftailTailnetLock.md`, behaviors N2, P, and Y7, unit tests 18, 19, and 21.

import CryptoKit
import Foundation
import Testing

import SwiftailBase
@testable import SwiftailControl
@testable import SwiftailTKA

@Suite("Tailnet lock: Deciding what to do")
struct TailnetLockPlanTests {
    private static func hash(_ byte: UInt8) -> AUMHash? { AUMHash([UInt8](repeating: byte, count: 32)) }

    /// What the server reports: disabled, enabled (no head), enabled (same head as local), and enabled (different head).
    private static let servers: [(name: String, state: ServerLockState)] = [
        ("Disabled", ServerLockState()),
        ("Disabled with a head", ServerLockState(isEnabled: false, head: hash(1))),
        ("Enabled without a head", ServerLockState(isEnabled: true)),
        ("Enabled with the same head", ServerLockState(isEnabled: true, head: hash(1))),
        ("Enabled with a different head", ServerLockState(isEnabled: true, head: hash(2))),
    ]

    @Test("Every table cell: local state × capability × server report")
    func table() {
        // (Whether local state exists, capability) → action for each of the five server states.
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
                #expect(actual == plan, "local \(row.hasLocal), capability \(row.hasCapability), server \(server.name)")
            }
        }
    }

    /// Rechecks the table from contract behavior N2 starting with the server's `TKAInfo`. An unreadable head means "enabled, head unknown," so without local state
    /// it bootstraps (`.unverified` during bootstrap and on failure), and with local state it synchronizes (filtering with the old state meanwhile). No cell means
    /// "pass through without filtering." The only `.nothing` cells have no local state and either no capability (as in Go) or a server report of disabled,
    /// or have matching local and server heads (§5, TL-11b item 3).
    @Test("From TKAInfo to action: An unreadable head means enabled with an unknown head")
    func tableFromTKAInfo() throws {
        let local = try #require(Self.hash(1)), other = try #require(Self.hash(2))
        // (Server-supplied TKAInfo, [no local state and no capability, no local state with capability, local state present])
        let rows: [(json: String?, plans: [TailnetLockPlan])] = [
            (nil, [.nothing, .nothing, .verifyDisablement]),
            (#"{"Disabled":true}"#, [.nothing, .nothing, .verifyDisablement]),
            (#"{"Disabled":true,"Head":"not-a-hash"}"#, [.nothing, .nothing, .verifyDisablement]),
            ("{}", [.nothing, .bootstrap, .synchronize]),
            (#"{"Head":"not-a-hash"}"#, [.nothing, .bootstrap, .synchronize]),
            // Go strips the newline and reads this text, while Swiftail rejects it (behavior D10).
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
            #expect(actual == row.plans, "\(row.json ?? "No TKAInfo")")
        }
    }

    @Test("Compares heads by their 32 bytes instead of their text")
    func headComparison() throws {
        let local = try #require(Self.hash(2))
        // Text differing only in the unused bits of the last character decodes to the same hash (final characters `A` and `B` for a hash whose last bit is 0).
        let sameBytes = try #require(AUMHash(text: String(local.text.dropLast()) + "B"))
        #expect(String(local.text.dropLast()) + "B" != local.text)
        let plan = TailnetLockPlan(localHead: local, hasCapability: false, server: ServerLockState(isEnabled: true, head: sameBytes))
        #expect(plan == .nothing)
    }

    @Test("Checks capability by combining the CapMap keys and the legacy Capabilities list")
    func capability() throws {
        let node = { (extra: String) in
            try JSONDecoder().decode(Node.self, from: Data(#"{"ID":1\#(extra)}"#.utf8))
        }
        #expect(try node("").hasTailnetLockCapability == false)
        #expect(try node(#","CapMap":{"https://tailscale.com/cap/tailnet-lock":null}"#).hasTailnetLockCapability)
        #expect(try node(#","Capabilities":["https://tailscale.com/cap/tailnet-lock"]"#).hasTailnetLockCapability)
        #expect(try node(#","CapMap":{"https://tailscale.com/cap/tailnet-lock-alpha":null}"#).hasTailnetLockCapability == false)
    }

    @Test(".unverified retry interval doubles from 5 seconds up to 5 minutes")
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

@Suite("Tailnet lock: Netmap filtering")
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

    @Test(".enforcing keeps signed peers and UnsignedPeerAPIOnly peers and removes unsigned peers and peers with invalid signatures while preserving order")
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
                // A signature for a different node key and a signature from an untrusted key.
                LockTesting.peerJSON(4, key: keys[2], signature: try signer.signature(for: keys[0])),
                LockTesting.peerJSON(5, key: keys[3], signature: try stranger.signature(for: keys[3])),
                LockTesting.peerJSON(6, key: keys[4], apiOnly: true),
            ]
        )
        let filtered = raw.filtered(by: authority, lockKey: lockKey)
        #expect(filtered.peers.map(\.id) == [2, 6])
        #expect(filtered.tailnetLock == TailnetLockStatus(mode: .enforcing, head: authority.head.text, filteredPeerCount: 3))
        #expect(!filtered.tailnetLock.isLockedOut)
        // Everything except the peers stays unchanged.
        var expected = raw
        expected.peers = filtered.peers
        expected.tailnetLock = filtered.tailnetLock
        #expect(filtered == expected)
    }

    @Test("A key made obsolete by rotation is removed even for an UnsignedPeerAPIOnly peer")
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
                // Two peers exempt from signature checks: one uses a key made obsolete by rotation, and the other uses an unrelated key.
                LockTesting.peerJSON(3, key: oldKey, apiOnly: true),
                LockTesting.peerJSON(4, key: bystander, apiOnly: true),
            ]
        )
        let filtered = raw.filtered(by: authority, lockKey: lockKey)
        #expect(filtered.peers.map(\.id) == [2, 4])
        #expect(filtered.tailnetLock.filteredPeerCount == 1)
    }

    @Test("The self node stays when its signature is missing or unverified, and signingRequest carries both nodekey: and tlpub:")
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
            // The signed peer stays (it excludes this node, so communication fails).
            #expect(filtered.peers.map(\.id) == [2])
        }
        let signed = try netmap(selfNode: LockTesting.selfJSON(key: selfKey, signature: signer.signature(for: selfKey)), peers: peers)
            .filtered(by: authority, lockKey: lockKey)
        #expect(signed.tailnetLock.signingRequest == nil)
    }

    @Test(".unverified removes all peers, including UnsignedPeerAPIOnly and signed peers. The unfiltered netmap is .disabled")
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

@Suite("Tailnet lock: RPC and map request JSON")
struct TKARequestJSONTests {
    private let nodeKey = NodePublicKey(rawValue: [UInt8](repeating: 0x11, count: 32)) ?? .zero

    private func json(_ value: some Encodable) throws -> String {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        return String(decoding: try encoder.encode(value), as: UTF8.self)
    }

    @Test("Three requests: Go field names, Version 148, empty Head as \"\", and empty MissingAUMs as []")
    func requests() throws {
        let key = keyText("nodekey:", byte: 0x11)
        #expect(try json(TKABootstrapRequest(nodeKey: nodeKey, head: "")) == #"{"Head":"","NodeKey":"\#(key)","Version":148}"#)
        #expect(try json(TKASyncOfferRequest(nodeKey: nodeKey, head: "H", ancestors: [])) ==
            #"{"Ancestors":[],"Head":"H","NodeKey":"\#(key)","Version":148}"#)
        #expect(try json(TKASyncOfferRequest(nodeKey: nodeKey, head: "H", ancestors: ["A", "B"])) ==
            #"{"Ancestors":["A","B"],"Head":"H","NodeKey":"\#(key)","Version":148}"#)
        #expect(try json(TKASyncSendRequest(nodeKey: nodeKey, head: "H", missingAUMs: [])) ==
            #"{"Head":"H","Interactive":false,"MissingAUMs":[],"NodeKey":"\#(key)","Version":148}"#)
        // AUMs use standard base64 with padding.
        #expect(try json(TKASyncSendRequest(nodeKey: nodeKey, head: "H", missingAUMs: [[0xfb, 0xff], [1]])) ==
            #"{"Head":"H","Interactive":false,"MissingAUMs":["+/8=","AQ=="],"NodeKey":"\#(key)","Version":148}"#)
    }

    @Test("Responses decode base64 to bytes and missing fields or null to empty values, and reject invalid base64")
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

    /// §5, TL-11b item 5: Check the count before base64-decoding entries. At 4,097 entries, even if the first entry is invalid base64,
    /// the error is the count limit instead.
    @Test("MissingAUMs in a sync/offer response accepts up to 4,096 entries and rejects 4,097 before decoding")
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
                Issue.record("Accepted 4,097 entries")
            } catch DecodingError.dataCorrupted(let context) {
                #expect(context.debugDescription.contains("개수 한도"), "\(first): \(context.debugDescription)")
            }
        }
        // An invalid base64 entry within the limit still fails.
        #expect(throws: DecodingError.self) {
            try JSONDecoder().decode(TKASyncOfferResponse.self, from: body(["*"] + Array(repeating: "AQ==", count: limit - 1)))
        }
    }

    @Test("MapRequest.TKAHead includes the head when present and omits the key when absent")
    func mapRequestHead() throws {
        let without = try json(MapRequest(nodeKey: nodeKey, discoKey: .zero, hostinfo: nil))
        #expect(!without.contains("TKAHead"))
        let with = try json(MapRequest(nodeKey: nodeKey, discoKey: .zero, hostinfo: nil, tkaHead: "HEAD"))
        #expect(with.contains(#""TKAHead":"HEAD""#))
    }
}
