import CryptoKit
import SwiftailBase
import Testing

@testable import SwiftailTKA

/// Peer set outcomes (contract behaviors P1–P5, unit test 11, note §4.9). Uses 8 `peerSets` from the actual Go `tkaFilterNetmapLocked` as the reference.
@Suite("Peer sets")
struct PeerAdmissionTests {
    @Test("All 8 peer sets match Go's retained peers and order")
    func goPeerSets() throws {
        let fixtures = try SignatureFixtureFile.load()
        #expect(fixtures.peerSets.count == 10)
        for item in fixtures.peerSets {
            let peers = try item.peers.map { peer in
                PeerCredential(
                    nodeKey: try SignatureTesting.nodeKey(peer.nodeKey),
                    keySignature: peer.signature.map(ModelTesting.bytes) ?? [],
                    unsignedPeerAPIOnly: peer.unsignedPeerAPIOnly
                )
            }
            let admitted = try fixtures.state(named: item.authority).admitted(peers)
            let kept = zip(peers, admitted).filter(\.1).map { ModelTesting.hex($0.0.nodeKey.rawValue) }
            #expect(kept == item.kept, "\(item.name)")
        }
    }

    /// Test 11 cases: missing signatures, stale keys, only the longest history within a rotation key group, all ties, and no grouping of credential chains.
    @Test("The reference fixtures cover test 11")
    func contractItemsPresent() throws {
        let names = Set(try SignatureFixtureFile.load().peerSets.map(\.name))
        for name in [
            "unsigned-invalid-and-api-only", "rotation-obsoletes-previous", "same-wrapping-longest-wins",
            "same-wrapping-equal-length", "credential-chains-not-grouped",
        ] {
            #expect(names.contains(name), "\(name)")
        }
    }

    /// Go checks all peers for stale keys (`ipn/ipnlocal/tailnet-lock.go:225-231`). The fixtures omit this outcome.
    @Test("An UnsignedPeerAPIOnly peer is also removed when rotation makes its key stale")
    func apiOnlyPeerWithObsoleteKey() throws {
        let lockKey = Curve25519.Signing.PrivateKey()
        let rotationKey = Curve25519.Signing.PrivateKey()
        let state = SignatureTesting.state(trusting: [lockKey])
        let (old, new) = (SignatureTesting.randomNodeKey(), SignatureTesting.randomNodeKey())
        let direct = try SignatureTesting.direct(old, by: lockKey, wrapping: rotationKey.publicKey)
        let rotation = try SignatureTesting.rotation(new, nesting: direct, by: rotationKey)
        let admitted = state.admitted([
            PeerCredential(nodeKey: old, keySignature: [], unsignedPeerAPIOnly: true),
            PeerCredential(nodeKey: new, keySignature: rotation.serialized(), unsignedPeerAPIOnly: false),
            PeerCredential(nodeKey: SignatureTesting.randomNodeKey(), keySignature: [], unsignedPeerAPIOnly: true),
        ])
        #expect(admitted == [false, true, true])
    }

    @Test("Of three peers in one group, only the longest history remains, independently of sorting")
    func longestOfThree() throws {
        let lockKey = Curve25519.Signing.PrivateKey()
        let rotationKey = Curve25519.Signing.PrivateKey()
        let state = SignatureTesting.state(trusting: [lockKey])
        let keys = (0..<6).map { _ in SignatureTesting.randomNodeKey() }
        // Three chains branching from the same direct signature (same rotation key), with history lengths 1, 3, and 2.
        let direct = try SignatureTesting.direct(keys[0], by: lockKey, wrapping: rotationKey.publicKey)
        let one = try SignatureTesting.rotation(keys[1], nesting: direct, by: rotationKey)
        var three = try SignatureTesting.rotation(keys[2], nesting: direct, by: rotationKey)
        three = try SignatureTesting.rotation(keys[3], nesting: three, by: rotationKey)
        three = try SignatureTesting.rotation(keys[4], nesting: three, by: rotationKey)
        var two = try SignatureTesting.rotation(keys[5], nesting: direct, by: rotationKey)
        two = try SignatureTesting.rotation(SignatureTesting.randomNodeKey(), nesting: two, by: rotationKey)
        let twoKey = try #require(NodePublicKey(binaryForm: two.publicKey))
        let admitted = state.admitted([
            PeerCredential(nodeKey: keys[1], keySignature: one.serialized(), unsignedPeerAPIOnly: false),
            PeerCredential(nodeKey: keys[4], keySignature: three.serialized(), unsignedPeerAPIOnly: false),
            PeerCredential(nodeKey: twoKey, keySignature: two.serialized(), unsignedPeerAPIOnly: false),
        ])
        #expect(admitted == [false, true, false])
    }
}
