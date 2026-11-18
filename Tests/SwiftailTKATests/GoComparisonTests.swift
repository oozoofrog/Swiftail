import CryptoKit
import Foundation
import SwiftailBase
import SwiftailCrypto
import Testing

@testable import SwiftailTKA

/// Compares Go `tka` outcomes (`Fixtures/tka-fixtures.json`) with Swift implementation outcomes for every row (contract §7, Go reference comparison, TL-5).
///
/// Written separately from the implementation sessions' unit tests using only the contract, fixtures, and tool. Gets results from the `package` surface used by later units (TL-6 and TL-7):
/// `AUM(decoding:)`·`validate()`·`serialized()`·`hash`·`signatureHash`, `NodeKeySignature(decoding:)`, `AUMHash(text:)`,
/// `Authority(bootstrappingWith:)`·`inform`·`syncOffer`·`missingAUMs`·`isValidDisablement`, `AuthorityState.authorize`·`admitted`,
/// `WrappedAuthKey(parsing:)`, `keySignature(for:)`, and `NodeKeySignature.resigned`. Internal declarations (memberwise initializers and
/// `binaryForm`) are used only to prepare test data.
///
/// Each test's comments state what must match per row. For intended differences defined by the contract, verify the expected Swift answer for the row
/// and count it by ID (behavior or decision) without skipping it. Print rows, matches, intended differences by ID, and mismatches once per array.
@Suite("Go comparison: every row in tka-fixtures.json")
struct GoComparisonTests {
    typealias G = GoComparison

    // MARK: Inventory

    /// The fixture contains only top-level arrays known to this test, and their row counts sum to `caseCount`. No array is missing from the comparison.
    @Test("Array inventory and caseCount")
    func inventory() throws {
        let data = try Data(contentsOf: try GoFixture.url)
        let object = try #require(try JSONSerialization.jsonObject(with: data) as? [String: Any])
        #expect(Set(object.keys) == GoFixture.sectionNames.union(["reference", "caseCount"]))
        let fixture = try GoFixture.load()
        #expect(fixture.reference.tailscale == "v1.104.6")
        let rows = fixture.countedRows
        #expect(rows.values.reduce(0, +) == fixture.caseCount)
        print(
            "Go comparison caseCount \(fixture.caseCount) ="
                + rows.sorted { $0.key < $1.key }.map { "\($0.key) \($0.value)" }.joined(separator: " + ")
        )
    }

    // MARK: Inputs (keys, authorities)

    /// Test keys: seed = SHA-256(seed string), Ed25519 public key, node key (X25519) public key, and `nodekey:` text match Go.
    /// This target has no surface for `tlpub:` text (SwiftailControl, TL-6 and TL-7).
    @Test("keys: Test key derivation")
    func keys() throws {
        let fixture = try GoFixture.load()
        for key in fixture.keys {
            let seed = Array(SHA256.hash(data: Array(key.seed.utf8)))
            var problems: [String] = []
            if G.hex(seed) != key.private { problems.append("seed") }
            switch key.role {
            case "node":
                let publicKey = try Curve25519.KeyAgreement.PrivateKey(rawRepresentation: seed).publicKey
                if G.hex(publicKey.rawRepresentation) != key.public { problems.append("public key") }
                if NodePublicKey(publicKey).description != key.text { problems.append("text") }
            case "disablement":
                break
            default:
                let publicKey = try Curve25519.Signing.PrivateKey(rawRepresentation: seed).publicKey
                if G.hex(publicKey.rawRepresentation) != key.public { problems.append("public key") }
            }
            ComparisonTally.record(
                problems.isEmpty ? .same : .mismatch(problems.joined(separator: ", ")), section: "keys",
                row: "\(key.role)/\(key.index)", total: fixture.keys.count
            )
        }
    }

    /// Trust state used for decisions: after bootstrap and one admission group, the head and state match Go.
    @Test("authorities: Trust state used for decisions")
    func authorities() throws {
        let fixture = try GoFixture.load()
        for entry in fixture.authorities {
            let authority = Result { () throws(TKAError) in try G.authority(entry.aums.map { hex throws(TKAError) in try G.aum(hex) }) }
            let comparison: Comparison
            switch authority {
            case .failure(let error): comparison = .mismatch("Swift rejects: \(error)")
            case .success(let authority):
                comparison = G.difference(authority, entry.state).map { .mismatch($0) } ?? .same
            }
            ComparisonTally.record(comparison, section: "authorities", row: entry.name, total: fixture.authorities.count)
        }
    }

    // MARK: text

    /// `AUMHash` text with line breaks. Go `UnmarshalText` measures the length before removing line breaks (`DecodedLen(52) = 32`),
    /// then `base32.Decode` removes `\r` and `\n` and reads the remaining 50, 51, or 48 characters, filling only 31 or 30 bytes and leaving the rest zero (`tka/aum.go:33-41`).
    /// The contract left this undecided (§5 TL-2, decide whether to match Go after comparison). Leave it as a mismatch.
    static let aumHashLineBreakRows: Set<String> = [
        "aum-hash-50-chars-crlf", "aum-hash-50-chars-lf-lf", "aum-hash-50-chars-cr-cr", "aum-hash-crlf-inside",
        "aum-hash-leading-lf-lf", "aum-hash-48-chars-4-lf", "aum-hash-51-chars-lf", "aum-hash-52-chars-lf",
        "aum-hash-52-chars-lf-inside",
    ]

    /// `AUMHash` writing and reading (outcome and the same 32 bytes if accepted), and node key text and binary format (`np` ‖ 32 bytes).
    /// `nlpub:`, `tlpub:`, and `nlpriv:` are SwiftailControl surfaces (TL-6. Checking the last 32 bytes of `nlpriv` is intended difference R1).
    @Test("text: AUMHash text and key text")
    func text() throws {
        let fixture = try GoFixture.load()
        for item in fixture.text where !Self.aumHashLineBreakRows.contains(item.name) {
            ComparisonTally.record(Self.compareText(item), section: "text", row: item.name, total: fixture.text.count)
        }
    }

    /// Go measures the character count before removing line breaks and decodes after removing them, filling only 31 or 30 bytes and accepting a **hash different from the original**
    /// (`tka/aum.go:33-41`). Swiftail accepts only 52 characters from the alphabet (contract behavior D10).
    @Test("text: Rejects AUMHash text with line breaks (Go accepts a truncated hash, intended difference D10)")
    func aumHashLineBreaks() throws {
        let fixture = try GoFixture.load()
        for item in fixture.text where Self.aumHashLineBreakRows.contains(item.name) {
            let comparison: Comparison = AUMHash(text: item.input) != nil
                ? .mismatch("Swift accepted text with line breaks")
                : item.ok ? .intended("D10") : .same
            ComparisonTally.record(comparison, section: "text", row: item.name, total: fixture.text.count)
        }
    }

    static func compareText(_ item: GoFixture.Text) -> Comparison {
        func check(_ same: Bool, _ detail: @autoclosure () -> String) -> Comparison { same ? .same : .mismatch(detail()) }
        switch item.kind {
        case "aumHash.encode":
            let text = AUMHash(G.bytes(item.input))?.text
            return check(text == item.output, "Swift \(text ?? "nil")")
        case "aumHash.decode":
            let hash = AUMHash(text: item.input)
            return check(
                (hash != nil) == item.ok && (hash == nil || hash.map { G.hex($0.bytes) } == item.output),
                "Go \(item.ok ? "accepted \(item.output ?? "")" : "rejected"), Swift \(hash.map { "accepted \(G.hex($0.bytes))" } ?? "rejected")"
            )
        case "nodePublic.encode":
            return check(NodePublicKey(rawValue: G.bytes(item.input))?.description == item.output, "text")
        case "nodePublic.binary":
            return check(NodePublicKey(rawValue: G.bytes(item.input)).map { G.hex($0.binaryForm) } == item.output, "binary format")
        default:
            return .noSurface("SwiftailControl NL key (TL-6)")
        }
    }

    // MARK: encodings

    /// Canonical bytes for a Key or State. Swift has no standalone encoding surface, so encode them within AUMs (AddKey `a3 0101 02f6 03 <Key>`,
    /// Checkpoint `a3 0105 02f6 05 <State>`). Swiftail writes Go nil arrays (`f6`) as empty arrays (`80`, intended difference E6).
    @Test("encodings: Canonical Key and State bytes")
    func encodings() throws {
        let fixture = try GoFixture.load()
        for item in fixture.encodings {
            let value = item.value
            let comparison: Comparison
            if item.type == "key" {
                let key = try Self.trustedKey(value.kind, value.votes, value.public, value.meta)
                let written = G.hex(AUM(messageKind: 1, prevAUMHash: nil, key: key).serialized())
                comparison = written == "a3010102f603" + item.encoded ? .same : .mismatch("Swift \(written)")
            } else {
                let state = AuthorityState(
                    lastAUMHash: value.lastAUMHash.flatMap { AUMHash(G.bytes($0)) },
                    disablementValues: (value.disablementValues ?? []).map(G.bytes),
                    keys: try (value.keys ?? []).map { try Self.trustedKey($0.kind, $0.votes, $0.public, $0.meta) },
                    stateID1: try #require(UInt64(value.stateID1 ?? "")),
                    stateID2: try #require(UInt64(value.stateID2 ?? ""))
                )
                let written = G.hex(AUM(messageKind: 5, prevAUMHash: nil, state: state).serialized())
                let goBytes = "a3010502f605" + item.encoded
                if value.disablementValues == nil || value.keys == nil {
                    // E6: State bytes must differ only in replacing Go nil arrays with `80` (a State with a null array has no elements).
                    var expected = item.encoded
                    if value.disablementValues == nil { expected = expected.replacingOccurrences(of: "02f6", with: "0280") }
                    if value.keys == nil { expected = expected.replacingOccurrences(of: "03f6", with: "0380") }
                    comparison = written == "a3010502f605" + expected ? .intended("E6") : .mismatch("Swift \(written)")
                } else {
                    comparison = written == goBytes ? .same : .mismatch("Swift \(written)")
                }
            }
            ComparisonTally.record(comparison, section: "encodings", row: item.name, total: fixture.encodings.count)
        }
    }

    static func trustedKey(_ kind: UInt8?, _ votes: UInt64?, _ publicKey: String?, _ meta: [String: String]?) throws -> TrustedKey {
        TrustedKey(
            kind: try #require(kind), votes: try #require(votes), publicKey: publicKey.map(G.bytes),
            meta: (meta ?? [:]).map { MetaEntry(key: Array($0.key.utf8), value: Array($0.value.utf8)) }
        )
    }

    // MARK: cbor

    /// Non-null `LastAUMHash` in checkpoint `State`: Go rejects it during static validation after reading it, and Swiftail rejects it during decoding (behavior D8).
    static let decodingD8: Set<String> = ["accept/checkpoint-last-aum-hash-2-bytes", "value/checkpoint-last-aum-hash"]

    /// AUM: Swift decoding and passing static validation matches Go `accepted`. Decode outcomes also match, except for D8.
    /// Inputs accepted by Go have identical rewritten bytes, `Hash`, and `SigHash` (behavior E5). Rewritten bytes for inputs both reject are not compared. Differences
    /// count as E6 (contract §7: only compare outcomes for inputs failing static validation). NKS: Decode outcomes match, and decoded inputs have the same rewritten bytes
    /// and `SigHash`.
    @Test("cbor: Decoding, static validation, canonical bytes, and hashes")
    func cbor() throws {
        let fixture = try GoFixture.load()
        for item in fixture.cbor {
            ComparisonTally.record(Self.compareCBOR(item), section: "cbor", row: item.name, total: fixture.cbor.count)
        }
    }

    static func compareCBOR(_ item: GoFixture.CBORCase) -> Comparison {
        let input = G.bytes(item.input)
        if item.type == "nks" {
            let decoded = Result { () throws(TKAError) in try NodeKeySignature(decoding: input) }
            switch decoded {
            case .failure(let error):
                return item.decoded ? .mismatch("Go decodes, Swift \(error)") : .same
            case .success(let signature):
                guard item.decoded else { return .mismatch("Go rejects (\(item.error ?? "")), Swift decodes") }
                let same = G.hex(signature.serialized()) == item.reencoded && G.hex(signature.signatureHash) == item.sigHash
                return same ? .same : .mismatch("Rewritten bytes \(G.hex(signature.serialized()))")
            }
        }
        let decoded = Result { () throws(TKAError) in try AUM(decoding: input) }
        switch decoded {
        case .failure(let error):
            if !item.decoded { return .same }
            if decodingD8.contains(item.name), error == .invalidStructure, item.staticValid == false, !item.accepted {
                return .intended("D8")
            }
            return .mismatch("Go decodes, Swift \(error)")
        case .success(let aum):
            guard item.decoded else { return .mismatch("Go rejects (\(item.error ?? "")), Swift decodes") }
            let valid = (try? aum.validate()) != nil
            guard valid == item.accepted else {
                return .mismatch("Static validation: Go \(item.accepted), Swift \(valid)")
            }
            let reencoded = G.hex(aum.serialized())
            if item.accepted {
                let same = reencoded == item.reencoded && G.hex(aum.hash.bytes) == item.hash && G.hex(aum.signatureHash) == item.sigHash
                return same ? .same : .mismatch("Rewritten bytes \(reencoded)")
            }
            return reencoded == item.reencoded ? .same : .intended("E6")
        }
    }

    // MARK: chains

    /// Per chain (one row): bootstrap outcome and initial state, then admission outcome, head, and state at each step (keys, Votes, Meta, disablement values, and StateID).
    @Test("chains: Bootstrap and per-step outcomes, head, and state")
    func chains() throws {
        let fixture = try GoFixture.load()
        for chain in fixture.chains {
            ComparisonTally.record(Self.compareChain(chain), section: "chains", row: chain.name, total: fixture.chains.count)
        }
    }

    static func compareChain(_ chain: GoFixture.Chain) -> Comparison {
        let bootstrapped = Result { () throws(TKAError) in try Authority(bootstrappingWith: G.aum(chain.bootstrap)) }
        guard case .success(var authority) = bootstrapped else {
            return chain.bootstrapOK ? .mismatch("Bootstrap: Swift \(bootstrapped)") : .same
        }
        guard chain.bootstrapOK else { return .mismatch("Bootstrap: Go rejects (\(chain.bootstrapError ?? ""))") }
        var problems: [String] = []
        if let initial = chain.initial, let difference = G.difference(authority, initial) { problems.append("Initial \(difference)") }
        for step in chain.steps {
            let result = Result { () throws(TKAError) in try authority.inform(step.aums.map { hex throws(TKAError) in try G.aum(hex) }) }
            let ok = if case .success = result { true } else { false }
            if ok != step.ok { problems.append("\(step.name) outcome: Go \(step.ok) \(step.error ?? ""), Swift \(result)") }
            if let difference = G.difference(authority, step.after) { problems.append("\(step.name) \(difference)") }
        }
        return problems.isEmpty ? .same : .mismatch(problems.joined(separator: "; "))
    }

    // MARK: sync

    static let syncCaseNames: [String] =
        (try? GoFixture.load()).map { $0.sync.flatMap { group in group.cases.map { "\(group.name)/\($0.name)" } } } ?? []

    /// For each case: both offers (head, ancestor list, and base32 text), `MissingAUMs` for the peer's offer (success, count, list of hashes, and their SHA-256),
    /// the outcome of admitting the peer's list, and the resulting head. As in Go, calculate both lists before admitting either (behaviors Y4 and Y5).
    @Test("sync: Offers, MissingAUMs, and head after admission", .timeLimit(.minutes(10)), arguments: syncCaseNames)
    func sync(_ name: String) throws {
        let fixture = try GoFixture.load()
        let group = try #require(fixture.sync.first { name.hasPrefix("\($0.name)/") })
        let syncCase = try #require(group.cases.first { "\(group.name)/\($0.name)" == name })
        let pool = try group.pool.map { hex throws(TKAError) in try G.aum(hex) }
        var local = try G.authority(syncCase.local.aums.map { pool[$0] })
        var remote = try G.authority(syncCase.remote.aums.map { pool[$0] })
        var problems: [String] = []
        let localOffer = local.syncOffer()
        let remoteOffer = remote.syncOffer()
        for (label, offer, expected) in [("local", localOffer, syncCase.local.offer), ("remote", remoteOffer, syncCase.remote.offer)] {
            let same =
                G.hex(offer.head.bytes) == expected.head && offer.ancestors.map { G.hex($0.bytes) } == expected.ancestors
                && offer.head.text == expected.headText && offer.ancestors.map(\.text) == expected.ancestorsText
            if !same { problems.append("\(label) offer") }
        }
        let localSends = Result { () throws(TKAError) in try local.missingAUMs(for: remoteOffer) }
        let remoteSends = Result { () throws(TKAError) in try remote.missingAUMs(for: localOffer) }
        for (label, sends, expected) in [("local", localSends, syncCase.local.missing), ("remote", remoteSends, syncCase.remote.missing)] {
            switch sends {
            case .failure(let error):
                if expected.ok { problems.append("\(label) MissingAUMs: Swift \(error)") }
            case .success(let aums):
                guard expected.ok else {
                    problems.append("\(label) MissingAUMs: Go fails (\(expected.error ?? ""))")
                    continue
                }
                let hashes = aums.map(\.hash.bytes)
                let digest = G.hex(SHA256.hash(data: hashes.flatMap { $0 }))
                if hashes.count != expected.count || digest != expected.digest
                    || (expected.hashes.map { $0 != hashes.map(G.hex) } ?? false)
                {
                    problems.append("\(label) MissingAUMs: Go count \(expected.count), Swift count \(hashes.count)")
                }
            }
        }
        func receive(_ sends: Result<[AUM], TKAError>, into authority: inout Authority, expected: GoFixture.SyncSide, _ label: String) {
            var ok = true
            if case .success(let aums) = sends, !aums.isEmpty {
                do { try authority.inform(aums) } catch { ok = false }
            }
            if ok != expected.informOK { problems.append("\(label) admission: Go \(expected.informOK) \(expected.informError ?? "")") }
            if G.hex(authority.head.bytes) != expected.headAfter { problems.append("\(label) head after admission") }
        }
        receive(remoteSends, into: &local, expected: syncCase.local, "local")
        receive(localSends, into: &remote, expected: syncCase.remote, "remote")
        ComparisonTally.record(
            problems.isEmpty ? .same : .mismatch(problems.joined(separator: "; ")), section: "sync", row: name,
            total: Self.syncCaseNames.count
        )
    }

    // MARK: signatures

    /// Per row: `authorize` outcome and, for accepted rotations, history (`PrevNodeKeys` order, first signature kind, and `WrappingPubkey`).
    /// If Go decodes an NKS, Swift also decodes it and matches `SigHash`.
    @Test("signatures: NKS outcomes and history")
    func signatures() throws {
        let fixture = try GoFixture.load()
        var states: [String: AuthorityState] = [:]
        for item in fixture.signatures {
            if states[item.authority] == nil { states[item.authority] = try G.authority(named: item.authority, in: fixture).state }
            let state = try #require(states[item.authority])
            var problems: [String] = []
            let nks = G.bytes(item.nks)
            if let goHash = item.sigHash {
                let swiftHash = (try? NodeKeySignature(decoding: nks)).map { G.hex($0.signatureHash) }
                if swiftHash != goHash { problems.append("SigHash: Swift \(swiftHash ?? "decode failed")") }
            }
            let verdict = G.verdict(authorized: item.authorized, error: item.error, rotation: item.rotation)
            if let difference = G.difference(state, nodeKey: try G.nodeKey(item.nodeKey), nks: nks, expected: verdict) {
                problems.append("\(difference) (Go: \(item.error ?? "authorized"))")
            }
            ComparisonTally.record(
                problems.isEmpty ? .same : .mismatch(problems.joined(separator: "; ")), section: "signatures", row: item.name,
                total: fixture.signatures.count
            )
        }
    }

    // MARK: peerSets

    static func peers(_ peers: [GoFixture.Peer]) throws -> [PeerCredential] {
        try peers.map {
            PeerCredential(nodeKey: try G.nodeKey($0.nodeKey), keySignature: G.bytes($0.signature), unsignedPeerAPIOnly: $0.unsignedPeerAPIOnly)
        }
    }

    static func kept(_ state: AuthorityState, _ peers: [PeerCredential]) -> [String] {
        zip(peers, state.admitted(peers)).filter(\.1).map { G.hex($0.0.nodeKey.rawValue) }
    }

    /// Per row: node keys and order of peers retained by `admitted` match Go `tkaFilterNetmapLocked`. Go ran the same input `runs` times
    /// and always gave the same answer, as verified by the tool.
    @Test("peerSets: Retained peers and order")
    func peerSets() throws {
        let fixture = try GoFixture.load()
        for item in fixture.peerSets {
            let kept = Self.kept(try G.authority(named: item.authority, in: fixture).state, try Self.peers(item.peers))
            let comparison: Comparison = kept == item.kept && item.runs > 1 ? .same : .mismatch("Swift \(kept)")
            ComparisonTally.record(comparison, section: "peerSets", row: item.name, total: fixture.peerSets.count)
        }
    }

    /// Inputs where Go's answer varies by run (the same node key is in groups for different rotation keys, and `rotationTracker.obsoleteKeys` iterates a map).
    /// Swift must give one of those answers (contract §5 TL-4: Swiftail processes groups in order of first appearance among peers).
    @Test("unorderedPeerSets: One of several Go outcomes")
    func unorderedPeerSets() throws {
        let fixture = try GoFixture.load()
        for item in fixture.unorderedPeerSets {
            let kept = Self.kept(try G.authority(named: item.authority, in: fixture).state, try Self.peers(item.peers))
            let comparison: Comparison =
                item.outcomes.contains(kept) ? (item.outcomes.count > 1 ? .oneOfGoOutcomes : .same) : .mismatch("Swift \(kept)")
            print("Go comparison unorderedPeerSets/\(item.name): \(item.outcomes.count) distinct outcomes from \(item.runs) Go runs, Swift \(kept)")
            ComparisonTally.record(comparison, section: "unorderedPeerSets", row: item.name, total: fixture.unorderedPeerSets.count)
        }
    }

    // MARK: disablement

    static let disablementNames: [String] = (try? GoFixture.load())?.disablement.map(\.name) ?? []

    /// Per row: membership of the Go `DisablementKDF` value among that state's disablement values matches `ValidDisablement`, and Swift `isValidDisablement` agrees.
    @Test("disablement: Disablement secret outcomes", .timeLimit(.minutes(5)), arguments: disablementNames)
    func disablement(_ name: String) throws {
        let fixture = try GoFixture.load()
        let item = try #require(fixture.disablement.first { $0.name == name })
        let authority = try G.authority(named: item.authority, in: fixture)
        let containsKDF = authority.state.disablementValues.contains(G.bytes(item.kdf))
        let valid = authority.isValidDisablement(secret: G.bytes(item.secret))
        ComparisonTally.record(
            valid == item.valid && containsKDF == item.valid ? .same : .mismatch("Swift \(valid)"), section: "disablement", row: name,
            total: Self.disablementNames.count
        )
    }

    // MARK: authKeys

    /// Wrapped auth keys Go accepts and Swiftail rejects during decoding (behavior R3, decisions L12 and L13). Swiftail sends nothing to the server and
    /// ends with `invalidConfiguration` (fails closed only for availability. This is unrelated to signing authority state decisions).
    static let authKeyRejections: [String: String] = [
        // L12: Go returns the entire original string, including the private key, as an auth key.
        "missing-dash": "L12", "padded-base64": "L12", "url-alphabet-key": "L12", "extra-dash": "L12",
        "credential-not-cbor": "L12", "empty-parts": "L12",
        // L12 (added by TL-4): Go `RawStdEncoding` ignores trailing bits, skips line breaks, and produces a signature. Swiftail accepts only canonical forms.
        "credential-trailing-bits": "L12", "key-trailing-bits": "L12", "credential-lf": "L12", "key-crlf": "L12",
        "key-trailing-lf": "L12",
        // L13: If B is not 64 bytes, Go panics during signing. If the last 32 bytes differ, it produces an unverifiable signature.
        "key-63-bytes": "L13", "key-65-bytes": "L13", "key-32-bytes": "L13", "key-public-half-mismatch": "L13",
        // R3: A that is not a credential, and a key different from A's WrappingPubkey.
        "credential-direct-kind": "R3", "credential-wrapping-other-key": "R3",
    ]

    /// Per row: input without `--TL` is a plain auth key (nil). When Go decodes a wrapped key and signs, Swift decodes the same prefix and credential,
    /// produces the same `SigHash` for a signature on the same node key, and matches Go's verification outcome in that state (CryptoKit signature bytes vary).
    /// Check that Swift throws `invalidAuthKey` on rows with intended differences.
    @Test("authKeys: Wrapped auth key decoding and signing")
    func authKeys() throws {
        let fixture = try GoFixture.load()
        for item in fixture.authKeys {
            ComparisonTally.record(try Self.compareAuthKey(item, fixture), section: "authKeys", row: item.name, total: fixture.authKeys.count)
        }
    }

    static func compareAuthKey(_ item: GoFixture.AuthKey, _ fixture: GoFixture) throws -> Comparison {
        let parsed = Result { () throws(TKAError) in try WrappedAuthKey(parsing: item.input) }
        if let code = authKeyRejections[item.name] {
            guard case .failure(.invalidAuthKey) = parsed else { return .mismatch("Swift did not reject: \(parsed)") }
            return .intended(code)
        }
        if !item.isWrapped {
            guard case .success(nil) = parsed, item.authKey == item.input else { return .mismatch("Go treats it as a plain auth key, Swift \(parsed)") }
            return .same
        }
        guard case .success(let key?) = parsed else { return .mismatch("Go decodes a wrapped key, Swift \(parsed)") }
        guard item.sign == "ok", key.controlValue == item.authKey, G.hex(key.credential.serialized()) == item.credential else {
            return .mismatch("prefix and credential")
        }
        let nodeKey = try G.nodeKey(try #require(item.nodeKey))
        let made = try key.keySignature(for: nodeKey)
        let goSignature = try NodeKeySignature(decoding: G.bytes(try #require(item.nks)))
        guard try NodeKeySignature(decoding: made).signatureHash == goSignature.signatureHash else { return .mismatch("SigHash") }
        if let authority = item.authority, let verdict = item.verdict {
            let state = try G.authority(named: authority, in: fixture).state
            if let difference = G.difference(state, nodeKey: nodeKey, nks: made, expected: verdict) { return .mismatch(difference) }
        }
        return .same
    }

    // MARK: resign

    /// Per row: when Go produces a signature, Swift does too, with identical original reuse, depth, and inner node keys, and identical `SigHash` when the chain was not shortened.
    /// The Swift signature has the same outcome Go gave its own result. Swift throws if Go fails.
    ///
    /// Intended difference (contract §5, Fixes from independent review: Control flow (TL-11b), item 1): Swiftail resigns only chains already signed using its own NL key.
    /// Go produces signatures without checking the old signature. For those rows, Swift throws `invalidSignature` (a rotation layer fails verification with the NL key)
    /// or `untrustedSigner` (the innermost `WrappingPubkey` differs from the NL key). Go's output fails authorization even under Go's verification
    /// (other nodes see the same outcome: both are locked out).
    static let resignIntended: [String: TKAError] = [
        // The old direct rotation key is nl/0, and the resigning node's NL key is nl/1.
        "direct-wrapping-is-other-key": .untrustedSigner,
        "direct-no-wrapping": .untrustedSigner,
        // The wrapped key (signed auth key) signed the rotation.
        "credential-chain": .invalidSignature,
    ]

    @Test("resign: Resigning")
    func resign() throws {
        let fixture = try GoFixture.load()
        for item in fixture.resign {
            ComparisonTally.record(try Self.compareResign(item, fixture), section: "resign", row: item.name, total: fixture.resign.count)
        }
    }

    static func publicKeys(_ signature: NodeKeySignature) -> [[UInt8]] {
        var out: [[UInt8]] = []
        var current: NodeKeySignature? = signature
        while let s = current {
            out.append(s.publicKey)
            current = s.nested
        }
        return out
    }

    static func compareResign(_ item: GoFixture.Resign, _ fixture: GoFixture) throws -> Comparison {
        let lockKey = try G.signingKey(seed: item.nlKey, in: fixture)
        let nodeKey = try G.nodeKey(item.nodeKey)
        let old = G.bytes(item.oldNKS)
        let made = Result { () throws(TKAError) in try NodeKeySignature.resigned(old, for: nodeKey, with: lockKey) }
        guard item.ok else {
            if case .success = made { return .mismatch("Go fails (\(item.error ?? "")), Swift produces a signature") }
            return .same
        }
        if let refusal = resignIntended[item.name] {
            guard case .failure(refusal) = made, item.verdict?.authorized == false else { return .mismatch("Swift \(made)") }
            return .intended("TL-11b 1")
        }
        guard case .success(let bytes) = made else { return .mismatch("Swift \(made)") }
        let result = try NodeKeySignature(decoding: bytes)
        let goResult = try NodeKeySignature(decoding: G.bytes(try #require(item.result)))
        var depth = 0
        var cursor: NodeKeySignature? = result
        while let s = cursor { depth += 1; cursor = s.nested }
        guard (bytes == old) == item.sameAsOld, depth == item.depth, publicKeys(result) == publicKeys(goResult) else {
            return .mismatch("shape (unchanged, depth, and node keys)")
        }
        if (goResult.nested == (try? NodeKeySignature(decoding: old)) || item.sameAsOld), G.hex(result.signatureHash) != item.sigHash {
            return .mismatch("SigHash")
        }
        let state = try G.authority(named: item.authority, in: fixture).state
        if let verdict = item.verdict, let difference = G.difference(state, nodeKey: nodeKey, nks: bytes, expected: verdict) {
            return .mismatch(difference)
        }
        return .same
    }

    // MARK: limits

    static let limitCaseNames: [String] = (try? GoFixture.load())?.limits.flatMap { g in g.cases.map { "\(g.name)/\($0.name)" } } ?? []

    /// Intended difference F7: for every admission outside the fast path Go recomputes from the root with a limit of 2,000 iterations (`computeChainCandidates`,
    /// `tka/tka.go:84-118`, after committing, so the failed AUM remains in storage). Swiftail puts no limit on recomputation from the root.
    /// At that step, Swift accepts, and the head is the pool entry selected by the fork rule (same weight and kind, so the lower hash wins).
    static let limitF7Heads: [String: [[Int]]] = [
        "long-chain/fork-at-depth-2000": [[2000, 2004]],
        "long-chain/held-and-new-at-depth-2000": [[2000], [2000]],
        "long-chain/fork-parent-path-2000": [[2001, 2005]],
    ]

    /// Per case: the same base (first `baseCount` pool entries) yields the same head, and each step matches Go's admission outcome and head. The F7 step follows the table above.
    /// Go and Swift retain the parent state lookup limit (2,000 from the checkpoint succeeds and 2,001 fails).
    @Test("limits: Chains of more than 2,000 from the root", .timeLimit(.minutes(10)), arguments: limitCaseNames)
    func limits(_ name: String) throws {
        let fixture = try GoFixture.load()
        let group = try #require(fixture.limits.first { name.hasPrefix("\($0.name)/") })
        let limitCase = try #require(group.cases.first { "\(group.name)/\($0.name)" == name })
        let poolGroup = try #require(fixture.sync.first { $0.name == group.pool })
        let pool = try (poolGroup.pool + group.extra).map { hex throws(TKAError) in try G.aum(hex) }
        var authority = try G.authority(Array(pool[..<limitCase.baseCount]))
        var problems: [String] = []
        var intended = false
        if G.hex(authority.head.bytes) != limitCase.baseHead { problems.append("base head") }
        for (index, step) in limitCase.steps.enumerated() {
            let result = Result { () throws(TKAError) in try authority.inform(step.aums.map { pool[$0] }) }
            let ok = if case .success = result { true } else { false }
            if let tips = Self.limitF7Heads[name]?[index], !step.ok, step.error?.contains("computing candidates") == true {
                let expected = tips.map { pool[$0].hash }.min { $0.bytes.lexicographicallyPrecedes($1.bytes) }
                if ok, authority.head == expected { intended = true } else { problems.append("\(step.name) F7: Swift \(result)") }
                continue
            }
            if ok != step.ok { problems.append("\(step.name) outcome: Go \(step.ok) \(step.error ?? ""), Swift \(result)") }
            if G.hex(authority.head.bytes) != step.head { problems.append("\(step.name) head") }
        }
        let comparison: Comparison = !problems.isEmpty ? .mismatch(problems.joined(separator: "; ")) : intended ? .intended("F7") : .same
        ComparisonTally.record(comparison, section: "limits", row: name, total: Self.limitCaseNames.count)
    }

    // MARK: padded

    /// Inputs exceeding Swiftail's byte limits (behavior M). Go has no such limit and accepts them all. The expected Swift outcomes are:
    /// - NKS of 8,193 bytes: denies authorization (drops the peer). Fails closed (availability).
    /// - Old signature of 8,193 bytes for resigning: `limitExceeded` (registers without a signature, behavior R5 ①). Fails closed (availability).
    /// - AUM of 524,289 bytes: `limitExceeded` (decision L16). **Rejecting inputs Go accepts may prevent following the chain.** The padding is an unknown
    ///   field, so the hash is the same. The control server could withhold the AUM entirely without appending anything, so this creates no new attack capability.
    /// - Auth key with a credential of 8,193 bytes: `invalidAuthKey` (behaviors R3 and M). Fails closed (availability).
    static let paddedIntended: [String: String] = [
        "nks-direct-8193-bytes": "M", "resign-old-8193-bytes": "M·R5", "aum-noop-524289-bytes": "M·L16",
        "auth-key-credential-8193-bytes": "M",
    ]

    @Test("padded: Swiftail byte limit boundaries")
    func padded() throws {
        let fixture = try GoFixture.load()
        for item in fixture.padded {
            ComparisonTally.record(try Self.comparePadded(item, fixture), section: "padded", row: item.name, total: fixture.padded.count)
        }
    }

    static func comparePadded(_ item: GoFixture.Padded, _ fixture: GoFixture) throws -> Comparison {
        let input = G.padded(item)
        guard input.count == item.length else { return .mismatch("Generated input length \(input.count)") }
        let intended = paddedIntended[item.name]
        let authority = try G.authority(named: try #require(item.authority), in: fixture)
        switch item.kind {
        case "authorize":
            let verdict = try #require(item.verdict)
            let nodeKey = try G.nodeKey(try #require(item.nodeKey))
            if let intended {
                let swift = Result { () throws(TKAError) in try authority.state.authorize(nodeKey, keySignature: input) }
                guard case .failure(.unauthorized) = swift, verdict.authorized else { return .mismatch("Swift \(swift)") }
                return .intended(intended)
            }
            return G.difference(authority.state, nodeKey: nodeKey, nks: input, expected: verdict).map { .mismatch($0) } ?? .same
        case "resign":
            let nodeKey = try G.nodeKey(try #require(item.nodeKey))
            let lockKey = try G.signingKey(seed: try #require(item.nlKey), in: fixture)
            let made = Result { () throws(TKAError) in try NodeKeySignature.resigned(input, for: nodeKey, with: lockKey) }
            guard let intended, item.ok, case .failure(.limitExceeded) = made else { return .mismatch("Swift \(made)") }
            return .intended(intended)
        case "inform":
            var next = authority
            let result = Result { () throws(TKAError) in try next.inform([AUM(decoding: input)]) }
            if let intended {
                guard item.ok, case .failure(.limitExceeded) = result, next.head == authority.head else { return .mismatch("Swift \(result)") }
                return .intended(intended)
            }
            let ok = if case .success = result { true } else { false }
            return ok == item.ok && G.hex(next.head.bytes) == item.head ? .same : .mismatch("Swift \(result)")
        case "authKey":
            let text = try #require(item.controlValue) + "--TL" + G.rawBase64(input) + "-" + G.rawBase64(G.bytes(try #require(item.privateKey)))
            let parsed = Result { () throws(TKAError) in try WrappedAuthKey(parsing: text) }
            guard let intended, item.ok, case .failure(.invalidAuthKey) = parsed else { return .mismatch("Swift \(parsed)") }
            return .intended(intended)
        default:
            return .mismatch("Unknown kind \(item.kind)")
        }
    }

    // MARK: openedStates

    /// State containing a key other than `Key25519` (Go opens it because `tka.Open` skips reverification. Swiftail revalidates on open and never holds such
    /// a state, decision L14). Compare only the decision function `AuthorityState.authorize`. In a state created by decoding the checkpoint alone, it behaves like Go `GetKey`:
    /// it denies authorization when the other key appears first, and authorizes when it appears later.
    @Test("openedStates: GetKey in state containing a key other than Key25519")
    func openedStates() throws {
        let fixture = try GoFixture.load()
        for item in fixture.openedStates {
            let state = try #require(try G.aum(item.checkpoint).state)
            let verdict = G.verdict(authorized: item.authorized, error: item.error, rotation: item.rotation)
            var comparison: Comparison = item.openOK
                ? G.difference(state, nodeKey: try G.nodeKey(item.nodeKey), nks: G.bytes(item.nks), expected: verdict).map { .mismatch($0) } ?? .same
                : .mismatch("Go could not open it (\(item.openError ?? ""))")
            // Swiftail does not build state from this checkpoint because it fails static validation.
            if (try? Authority(bootstrappingWith: G.aum(item.checkpoint))) != nil { comparison = .mismatch("Swift bootstraps") }
            ComparisonTally.record(comparison, section: "openedStates", row: item.name, total: fixture.openedStates.count)
        }
    }

    // MARK: Regeneration and comparison

    /// Tool path printed by `sh Scripts/build-interop-tools.sh tkafixtures`. Run the tool in `Tools/interop` with the environment from the README
    /// (`GOCACHE`, `GOMODCACHE`, and `GOFLAGS`). The peer set overlay build uses that go.mod.
    static let fixtureTool = ProcessInfo.processInfo.environment["SWIFTAIL_TKAFIXTURES"].flatMap { $0.isEmpty ? nil : $0 }

    @Test(
        "Fixtures regenerated with the Go tool match the saved fixtures byte for byte (skipped if SWIFTAIL_TKAFIXTURES is missing)",
        .enabled(if: fixtureTool != nil), .timeLimit(.minutes(5))
    )
    func freshGoFixtures() throws {
        let root = URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
        let process = Process()
        process.executableURL = URL(fileURLWithPath: try #require(Self.fixtureTool))
        process.currentDirectoryURL = root.appendingPathComponent("Tools/interop")
        let pipe = Pipe()
        process.standardOutput = pipe
        try process.run()
        let fresh = pipe.fileHandleForReading.readDataToEndOfFile()
        process.waitUntilExit()
        #expect(process.terminationStatus == 0)
        let stored = try Data(contentsOf: try GoFixture.url)
        #expect(fresh == stored, "Stored tka-fixtures.json differs from the tool output (\(fresh.count) bytes, stored \(stored.count) bytes)")
    }
}
