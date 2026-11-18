import Foundation
import SwiftailBase

// The bodies of three tailnet lock (TKA) RPCs. Go `tailcfg`'s `TKABootstrap*`, `TKASyncOffer*`, and `TKASyncSend*`.
//
// All three are `GET` requests over the Noise channel and carry JSON bodies. The Go structs omit JSON tags, so the exact field names are the keys.
// AUM hashes are base32 text. AUMs and disablement secrets are base64 (`[]byte`). This layer reads received fields as strings or bytes.
// The consumer (the `ControlClient` procedure) interprets them as hashes and AUMs.
//
// `docs/protocol-notes/tailnet-lock.md` §3.10, contract `docs/contracts/SwiftailTailnetLock.md` behavior Y7
// (origin: tailscale.com `tailcfg/tka.go`, BSD-3-Clause).

/// The body of `GET /machine/tka/bootstrap`. Requests the values needed to enable or disable the lock.
struct TKABootstrapRequest: Encodable, Sendable {
    /// The client's capability version.
    var version = 148
    var nodeKey: NodePublicKey
    /// The local head in base32. An empty string when lock state is absent. The field is always present.
    var head: String

    private enum CodingKeys: String, CodingKey {
        case version = "Version"
        case nodeKey = "NodeKey"
        case head = "Head"
    }
}

/// The bootstrap RPC response. Each field defaults to an empty byte array if absent.
struct TKABootstrapResponse: Decodable, Sendable {
    /// The checkpoint AUM (CBOR) for initializing signing authority state.
    var genesisAUM: [UInt8]
    /// The secret that disables the lock. Discarded after verification, without storing or logging it.
    var disablementSecret: [UInt8]

    private enum CodingKeys: String, CodingKey {
        case genesisAUM = "GenesisAUM"
        case disablementSecret = "DisablementSecret"
    }

    init(from decoder: any Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        genesisAUM = try container.decodeBytesIfPresent(forKey: .genesisAUM) ?? []
        disablementSecret = try container.decodeBytesIfPresent(forKey: .disablementSecret) ?? []
    }
}

/// The body of `GET /machine/tka/sync/offer`. Reports the local head and ancestors for finding an intersection.
struct TKASyncOfferRequest: Encodable, Sendable {
    var version = 148
    var nodeKey: NodePublicKey
    var head: String
    var ancestors: [String]

    private enum CodingKeys: String, CodingKey {
        case version = "Version"
        case nodeKey = "NodeKey"
        case head = "Head"
        case ancestors = "Ancestors"
    }
}

/// The sync/offer response, including the server's head and ancestors and the AUMs the server believes this node is missing.
struct TKASyncOfferResponse: Decodable, Sendable {
    var head: String
    var ancestors: [String]
    /// The AUMs' CBOR bytes in received order.
    var missingAUMs: [[UInt8]]

    private enum CodingKeys: String, CodingKey {
        case head = "Head"
        case ancestors = "Ancestors"
        case missingAUMs = "MissingAUMs"
    }

    /// The `MissingAUMs` count limit. Matches the limit on AUMs accepted at once (4,096, contract behavior M and decision L16).
    ///
    /// Acceptance checks the same limit. Count the entries here before decoding their base64 and then their AUMs (§5 TL-11b item 5).
    /// An 8MiB body can hold more than a million entries a few bytes long.
    static let maximumMissingAUMCount = 4_096

    init(from decoder: any Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        head = try container.decodeIfPresent(String.self, forKey: .head) ?? ""
        ancestors = try container.decodeIfPresent([String].self, forKey: .ancestors) ?? []
        missingAUMs = []
        guard container.contains(.missingAUMs), try !container.decodeNil(forKey: .missingAUMs) else { return }
        var items = try container.nestedUnkeyedContainer(forKey: .missingAUMs)
        guard let count = items.count, count <= Self.maximumMissingAUMCount else {
            throw DecodingError.dataCorruptedError(
                forKey: .missingAUMs, in: container, debugDescription: "MissingAUMs exceeds the count limit"
            )
        }
        missingAUMs.reserveCapacity(count)
        while !items.isAtEnd {
            guard let data = Data(base64Encoded: try items.decode(String.self)) else {
                throw DecodingError.dataCorruptedError(forKey: .missingAUMs, in: container, debugDescription: "Expected base64")
            }
            missingAUMs.append([UInt8](data))
        }
    }
}

/// The body of `GET /machine/tka/sync/send`. Reports local AUMs unknown to the server and the local head after synchronization.
struct TKASyncSendRequest: Encodable, Sendable {
    var version = 148
    var nodeKey: NodePublicKey
    var head: String
    /// The AUMs' CBOR bytes. Sends `[]` even with nothing to send (never null).
    var missingAUMs: [[UInt8]]
    /// Whether this is an interactive administrator operation. Ordinary nodes always send false because they synchronize automatically.
    var interactive = false

    private enum CodingKeys: String, CodingKey {
        case version = "Version"
        case nodeKey = "NodeKey"
        case head = "Head"
        case missingAUMs = "MissingAUMs"
        case interactive = "Interactive"
    }

    func encode(to encoder: any Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(version, forKey: .version)
        try container.encode(nodeKey, forKey: .nodeKey)
        try container.encode(head, forKey: .head)
        try container.encode(missingAUMs.map { Data($0).base64EncodedString() }, forKey: .missingAUMs)
        try container.encode(interactive, forKey: .interactive)
    }
}

/// The sync/send response, containing the server head after accepting the AUMs.
struct TKASyncSendResponse: Decodable, Sendable {
    var head: String

    private enum CodingKeys: String, CodingKey {
        case head = "Head"
    }

    init(from decoder: any Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        head = try container.decodeIfPresent(String.self, forKey: .head) ?? ""
    }
}
