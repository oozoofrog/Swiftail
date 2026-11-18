import Foundation
import Swiftail

/// The host's paired peer list and its file format (contract behaviors S1, S3, and S4). This value type leaves file access to `PairedPeerFile`.
///
/// The file is `{"version":1,"peers":[…]}`. Each entry contains `stableID`, `name`, `computedName`, and `loginName` (the `PeerIdentity`
/// at pairing), `deviceName`, and `pairedAt` (Unix seconds). Ignore unknown fields.
struct PairedPeerList: Sendable, Equatable {
    /// The paired peer limit (S4).
    static let limit = 256
    /// The current file version.
    static let version = 1

    /// In pairing order.
    private(set) var peers: [PairedPeer] = []

    init() {}

    func peer(withStableID stableID: String) -> PairedPeer? {
        peers.first { $0.peer.stableID == stableID }
    }

    /// Adds a paired peer. If the same `StableID` exists, replaces its entry in place (S1).
    ///
    /// - Returns: false without adding if the peer is new and the list is full (S4).
    mutating func insert(_ peer: PairedPeer) -> Bool {
        if let index = peers.firstIndex(where: { $0.peer.stableID == peer.peer.stableID }) {
            peers[index] = peer
            return true
        }
        guard peers.count < Self.limit else { return false }
        peers.append(peer)
        return true
    }

    /// Removes a paired peer. Returns true if an entry was removed.
    mutating func remove(stableID: String) -> Bool {
        guard let index = peers.firstIndex(where: { $0.peer.stableID == stableID }) else { return false }
        peers.remove(at: index)
        return true
    }

    // MARK: File Format

    private struct File: Codable {
        var version: Int
        var peers: [Record]
    }

    private struct Record: Codable {
        var stableID: String
        var name: String
        var computedName: String
        var loginName: String
        var deviceName: String
        var pairedAt: Date
    }

    /// Reads the file contents. Returns nil if unreadable (S3): invalid JSON, a different `version`, empty or duplicate `StableID`,
    /// or more than 256 entries. Treating an unreadable file as empty would erase all paired peers on the next save, so the caller treats it as a failure.
    init?(fileContents: Data) {
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .secondsSince1970
        guard let file = try? decoder.decode(File.self, from: fileContents), file.version == Self.version,
              file.peers.count <= Self.limit, file.peers.allSatisfy({ !$0.stableID.isEmpty }),
              Set(file.peers.map(\.stableID)).count == file.peers.count
        else { return nil }
        peers = file.peers.map { record in
            PairedPeer(
                peer: PeerIdentity(
                    stableID: record.stableID, name: record.name, computedName: record.computedName,
                    loginName: record.loginName),
                deviceName: record.deviceName, pairedAt: record.pairedAt)
        }
    }

    /// The contents to write to the file, or nil if they cannot be generated.
    var fileContents: Data? {
        let records = peers.map { peer in
            Record(
                stableID: peer.peer.stableID, name: peer.peer.name, computedName: peer.peer.computedName,
                loginName: peer.peer.loginName, deviceName: peer.deviceName, pairedAt: peer.pairedAt)
        }
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .secondsSince1970
        encoder.outputFormatting = .sortedKeys
        return try? encoder.encode(File(version: Self.version, peers: records))
    }
}
