import Foundation
import Swiftail

/// 여는 쪽의 짝 목록과 그 파일 형식(계약 동작 S1·S3·S4). 값 타입이고 파일을 만지지 않는다(`PairedPeerFile`이 한다).
///
/// 파일은 `{"version":1,"peers":[…]}`다. 항목은 `stableID`·`name`·`computedName`·`loginName`(짝을 맺을 때의
/// `PeerIdentity`), `deviceName`, `pairedAt`(유닉스 초)이다. 모르는 필드는 넘긴다.
struct PairedPeerList: Sendable, Equatable {
    /// 짝의 한도(S4).
    static let limit = 256
    /// 지금의 파일 판.
    static let version = 1

    /// 짝이 된 차례대로.
    private(set) var peers: [PairedPeer] = []

    init() {}

    func peer(withStableID stableID: String) -> PairedPeer? {
        peers.first { $0.peer.stableID == stableID }
    }

    /// 짝을 넣는다. 같은 `StableID`가 있으면 그 자리의 항목을 바꾼다(S1).
    ///
    /// - Returns: 새 짝인데 목록이 가득 찼으면 넣지 않고 false(S4).
    mutating func insert(_ peer: PairedPeer) -> Bool {
        if let index = peers.firstIndex(where: { $0.peer.stableID == peer.peer.stableID }) {
            peers[index] = peer
            return true
        }
        guard peers.count < Self.limit else { return false }
        peers.append(peer)
        return true
    }

    /// 짝을 지운다. 지운 것이 있으면 true.
    mutating func remove(stableID: String) -> Bool {
        guard let index = peers.firstIndex(where: { $0.peer.stableID == stableID }) else { return false }
        peers.remove(at: index)
        return true
    }

    // MARK: 파일 형식

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

    /// 파일의 내용을 읽는다. 읽지 못하면 nil이다(S3): JSON이 아님, 다른 `version`, 빈 `StableID`, 겹친 `StableID`,
    /// 256개 초과. 읽지 못한 파일을 빈 목록으로 보면 다음 저장이 짝을 모두 지우므로, 부르는 쪽은 실패로 다룬다.
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

    /// 파일에 쓸 내용. 만들지 못하면 nil.
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
