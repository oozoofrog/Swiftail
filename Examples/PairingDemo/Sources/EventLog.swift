import Foundation
import Observation

/// 앱이 파일을 두는 자리. 모두 Application Support 아래다(샌드박스에서는 앱 컨테이너 안).
enum Storage {
    static let root = URL.applicationSupportDirectory
        .appending(path: Bundle.main.bundleIdentifier ?? "PairingDemo", directoryHint: .isDirectory)
    /// 노드의 신원(`TailnetNode`의 상태 디렉터리).
    static let nodeState = root.appending(path: "node", directoryHint: .isDirectory)
    /// 여는 쪽의 짝 목록(`PairingHost`의 `storeDirectory`).
    static let pairingStore = root.appending(path: "pairing", directoryHint: .isDirectory)
    /// 들어오는 쪽이 짝이 된 여는 쪽(`PairedHost`).
    static let pairedHost = root.appending(path: "paired-host.json")
    static let events = root.appending(path: "events.jsonl")
    /// 자동화 모드에서만 쓰는 제안 링크 파일.
    static let offerLink = root.appending(path: "offer-link.txt")
}

/// 단계마다의 사건 기록. 화면의 목록과 `events.jsonl`(한 줄에 사건 하나)에 함께 남긴다.
///
/// 제안의 링크, 비밀, 인증 키, OAuth 비밀, 로그인 URL은 남기지 않는다. 확인 숫자는 자동화 모드가 켰을 때만 남긴다.
@MainActor @Observable
final class EventLog {
    enum Source: String, Encodable {
        case app, node, host, joiner
    }

    struct Entry: Identifiable, Encodable {
        let id = UUID()
        let time: Date
        let role: Source
        let event: String
        let result: String

        private enum CodingKeys: String, CodingKey {
            case time, role, event, result
        }
    }

    /// 새 것이 앞에 온다.
    private(set) var entries: [Entry] = []
    private let encoder: JSONEncoder = {
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .iso8601
        encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        return encoder
    }()

    func record(_ role: Source, _ event: String, _ result: String) {
        let entry = Entry(time: Date(), role: role, event: event, result: result)
        entries.insert(entry, at: 0)
        // 파일에 쓰지 못해도 화면의 목록은 남는다. 기록 때문에 짝 맺기를 멈추지 않는다.
        guard var line = try? encoder.encode(entry) else { return }
        line.append(0x0A)
        try? FileManager.default.createDirectory(at: Storage.root, withIntermediateDirectories: true)
        if let handle = try? FileHandle(forWritingTo: Storage.events) {
            defer { try? handle.close() }
            _ = try? handle.seekToEnd()
            try? handle.write(contentsOf: line)
        } else {
            try? line.write(to: Storage.events)
        }
    }
}
