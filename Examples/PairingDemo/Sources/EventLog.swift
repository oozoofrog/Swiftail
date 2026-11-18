import Foundation
import Observation

/// The app's file locations. All are under Application Support (inside the app container when sandboxed).
enum Storage {
    static let root = URL.applicationSupportDirectory
        .appending(path: Bundle.main.bundleIdentifier ?? "PairingDemo", directoryHint: .isDirectory)
    /// The node's identity (the state directory for `TailnetNode`).
    static let nodeState = root.appending(path: "node", directoryHint: .isDirectory)
    /// The host's paired peer list (the `storeDirectory` for `PairingHost`).
    static let pairingStore = root.appending(path: "pairing", directoryHint: .isDirectory)
    /// The host paired with the joiner (`PairedHost`).
    static let pairedHost = root.appending(path: "paired-host.json")
    static let events = root.appending(path: "events.jsonl")
    /// The offer link file used only in automation mode.
    static let offerLink = root.appending(path: "offer-link.txt")
}

/// Logs events at each step. Records them both in the on-screen list and in `events.jsonl` (one event per line).
///
/// The log omits offer links, secrets, auth keys, OAuth secrets, and sign-in URLs. It records the SAS only when automation mode is enabled.
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

    /// Newest entries come first.
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
        // The on-screen list remains available if writing to the file fails. Logging does not interrupt pairing.
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
