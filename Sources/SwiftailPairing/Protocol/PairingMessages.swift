/// Pairing protocol messages and their bytes (contract §5).
///
/// ```
/// J→H  hello     "SWPR" ‖ 0x03 ‖ commitJ(32) ‖ length(1) ‖ device name(UTF-8, 1–64 bytes)
/// H→J  challenge status(1) ‖ commitH(32)
/// J→H  proof     nonceJ(32) ‖ HMAC(32)
/// H→J  accepted  nonceH(32) ‖ HMAC(32)
/// H→J  decision  D ‖ HMAC(32)     D = status(1) ‖ [approved: length(1) ‖ StableID ‖ length(1) ‖ display name]
/// ```
///
/// `hello` and `challenge` carry nonce commitments. The joiner reveals its nonce in `proof`, and the host reveals its nonce in accepted after that proof
/// verifies. Neither side can choose its own nonce after seeing the other's, and the joiner cannot see the host's nonce before proving knowledge
/// of the secret (`PairingTranscript`).
///
/// Each message has a defined length. The reader accumulates bytes and passes them to `parse`, which returns `incomplete` when more are needed,
/// `invalid` when they violate the specification, or the value and consumed length when complete. The state machine knows the sequence and decides whether extra bytes violate it.
enum PairingMessage {
    /// The length of a nonce and its commitment.
    static let nonceLength = 32
    /// The HMAC-SHA256 length for `proof`, `accepted`, and `decision`.
    static let codeLength = 32

    /// The maximum bytes the joiner sends during the protocol, the longest `hello` plus `proof`. Any excess already violates the protocol.
    static let maximumJoinerLength = Hello.prefix.count + nonceLength + 1 + DeviceName.maximumLength + Proof.length

    /// J→H proof. Reveals the committed nonceJ, followed by the HMAC proving knowledge of the secret.
    typealias Proof = Opening
    /// H→J acceptance. Reveals the committed nonceH only after `proof` verifies, followed by the HMAC proving the host knows the secret.
    typealias Accepted = Opening

    /// The result of parsing one message from the accumulated bytes.
    enum Parsed<Message> {
        case incomplete
        case invalid
        case complete(Message, length: Int)
    }

    /// The first J→H message. Includes protocol magic and version (3), the joiner's nonce commitment, and its self-reported device name.
    struct Hello: Sendable, Equatable {
        static let prefix = Array("SWPR".utf8) + [0x03]

        /// commitJ. nonceJ arrives in `proof`.
        var commitment: [UInt8]
        var deviceName: DeviceName

        var encoded: [UInt8] {
            Self.prefix + commitment + [UInt8(deviceName.bytes.count)] + deviceName.bytes
        }

        static func parse(_ buffer: [UInt8]) -> Parsed<Hello> {
            guard buffer.prefix(prefix.count).elementsEqual(prefix.prefix(buffer.count)) else { return .invalid }
            let nameStart = prefix.count + nonceLength + 1
            guard buffer.count >= nameStart else { return .incomplete }
            let nameLength = Int(buffer[nameStart - 1])
            guard (1...DeviceName.maximumLength).contains(nameLength) else { return .invalid }
            guard buffer.count >= nameStart + nameLength else { return .incomplete }
            guard let name = DeviceName(bytes: buffer[nameStart..<nameStart + nameLength]) else { return .invalid }
            let commitment = Array(buffer[prefix.count..<prefix.count + nonceLength])
            return .complete(Hello(commitment: commitment, deviceName: name), length: nameStart + nameLength)
        }
    }

    /// A message revealing a committed nonce followed by an HMAC. `proof` and `accepted` use this format.
    struct Opening: Sendable, Equatable {
        static let length = nonceLength + codeLength

        var nonce: [UInt8]
        var code: [UInt8]

        var encoded: [UInt8] { nonce + code }

        /// Parses only when exactly `length` bytes are available. Returns nil when too short (the state machine checks for excess based on sequence).
        init?(_ buffer: [UInt8]) {
            guard buffer.count == Self.length else { return nil }
            nonce = Array(buffer[..<nonceLength])
            code = Array(buffer[nonceLength...])
        }

        init(nonce: [UInt8], code: [UInt8]) {
            self.nonce = nonce
            self.code = code
        }
    }

    /// The H→J response. Indicates whether to continue and includes the host's nonce commitment (commitH). nonceH arrives in `accepted`.
    struct Challenge: Sendable, Equatable {
        enum Status: UInt8 {
            /// Continues the protocol.
            case proceed = 0
            /// No open offer (absent, expired, or already used). The host closes.
            case noOffer = 1
        }

        static let length = 1 + nonceLength

        var status: Status
        var commitment: [UInt8]

        var encoded: [UInt8] { [status.rawValue] + commitment }

        static func parse(_ buffer: [UInt8]) -> Parsed<Challenge> {
            guard let first = buffer.first else { return .incomplete }
            guard let status = Status(rawValue: first) else { return .invalid }
            guard buffer.count >= length else { return .incomplete }
            return .complete(Challenge(status: status, commitment: Array(buffer[1..<length])), length: length)
        }
    }

    /// The H→J decision. Handles only the body (D). `PairingTranscript.decisionCode(for:secret:)` generates the trailing HMAC.
    enum Decision: Sendable, Equatable {
        /// Approval. Includes the host's `StableID` and display name.
        case approved(stableID: String, name: String)
        /// Denial (app denial, changed identity, or failure to save).
        case denied
        /// Approval timed out.
        case timedOut

        /// The display name limit in bytes.
        static let maximumNameLength = 64

        /// The approval to send from the host. Returns nil unless `StableID` is 1–255 bytes of printable ASCII. Truncates the display name at a character
        /// boundary to fit 64 bytes and clears it if it contains nondisplayable text (the name is for display and checks use `StableID`).
        static func approval(stableID: String, name: String) -> Decision? {
            guard isValidStableID(stableID.utf8) else { return nil }
            var name = PairingText.displayable(name.utf8) ?? ""
            while name.utf8.count > maximumNameLength { name.removeLast() }
            return .approved(stableID: stableID, name: name)
        }

        /// The body D.
        var body: [UInt8] {
            switch self {
            case .approved(let stableID, let name):
                [1, UInt8(stableID.utf8.count)] + stableID.utf8 + [UInt8(name.utf8.count)] + name.utf8
            case .denied: [2]
            case .timedOut: [3]
            }
        }

        /// Splits the body and HMAC from the accumulated bytes. Leaves the contents unread until HMAC verification, then uses `init(body:)`.
        /// Returns `invalid` if status is outside 1–3 because the length is unknown.
        static func frame(_ buffer: [UInt8]) -> Parsed<(body: [UInt8], code: [UInt8])> {
            guard let status = buffer.first else { return .incomplete }
            var bodyLength = 1
            switch status {
            case 1:
                for _ in 0..<2 {
                    guard buffer.count > bodyLength else { return .incomplete }
                    bodyLength += 1 + Int(buffer[bodyLength])
                }
            case 2, 3:
                break
            default:
                return .invalid
            }
            let length = bodyLength + codeLength
            guard buffer.count >= length else { return .incomplete }
            return .complete((Array(buffer[..<bodyLength]), Array(buffer[bodyLength..<length])), length: length)
        }

        /// Reads a body whose HMAC has been verified (contract behavior J5). `StableID` must be 1–255 bytes of printable ASCII and the display name
        /// must be 0–64 bytes of displayable text. Returns nil otherwise.
        init?(body: [UInt8]) {
            switch body.first {
            case 2 where body.count == 1:
                self = .denied
            case 3 where body.count == 1:
                self = .timedOut
            case 1 where body.count >= 3:
                let stableID = body.dropFirst(2).prefix(Int(body[1]))
                let rest = body.dropFirst(2 + stableID.count)
                guard stableID.count == Int(body[1]), let nameLength = rest.first.map(Int.init),
                      rest.count == 1 + nameLength, nameLength <= Self.maximumNameLength,
                      Self.isValidStableID(stableID), let name = PairingText.displayable(rest.dropFirst())
                else { return nil }
                self = .approved(stableID: String(decoding: stableID, as: UTF8.self), name: name)
            default:
                return nil
            }
        }

        private static func isValidStableID(_ bytes: some Collection<UInt8>) -> Bool {
            (1...255).contains(bytes.count) && bytes.allSatisfy { (0x20...0x7E).contains($0) }
        }
    }
}
