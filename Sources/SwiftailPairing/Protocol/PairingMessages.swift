/// 짝 맺기 절차의 메시지와 그 바이트(계약 5절).
///
/// ```
/// J→H  hello     "SWPR" ‖ 0x03 ‖ commitJ(32) ‖ 길이(1) ‖ 기기 이름(UTF-8, 1~64바이트)
/// H→J  challenge 상태(1) ‖ commitH(32)
/// J→H  proof     nonceJ(32) ‖ HMAC(32)
/// H→J  accepted  nonceH(32) ‖ HMAC(32)
/// H→J  decision  D ‖ HMAC(32)     D = 상태(1) ‖ [승인: 길이(1) ‖ StableID ‖ 길이(1) ‖ 표시 이름]
/// ```
///
/// `hello`와 `challenge`가 싣는 것은 nonce가 아니라 그 약속이다. 들어오는 쪽은 `proof`에서, 여는 쪽은 그 `proof`가 맞은
/// 뒤 `accepted`에서 nonce를 연다. 어느 쪽도 상대의 nonce를 본 뒤에 자기 nonce를 고를 수 없고, 들어오는 쪽은 비밀을
/// 증명하기 전에는 여는 쪽의 nonce를 보지 못한다(`PairingTranscript`).
///
/// 길이는 메시지마다 정해져 있다. 읽기는 받은 바이트를 모아 두고 `parse`에 넘긴다: 아직 모자라면 `incomplete`, 규격과
/// 다르면 `invalid`, 다 왔으면 값과 쓴 길이다. 남은 바이트가 위반인지는 차례를 아는 상태 기계가 정한다.
enum PairingMessage {
    /// nonce와 그 약속의 길이.
    static let nonceLength = 32
    /// `proof`·`accepted`와 `decision`의 HMAC-SHA256 길이.
    static let codeLength = 32

    /// 들어오는 쪽이 절차에서 보내는 바이트의 상한: 가장 긴 `hello`와 `proof`. 이보다 많이 왔으면 이미 위반이다.
    static let maximumJoinerLength = Hello.prefix.count + nonceLength + 1 + DeviceName.maximumLength + Proof.length

    /// J→H 증명. 약속해 둔 nonceJ를 열고, 그 뒤에 비밀을 안다는 HMAC을 붙인다.
    typealias Proof = Opening
    /// H→J 수락. `proof`가 맞은 뒤에야 약속해 둔 nonceH를 열고, 그 뒤에 여는 쪽이 비밀을 안다는 HMAC을 붙인다.
    typealias Accepted = Opening

    /// 모아 둔 바이트를 메시지 하나로 읽은 결과.
    enum Parsed<Message> {
        case incomplete
        case invalid
        case complete(Message, length: Int)
    }

    /// J→H 첫 메시지. 프로토콜의 표식과 판(3), 들어오는 쪽 nonce의 약속, 스스로 밝힌 기기 이름.
    struct Hello: Sendable, Equatable {
        static let prefix = Array("SWPR".utf8) + [0x03]

        /// commitJ. nonceJ는 `proof`에서 온다.
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

    /// 약속해 둔 nonce를 열고 HMAC을 붙인 메시지. `proof`와 `accepted`가 이 모양이다.
    struct Opening: Sendable, Equatable {
        static let length = nonceLength + codeLength

        var nonce: [UInt8]
        var code: [UInt8]

        var encoded: [UInt8] { nonce + code }

        /// 정확히 `length`바이트일 때만 읽는다. 모자라면 nil(더 넘치는지는 차례를 아는 상태 기계가 본다).
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

    /// H→J 답. 계속할지와 여는 쪽 nonce의 약속(commitH). nonceH는 `accepted`에서 온다.
    struct Challenge: Sendable, Equatable {
        enum Status: UInt8 {
            /// 계속한다.
            case proceed = 0
            /// 열린 제안이 없다(없음, 만료, 이미 씀). 여는 쪽이 닫는다.
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

    /// H→J 결정. 본문(D)만 다룬다. 뒤에 붙는 HMAC은 `PairingTranscript.decisionCode(for:secret:)`가 만든다.
    enum Decision: Sendable, Equatable {
        /// 승인. 여는 쪽의 `StableID`와 표시 이름을 싣는다.
        case approved(stableID: String, name: String)
        /// 거절(앱의 거절, 신원이 달라짐, 저장 실패).
        case denied
        /// 승인 시간 초과.
        case timedOut

        /// 표시 이름의 한도(바이트).
        static let maximumNameLength = 64

        /// 여는 쪽이 보낼 승인. `StableID`가 1~255바이트의 인쇄 가능 ASCII가 아니면 nil. 표시 이름은 64바이트에 들게
        /// 글자 경계에서 자르고, 표시할 수 없는 글이면 비운다(이름은 표시용이고 판정은 `StableID`로 한다).
        static func approval(stableID: String, name: String) -> Decision? {
            guard isValidStableID(stableID.utf8) else { return nil }
            var name = PairingText.displayable(name.utf8) ?? ""
            while name.utf8.count > maximumNameLength { name.removeLast() }
            return .approved(stableID: stableID, name: name)
        }

        /// 본문 D.
        var body: [UInt8] {
            switch self {
            case .approved(let stableID, let name):
                [1, UInt8(stableID.utf8.count)] + stableID.utf8 + [UInt8(name.utf8.count)] + name.utf8
            case .denied: [2]
            case .timedOut: [3]
            }
        }

        /// 모아 둔 바이트에서 본문과 HMAC을 가른다. 내용은 보지 않는다(HMAC을 확인한 뒤에 `init(body:)`로 읽는다).
        /// 상태가 1~3이 아니면 길이를 알 수 없으므로 `invalid`다.
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

        /// HMAC을 확인한 본문을 읽는다(계약 동작 J5). `StableID`는 1~255바이트의 인쇄 가능 ASCII, 표시 이름은 0~64바이트의
        /// 표시할 수 있는 글이어야 한다. 어긋나면 nil.
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
