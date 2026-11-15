import Testing

@testable import SwiftailTKA

/// 자료 형식 시험이 함께 쓰는 도구. 같은 시험 타깃의 다른 단위와 이름이 부딪치지 않게 한 이름 아래 둔다.
enum ModelTesting {
    static func bytes(_ hex: String) -> [UInt8] {
        guard let bytes = CBORTesting.bytes(hex: hex) else {
            Issue.record("16진이 아니다: \(hex)")
            return []
        }
        return bytes
    }

    static func hex(_ bytes: [UInt8]) -> String { CBORTesting.hex(bytes) }

    /// `AUM(decoding:)`의 판정. 받아들이면 값, 아니면 오류.
    static func decodeAUM(_ hex: String) -> Result<AUM, TKAError> {
        Result { () throws(TKAError) in try AUM(decoding: bytes(hex)) }
    }

    static func decodeNKS(_ hex: String) -> Result<NodeKeySignature, TKAError> {
        Result { () throws(TKAError) in try NodeKeySignature(decoding: bytes(hex)) }
    }

    // MARK: 생성기

    /// 정준 쓰기의 성질 시험에 쓰는 임의의 값. 쓰고 읽으면 같은 값이 되는 모양만 만든다:
    /// 인코딩에서 빠지는 빈 값(`keyID`·`meta`의 빈 배열)은 nil로, `State.lastAUMHash`는 nil로(동작 D8) 둔다.
    struct Generator {
        var random: CBORTesting.Random

        mutating func bytes(maximumCount: Int = 40) -> [UInt8] {
            let count = [0, 1, 2, 23, 24, 32, 33, 64, Int.random(in: 0...maximumCount, using: &random)]
                .randomElement(using: &random) ?? 0
            return (0..<count).map { _ in UInt8.random(in: 0...255, using: &random) }
        }

        mutating func number() -> UInt64 {
            let boundaries: [UInt64] = [0, 1, 23, 24, 255, 256, 4_096, 65_535, 65_536, 0xffff_ffff, 1 << 32, .max]
            if Bool.random(using: &random) { return boundaries.randomElement(using: &random) ?? 0 }
            return UInt64.random(in: 0...(UInt64.max >> UInt64.random(in: 0...63, using: &random)), using: &random)
        }

        mutating func meta() -> [MetaEntry] {
            var entries: [MetaEntry] = []
            for _ in 0..<Int.random(in: 0...4, using: &random) {
                // 올바른 UTF-8: 한 바이트 글자와 두 바이트 글자(é)를 섞는다.
                let key = (0..<Int.random(in: 0...3, using: &random)).flatMap { _ in
                    Bool.random(using: &random) ? [UInt8.random(in: 0x61...0x7a, using: &random)] : [0xc3, 0xa9]
                }
                guard !entries.contains(where: { $0.key == key }) else { continue }
                entries.append(MetaEntry(key: key, value: Array("v\(entries.count)".utf8)))
            }
            return entries.canonicallyOrdered()
        }

        mutating func trustedKey() -> TrustedKey {
            TrustedKey(
                kind: UInt8.random(in: 0...255, using: &random),
                votes: number(),
                publicKey: Bool.random(using: &random) ? nil : bytes(),
                meta: meta()
            )
        }

        mutating func state() -> AuthorityState {
            AuthorityState(
                lastAUMHash: nil,
                disablementValues: (0..<Int.random(in: 0...3, using: &random)).map { _ in bytes() },
                keys: (0..<Int.random(in: 0...3, using: &random)).map { _ in trustedKey() },
                stateID1: Bool.random(using: &random) ? 0 : number(),
                stateID2: Bool.random(using: &random) ? 0 : number()
            )
        }

        mutating func aum() -> AUM {
            let keyID = bytes()
            let meta = meta()
            return AUM(
                messageKind: UInt8.random(in: 0...255, using: &random),
                prevAUMHash: Bool.random(using: &random) ? nil : bytes(),
                key: Bool.random(using: &random) ? trustedKey() : nil,
                keyID: keyID.isEmpty ? nil : keyID,
                state: Bool.random(using: &random) ? state() : nil,
                votes: Bool.random(using: &random) ? number() : nil,
                meta: meta.isEmpty ? nil : meta,
                signatures: (0..<Int.random(in: 0...3, using: &random)).map { _ in
                    AUMSignature(keyID: bytes(), signature: bytes(maximumCount: 70))
                }
            )
        }

        mutating func nodeKeySignature(depth: Int = 0) -> NodeKeySignature {
            NodeKeySignature(
                kind: UInt8.random(in: 0...255, using: &random),
                publicKey: bytes(),
                keyID: bytes(),
                signature: bytes(maximumCount: 70),
                nested: depth < 6 && Bool.random(using: &random) ? nodeKeySignature(depth: depth + 1) : nil,
                wrappingPublicKey: bytes()
            )
        }

        /// 정준이 아니어도 Go가 받아들이는 인코딩: 머리의 인자 폭을 필요보다 넓게 고르고, 맵의 쌍을 섞고,
        /// 구조 맵에는 모르는 필드를 하나 더한다(키 8~11은 어느 구조에도 없다).
        mutating func looseEncoding(of value: CBORValue, isStructure: Bool = true) -> [UInt8] {
            switch value {
            case .unsigned(let number):
                return head(major: 0, argument: number)
            case .bytes(let content):
                return head(major: 2, argument: UInt64(content.count)) + content
            case .text(let content):
                return head(major: 3, argument: UInt64(content.count)) + content
            case .array(let elements):
                return elements.reduce(head(major: 4, argument: UInt64(elements.count))) {
                    $0 + looseEncoding(of: $1)
                }
            case .map(let pairs):
                // 텍스트 키의 맵은 `Meta`다. 모르는 필드를 더하지 않는다.
                let isMeta = pairs.contains { if case .text = $0.key { true } else { false } }
                var encodedPairs = pairs.map { looseEncoding(of: $0.key) + looseEncoding(of: $0.value) }
                if isStructure, !isMeta, Bool.random(using: &random) {
                    let unknownKey = UInt64.random(in: 8...11, using: &random)
                    encodedPairs.append(head(major: 0, argument: unknownKey) + [0xf9, 0x3c, 0x00])
                }
                return encodedPairs.shuffled(using: &random).reduce(head(major: 5, argument: UInt64(encodedPairs.count)), +)
            case .null:
                return [0xf6]
            case .negative, .simple, .simpleOrFloat:
                Issue.record("정준 바이트에는 없는 항목이다")
                return []
            }
        }

        private mutating func head(major: UInt8, argument: UInt64) -> [UInt8] {
            let minimumWidth: Int =
                switch argument {
                case 0..<24: 0
                case ...0xff: 1
                case ...0xffff: 2
                case ...0xffff_ffff: 4
                default: 8
                }
            let width = [0, 1, 2, 4, 8].filter { $0 >= minimumWidth }.randomElement(using: &random) ?? 8
            guard width > 0 else { return [major << 5 | UInt8(argument)] }
            let info = UInt8(24 + width.trailingZeroBitCount)
            return [major << 5 | info] + (0..<width).reversed().map { UInt8(truncatingIfNeeded: argument >> UInt64($0 * 8)) }
        }
    }
}
