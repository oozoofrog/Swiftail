// 이름 읽기는 golang.org/x/net의 `dns/dnsmessage/message.go` `Name.unpack`(BSD-3-Clause, Copyright 2009 The Go Authors),
// 문자열 이름의 검사는 Tailscale의 `util/dnsname/dnsname.go` `ToFQDN`(BSD-3-Clause, Copyright (c) Tailscale Inc &
// contributors)을 따른다. 규칙과 상수만 옮겼고 코드는 Swift로 새로 썼다.

extension DNSMessage {
    /// DNS 이름. 레이블의 바이트를 받은 그대로(대소문자 포함) 들고 있다.
    ///
    /// 질의에서 읽은 이름은 응답의 질문·답변에 그대로 다시 쓰고, 비교는 `lowercased()`로 한다(노트 3.1).
    /// 레이블은 1…63바이트이고 `.`이 없으며, 끝 점을 포함한 표기 길이는 254바이트 이하다(선 형식 255바이트, RFC 1035 3.1).
    struct Name: Hashable, Sendable {
        /// 레이블. 빈 배열은 루트(`.`)다.
        let labels: [[UInt8]]

        /// 끝 점을 포함한 표기 길이의 최대. Go `nonEncodedNameMax`, `dnsname.maxNameLength`.
        static let maxPresentationLength = 254
        /// 레이블 길이의 최대. 길이 바이트의 상위 두 비트는 포인터·예약 표지다.
        static let maxLabelLength = 63
        /// 한 이름에서 따라가는 압축 포인터의 최대. Go `dnsmessage`의 값이다(노트 5장).
        static let maxPointers = 10

        /// 이름을 읽지 못한 이유. 모두 질의의 FORMERR로 이어진다.
        enum ParseError: Error, Equatable, Sendable {
            /// 레이블이나 포인터가 메시지 끝을 넘는다.
            case truncated
            /// 길이 바이트의 상위 두 비트가 01 또는 10이다(RFC 6891이 없앤 확장 레이블 포함).
            case reservedLabelType
            /// 레이블 안에 `.` 바이트가 있다. 표기로 옮기면 다른 이름이 되므로 받지 않는다(Go 이슈 56246).
            case labelContainsDot
            /// 끝 점을 포함한 표기 길이가 254바이트를 넘는다.
            case tooLong
            /// 포인터를 10번 넘게 따라갔다. 고리를 이루는 포인터가 여기서 끝난다.
            case tooManyPointers
        }

        private init(validatedLabels: [[UInt8]]) {
            labels = validatedLabels
        }

        /// 표기 문자열(`rd-mac-1a2b3c4d.tail0001.ts.net.`)을 이름으로 바꾼다. Go `dnsname.ToFQDN`의 검사를 한다.
        ///
        /// 끝 점은 있어도 없어도 되고, 앞 점 하나는 떼어 낸다. 빈 문자열과 `.`은 루트다. 레이블이 비었거나 63바이트를 넘거나,
        /// 공백·제어 문자(0x20 이하, 0x7F)가 있거나, 끝 점을 더해 254바이트를 넘으면 nil.
        /// netmap의 노드 이름, `ExtraRecords` 이름, 응답기의 영역을 읽을 때 쓴다.
        init?(_ text: String) {
            var bytes = Array(text.utf8)
            if bytes.first == Self.dot { bytes.removeFirst() }
            if bytes.last == Self.dot { bytes.removeLast() }
            guard !bytes.isEmpty else {
                // "", ".", ".."은 Go에서도 루트다.
                self.init(validatedLabels: [])
                return
            }
            guard bytes.count + 1 <= Self.maxPresentationLength, Self.isPrintable(bytes) else { return nil }
            let labels = bytes.split(separator: Self.dot, omittingEmptySubsequences: false).map(Array.init)
            guard labels.allSatisfy({ (1...Self.maxLabelLength).contains($0.count) }) else { return nil }
            self.init(validatedLabels: labels)
        }

        /// 메시지의 `offset`에서 이름 하나를 읽는다. Go `Name.unpack`과 같은 규칙이다(노트 3.1).
        ///
        /// 포인터(상위 두 비트 11)는 앞뒤 어느 쪽을 가리켜도 따라가되 10번까지만 따라간다. Go와 같고, 고리는 이 횟수로 끝난다.
        /// 포인터 사이에서는 읽는 위치가 늘 앞으로 가므로 어떤 입력에서도 반복이 메시지 길이의 11배를 넘지 않고,
        /// 길이 검사가 레이블 수를 묶는다.
        ///
        /// - Returns: 이름과 이름 다음 바이트의 위치. 포인터가 있으면 첫 포인터 바로 뒤다.
        static func read(from message: [UInt8], at offset: Int) throws(ParseError) -> (name: Name, end: Int) {
            var labels: [[UInt8]] = []
            var presentationLength = 0
            var cursor = offset
            var end: Int?
            var pointers = 0
            while true {
                guard cursor < message.count else { throw .truncated }
                let lead = message[cursor]
                cursor += 1
                switch lead & 0xC0 {
                case 0x00:
                    if lead == 0 {
                        return (Name(validatedLabels: labels), end ?? cursor)
                    }
                    let labelEnd = cursor + Int(lead)
                    guard labelEnd <= message.count else { throw .truncated }
                    let label = message[cursor..<labelEnd]
                    guard !label.contains(dot) else { throw .labelContainsDot }
                    // 이 레이블과 그 끝 점을 더한 표기 길이가 254를 넘으면 안 된다.
                    guard presentationLength + label.count < maxPresentationLength else { throw .tooLong }
                    labels.append(Array(label))
                    presentationLength += label.count + 1
                    cursor = labelEnd
                case 0xC0:
                    guard cursor < message.count else { throw .truncated }
                    let low = message[cursor]
                    cursor += 1
                    if pointers == 0 { end = cursor }
                    pointers += 1
                    guard pointers <= maxPointers else { throw .tooManyPointers }
                    cursor = Int(lead & 0x3F) << 8 | Int(low)
                default:
                    throw .reservedLabelType
                }
            }
        }

        /// 압축 없는 선 형식: 레이블마다 길이 바이트와 내용, 끝에 0.
        var wireFormat: [UInt8] {
            var bytes: [UInt8] = []
            for label in labels {
                bytes.append(UInt8(label.count))
                bytes += label
            }
            bytes.append(0)
            return bytes
        }

        /// ASCII `A`-`Z`만 소문자로 바꾼 이름. 이름 비교는 이것으로 한다(Go `rawNameToLower`).
        func lowercased() -> Name {
            Name(validatedLabels: labels.map { $0.map(Self.lowercased) })
        }

        /// 공백·제어 문자(0x20 이하, 0x7F)가 없다. 질의 이름이 Go `dnsname.ToFQDN`을 통과하는 조건이다.
        /// 선 형식에서 읽은 이름은 레이블 길이와 전체 길이를 이미 지키므로 이것만 더 보면 된다.
        var isPrintable: Bool {
            labels.allSatisfy(Self.isPrintable)
        }

        /// `zone`과 같거나 그 아래의 이름이다. 레이블 단위로 견준다(Go `FQDN.Contains`). 둘 다 소문자여야 한다.
        func isWithin(_ zone: Name) -> Bool {
            labels.count >= zone.labels.count && labels.suffix(zone.labels.count).elementsEqual(zone.labels)
        }

        private static let dot = UInt8(ascii: ".")

        private static func isPrintable(_ bytes: [UInt8]) -> Bool {
            bytes.allSatisfy { $0 > 0x20 && $0 != 0x7F }
        }

        static func lowercased(_ byte: UInt8) -> UInt8 {
            (UInt8(ascii: "A")...UInt8(ascii: "Z")).contains(byte) ? byte + 0x20 : byte
        }
    }
}
