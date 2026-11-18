// Name parsing follows `Name.unpack` in golang.org/x/net `dns/dnsmessage/message.go` (BSD-3-Clause, Copyright 2009 The Go Authors).
// String name validation follows `ToFQDN` in Tailscale's `util/dnsname/dnsname.go` (BSD-3-Clause, Copyright (c) Tailscale Inc &
// contributors). Only the rules and constants were ported. The code was written from scratch in Swift.

extension DNSMessage {
    /// A DNS name that retains the label bytes as received, including case.
    ///
    /// A name read from a query is written unchanged in the response question and answer. Comparisons use `lowercased()` (notes 3.1).
    /// Labels are 1…63 bytes with no `.`, and the presentation length including the trailing dot is at most 254 bytes (255 bytes on the wire, RFC 1035 3.1).
    struct Name: Hashable, Sendable {
        /// The labels. An empty array is the root (`.`).
        let labels: [[UInt8]]

        /// The maximum presentation length including the trailing dot. Go `nonEncodedNameMax` and `dnsname.maxNameLength`.
        static let maxPresentationLength = 254
        /// The maximum label length. The top two bits of the length byte mark pointers or reserved values.
        static let maxLabelLength = 63
        /// The maximum number of compression pointers followed in one name. Uses the Go `dnsmessage` value (notes §5).
        static let maxPointers = 10

        /// A reason a name could not be read. All reasons yield FORMERR for the query.
        enum ParseError: Error, Equatable, Sendable {
            /// A label or pointer extends past the end of the message.
            case truncated
            /// The top two bits of the length byte are 01 or 10 (including extended labels removed by RFC 6891).
            case reservedLabelType
            /// A label contains a `.` byte. Rejects it because presentation format would produce a different name (Go issue 56246).
            case labelContainsDot
            /// The presentation length including the trailing dot exceeds 254 bytes.
            case tooLong
            /// Followed more than 10 pointers. This stops pointer loops.
            case tooManyPointers
        }

        private init(validatedLabels: [[UInt8]]) {
            labels = validatedLabels
        }

        /// Converts a presentation string (`rd-mac-1a2b3c4d.tail0001.ts.net.`) to a name. Uses Go's `dnsname.ToFQDN` checks.
        ///
        /// The trailing dot is optional. Removes one leading dot. The empty string and `.` are the root. If a label is empty or over 63 bytes,
        /// the name contains a space or control character (0x20 or below, or 0x7F), or adding the trailing dot would exceed 254 bytes, returns nil.
        /// Used to read netmap node names, `ExtraRecords` names, and responder zones.
        init?(_ text: String) {
            var bytes = Array(text.utf8)
            if bytes.first == Self.dot { bytes.removeFirst() }
            if bytes.last == Self.dot { bytes.removeLast() }
            guard !bytes.isEmpty else {
                // "", ".", and ".." are also the root in Go.
                self.init(validatedLabels: [])
                return
            }
            guard bytes.count + 1 <= Self.maxPresentationLength, Self.isPrintable(bytes) else { return nil }
            let labels = bytes.split(separator: Self.dot, omittingEmptySubsequences: false).map(Array.init)
            guard labels.allSatisfy({ (1...Self.maxLabelLength).contains($0.count) }) else { return nil }
            self.init(validatedLabels: labels)
        }

        /// Reads one name from `offset` in the message. Follows the same rules as Go `Name.unpack` (notes 3.1).
        ///
        /// Follows a pointer (top two bits 11) in either direction, at most 10 times. This matches Go and bounds loops by the pointer count.
        /// Between pointers, the read position always moves forward, so the number of iterations is at most 11 times the message length for any input,
        /// and the length check bounds the label count.
        ///
        /// - Returns: The name and the offset of the byte after it. If there is a pointer, the offset is immediately after the first pointer.
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
                    // The presentation length must stay at or below 254 after adding this label and its trailing dot.
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

        /// Uncompressed wire format, with each label's length byte and contents, then a final 0.
        var wireFormat: [UInt8] {
            var bytes: [UInt8] = []
            for label in labels {
                bytes.append(UInt8(label.count))
                bytes += label
            }
            bytes.append(0)
            return bytes
        }

        /// A name with only ASCII `A`-`Z` converted to lowercase. Used for name comparisons (Go `rawNameToLower`).
        func lowercased() -> Name {
            Name(validatedLabels: labels.map { $0.map(Self.lowercased) })
        }

        /// Contains no spaces or control characters (0x20 or below, or 0x7F). This is required for a query name to pass Go `dnsname.ToFQDN`.
        /// A name read from the wire already meets the label and total length limits, so only this additional check is needed.
        var isPrintable: Bool {
            labels.allSatisfy(Self.isPrintable)
        }

        /// Whether the name equals `zone` or is below it. Compares whole labels (Go `FQDN.Contains`). Both must be lowercase.
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
