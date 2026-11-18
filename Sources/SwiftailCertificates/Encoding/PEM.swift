import Foundation

/// PEM labels (RFC 7468) that this target reads and writes. It reads only these labels.
enum PEMLabel: String, Sendable, CaseIterable {
    /// DER for an X.509 certificate (RFC 7468 §5). Used in the chain returned by ACME and in `<name>.crt`.
    case certificate = "CERTIFICATE"
    /// DER for PKCS#8 `PrivateKeyInfo` (RFC 7468 §10). Used in the key files Swiftail writes and in CryptoKit's `pemRepresentation`.
    case privateKey = "PRIVATE KEY"
    /// DER for SEC1 `ECPrivateKey` (RFC 5915 §3). Used in the account and certificate key files Go writes (notes §3.7).
    case ecPrivateKey = "EC PRIVATE KEY"
}

/// A PEM block holding a label and its DER bytes.
struct PEMBlock: Sendable, Equatable {
    var label: PEMLabel
    var der: [UInt8]
}

/// The reason PEM input was rejected.
enum PEMError: Error, Sendable, Equatable {
    /// The input exceeds the caller's byte limit. Reject it before decoding.
    case tooLarge
    /// Malformed input includes non-whitespace bytes outside blocks, mismatched or truncated boundaries, an invalid base64 body, an empty body,
    /// or a key block CryptoKit could not read as a P-256 key.
    case malformed
    /// An unknown or disallowed label, such as `PRIVATE KEY` in a chain (RFC 8555 11.4).
    case unexpectedLabel
    /// An incorrect block count (1–5 certificates for a chain or one block for a key file).
    case wrongBlockCount
}

/// Reads and writes PEM (RFC 7468).
///
/// Reading checks the entire input from beginning to end (contract behaviors X3 ① and S3 ②). RFC 7468 §2 allows explanatory text outside
/// boundaries, but this target allows only whitespace (SP, HT, CR, LF) outside blocks. This prevents a malicious ACME server from inserting
/// other blocks or text into the chain (RFC 8555 11.4). Go's `pem.Decode` loop simply stops where it cannot decode,
/// leaving the remainder without rejecting it (notes §3.7). This behavior differs from Go.
///
/// Inside a block, follow the standard grammar in RFC 7468 §3. Each line contains base64 characters (trailing whitespace allowed), with `=` only at the end.
/// Line lengths are unrestricted (RFC 7468 §2 "Parsers MAY handle other line sizes"). Skip whitespace-only lines.
/// Boundaries start at the beginning of a line, and BEGIN and END must have matching labels.
enum PEM {
    /// The maximum certificate count accepted in a chain (contract behaviors X3 ② and S3 ②).
    static let maximumChainLength = 5

    /// Encodes a block as PEM text. Wraps the body at 64 columns and uses LF line endings (RFC 7468 §2 "exactly 64 characters").
    static func encode(_ block: PEMBlock) -> String {
        let body = Array(Data(block.der).base64EncodedString().utf8)
        var text = "-----BEGIN \(block.label.rawValue)-----\n"
        for start in stride(from: 0, to: body.count, by: 64) {
            text += String(decoding: body[start..<min(start + 64, body.count)], as: UTF8.self)
            text += "\n"
        }
        text += "-----END \(block.label.rawValue)-----\n"
        return text
    }

    /// Decodes the entire PEM input into blocks. Returns an empty array if there are no blocks and the input contains only whitespace.
    ///
    /// - Parameter maximumByteCount: The maximum input byte count (256KiB for an ACME chain response, 64KiB for a disk file,
    ///   contract behavior M).
    static func decode(_ input: [UInt8], maximumByteCount: Int) throws(PEMError) -> [PEMBlock] {
        guard input.count <= maximumByteCount else { throw .tooLarge }
        var blocks: [PEMBlock] = []
        var open: (label: PEMLabel, base64: [UInt8])?
        // CR, LF, and CRLF are all line endings (RFC 7468 §3 `eol`). Skip the empty line created between CR and LF as whitespace-only.
        for rawLine in input.split(omittingEmptySubsequences: false, whereSeparator: { $0 == cr || $0 == lf }) {
            let end = rawLine.lastIndex(where: { !isLinearWhitespace($0) }).map(rawLine.index(after:)) ?? rawLine.startIndex
            let line = rawLine[..<end]
            guard !line.isEmpty else {
                continue
            }
            if let current = open {
                if let label = try boundaryLabel(line, prefix: endPrefix) {
                    guard label == current.label else { throw .malformed }
                    blocks.append(PEMBlock(label: label, der: try decodeBody(current.base64)))
                    open = nil
                } else {
                    guard line.allSatisfy(isBase64Character) else { throw .malformed }
                    open?.base64.append(contentsOf: line)
                }
            } else {
                guard let label = try boundaryLabel(line, prefix: beginPrefix) else { throw .malformed }
                open = (label, [])
            }
        }
        // Input that ends without END is truncated.
        guard open == nil else { throw .malformed }
        return blocks
    }

    /// Decodes the certificate chain in an ACME response or `<name>.crt` into a DER array. The leaf comes first (RFC 8555 7.4.2).
    ///
    /// Rejects the entire chain if any block has a label other than `CERTIFICATE` (RFC 8555 11.4) and accepts only 1–5 certificates.
    /// Leaves DER undecoded. Security verifies X.509 (contract behaviors S3 ⑤ and X3 ④).
    static func certificateChain(from input: [UInt8], maximumByteCount: Int) throws(PEMError) -> [[UInt8]] {
        let blocks = try decode(input, maximumByteCount: maximumByteCount)
        guard blocks.allSatisfy({ $0.label == .certificate }) else { throw .unexpectedLabel }
        guard (1...maximumChainLength).contains(blocks.count) else { throw .wrongBlockCount }
        return blocks.map(\.der)
    }

    // MARK: - Boundaries and Body

    private static let cr = UInt8(ascii: "\r")
    private static let lf = UInt8(ascii: "\n")
    private static let beginPrefix = Array("-----BEGIN ".utf8)
    private static let endPrefix = Array("-----END ".utf8)
    private static let boundarySuffix = Array("-----".utf8)

    /// Parses a line starting with `prefix` as a boundary and returns its label. Returns `nil` for lines without the prefix (not boundaries).
    /// Throws if a line with the prefix does not end in `-----` or has an unknown label.
    private static func boundaryLabel(_ line: some Collection<UInt8>, prefix: [UInt8]) throws(PEMError) -> PEMLabel? {
        guard line.starts(with: prefix) else { return nil }
        let rest = Array(line.dropFirst(prefix.count))
        guard rest.count > boundarySuffix.count, rest.suffix(boundarySuffix.count).elementsEqual(boundarySuffix) else {
            throw .malformed
        }
        let name = String(decoding: rest.dropLast(boundarySuffix.count), as: UTF8.self)
        guard let label = PEMLabel(rawValue: name) else { throw .unexpectedLabel }
        return label
    }

    /// Decodes the block body's standard base64 (RFC 4648 §4, including padding). The `=` character can appear only at the end.
    private static func decodeBody(_ base64: [UInt8]) throws(PEMError) -> [UInt8] {
        let padding = base64.reversed().prefix(while: { $0 == UInt8(ascii: "=") }).count
        guard padding <= 2, !base64.dropLast(padding).contains(UInt8(ascii: "=")),
              let data = Data(base64Encoded: Data(base64)), !data.isEmpty
        else { throw .malformed }
        return Array(data)
    }

    private static func isLinearWhitespace(_ byte: UInt8) -> Bool {
        byte == UInt8(ascii: " ") || byte == UInt8(ascii: "\t")
    }

    private static func isBase64Character(_ byte: UInt8) -> Bool {
        switch byte {
        case UInt8(ascii: "A")...UInt8(ascii: "Z"), UInt8(ascii: "a")...UInt8(ascii: "z"),
             UInt8(ascii: "0")...UInt8(ascii: "9"), UInt8(ascii: "+"), UInt8(ascii: "/"), UInt8(ascii: "="):
            true
        default:
            false
        }
    }
}
