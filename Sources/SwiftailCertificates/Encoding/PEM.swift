import Foundation

/// 이 타깃이 읽고 쓰는 PEM 라벨(RFC 7468). 이 밖의 라벨은 읽지 않는다.
enum PEMLabel: String, Sendable, CaseIterable {
    /// X.509 인증서의 DER(RFC 7468 5절). ACME가 내려 주는 사슬과 `<이름>.crt`.
    case certificate = "CERTIFICATE"
    /// PKCS#8 `PrivateKeyInfo`의 DER(RFC 7468 10절). Swiftail이 쓰는 키 파일과 CryptoKit의 `pemRepresentation`.
    case privateKey = "PRIVATE KEY"
    /// SEC1 `ECPrivateKey`의 DER(RFC 5915 3절). Go가 쓰는 계정 키·인증서 키 파일이다(노트 3.7).
    case ecPrivateKey = "EC PRIVATE KEY"
}

/// PEM 블록 하나: 라벨과 그 안의 DER 바이트.
struct PEMBlock: Sendable, Equatable {
    var label: PEMLabel
    var der: [UInt8]
}

/// PEM 입력을 받지 않은 까닭.
enum PEMError: Error, Sendable, Equatable {
    /// 입력이 부르는 쪽이 정한 바이트 한도를 넘는다. 읽기 전에 거절한다.
    case tooLarge
    /// 형식이 틀렸다: 블록 밖에 공백이 아닌 바이트, 짝이 맞지 않거나 잘린 경계선, base64가 아닌 본문, 빈 본문,
    /// CryptoKit이 P-256 키로 읽지 못한 키 블록.
    case malformed
    /// 모르는 라벨이거나, 이 자리에 올 수 없는 라벨이다(사슬 안의 `PRIVATE KEY` 등. RFC 8555 11.4).
    case unexpectedLabel
    /// 블록 수가 맞지 않는다(사슬은 1~5장, 키 파일은 한 블록).
    case wrongBlockCount
}

/// PEM(RFC 7468) 쓰기와 읽기.
///
/// 읽기는 입력 전체를 처음부터 끝까지 검사한다(계약 동작 X3 ①·S3 ②). RFC 7468 2절은 경계선 밖의 설명 글을
/// 허용하지만, 이 타깃은 블록 밖에 공백(SP, HT, CR, LF)만 받는다. 악의적인 ACME 서버가 사슬에 다른 블록이나
/// 글을 끼워 넣는 것을 막기 위해서다(RFC 8555 11.4). Go의 `pem.Decode` 루프는 해석되지 않는 곳에서 멈출 뿐
/// 뒤를 거절하지 않는다(노트 3.7). 이 점은 Go와 다르다.
///
/// 블록 안에서는 RFC 7468 3절의 표준 문법을 따른다: 줄마다 base64 문자(줄 끝의 공백은 허용), 마지막에만 `=`,
/// 줄 길이는 묻지 않는다(RFC 7468 2절 "Parsers MAY handle other line sizes"). 공백뿐인 줄은 건너뛴다.
/// 경계선은 줄의 처음에서 시작하고 BEGIN과 END의 라벨이 같아야 한다.
enum PEM {
    /// 인증서 사슬에 받는 최대 장수(계약 동작 X3 ②·S3 ②).
    static let maximumChainLength = 5

    /// 블록 하나를 PEM 글로 적는다. 본문은 64열로 감싸고 줄 끝은 LF다(RFC 7468 2절 "exactly 64 characters").
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

    /// PEM 입력 전체를 블록들로 읽는다. 블록이 없고 공백뿐이면 빈 배열이다.
    ///
    /// - Parameter maximumByteCount: 받는 입력의 최대 바이트 수(ACME 사슬 응답 256KiB, 디스크의 파일 64KiB.
    ///   계약 동작 M).
    static func decode(_ input: [UInt8], maximumByteCount: Int) throws(PEMError) -> [PEMBlock] {
        guard input.count <= maximumByteCount else { throw .tooLarge }
        var blocks: [PEMBlock] = []
        var open: (label: PEMLabel, base64: [UInt8])?
        // CR, LF, CRLF 모두 줄 끝이다(RFC 7468 3절 `eol`). CRLF 사이에 생기는 빈 줄은 공백뿐인 줄로 건너뛴다.
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
        // END 없이 끝난 입력은 잘린 것이다.
        guard open == nil else { throw .malformed }
        return blocks
    }

    /// ACME 응답이나 `<이름>.crt`의 인증서 사슬을 DER 배열로 읽는다. leaf가 먼저다(RFC 8555 7.4.2).
    ///
    /// `CERTIFICATE`가 아닌 블록이 하나라도 있으면 전체를 버리고(RFC 8555 11.4), 1~5장만 받는다.
    /// DER는 해석하지 않는다. X.509 검증은 Security가 한다(계약 동작 S3 ⑤·X3 ④).
    static func certificateChain(from input: [UInt8], maximumByteCount: Int) throws(PEMError) -> [[UInt8]] {
        let blocks = try decode(input, maximumByteCount: maximumByteCount)
        guard blocks.allSatisfy({ $0.label == .certificate }) else { throw .unexpectedLabel }
        guard (1...maximumChainLength).contains(blocks.count) else { throw .wrongBlockCount }
        return blocks.map(\.der)
    }

    // MARK: - 경계선과 본문

    private static let cr = UInt8(ascii: "\r")
    private static let lf = UInt8(ascii: "\n")
    private static let beginPrefix = Array("-----BEGIN ".utf8)
    private static let endPrefix = Array("-----END ".utf8)
    private static let boundarySuffix = Array("-----".utf8)

    /// 줄이 `prefix`로 시작하면 경계선으로 읽어 라벨을 낸다. 시작하지 않으면 `nil`(경계선이 아니다).
    /// 시작하는데 `-----`로 끝나지 않거나 라벨을 모르면 던진다.
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

    /// 블록 본문의 표준 base64(RFC 4648 4절, 채움 포함)를 읽는다. `=`는 끝에만 올 수 있다.
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
