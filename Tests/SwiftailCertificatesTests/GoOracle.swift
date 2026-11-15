// Go 기준값 대조 시험(`GoComparisonTests`)의 지원 코드: 자료 읽기, hex, DER의 최소 읽기, Go 도구 실행.
//
// 자료(`Fixtures/acme-fixtures.json`)는 `Tools/interop/cmd/acmefixtures`가 `tailscale.com/tempfork/acme`와 Go 표준
// 라이브러리로 만든 것이다(`Fixtures/README.md`). 이 파일의 DER 읽기는 시험 전용이며 라이브러리에 넣지 않는다.

import CryptoKit
import Darwin
import Foundation
import Testing

@testable import SwiftailCertificates

// MARK: - 자료

/// 자료의 키 하나. 개인 키는 공개된 고정 씨앗에서 만든 시험 전용 값이다.
struct OracleKey: Decodable, Sendable {
    struct PublicJWK: Decodable, Sendable, Equatable {
        var crv: String
        var kty: String
        var x: String
        var y: String
    }

    var id: String
    var scalarHex: String
    var publicKey: PublicJWK
    var jwkJSON: String
    var thumbprint: String
    var sec1PEM: String
    var pkcs8PEM: String

    /// `scalarHex`의 개인 키.
    func privateKey() throws -> P256.Signing.PrivateKey {
        let scalar = try #require(GoOracle.bytes(fromHex: scalarHex), "키 \(id): scalarHex가 hex가 아님")
        return try P256.Signing.PrivateKey(rawRepresentation: scalar)
    }
}

/// 키 인가 자료 하나.
struct OracleChallenge: Decodable, Sendable {
    var keyID: String
    var token: String
    var keyAuthorization: String
    var dns01TXT: String
}

/// JWS 자료 하나. `verifiedExample`은 Go가 서명한 실제 JWS다.
struct OracleJWS: Decodable, Sendable {
    struct Example: Decodable, Sendable {
        var protected: String
        var payload: String
        var signature: String
    }

    var keyID: String
    var mode: String
    var protectedJSON: String
    var payloadJSON: String
    var signingInput: String
    var verifiedExample: Example
}

/// CSR 자료 하나.
struct OracleCSR: Decodable, Sendable {
    var name: String
    var keyID: String
    var domain: String
    var derHex: String
    var certificationRequestInfoHex: String
    var cnStringTag: Int
}

/// 자료 파일 전체. 22개 사례는 `keys`(3) + `challenges`(9) + `jws`(6) + `csrs`(4)다.
struct OracleFixtures: Decodable, Sendable {
    var caseCount: Int
    var keys: [OracleKey]
    var challenges: [OracleChallenge]
    var jws: [OracleJWS]
    var csrs: [OracleCSR]

    func key(_ id: String) throws -> OracleKey {
        try #require(keys.first { $0.id == id }, "자료에 키 \(id)가 없음")
    }
}

// MARK: - 도구 실패

/// 도구 실행이나 자료 읽기가 시험의 전제를 만족하지 못했다.
struct OracleFailure: Error, CustomStringConvertible {
    let description: String
    init(_ description: String) { self.description = description }
}

// MARK: - 읽기 전용 DER

/// DER의 TLV 하나: 태그, 내용, 그리고 태그부터 내용 끝까지 통째.
struct OracleTLV {
    var tag: UInt8
    var content: [UInt8]
    var encoded: [UInt8]
}

enum GoOracle {
    // MARK: 자료 읽기

    /// 자료 파일을 읽는다. 파일이 없거나 형식이 다르면 던진다(시험이 조용히 통과하지 않는다).
    static func fixtures() throws -> OracleFixtures {
        let url = try #require(
            Bundle.module.url(forResource: "acme-fixtures", withExtension: "json", subdirectory: "Fixtures"),
            "기대=acme-fixtures.json 리소스 실제=없음")
        return try JSONDecoder().decode(OracleFixtures.self, from: Data(contentsOf: url))
    }

    // MARK: hex

    /// 소문자·대문자 hex를 바이트로. 홀수 길이나 hex가 아닌 글자가 있으면 `nil`.
    static func bytes(fromHex text: String) -> [UInt8]? {
        let digits = Array(text.utf8)
        guard digits.count % 2 == 0 else { return nil }
        func nibble(_ character: UInt8) -> UInt8? {
            switch character {
            case UInt8(ascii: "0")...UInt8(ascii: "9"): character - UInt8(ascii: "0")
            case UInt8(ascii: "a")...UInt8(ascii: "f"): character - UInt8(ascii: "a") + 10
            case UInt8(ascii: "A")...UInt8(ascii: "F"): character - UInt8(ascii: "A") + 10
            default: nil
            }
        }
        var result: [UInt8] = []
        result.reserveCapacity(digits.count / 2)
        for index in stride(from: 0, to: digits.count, by: 2) {
            guard let high = nibble(digits[index]), let low = nibble(digits[index + 1]) else { return nil }
            result.append(high << 4 | low)
        }
        return result
    }

    /// 바이트를 소문자 hex로.
    static func hexString(_ bytes: [UInt8]) -> String {
        let digits = Array("0123456789abcdef".utf8)
        var text: [UInt8] = []
        text.reserveCapacity(bytes.count * 2)
        for byte in bytes {
            text.append(digits[Int(byte >> 4)])
            text.append(digits[Int(byte & 0x0F)])
        }
        return String(decoding: text, as: UTF8.self)
    }

    // MARK: DER 읽기(시험 전용)

    /// `bytes`의 맨 앞 TLV 하나를 읽는다. 짧은 형식과 1~4바이트의 긴 형식 길이를 받고, 부정 길이나 잘린 입력은
    /// `nil`이다. 태그는 한 바이트(번호 31 미만)만 받는다.
    static func readTLV(_ bytes: ArraySlice<UInt8>) -> OracleTLV? {
        var index = bytes.startIndex
        guard index < bytes.endIndex else { return nil }
        let tag = bytes[index]
        guard tag & 0x1F != 0x1F else { return nil }
        index += 1
        guard index < bytes.endIndex else { return nil }
        var length = Int(bytes[index])
        index += 1
        if length & 0x80 != 0 {
            let count = length & 0x7F
            guard (1...4).contains(count), index + count <= bytes.endIndex else { return nil }
            length = 0
            for _ in 0..<count {
                length = length << 8 | Int(bytes[index])
                index += 1
            }
        }
        guard index + length <= bytes.endIndex else { return nil }
        return OracleTLV(
            tag: tag,
            content: Array(bytes[index..<index + length]),
            encoded: Array(bytes[bytes.startIndex..<index + length]))
    }

    /// 내용을 TLV들로 가른다. 한 바이트도 남지 않아야 한다.
    static func children(of content: [UInt8]) -> [OracleTLV]? {
        var result: [OracleTLV] = []
        var rest = content[...]
        while !rest.isEmpty {
            guard let tlv = readTLV(rest) else { return nil }
            result.append(tlv)
            rest = rest.dropFirst(tlv.encoded.count)
        }
        return result
    }

    /// CSR 전체 DER의 바깥 SEQUENCE 셋: `certificationRequestInfo`, `signatureAlgorithm`, `signature`.
    struct CSRParts {
        var info: OracleTLV
        var algorithm: OracleTLV
        var signature: OracleTLV
        /// BIT STRING의 내용에서 "안 쓰는 비트 수"(0)를 뗀 DER ECDSA-Sig-Value.
        var signatureDER: [UInt8]
    }

    static func csrParts(_ der: [UInt8]) -> CSRParts? {
        guard let outer = readTLV(der[...]), outer.tag == 0x30, outer.encoded.count == der.count,
              let parts = children(of: outer.content), parts.count == 3,
              parts[0].tag == 0x30, parts[1].tag == 0x30, parts[2].tag == 0x03,
              parts[2].content.first == 0
        else { return nil }
        return CSRParts(info: parts[0], algorithm: parts[1], signature: parts[2], signatureDER: Array(parts[2].content.dropFirst()))
    }

    /// `certificationRequestInfo`의 주체 CN 값의 태그(PrintableString이면 0x13). 구조가 다르면 `nil`.
    static func commonNameStringTag(info: [UInt8]) -> UInt8? {
        // CertificationRequestInfo ::= SEQUENCE { version, subject, subjectPKInfo, attributes }
        guard let sequence = readTLV(info[...]), let fields = children(of: sequence.content), fields.count == 4,
              let set = children(of: fields[1].content)?.first, set.tag == 0x31,
              let attribute = children(of: set.content)?.first, attribute.tag == 0x30,
              let pair = children(of: attribute.content), pair.count == 2
        else { return nil }
        return pair[1].tag
    }

    // MARK: JWK

    /// 도구 입력의 `jwk` 객체.
    static func jwkObject(_ publicKey: P256.Signing.PublicKey) -> [String: String] {
        let jwk = JWK(publicKey)
        return ["crv": "P-256", "kty": "EC", "x": Base64URL.encode(jwk.x), "y": Base64URL.encode(jwk.y)]
    }

    // MARK: Go 도구

    /// 환경 변수 `SWIFTAIL_ACMEFIXTURES`가 가리키는 `acmefixtures` 실행 파일. 없으면 `nil`(상호 운용 묶음을 건너뛴다).
    /// 만드는 법: `sh Scripts/build-interop-tools.sh acmefixtures`.
    static let toolPath: String? = ProcessInfo.processInfo.environment["SWIFTAIL_ACMEFIXTURES"].flatMap { $0.isEmpty ? nil : $0 }

    /// 도구에 한 번 묻는다: 표준 입력으로 JSON 객체 하나를 주고, 표준 출력의 한 줄(JSON 객체)을 읽는다.
    /// 종료 코드 0(`ok:true`)과 1(`ok:false`)을 모두 정상 응답으로 본다. 기한 안에 끝나지 않으면 프로세스를
    /// 죽이고 던진다.
    static func ask(_ command: String, _ request: [String: Any], timeout: Duration = .seconds(20)) async throws -> [String: Any] {
        guard let toolPath else { throw OracleFailure("SWIFTAIL_ACMEFIXTURES가 없음") }
        let input = try JSONSerialization.data(withJSONObject: request)
        let output = try await Task.detached {
            try runBlocking(path: toolPath, command: command, input: input, timeout: timeout)
        }.value
        guard output.last == UInt8(ascii: "\n"), !output.dropLast().contains(UInt8(ascii: "\n")) else {
            throw OracleFailure("\(command): 표준 출력이 JSON 한 줄이 아님(\(output.count)바이트)")
        }
        guard let object = try JSONSerialization.jsonObject(with: output) as? [String: Any], object["ok"] is Bool else {
            throw OracleFailure("\(command): 응답이 `ok`가 있는 JSON 객체가 아님")
        }
        return object
    }

    /// 프로세스를 띄우고 끝날 때까지 기다린다. 읽기가 막히는 도구는 감시 타이머가 SIGKILL로 끊는다.
    private static func runBlocking(path: String, command: String, input: Data, timeout: Duration) throws -> Data {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: path)
        process.arguments = [command]
        let standardInput = Pipe()
        let standardOutput = Pipe()
        let standardError = Pipe()
        process.standardInput = standardInput
        process.standardOutput = standardOutput
        process.standardError = standardError
        // 도구가 입력을 다 읽기 전에 끝나도 SIGPIPE로 시험 프로세스가 죽지 않게 한다.
        guard fcntl(standardInput.fileHandleForWriting.fileDescriptor, F_SETNOSIGPIPE, 1) == 0 else {
            throw OracleFailure("표준 입력 F_SETNOSIGPIPE 실패: \(errno)")
        }
        try process.run()
        let pid = process.processIdentifier
        let seconds = Double(timeout.components.seconds)
        let watchdog = DispatchWorkItem { _ = kill(pid, SIGKILL) }
        DispatchQueue.global().asyncAfter(deadline: .now() + seconds, execute: watchdog)
        defer { watchdog.cancel() }

        try standardInput.fileHandleForWriting.write(contentsOf: input)
        try standardInput.fileHandleForWriting.close()
        let output = try standardOutput.fileHandleForReading.readToEnd() ?? Data()
        let diagnostics = try standardError.fileHandleForReading.readToEnd() ?? Data()
        process.waitUntilExit()
        if process.terminationReason == .uncaughtSignal {
            throw OracleFailure("\(command): 도구가 \(Int(seconds))초 안에 끝나지 않아 죽였거나 신호로 끝남(신호 \(process.terminationStatus))")
        }
        guard process.terminationStatus == 0 || process.terminationStatus == 1 else {
            throw OracleFailure("\(command): 종료 코드 \(process.terminationStatus), 진단 \(diagnostics.count)바이트")
        }
        return output
    }
}
