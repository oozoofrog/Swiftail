// Support code for Go reference comparisons (`GoComparisonTests`): fixture loading, hex, minimal DER parsing, and running the Go tool.
//
// `Tools/interop/cmd/acmefixtures` generated `Fixtures/acme-fixtures.json` using `tailscale.com/tempfork/acme` and the Go standard
// library (`Fixtures/README.md`). This file's DER reader is test-only and stays outside the library.

import CryptoKit
import Darwin
import Foundation
import Testing

@testable import SwiftailCertificates

// MARK: - Fixtures

/// One fixture key. The private key is test-only, derived from a public fixed seed.
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

    /// The private key represented by `scalarHex`.
    func privateKey() throws -> P256.Signing.PrivateKey {
        let scalar = try #require(GoOracle.bytes(fromHex: scalarHex), "Key \(id): scalarHex is not hex")
        return try P256.Signing.PrivateKey(rawRepresentation: scalar)
    }
}

/// One key authorization fixture.
struct OracleChallenge: Decodable, Sendable {
    var keyID: String
    var token: String
    var keyAuthorization: String
    var dns01TXT: String
}

/// One JWS fixture. `verifiedExample` is an actual JWS signed by Go.
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

/// One CSR fixture.
struct OracleCSR: Decodable, Sendable {
    var name: String
    var keyID: String
    var domain: String
    var derHex: String
    var certificationRequestInfoHex: String
    var cnStringTag: Int
}

/// The complete fixture file. The 22 cases are `keys` (3) + `challenges` (9) + `jws` (6) + `csrs` (4).
struct OracleFixtures: Decodable, Sendable {
    var caseCount: Int
    var keys: [OracleKey]
    var challenges: [OracleChallenge]
    var jws: [OracleJWS]
    var csrs: [OracleCSR]

    func key(_ id: String) throws -> OracleKey {
        try #require(keys.first { $0.id == id }, "Fixture key \(id) is missing")
    }
}

// MARK: - Tool failures

/// Running the tool or reading the fixture failed to meet a test prerequisite.
struct OracleFailure: Error, CustomStringConvertible {
    let description: String
    init(_ description: String) { self.description = description }
}

// MARK: - Read-only DER

/// A DER TLV: the tag, contents, and complete bytes from the tag through the end of the contents.
struct OracleTLV {
    var tag: UInt8
    var content: [UInt8]
    var encoded: [UInt8]
}

enum GoOracle {
    // MARK: Fixture loading

    /// Loads the fixture file. Throws if the file is missing or its format differs, so the test cannot pass silently.
    static func fixtures() throws -> OracleFixtures {
        let url = try #require(
            Bundle.module.url(forResource: "acme-fixtures", withExtension: "json", subdirectory: "Fixtures"),
            "Expected=acme-fixtures.json resource Actual=missing")
        return try JSONDecoder().decode(OracleFixtures.self, from: Data(contentsOf: url))
    }

    // MARK: hex

    /// Decodes lowercase or uppercase hex to bytes. Returns `nil` for odd lengths or non-hex characters.
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

    /// Encodes bytes as lowercase hex.
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

    // MARK: DER parsing (test-only)

    /// Reads the first TLV in `bytes`. Accepts short-form and 1–4-byte long-form lengths. Returns
    /// `nil` for indefinite lengths or truncated input. Accepts only single-byte tags (tag numbers below 31).
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

    /// Splits the content into TLVs. No bytes may remain.
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

    /// The three elements of the full CSR DER's outer SEQUENCE: `certificationRequestInfo`, `signatureAlgorithm`, and `signature`.
    struct CSRParts {
        var info: OracleTLV
        var algorithm: OracleTLV
        var signature: OracleTLV
        /// The DER ECDSA-Sig-Value after removing the unused-bit count (0) from the BIT STRING contents.
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

    /// The tag of the subject CN in `certificationRequestInfo` (0x13 for PrintableString). Returns `nil` if the structure differs.
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

    /// The `jwk` object in the input to the tool.
    static func jwkObject(_ publicKey: P256.Signing.PublicKey) -> [String: String] {
        let jwk = JWK(publicKey)
        return ["crv": "P-256", "kty": "EC", "x": Base64URL.encode(jwk.x), "y": Base64URL.encode(jwk.y)]
    }

    // MARK: Go tool

    /// The `acmefixtures` executable pointed to by `SWIFTAIL_ACMEFIXTURES`. Returns `nil` if unavailable, skipping the interop test group.
    /// Build with `sh Scripts/build-interop-tools.sh acmefixtures`.
    static let toolPath: String? = ProcessInfo.processInfo.environment["SWIFTAIL_ACMEFIXTURES"].flatMap { $0.isEmpty ? nil : $0 }

    /// Queries the tool once: sends one JSON object to standard input and reads one line (a JSON object) from standard output.
    /// Treats both exit code 0 (`ok:true`) and 1 (`ok:false`) as normal responses. If the deadline passes, kills the process
    /// and throws.
    static func ask(_ command: String, _ request: [String: Any], timeout: Duration = .seconds(20)) async throws -> [String: Any] {
        guard let toolPath else { throw OracleFailure("SWIFTAIL_ACMEFIXTURES is missing") }
        let input = try JSONSerialization.data(withJSONObject: request)
        let output = try await Task.detached {
            try runBlocking(path: toolPath, command: command, input: input, timeout: timeout)
        }.value
        guard output.last == UInt8(ascii: "\n"), !output.dropLast().contains(UInt8(ascii: "\n")) else {
            throw OracleFailure("\(command): standard output is not a single JSON line (\(output.count) bytes)")
        }
        guard let object = try JSONSerialization.jsonObject(with: output) as? [String: Any], object["ok"] is Bool else {
            throw OracleFailure("\(command): response is not a JSON object with an ok member")
        }
        return object
    }

    /// Starts the process and waits for it to exit. A watchdog uses SIGKILL if the tool blocks the read.
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
        // Prevents SIGPIPE from killing the test process if the tool exits before reading all its input.
        guard fcntl(standardInput.fileHandleForWriting.fileDescriptor, F_SETNOSIGPIPE, 1) == 0 else {
            throw OracleFailure("Standard input F_SETNOSIGPIPE failed: \(errno)")
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
            throw OracleFailure("\(command): tool did not finish within \(Int(seconds)) seconds and was killed, or exited on a signal (signal \(process.terminationStatus))")
        }
        guard process.terminationStatus == 0 || process.terminationStatus == 1 else {
            throw OracleFailure("\(command): exit code \(process.terminationStatus), \(diagnostics.count) bytes of diagnostics")
        }
        return output
    }
}
