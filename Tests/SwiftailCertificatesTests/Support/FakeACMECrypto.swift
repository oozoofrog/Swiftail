// RFC 8555 6.2·8.1·8.4·11.1의 서버 검사를 위한 독립 구현이다.
// 라이브러리의 JOSE·CSR·DER 해석기를 쓰지 않아 같은 결함을 공유하지 않는다.
import CryptoKit
import Foundation

enum FakeACMECrypto {
    static func base64URL(_ data: some Sequence<UInt8>) -> String {
        Data(data).base64EncodedString().replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_").replacingOccurrences(of: "=", with: "")
    }

    static func decode(_ text: String) -> Data? {
        guard text.utf8.allSatisfy({
            (65...90).contains($0) || (97...122).contains($0) || (48...57).contains($0) || $0 == 45 || $0 == 95
        }), text.utf8.count % 4 != 1 else { return nil }
        let standard = text.replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/")
        guard let bytes = Data(base64Encoded: standard + String(repeating: "=", count: (4 - standard.count % 4) % 4)),
              base64URL(bytes) == text else { return nil }
        return bytes
    }

    struct JWK: Codable, Sendable, Equatable {
        var crv: String
        var kty: String
        var x: String
        var y: String

        init(_ key: P256.Signing.PublicKey) {
            let bytes = key.x963Representation
            crv = "P-256"
            kty = "EC"
            x = base64URL(bytes[1..<33])
            y = base64URL(bytes[33..<65])
        }

        func publicKey() throws -> P256.Signing.PublicKey {
            guard crv == "P-256", kty == "EC", let x = decode(x), let y = decode(y),
                  x.count == 32, y.count == 32 else { throw Invalid.encoding }
            return try P256.Signing.PublicKey(x963Representation: Data([4]) + x + y)
        }

        var thumbprint: String {
            // RFC 7638: 필수 멤버만 사전식 순서로 놓는다. 좌표는 32바이트를 보존한다.
            let canonical = "{\"crv\":\"P-256\",\"kty\":\"EC\",\"x\":\"\(x)\",\"y\":\"\(y)\"}"
            return base64URL(SHA256.hash(data: Data(canonical.utf8)))
        }
    }

    struct Protected: Codable, Sendable, Equatable {
        var alg: String = "ES256"
        var nonce: String?
        var url: String
        var jwk: JWK?
        var kid: String?
        var b64: Bool?
        var crit: [String]?
    }

    struct Envelope: Codable {
        var protected: String
        var payload: String
        var signature: String
    }

    enum Invalid: Error { case encoding, csr }

    /// 서버 자체 시험의 잘못된 요청도 라이브러리의 서명기를 거치지 않고 만든다.
    static func request(
        url: String, key: P256.Signing.PrivateKey, header: Protected, payload: Data,
        signingKey: P256.Signing.PrivateKey? = nil
    ) throws -> [UInt8] {
        let protected = base64URL(try JSONEncoder().encode(header))
        let encodedPayload = base64URL(payload)
        let signature = try (signingKey ?? key).signature(for: Data("\(protected).\(encodedPayload)".utf8))
        return Array(try JSONEncoder().encode(Envelope(
            protected: protected, payload: encodedPayload, signature: base64URL(signature.rawRepresentation)
        )))
    }

    static func dnsValue(token: String, account: JWK) -> String {
        base64URL(SHA256.hash(data: Data("\(token).\(account.thumbprint)".utf8)))
    }

    /// CSR에 필요한 DER만 읽는다. 길이·경계·비정규 길이·뒤에 남는 바이트를 검사한다.
    struct DER {
        let tag: UInt8
        let content: Data
        let encoded: Data

        static func read(_ bytes: Data) throws -> [DER] {
            let bytes = Array(bytes)
            var offset = 0
            var result: [DER] = []
            while offset < bytes.count {
                let start = offset
                guard bytes.count - offset >= 2 else { throw Invalid.encoding }
                let tag = bytes[offset]
                let first = Int(bytes[offset + 1])
                offset += 2
                var length = first
                if first >= 128 {
                    let count = first & 127
                    guard (1...4).contains(count), bytes.count - offset >= count,
                          bytes[offset] != 0 else { throw Invalid.encoding }
                    length = 0
                    for byte in bytes[offset..<(offset + count)] { length = length * 256 + Int(byte) }
                    guard length >= 128 else { throw Invalid.encoding }
                    offset += count
                }
                guard length <= bytes.count - offset else { throw Invalid.encoding }
                let end = offset + length
                result.append(DER(tag: tag, content: Data(bytes[offset..<end]), encoded: Data(bytes[start..<end])))
                offset = end
            }
            return result
        }

        func children(_ expectedTag: UInt8) throws -> [DER] {
            guard tag == expectedTag else { throw Invalid.encoding }
            return try Self.read(content)
        }
    }

    struct CSR {
        var publicKey: P256.Signing.PublicKey
        var names: Set<String>

        init(_ bytes: Data) throws {
            let outer = try DER.read(bytes)
            guard outer.count == 1 else { throw Invalid.csr }
            let request = try outer[0].children(0x30)
            guard request.count == 3, request[0].tag == 0x30,
                  request[1].encoded == Data([0x30, 0x0A, 0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x02]),
                  request[2].tag == 3, request[2].content.first == 0 else { throw Invalid.csr }
            let info = try request[0].children(0x30)
            guard info.count == 4, info[0].encoded == Data([2, 1, 0]) else { throw Invalid.csr }
            publicKey = try P256.Signing.PublicKey(derRepresentation: info[2].encoded)
            let signature = try P256.Signing.ECDSASignature(derRepresentation: request[2].content.dropFirst())
            guard publicKey.isValidSignature(signature, for: request[0].encoded) else { throw Invalid.csr }
            names = []
            for rdn in try info[1].children(0x30) {
                for attribute in try rdn.children(0x31) {
                    let pair = try attribute.children(0x30)
                    guard pair.count == 2 else { throw Invalid.csr }
                    if pair[0].encoded == Data([6, 3, 0x55, 4, 3]) {
                        guard [UInt8(0x13), 0x0C].contains(pair[1].tag),
                              let name = String(data: pair[1].content, encoding: .utf8) else { throw Invalid.csr }
                        names.insert(name)
                    }
                }
            }
            for attribute in try info[3].children(0xA0) {
                let pair = try attribute.children(0x30)
                guard pair.count == 2,
                      pair[0].encoded == Data([6, 9, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 1, 9, 0x0E])
                else { throw Invalid.csr }
                for value in try pair[1].children(0x31) {
                    for ext in try value.children(0x30) {
                        let fields = try ext.children(0x30)
                        guard fields.count >= 2 else { throw Invalid.csr }
                        if fields[0].encoded == Data([6, 3, 0x55, 0x1D, 0x11]) {
                            guard let octets = fields.last, octets.tag == 4 else { throw Invalid.csr }
                            let san = try DER.read(octets.content)
                            guard san.count == 1 else { throw Invalid.csr }
                            for name in try san[0].children(0x30) {
                                guard name.tag == 0x82, let dns = String(data: name.content, encoding: .ascii)
                                else { throw Invalid.csr }
                                names.insert(dns)
                            }
                        }
                    }
                }
            }
            guard !names.isEmpty else { throw Invalid.csr }
        }
    }
}
