// 시험 안에서 만드는 자체 서명 인증서와 TLS 신원. 키체인을 쓰지 않는다(계약 6절의 조각과 같은 길:
// `SecKeyCreateWithData` → `SecCertificateCreateWithData` → `SecIdentityCreate`). 키는 시험마다 새로 만들고 버린다.

import CryptoKit
import Foundation
import Network
import Security

enum SelfSignedIdentity {
    struct Failure: Error {}

    /// `CN=localhost`인 P-256 자체 서명 인증서의 TLS 신원.
    static func make() throws -> SecIdentity {
        let key = P256.Signing.PrivateKey()
        let certificate = try certificateDER(for: key)
        let attributes: [CFString: Any] = [
            kSecAttrKeyType: kSecAttrKeyTypeECSECPrimeRandom, kSecAttrKeyClass: kSecAttrKeyClassPrivate,
        ]
        guard let secKey = SecKeyCreateWithData(key.x963Representation as CFData, attributes as CFDictionary, nil),
              let secCertificate = SecCertificateCreateWithData(nil, Data(certificate) as CFData),
              let identity = SecIdentityCreate(nil, secCertificate, secKey)
        else { throw Failure() }
        return identity
    }

    /// 리스너의 TLS 옵션.
    static func serverOptions(_ identity: SecIdentity) throws -> NWProtocolTLS.Options {
        let tls = NWProtocolTLS.Options()
        guard let secIdentity = sec_identity_create(identity) else { throw Failure() }
        sec_protocol_options_set_local_identity(tls.securityProtocolOptions, secIdentity)
        return tls
    }

    /// 시험의 TLS 클라이언트. 인증서를 검사하지 않는다(시험 안에서 만든 인증서다).
    static func clientOptions() -> NWProtocolTLS.Options {
        let tls = NWProtocolTLS.Options()
        sec_protocol_options_set_verify_block(tls.securityProtocolOptions, { _, _, complete in complete(true) }, .global())
        return tls
    }

    // MARK: DER

    private static let ecdsaWithSHA256: [UInt8] = [0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x02]
    private static let ecPublicKey: [UInt8] = [0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01]
    private static let prime256v1: [UInt8] = [0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07]
    private static let commonName: [UInt8] = [0x06, 0x03, 0x55, 0x04, 0x03]

    private static func certificateDER(for key: P256.Signing.PrivateKey) throws -> [UInt8] {
        let name = sequence(set(sequence(commonName + element(0x0C, Array("localhost".utf8)))))
        let validity = sequence(element(0x17, Array("250101000000Z".utf8)) + element(0x17, Array("351231235959Z".utf8)))
        let publicKey = sequence(sequence(ecPublicKey + prime256v1) + element(0x03, [0] + Array(key.publicKey.x963Representation)))
        let algorithm = sequence(ecdsaWithSHA256)
        let tbs = sequence(
            element(0xA0, element(0x02, [2])) + element(0x02, [1]) + algorithm + name + validity + name + publicKey)
        let signature = try key.signature(for: Data(tbs)).derRepresentation
        return sequence(tbs + algorithm + element(0x03, [0] + Array(signature)))
    }

    private static func sequence(_ content: [UInt8]) -> [UInt8] { element(0x30, content) }
    private static func set(_ content: [UInt8]) -> [UInt8] { element(0x31, content) }

    private static func element(_ tag: UInt8, _ content: [UInt8]) -> [UInt8] {
        let count = content.count
        let length: [UInt8] = switch count {
        case ..<0x80: [UInt8(count)]
        case ..<0x100: [0x81, UInt8(count)]
        default: [0x82, UInt8(count >> 8), UInt8(count & 0xFF)]
        }
        return [tag] + length + content
    }
}
