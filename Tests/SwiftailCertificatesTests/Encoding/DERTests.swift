// 계약 7절 시험 4(DER 쓰기: 길이 127·128·255·256·65,535의 경계, INTEGER 0, OID)와 시험 7(양수 INTEGER의 선행 0x00).

import CryptoKit
import SwiftailBase
import Testing

@testable import SwiftailCertificates

@Suite("DER 쓰기")
struct DERTests {
    @Test("길이의 정규 인코딩 (X.690 8.1.3·10.1)", arguments: [
        (0, "00"), (1, "01"), (127, "7f"), (128, "8180"), (255, "81ff"),
        (256, "820100"), (65_535, "82ffff"), (65_536, "83010000"),
    ] as [(Int, String)])
    func lengthBoundaries(length: Int, header: String) {
        let encoded = DERValue.octetString([UInt8](repeating: 0xAB, count: length)).encoded
        let headerLength: Int = 1 + header.utf8.count / 2
        let expectedHeader: String = "04" + header
        #expect(Array(encoded.prefix(headerLength)).hex == expectedHeader)
        #expect(encoded.count == headerLength + length)
    }

    @Test("음이 아닌 INTEGER: 0, 앞의 0 떼기, 첫 비트가 1이면 0x00 (X.690 8.3)", arguments: [
        ([], "020100"), ([0x00], "020100"), ([0x00, 0x00], "020100"), ([0x05], "020105"),
        ([0x00, 0x00, 0x05], "020105"), ([0x7F], "02017f"), ([0x80], "02020080"),
        ([0x00, 0x80], "02020080"), ([0xFF, 0xFF], "020300ffff"), ([0x01, 0x00], "02020100"),
    ] as [([UInt8], String)])
    func integers(magnitude: [UInt8], expected: String) {
        #expect(DERValue.integer(magnitude: magnitude).encoded.hex == expected)
    }

    /// 기대값은 `openssl asn1parse -genstr OID:<점 표기>`로 따로 만들었다.
    @Test("OID 상수 (X.690 8.19)", arguments: [
        (ASN1ObjectIdentifier.commonName, [2, 5, 4, 3], "0603550403"),
        (.subjectAltName, [2, 5, 29, 17], "0603551d11"),
        (.ecPublicKey, [1, 2, 840, 10045, 2, 1], "06072a8648ce3d0201"),
        (.secp256r1, [1, 2, 840, 10045, 3, 1, 7], "06082a8648ce3d030107"),
        (.ecdsaWithSHA256, [1, 2, 840, 10045, 4, 3, 2], "06082a8648ce3d040302"),
        (.extensionRequest, [1, 2, 840, 113549, 1, 9, 14], "06092a864886f70d01090e"),
    ] as [(ASN1ObjectIdentifier, [UInt64], String)])
    func objectIdentifiers(identifier: ASN1ObjectIdentifier, arcs: [UInt64], expected: String) {
        #expect(identifier.arcs == arcs)
        #expect(DERValue.objectIdentifier(identifier).encoded.hex == expected)
    }

    @Test("문자열의 태그: PrintableString 0x13, IA5String 0x16")
    func stringTags() throws {
        #expect(DERValue.printableString(try #require(PrintableString("ab"))).encoded.hex == "13026162")
        #expect(DERValue.ia5String(try #require(IA5String("ab"))).encoded.hex == "16026162")
    }

    @Test("PrintableString의 문자 집합 (RFC 4517 3.2)")
    func printableCharacters() {
        #expect(PrintableString("AZaz09 '()+,-./:=?") != nil)
        #expect(PrintableString("") != nil)
        for rejected in ["_", "*", "&", "@", "!", "\"", ";", "<", "é", "\u{0}", "\n", "a\u{7F}"] {
            #expect(PrintableString(rejected) == nil, "\(rejected.unicodeScalars.map(\.value))")
        }
        #expect(IA5String("a_*@\u{0}\u{7F}") != nil)
        #expect(IA5String("é") == nil)
    }

    @Test("BIT STRING은 안 쓰는 비트 0을 앞에 둔다, OCTET STRING, 빈 SEQUENCE")
    func primitives() {
        #expect(DERValue.bitString([0x01, 0x02]).encoded.hex == "0303000102")
        #expect(DERValue.bitString([]).encoded.hex == "030100")
        #expect(DERValue.octetString([]).encoded.hex == "0400")
        #expect(DERValue.sequence([]).encoded.hex == "3000")
        #expect(DERValue.sequence([.integer(magnitude: []), .octetString([0xAA])]).encoded.hex == "3006" + "020100" + "0401aa")
    }

    @Test("SET OF는 원소의 인코딩 순으로 적는다 (X.690 11.6)")
    func setOfIsSorted() {
        let a = DERValue.octetString([0x01, 0x02])   // 04 02 01 02
        let b = DERValue.octetString([0x01, 0x01])   // 04 02 01 01
        let c = DERValue.octetString([0x01])         // 04 01 01: 둘째 바이트 01 < 02
        let d = DERValue.integer(magnitude: [0x09])  // 02 01 09: 태그 02 < 04
        #expect(DERValue.setOf([a, b, c, d]).encoded.hex == "310e" + "020109" + "040101" + "04020101" + "04020102")
        #expect(DERValue.setOf([]).encoded.hex == "3100")
    }

    @Test("IMPLICIT 문맥 태그: 원시형·구성형, 높은 번호 형식 (X.690 8.1.2·8.14.3)")
    func implicitTags() throws {
        let name = try #require(IA5String("a"))
        #expect(DERValue.implicitlyTagged(number: 2, .ia5String(name)).encoded.hex == "820161")
        #expect(DERValue.implicitlyTagged(number: 0, .setOf([])).encoded.hex == "a000")
        #expect(DERValue.implicitlyTagged(number: 30, .octetString([])).encoded.hex == "9e00")
        #expect(DERValue.implicitlyTagged(number: 31, .octetString([])).encoded.hex == "9f1f00")
        #expect(DERValue.implicitlyTagged(number: 200, .sequence([])).encoded.hex == "bf814800")
        #expect(DERValue.implicitlyTagged(number: 1, .implicitlyTagged(number: 5, .sequence([]))).encoded.hex == "a100")
    }

    /// 서명의 r·s는 첫 비트가 1이면 0x00이 붙는 양수 INTEGER다(RFC 3279 2.2.3). CryptoKit의 DER 서명과 견준다.
    @Test("ECDSA-Sig-Value: raw r‖s로 적은 SEQUENCE가 CryptoKit의 derRepresentation과 같다")
    func signatureIntegersMatchCryptoKit() throws {
        let key = P256.Signing.PrivateKey()
        var sawHighBit = false
        for index in 0..<200 {
            let signature = try key.signature(for: [UInt8(truncatingIfNeeded: index)])
            let raw = Array(signature.rawRepresentation)
            let r = Array(raw.prefix(32)), s = Array(raw.suffix(32))
            sawHighBit = sawHighBit || r[0] & 0x80 != 0
            let encoded = DERValue.sequence([.integer(magnitude: r), .integer(magnitude: s)]).encoded
            #expect(encoded == Array(signature.derRepresentation))
        }
        #expect(sawHighBit)
    }
}
