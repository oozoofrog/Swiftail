import Testing

import SwiftailBase

@testable import SwiftailMagicsock

/// STUN 바인딩 요청·응답의 부호화와 해석(DERP 노트 3.8·3.9·4.10 3, 노트 4.1 1).
///
/// 기준값(`goRequest`, `goResponse…`)은 Go `tailscale.com@v1.104.6/net/stun`을 임시 프로그램으로 불러 얻었다.
/// TxID는 `01 02 … 0c`, 주소는 `192.0.2.33:41641`·`[2001:db8::1]:41641`·`[::ffff:192.0.2.33]:41641`이다.
/// `stun.Request(tx)`와 `stun.Response(tx, addrPort)`의 바이트이고, 같은 응답을 `stun.ParseResponse`에 넣으면
/// 각각 `192.0.2.33:41641`, `[2001:db8::1]:41641`, `192.0.2.33:41641`(IPv4-mapped를 푼다)이 나왔다.
@Suite("STUN 메시지")
struct STUNMessageTests {
    private static let txBytes = Array(UInt8(1)...UInt8(12))
    private static let transactionID = TransactionID(txBytes)!

    private static let goRequest = hex("000100142112a4420102030405060708090a0b0c802200087461696c6e6f646580280004b32c370f")
    private static let goResponseV4 = hex("0101000c2112a4420102030405060708090a0b0c00200008000183bbe112a663")
    private static let goResponseV6 = hex("010100182112a4420102030405060708090a0b0c00200014000283bb0113a9fa0102030405060708090a0b0d")
    private static let goResponseMapped = hex("010100182112a4420102030405060708090a0b0c00200014000283bb2112a442010203040506f8f7c90a092d")

    private static let v4 = IPEndpoint("192.0.2.33:41641")!
    private static let v6 = IPEndpoint("[2001:db8::1]:41641")!

    private static func hex(_ text: String) -> [UInt8] {
        var bytes: [UInt8] = []
        var index = text.startIndex
        while index < text.endIndex {
            let next = text.index(index, offsetBy: 2)
            bytes.append(UInt8(text[index..<next], radix: 16)!)
            index = next
        }
        return bytes
    }

    /// 헤더(성공 응답) + 속성들. 본문 길이는 속성의 합으로 채운다.
    private static func response(_ attributes: [UInt8], declaredLength: Int? = nil) -> [UInt8] {
        let length = declaredLength ?? attributes.count
        return [0x01, 0x01, UInt8(length >> 8), UInt8(length & 0xff)] + STUNMessage.magicCookie + txBytes + attributes
    }

    /// 속성 하나: 종류(2) ‖ 길이(2) ‖ 값 ‖ 4바이트 정렬 패딩.
    private static func attribute(_ type: UInt16, _ value: [UInt8]) -> [UInt8] {
        let padding = (4 - value.count % 4) % 4
        return [UInt8(type >> 8), UInt8(type & 0xff), UInt8(value.count >> 8), UInt8(value.count & 0xff)]
            + value + [UInt8](repeating: 0, count: padding)
    }

    /// XOR-MAPPED-ADDRESS의 값. `address`는 4바이트(IPv4) 또는 16바이트(IPv6)다.
    private static func xorValue(family: UInt8, port: UInt16, address: [UInt8]) -> [UInt8] {
        let mask = STUNMessage.magicCookie + txBytes
        let xoredPort = port ^ 0x2112
        return [0, family, UInt8(xoredPort >> 8), UInt8(xoredPort & 0xff)]
            + address.enumerated().map { $0.element ^ mask[$0.offset] }
    }

    private static func mappedValue(family: UInt8, port: UInt16, address: [UInt8]) -> [UInt8] {
        [0, family, UInt8(port >> 8), UInt8(port & 0xff)] + address
    }

    // MARK: 요청

    @Test("바인딩 요청 40바이트는 Go stun.Request와 바이트 단위로 같다")
    func requestMatchesGo() {
        #expect(STUNMessage.bindingRequest(Self.transactionID) == Self.goRequest)
    }

    @Test("요청의 필드가 노트 3.8의 표와 같다")
    func requestLayout() {
        let request = STUNMessage.bindingRequest(Self.transactionID)
        #expect(request.count == 40)
        #expect(Array(request[0..<2]) == [0x00, 0x01])  // binding request
        #expect(Array(request[2..<4]) == [0x00, 0x14])  // 헤더 뒤 20바이트
        #expect(Array(request[4..<8]) == [0x21, 0x12, 0xa4, 0x42])
        #expect(Array(request[8..<20]) == Self.txBytes)
        #expect(Array(request[20..<24]) == [0x80, 0x22, 0x00, 0x08])  // SOFTWARE
        #expect(Array(request[24..<32]) == Array("tailnode".utf8))
        #expect(Array(request[32..<36]) == [0x80, 0x28, 0x00, 0x04])  // FINGERPRINT
    }

    @Test("TxID가 달라지면 FINGERPRINT도 달라지고, 요청은 STUN으로 판정된다")
    func requestVariesWithTransactionID() throws {
        let other = try #require(TransactionID([UInt8](repeating: 0xaa, count: 12)))
        let first = STUNMessage.bindingRequest(Self.transactionID)
        let second = STUNMessage.bindingRequest(other)
        #expect(Array(first[36...]) != Array(second[36...]))
        #expect(Array(second[8..<20]) == other.bytes)
        #expect(STUNMessage.looksLikeSTUN(second))
    }

    // MARK: 응답 해석

    @Test("Go가 만든 IPv4 응답을 해석한다")
    func parsesGoIPv4() throws {
        let (id, endpoint) = try #require(STUNMessage.parseBindingResponse(Self.goResponseV4))
        #expect(id == Self.transactionID)
        #expect(endpoint == Self.v4)
    }

    @Test("Go가 만든 IPv6 응답을 해석한다")
    func parsesGoIPv6() throws {
        let (id, endpoint) = try #require(STUNMessage.parseBindingResponse(Self.goResponseV6))
        #expect(id == Self.transactionID)
        #expect(endpoint == Self.v6)
    }

    @Test("IPv4-mapped IPv6 주소는 IPv4로 푼다")
    func unmapsIPv4MappedAddress() throws {
        let (_, endpoint) = try #require(STUNMessage.parseBindingResponse(Self.goResponseMapped))
        #expect(endpoint == Self.v4)
        #expect(endpoint.address.isIPv4)
    }

    @Test("대체 타입 0x8020도 XOR-MAPPED-ADDRESS로 처리한다")
    func parsesAlternateXORType() throws {
        var bytes = Self.goResponseV4
        bytes[20] = 0x80  // 0x0020 → 0x8020
        let (_, endpoint) = try #require(STUNMessage.parseBindingResponse(bytes))
        #expect(endpoint == Self.v4)
    }

    @Test("MAPPED-ADDRESS만 있는 응답은 그 주소를 쓴다")
    func parsesMappedAddressOnly() throws {
        let value = Self.mappedValue(family: 1, port: 41641, address: [192, 0, 2, 33])
        let (_, endpoint) = try #require(STUNMessage.parseBindingResponse(Self.response(Self.attribute(0x0001, value))))
        #expect(endpoint == Self.v4)
    }

    @Test("XOR 주소가 있으면 MAPPED-ADDRESS보다 앞선다(속성 순서와 무관)")
    func xorWinsOverMapped() throws {
        let mapped = Self.attribute(0x0001, Self.mappedValue(family: 1, port: 1111, address: [10, 0, 0, 1]))
        let xor = Self.attribute(0x0020, Self.xorValue(family: 1, port: 41641, address: [192, 0, 2, 33]))
        for attributes in [mapped + xor, xor + mapped] {
            let (_, endpoint) = try #require(STUNMessage.parseBindingResponse(Self.response(attributes)))
            #expect(endpoint == Self.v4)
        }
    }

    @Test("MAPPED-ADDRESS의 IPv6 주소를 해석한다")
    func parsesMappedIPv6() throws {
        let address = try #require(IPAddress("2001:db8::1")).bytes
        let value = Self.mappedValue(family: 2, port: 41641, address: address)
        let (_, endpoint) = try #require(STUNMessage.parseBindingResponse(Self.response(Self.attribute(0x0001, value))))
        #expect(endpoint == Self.v6)
    }

    @Test("모르는 속성은 4바이트 패딩까지 건너뛴다")
    func skipsUnknownAttributesWithPadding() throws {
        // 길이 1·2·3·5인 SOFTWARE 속성은 각각 3·2·1·3바이트의 패딩이 붙는다.
        let unknown = [1, 2, 3, 5].flatMap { Self.attribute(0x8022, [UInt8](repeating: 0x41, count: $0)) }
        let xor = Self.attribute(0x0020, Self.xorValue(family: 1, port: 41641, address: [192, 0, 2, 33]))
        let (_, endpoint) = try #require(STUNMessage.parseBindingResponse(Self.response(unknown + xor)))
        #expect(endpoint == Self.v4)
    }

    @Test("선언 길이 밖의 꼬리 바이트는 버린다")
    func ignoresTrailingBytes() throws {
        let (_, endpoint) = try #require(STUNMessage.parseBindingResponse(Self.goResponseV4 + [0xde, 0xad, 0xbe, 0xef, 0x01]))
        #expect(endpoint == Self.v4)
    }

    @Test("응답의 FINGERPRINT는 검사하지 않는다")
    func doesNotCheckFingerprint() throws {
        let xor = Self.attribute(0x0020, Self.xorValue(family: 1, port: 41641, address: [192, 0, 2, 33]))
        let fingerprint = Self.attribute(0x8028, [0xde, 0xad, 0xbe, 0xef])
        let (_, endpoint) = try #require(STUNMessage.parseBindingResponse(Self.response(xor + fingerprint)))
        #expect(endpoint == Self.v4)
    }

    // MARK: 거절

    @Test("20바이트 미만은 거절한다")
    func rejectsTruncatedHeader() {
        #expect(STUNMessage.parseBindingResponse(Array(Self.goResponseV4[..<19])) == nil)
        #expect(STUNMessage.parseBindingResponse([]) == nil)
    }

    @Test("cookie가 틀리면 거절한다", arguments: 4..<8)
    func rejectsWrongCookie(_ index: Int) {
        var bytes = Self.goResponseV4
        bytes[index] ^= 0x01
        #expect(STUNMessage.parseBindingResponse(bytes) == nil)
    }

    @Test("첫 바이트의 상위 2비트가 0이 아니면 거절한다", arguments: [UInt8(0x41), 0x81, 0xc1])
    func rejectsTopBits(_ first: UInt8) {
        var bytes = Self.goResponseV4
        bytes[0] = first
        #expect(STUNMessage.parseBindingResponse(bytes) == nil)
    }

    @Test("종류가 01 01이 아니면 거절한다", arguments: [[UInt8(0x00), 0x01], [0x01, 0x11], [0x01, 0x02], [0x00, 0x00]])
    func rejectsWrongType(_ type: [UInt8]) {
        var bytes = Self.goResponseV4
        bytes.replaceSubrange(0..<2, with: type)
        #expect(STUNMessage.parseBindingResponse(bytes) == nil)
    }

    @Test("선언한 본문 길이가 남은 바이트를 넘으면 거절한다")
    func rejectsDeclaredLengthBeyondPacket() {
        var bytes = Self.goResponseV4
        bytes[3] += 1
        #expect(STUNMessage.parseBindingResponse(bytes) == nil)
    }

    @Test("속성 길이가 남은 바이트를 넘으면 거절한다")
    func rejectsAttributeLengthBeyondBody() {
        var bytes = Self.goResponseV4
        bytes[23] = 0x0c  // 값 길이 8 → 12
        #expect(STUNMessage.parseBindingResponse(bytes) == nil)
    }

    @Test("패딩이 본문을 넘으면 거절한다")
    func rejectsPaddingBeyondBody() {
        // 값 5바이트(패딩 3)인 속성이 본문 끝에서 패딩 없이 끝난다.
        let truncated = Array(Self.attribute(0x8022, [1, 2, 3, 4, 5]).dropLast(3))
        #expect(STUNMessage.parseBindingResponse(Self.response(truncated)) == nil)
    }

    @Test("속성 머리가 4바이트보다 짧으면 거절한다")
    func rejectsShortAttributeHeader() {
        let xor = Self.attribute(0x0020, Self.xorValue(family: 1, port: 41641, address: [192, 0, 2, 33]))
        #expect(STUNMessage.parseBindingResponse(Self.response(xor + [0x80, 0x22, 0x00])) == nil)
    }

    @Test("주소 속성의 family가 1·2가 아니면 거절한다", arguments: [UInt8(0), 3, 0xff])
    func rejectsUnknownFamily(_ family: UInt8) {
        let xor = Self.attribute(0x0020, Self.xorValue(family: family, port: 41641, address: [192, 0, 2, 33]))
        #expect(STUNMessage.parseBindingResponse(Self.response(xor)) == nil)
        let mapped = Self.attribute(0x0001, Self.mappedValue(family: family, port: 1, address: [192, 0, 2, 33]))
        #expect(STUNMessage.parseBindingResponse(Self.response(mapped)) == nil)
    }

    @Test("주소 속성의 값이 짧으면 거절한다")
    func rejectsShortAddressValue() {
        // 4바이트 미만, family 1에 주소 3바이트, family 2에 주소 15바이트.
        let shortValues: [[UInt8]] = [[0, 1, 0x21], [0, 1, 0, 1, 1, 2, 3], [0, 2, 0, 1] + [UInt8](repeating: 1, count: 15)]
        for value in shortValues {
            for type: UInt16 in [0x0020, 0x8020, 0x0001] {
                #expect(STUNMessage.parseBindingResponse(Self.response(Self.attribute(type, value))) == nil)
            }
        }
    }

    @Test("잘못된 주소 속성은 다른 속성이 올바르더라도 응답 전체를 거절한다")
    func badAddressAttributePoisonsResponse() {
        let good = Self.attribute(0x0020, Self.xorValue(family: 1, port: 41641, address: [192, 0, 2, 33]))
        let bad = Self.attribute(0x0001, [0, 3, 0, 1, 1, 2, 3, 4])
        #expect(STUNMessage.parseBindingResponse(Self.response(good + bad)) == nil)
    }

    @Test("주소 속성이 없으면 거절한다")
    func rejectsResponseWithoutAddress() {
        #expect(STUNMessage.parseBindingResponse(Self.response([])) == nil)
        #expect(STUNMessage.parseBindingResponse(Self.response(Self.attribute(0x8022, Array("tailnode".utf8)))) == nil)
    }

    @Test("바인딩 요청 자체는 응답으로 해석하지 않는다")
    func requestIsNotAResponse() {
        #expect(STUNMessage.parseBindingResponse(Self.goRequest) == nil)
    }

    // MARK: 판정

    @Test("looksLikeSTUN은 길이 20이 경계다")
    func looksLikeSTUNLengthBoundary() {
        #expect(STUNMessage.looksLikeSTUN(Self.goResponseV4))
        let header = Array(Self.goResponseV4[..<20])
        #expect(STUNMessage.looksLikeSTUN(header))
        #expect(!STUNMessage.looksLikeSTUN(Array(header[..<19])))
        #expect(!STUNMessage.looksLikeSTUN([]))
    }

    @Test("looksLikeSTUN은 상위 2비트, cookie, 바이트 1을 본다")
    func looksLikeSTUNFields() {
        let valid = Array(Self.goResponseV4[..<20])
        for first in [UInt8(0x40), 0x80, 0xc0] {
            var bytes = valid
            bytes[0] = first
            #expect(!STUNMessage.looksLikeSTUN(bytes))
        }
        var lowBits = valid
        lowBits[0] = 0x3f  // 상위 2비트만 본다
        #expect(STUNMessage.looksLikeSTUN(lowBits))
        for index in 4..<8 {
            var bytes = valid
            bytes[index] ^= 0x80
            #expect(!STUNMessage.looksLikeSTUN(bytes))
        }
        var otherMethod = valid
        otherMethod[1] = 0x02
        #expect(!STUNMessage.looksLikeSTUN(otherMethod))
        otherMethod[1] = 0x11
        #expect(!STUNMessage.looksLikeSTUN(otherMethod))
    }

    @Test("WireGuard 메시지는 STUN으로 판정되지 않는다")
    func wireGuardIsNotSTUN() {
        var initiation = [UInt8](repeating: 0, count: 148)
        initiation[0] = 1
        var transport = [UInt8](repeating: 0x5a, count: 64)
        transport[0] = 4
        transport[1...3] = [0, 0, 0]
        #expect(!STUNMessage.looksLikeSTUN(initiation))
        #expect(!STUNMessage.looksLikeSTUN(transport))
    }

    // MARK: 임의 입력

    /// 시험 전용 결정적 생성기(SplitMix64).
    private struct SplitMix: RandomNumberGenerator {
        var state: UInt64
        mutating func next() -> UInt64 {
            state &+= 0x9e37_79b9_7f4a_7c15
            var z = state
            z = (z ^ (z >> 30)) &* 0xbf58_476d_1ce4_e5b9
            z = (z ^ (z >> 27)) &* 0x94d0_49bb_1331_11eb
            return z ^ (z >> 31)
        }
    }

    @Test("임의 바이트열로 죽지 않는다")
    func randomBytesDoNotTrap() {
        var generator = SplitMix(state: 1)
        for _ in 0..<2000 {
            let length = Int.random(in: 0...300, using: &generator)
            var bytes = (0..<length).map { _ in UInt8.random(in: .min ... .max, using: &generator) }
            _ = STUNMessage.looksLikeSTUN(bytes)
            _ = STUNMessage.parseBindingResponse(bytes)
            // 헤더만 STUN답게 고쳐 속성 해석까지 닿게 한다.
            if bytes.count >= 20 {
                bytes[0] = 0x01
                bytes[1] = 0x01
                bytes.replaceSubrange(4..<8, with: STUNMessage.magicCookie)
                _ = STUNMessage.parseBindingResponse(bytes)
            }
        }
    }

    @Test("올바른 응답의 모든 접두와 한 바이트 변조로 죽지 않는다")
    func truncationsAndMutationsDoNotTrap() {
        for response in [Self.goResponseV4, Self.goResponseV6, Self.goResponseMapped] {
            for length in 0...response.count {
                _ = STUNMessage.parseBindingResponse(Array(response[..<length]))
            }
            for index in response.indices {
                for value in [UInt8(0), 0x01, 0x7f, 0x80, 0xff] {
                    var changed = response
                    changed[index] = value
                    _ = STUNMessage.parseBindingResponse(changed)
                }
            }
        }
    }
}
