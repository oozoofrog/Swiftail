import CryptoKit
import Foundation
import SwiftailBase

/// 짝 맺기 연결 하나의 두 끝. 양쪽이 같은 네 값을 본다(tailnet 안에서는 주소가 바뀌지 않는다).
struct PairingEndpoints: Sendable, Equatable {
    /// 들어오는 쪽(J)의 주소와 포트.
    var joiner: IPEndpoint
    /// 여는 쪽(H)의 주소와 포트.
    var host: IPEndpoint

    /// 두 끝이 모두 tailnet 주소(`100.64.0.0/10`, `fd7a:115c:a1e0::/48`)인가(계약 동작 J2).
    ///
    /// OS 소켓으로 들어오는 쪽은 이름 풀이를 OS에 맡긴다. 이름이 tailnet 밖의 주소로 풀렸으면 그 연결은 WireGuard가
    /// 인증한 것이 아니므로 `hello`를 보내지 않는다.
    var isOnTailnet: Bool {
        Self.isTailnetAddress(joiner.address) && Self.isTailnetAddress(host.address)
    }

    static func isTailnetAddress(_ address: IPAddress) -> Bool {
        let mapped = address.mapped
        if mapped.starts(with: IPAddress.mappedPrefix) { return mapped[12] == 100 && mapped[13] & 0xC0 == 64 }
        return mapped.starts(with: [0xFD, 0x7A, 0x11, 0x5C, 0xA1, 0xE0])
    }
}

extension IPAddress {
    fileprivate static let mappedPrefix: [UInt8] = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xFF, 0xFF]

    /// 16바이트 표기. IPv4는 IPv4-mapped IPv6(`::ffff:a.b.c.d`)다. T에 이 모양으로 넣는다.
    fileprivate var mapped: [UInt8] {
        isIPv4 ? Self.mappedPrefix + bytes : bytes
    }
}

/// 절차의 전사 T와, 제안의 비밀로 T에 매기는 네 값(계약 5절).
///
/// ```
/// T = nonceJ ‖ nonceH ‖ SHA256(제안의 host) ‖ 제안의 port(2) ‖ SHA256(기기 이름) ‖ J의 주소(16) ‖ J의 포트(2)
///     ‖ H의 주소(16) ‖ H의 포트(2)                                                          166바이트
/// ```
///
/// 양쪽이 본 연결의 두 끝을 묶는다. 중간에서 바이트를 넘겨주는 노드가 끼면 두 쪽이 본 끝이 달라 T가 달라지고, 한쪽이
/// 만든 증명이 다른 쪽에서 맞지 않는다. 네 값은 꼬리표(`swiftail-pairing-1 …`)가 달라 서로 바꿔 쓸 수 없다.
struct PairingTranscript: Sendable, Equatable {
    /// T의 길이.
    static let length = 166

    let bytes: [UInt8]

    init(
        joinerNonce: [UInt8], hostNonce: [UInt8], offerHost: String, offerPort: UInt16, deviceName: [UInt8],
        endpoints: PairingEndpoints
    ) {
        bytes = joinerNonce + hostNonce
            + SHA256.hash(data: Data(offerHost.utf8)) + offerPort.bigEndianBytes
            + SHA256.hash(data: Data(deviceName))
            + endpoints.joiner.address.mapped + endpoints.joiner.port.bigEndianBytes
            + endpoints.host.address.mapped + endpoints.host.port.bigEndianBytes
    }

    /// J→H `proof`: 들어오는 쪽이 비밀을 안다.
    func proof(secret: [UInt8]) -> [UInt8] {
        authenticate("swiftail-pairing-1 joiner", bytes, secret: secret)
    }

    /// H→J `accepted`: 여는 쪽이 비밀을 안다.
    func accepted(secret: [UInt8]) -> [UInt8] {
        authenticate("swiftail-pairing-1 host", bytes, secret: secret)
    }

    /// `decision`의 본문 `body`에 붙이는 HMAC. 결정을 비밀을 아는 쪽이 냈음을 보인다.
    func decisionCode(for body: [UInt8], secret: [UInt8]) -> [UInt8] {
        authenticate("swiftail-pairing-1 decision", bytes + body, secret: secret)
    }

    /// 양쪽 화면에 보이는 확인 숫자 6자리. 사용자가 두 화면의 숫자가 같을 때 승인한다(계약 동작 P5).
    func confirmationCode(secret: [UInt8]) -> String {
        let code = authenticate("swiftail-pairing-1 sas", bytes, secret: secret)
        let number = code.prefix(4).reduce(UInt32(0)) { $0 << 8 | UInt32($1) } % 1_000_000
        let digits = String(number)
        return String(repeating: "0", count: 6 - digits.count) + digits
    }

    private func authenticate(_ label: String, _ message: [UInt8], secret: [UInt8]) -> [UInt8] {
        Array(HMAC<SHA256>.authenticationCode(for: Array(label.utf8) + message, using: SymmetricKey(data: secret)))
    }
}

extension UInt16 {
    /// 빅 엔디언 2바이트.
    var bigEndianBytes: [UInt8] { [UInt8(self >> 8), UInt8(truncatingIfNeeded: self)] }
}
