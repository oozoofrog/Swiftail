import CryptoKit
import Foundation
import SwiftailBase

/// 짝 맺기 연결 하나의 두 끝. 양쪽이 같은 네 값을 본다(tailnet 안에서는 주소가 바뀌지 않는다).
struct PairingEndpoints: Sendable, Equatable {
    /// 들어오는 쪽(J)의 주소와 포트.
    var joiner: IPEndpoint
    /// 여는 쪽(H)의 주소와 포트.
    var host: IPEndpoint

    /// OS 소켓으로 건 연결이 터널을 거친 것으로 볼 수 있는가(계약 동작 J2): 이쪽 끝이 이 기기의 tailnet 주소
    /// `localAddress`이고, 상대 끝이 tailnet 대역(`100.64.0.0/10`, `fd7a:115c:a1e0::/48`)이다.
    ///
    /// OS 소켓으로 들어오는 쪽은 이름 풀이와 경로를 OS에 맡긴다. 대역만 보면, 터널이 꺼진 채 같은 대역을 쓰는 로컬
    /// 네트워크(통신사 NAT, 공유기)로 나간 연결이 통과한다. 그 연결은 WireGuard가 인증한 것이 아니므로 `hello`를 보내지
    /// 않는다. 이쪽 끝이 터널의 주소인지는 앱이 넘긴 값과 견주어 본다.
    func isOnTailnet(localAddress: IPAddress) -> Bool {
        isLocal(localAddress) && Self.isTailnetAddress(host.address)
    }

    /// 이쪽 끝의 주소가 `address`인가. IPv4와 그 IPv4-mapped IPv6는 같은 주소로 본다.
    func isLocal(_ address: IPAddress) -> Bool {
        joiner.address.mapped == address.mapped
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

/// `proof`가 매겨지는 전사 P: 여는 쪽의 nonce가 열리기 전에 정해지는 것 전부(계약 5절).
///
/// ```
/// P = commitJ ‖ commitH ‖ nonceJ ‖ SHA256(제안의 host) ‖ 제안의 port(2) ‖ SHA256(기기 이름) ‖ J의 주소(16)
///     ‖ J의 포트(2) ‖ H의 주소(16) ‖ H의 포트(2)                                            198바이트
/// ```
///
/// 양쪽이 본 연결의 두 끝을 묶는다. 중간에서 바이트를 넘겨주는 노드가 끼면 두 쪽이 본 끝이 달라 P가 달라지고, 한쪽이
/// 만든 증명이 다른 쪽에서 맞지 않는다. nonceH는 들어 있지 않다: 들어오는 쪽은 그것을 모르는 채 `proof`를 낸다.
struct PairingProofTranscript: Sendable, Equatable {
    /// P의 길이.
    static let length = 198

    let bytes: [UInt8]
    /// `challenge`로 받은(여는 쪽은 자기가 보낸) commitH.
    private let hostCommitment: [UInt8]

    /// - Parameters:
    ///   - joinerNonce: 열린 nonceJ. 여는 쪽은 `hello`의 약속과 맞는지 먼저 본 값을 넣는다.
    ///   - hostCommitment: 여는 쪽 nonce의 약속 commitH.
    init(
        joinerNonce: [UInt8], hostCommitment: [UInt8], offerHost: String, offerPort: UInt16, deviceName: [UInt8],
        endpoints: PairingEndpoints
    ) {
        self.hostCommitment = hostCommitment
        bytes = PairingTranscript.commitment(toJoinerNonce: joinerNonce) + hostCommitment + joinerNonce
            + SHA256.hash(data: Data(offerHost.utf8)) + offerPort.bigEndianBytes
            + SHA256.hash(data: Data(deviceName))
            + endpoints.joiner.address.mapped + endpoints.joiner.port.bigEndianBytes
            + endpoints.host.address.mapped + endpoints.host.port.bigEndianBytes
    }

    /// J→H `proof`의 HMAC: 들어오는 쪽이 비밀을 안다.
    func proof(secret: [UInt8]) -> [UInt8] {
        authenticate("swiftail-pairing-3 joiner", bytes, secret: secret)
    }

    /// 여는 쪽의 nonce가 열린 뒤의 전사 T. `hostNonce`가 약속 commitH와 다르면 nil이다: `challenge`를 보낸 뒤에 고른
    /// nonce로는 T를 만들 수 없다.
    func opened(with hostNonce: [UInt8]) -> PairingTranscript? {
        // 약속과 nonce는 선 위에 나온 값이라 상수 시간으로 견줄 까닭이 없다.
        guard PairingTranscript.commitment(toHostNonce: hostNonce) == hostCommitment else { return nil }
        return PairingTranscript(bytes: bytes + hostNonce)
    }
}

/// 두 nonce가 모두 열린 뒤의 전사 T와, 제안의 비밀로 T에 매기는 세 값(계약 5절).
///
/// ```
/// T = P ‖ nonceH                                                                            230바이트
/// ```
///
/// 확인 숫자는 20비트 남짓이라, 상대의 nonce를 본 뒤에 자기 nonce를 고를 수 있는 쪽은 값을 갈아 원하는 숫자를 맞출 수
/// 있다. 그래서 두 nonce는 약속으로 먼저 고정된다. 들어오는 쪽은 `hello`에 commitJ를 싣고 `proof`에서 nonceJ를 연다. 여는
/// 쪽은 `challenge`에 commitH를 싣고, `proof`가 맞아 제안을 쓴 뒤에야 `accepted`에서 nonceH를 연다. 비밀을 아는 쪽이라도
/// 확인 숫자를 보려면 제안을 써야 하므로, 숫자가 마음에 들 때까지 다시 걸 수 없다.
///
/// 값마다 꼬리표(`swiftail-pairing-3 …`)가 달라 서로 바꿔 쓸 수 없다. 두 약속의 꼬리표도 달라, 상대의 약속을 되비춰
/// 자기 약속으로 낼 수 없다.
struct PairingTranscript: Sendable, Equatable {
    /// T의 길이.
    static let length = PairingProofTranscript.length + PairingMessage.nonceLength

    let bytes: [UInt8]

    /// 들어오는 쪽 nonce의 약속 commitJ = SHA256("swiftail-pairing-3 commit joiner" ‖ nonceJ).
    static func commitment(toJoinerNonce nonce: [UInt8]) -> [UInt8] {
        Array(SHA256.hash(data: Data(Array("swiftail-pairing-3 commit joiner".utf8) + nonce)))
    }

    /// 여는 쪽 nonce의 약속 commitH = SHA256("swiftail-pairing-3 commit host" ‖ nonceH).
    static func commitment(toHostNonce nonce: [UInt8]) -> [UInt8] {
        Array(SHA256.hash(data: Data(Array("swiftail-pairing-3 commit host".utf8) + nonce)))
    }

    /// `PairingProofTranscript.opened(with:)`만 만든다. nonceH가 약속과 맞는 T만 있다.
    fileprivate init(bytes: [UInt8]) {
        self.bytes = bytes
    }

    /// H→J `accepted`의 HMAC: 여는 쪽이 비밀을 안다.
    func accepted(secret: [UInt8]) -> [UInt8] {
        authenticate("swiftail-pairing-3 host", bytes, secret: secret)
    }

    /// `decision`의 본문 `body`에 붙이는 HMAC. 결정을 비밀을 아는 쪽이 냈음을 보인다.
    func decisionCode(for body: [UInt8], secret: [UInt8]) -> [UInt8] {
        authenticate("swiftail-pairing-3 decision", bytes + body, secret: secret)
    }

    /// 양쪽 화면에 보이는 확인 숫자 6자리. 사용자가 두 화면의 숫자가 같을 때 승인한다(계약 동작 P5).
    func confirmationCode(secret: [UInt8]) -> String {
        let code = authenticate("swiftail-pairing-3 sas", bytes, secret: secret)
        let number = code.prefix(4).reduce(UInt32(0)) { $0 << 8 | UInt32($1) } % 1_000_000
        let digits = String(number)
        return String(repeating: "0", count: 6 - digits.count) + digits
    }
}

/// HMAC-SHA256(비밀, 꼬리표 ‖ 메시지).
private func authenticate(_ label: String, _ message: [UInt8], secret: [UInt8]) -> [UInt8] {
    Array(HMAC<SHA256>.authenticationCode(for: Array(label.utf8) + message, using: SymmetricKey(data: secret)))
}

extension UInt16 {
    /// 빅 엔디언 2바이트.
    var bigEndianBytes: [UInt8] { [UInt8(self >> 8), UInt8(truncatingIfNeeded: self)] }
}
