import CryptoKit
import SwiftailBase

/// 제어 Noise(Noise_IK_25519_ChaChaPoly_BLAKE2s)의 초기자.
///
/// 만들 때 initiation을 계산해 두고(업그레이드 요청 헤더에 싣는다), 101 응답 뒤 서버가 보낸 바이트를
/// 받아 response를 읽는다. response가 열리면 전송 단계 `ControlSession`과, 같은 읽기에 이미 따라온
/// 바이트(보통 early payload나 HTTP/2를 담은 레코드)를 돌려준다.
///
/// 소켓·시계를 갖지 않는다. response가 오기 전에 연결이 끝나면(101 뒤 EOF) 핸드셰이크 실패다. 서버는
/// 핸드셰이크에 실패하면 error 메시지 없이 연결을 닫기도 한다.
///
/// `docs/protocol-notes/control-transport.md` 4.4절 2단계, 4.5절 9~16단계
/// (출처: tailscale.com `control/controlbase/handshake.go`).
public struct ControlHandshake: Sendable {
    /// 서버에 보낼 initiation 101바이트.
    public let initiation: [UInt8]

    private var state: State
    private var received: [UInt8] = []

    private enum State: Sendable {
        case awaitingResponse(PendingHandshake)
        case done
    }

    /// 시스템 난수로 임시 키를 만들어 initiation을 계산한다.
    ///
    /// - Parameters:
    ///   - machineKey: 이 기기의 machine 개인 키.
    ///   - serverKey: `/key`로 받은 서버의 Noise 공개 키(`publicKey`).
    ///   - protocolVersion: capability version. 프롤로그와 initiation 머리에 실린다.
    /// - Throws: 서버 키가 저차 점이라 공유 비밀이 0이면 `handshakeFailed`. 보낼 initiation이 없다.
    public init(
        machineKey: Curve25519.KeyAgreement.PrivateKey,
        serverKey: MachinePublicKey,
        protocolVersion: UInt16 = 148
    ) throws(ControlTransportError) {
        try self.init(machineKey: machineKey, serverKey: serverKey, protocolVersion: protocolVersion, ephemeral: Curve25519.KeyAgreement.PrivateKey())
    }

    /// 임시 키를 인자로 받는다. 고정 벡터 시험용이다.
    init(
        machineKey: Curve25519.KeyAgreement.PrivateKey,
        serverKey: MachinePublicKey,
        protocolVersion: UInt16,
        ephemeral: Curve25519.KeyAgreement.PrivateKey
    ) throws(ControlTransportError) {
        guard let (message, pending) = NoiseIK.makeInitiation(
            machineKey: machineKey,
            serverKey: serverKey,
            protocolVersion: protocolVersion,
            ephemeral: ephemeral
        ) else { throw .handshakeFailed }
        initiation = message.bytes
        state = .awaitingResponse(pending)
    }

    /// 서버가 보낸 바이트를 넣는다. response가 다 오지 않았으면 nil.
    /// 다 왔으면 전송 단계 세션과, response 뒤에 이미 도착한 바이트.
    ///
    /// - Throws: response가 열리지 않거나 서버가 error 메시지를 보내면 `handshakeFailed`, type·길이가
    ///   틀리면 `malformed`, 세션을 이미 돌려줬거나 실패한 뒤면 `closed`.
    public mutating func receive(_ bytes: [UInt8]) throws(ControlTransportError) -> (session: ControlSession, remainder: [UInt8])? {
        guard case .awaitingResponse(let pending) = state else { throw .closed }

        received += bytes
        do throws(ControlTransportError) {
            guard let response = try HandshakeResponse(parsingPrefixOf: received) else { return nil }
            guard let keys = NoiseIK.consumeResponse(response, pending: pending) else { throw .handshakeFailed }
            let remainder = Array(received[HandshakeResponse.size...])
            state = .done
            received = []
            return (ControlSession(keys: keys), remainder)
        } catch {
            state = .done
            received = []
            throw error
        }
    }
}

extension ControlHandshake: CustomReflectable {
    /// 장기 키, 임시 키, chaining key를 쥐고 있으므로 `dump`와 `print`에 아무것도 드러내지 않는다.
    public var customMirror: Mirror { Mirror(self, children: [:]) }
}
