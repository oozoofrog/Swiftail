import CryptoKit

/// 제어 Noise 핸드셰이크(Noise_IK_25519_ChaChaPoly_BLAKE2s)의 초기자 쪽 두 단계.
///
/// 클라이언트는 `/key`로 서버의 정적 공개 키를 미리 안다(IK). initiation 하나와 response 하나로
/// 서로를 인증하고 방향별 전송 키를 얻는다. 패턴은 `<- s ... -> e, es, s, ss <- e, ee, se`다.
/// 각 단계는 키와 메시지를 받아 결과를 돌려주는 순수 함수다. 임시 키도 인자로 받는다.
///
/// 프로토콜 버전은 initiation 머리에 평문으로 실리고, 프롤로그 `"Tailscale Control Protocol v<10진>"`로
/// transcript에 섞여 인증된다. 메시지의 type·길이 머리 자체는 transcript에 들어가지 않는다.
///
/// `docs/protocol-notes/control-transport.md` 4.5절 1~16단계
/// (출처: tailscale.com `control/controlbase/handshake.go`의 `ClientDeferred`, `continueClientHandshake`).
enum NoiseIK {
    static let protocolName = "Noise_IK_25519_ChaChaPoly_BLAKE2s"

    static func prologue(protocolVersion: UInt16) -> [UInt8] {
        Array("Tailscale Control Protocol v\(protocolVersion)".utf8)
    }

    /// 1~8단계: initiation을 만든다.
    ///
    /// - Parameter ephemeral: 이번 연결에만 쓰는 새 임시 키.
    /// - Returns: 서버 정적 키와의 DH(es, ss)가 0이면 `nil`.
    static func makeInitiation(
        machineKey: Curve25519.KeyAgreement.PrivateKey,
        serverKey: MachinePublicKey,
        protocolVersion: UInt16,
        ephemeral: Curve25519.KeyAgreement.PrivateKey
    ) -> (HandshakeInitiation, PendingHandshake)? {
        var state = SymmetricState(protocolName: protocolName)
        state.mixHash(prologue(protocolVersion: protocolVersion))
        state.mixHash(serverKey.rawValue)

        let ephemeralPublic = Array(ephemeral.publicKey.rawRepresentation)
        state.mixHash(ephemeralPublic)
        guard let esKey = state.mixDH(ephemeral, serverKey.rawValue) else { return nil }
        let encryptedMachineKey = state.encryptAndHash(Array(machineKey.publicKey.rawRepresentation), key: esKey)

        guard let ssKey = state.mixDH(machineKey, serverKey.rawValue) else { return nil }
        let tag = state.encryptAndHash([], key: ssKey)

        let initiation = HandshakeInitiation(
            protocolVersion: protocolVersion,
            ephemeralPublicKey: ephemeralPublic,
            encryptedMachineKey: encryptedMachineKey,
            tag: tag
        )
        return (initiation, PendingHandshake(state: state, machineKey: machineKey, ephemeral: ephemeral))
    }

    /// 11~15단계: response를 열어 서버를 인증하고 전송 키를 유도한다.
    ///
    /// - Returns: DH(ee, se)가 0이거나 태그가 맞지 않으면 `nil`.
    static func consumeResponse(_ response: HandshakeResponse, pending: PendingHandshake) -> TransportKeys? {
        var state = pending.state
        state.mixHash(response.ephemeralPublicKey)
        // ee: 키는 버리고 ck만 갱신한다.
        guard state.mixDH(pending.ephemeral, response.ephemeralPublicKey) != nil,
              let seKey = state.mixDH(pending.machineKey, response.ephemeralPublicKey),
              state.decryptAndHash(response.tag, key: seKey) != nil
        else { return nil }
        let (send, receive) = state.split()
        return TransportKeys(send: send, receive: receive)
    }
}

/// initiation을 보낸 뒤 response를 기다리는 동안의 상태.
struct PendingHandshake: Sendable {
    let state: SymmetricState
    let machineKey: Curve25519.KeyAgreement.PrivateKey
    let ephemeral: Curve25519.KeyAgreement.PrivateKey
}

/// 핸드셰이크가 낳은 방향별 전송 키.
struct TransportKeys: Sendable {
    let send: SymmetricKey
    let receive: SymmetricKey
}
