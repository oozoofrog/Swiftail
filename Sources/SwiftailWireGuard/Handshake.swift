import CryptoKit
import SwiftailCrypto

/// Noise IKpsk2 핸드셰이크의 네 단계: initiation 만들기·열기, response 만들기·열기.
///
/// 초기자 I는 응답자 R의 정적 공개 키를 미리 안다(IK). 한 번 왕복으로 서로를 인증하고 전송 키 둘을
/// 얻는다. 각 단계는 입력을 받아 메시지와 다음 상태를 돌려주는 순수 함수다. index 배정, 피어 조회,
/// 재전송 검사 같은 장치 수준 결정은 `WireGuardDevice`가 한다.
///
/// 단계 사이에 상대가 바뀌지 않았음을 hash(transcript)가 보장한다. 어느 AEAD든 열리지 않으면 그 메시지는
/// 버린다.
///
/// 백서 §5.4.2–§5.4.5, `docs/protocol-notes/wireguard.md` "초기자: initiation 만들기"부터
/// "전송 키 유도"까지 (출처: wireguard-go `device/noise-protocol.go`).
enum Handshake {
    // shortcut: PSK는 32바이트 0으로 고정한다. Tailscale은 PSK를 설정하지 않는다. PSK가 필요한 사용처가 생기면 피어 설정에 올린다.
    private static let presharedKey = [UInt8](repeating: 0, count: 32)

    /// 초기자: initiation을 만든다. MAC은 붙이지 않는다(`CookieGenerator`가 붙인다).
    ///
    /// - Parameters:
    ///   - staticStaticSecret: 미리 계산한 DH(S_i, S_r).
    ///   - ephemeral: 이번 시도에만 쓰는 새 임시 키. 재시도마다 새로 만든다.
    /// - Returns: 상대 정적 키와의 DH가 실패하면 `nil`.
    static func makeInitiation(
        localStatic: Curve25519.KeyAgreement.PrivateKey,
        remoteStatic: PublicKey,
        staticStaticSecret: [UInt8],
        timestamp: TAI64N,
        localIndex: UInt32,
        ephemeral: Curve25519.KeyAgreement.PrivateKey
    ) -> (Initiation, PendingHandshake)? {
        var state = SymmetricState.initial
        state.mixHash(remoteStatic.rawValue)

        let ephemeralPublic = Array(ephemeral.publicKey.rawRepresentation)
        state.mixKey(ephemeralPublic)
        state.mixHash(ephemeralPublic)

        guard let es = sharedSecret(ephemeral, remoteStatic.rawValue) else { return nil }
        let staticKey = state.mixKeyAndDeriveKey(es)
        let encryptedStatic = state.encryptAndHash(Array(localStatic.publicKey.rawRepresentation), key: staticKey)

        let timestampKey = state.mixKeyAndDeriveKey(staticStaticSecret)
        let encryptedTimestamp = state.encryptAndHash(timestamp.bytes, key: timestampKey)

        let message = Initiation(
            sender: localIndex,
            ephemeral: ephemeralPublic,
            encryptedStatic: encryptedStatic,
            encryptedTimestamp: encryptedTimestamp
        )
        return (message, PendingHandshake(localIndex: localIndex, state: state, ephemeral: ephemeral))
    }

    /// 응답자 1단계: initiation에서 초기자의 정적 공개 키를 꺼낸다.
    ///
    /// 이 단계만으로는 아무것도 인증되지 않는다. 누가 보냈다고 주장하는지 알아내 피어를 찾을 뿐이다.
    static func openInitiation(_ message: Initiation, localStatic: Curve25519.KeyAgreement.PrivateKey) -> OpenedInitiation? {
        var state = SymmetricState.initial
        state.mixHash(Array(localStatic.publicKey.rawRepresentation))
        state.mixHash(message.ephemeral)
        state.mixKey(message.ephemeral)

        guard let es = sharedSecret(localStatic, message.ephemeral) else { return nil }
        let staticKey = state.mixKeyAndDeriveKey(es)
        guard let staticBytes = state.decryptAndHash(message.encryptedStatic, key: staticKey),
              let initiator = PublicKey(rawValue: staticBytes)
        else { return nil }
        return OpenedInitiation(initiator: initiator, message: message, state: state)
    }

    /// 응답자 2단계: 정적 키끼리의 DH로 timestamp를 연다. 열리면 초기자가 그 정적 비밀 키를 가졌다는 뜻이다.
    ///
    /// timestamp 재전송·flood 검사는 피어 상태가 필요하므로 호출하는 쪽이 한다.
    static func authenticate(_ opened: OpenedInitiation, staticStaticSecret: [UInt8]) -> AuthenticatedInitiation? {
        var state = opened.state
        let timestampKey = state.mixKeyAndDeriveKey(staticStaticSecret)
        guard let timestampBytes = state.decryptAndHash(opened.message.encryptedTimestamp, key: timestampKey),
              let timestamp = TAI64N(bytes: timestampBytes)
        else { return nil }
        return AuthenticatedInitiation(
            initiator: opened.initiator,
            sender: opened.message.sender,
            ephemeral: opened.message.ephemeral,
            timestamp: timestamp,
            state: state
        )
    }

    /// 응답자 3단계: response를 만들고 곧바로 전송 키를 유도한다.
    /// - Returns: 상대 임시·정적 키와의 DH가 실패하면 `nil`.
    static func makeResponse(
        to initiation: AuthenticatedInitiation,
        localIndex: UInt32,
        ephemeral: Curve25519.KeyAgreement.PrivateKey
    ) -> (Response, SessionKeys)? {
        var state = initiation.state
        let ephemeralPublic = Array(ephemeral.publicKey.rawRepresentation)
        state.mixHash(ephemeralPublic)
        state.mixKey(ephemeralPublic)

        guard let ee = sharedSecret(ephemeral, initiation.ephemeral),
              let se = sharedSecret(ephemeral, initiation.initiator.rawValue)
        else { return nil }
        state.mixKey(ee)
        state.mixKey(se)

        let key = state.mixPresharedKey(presharedKey)
        let encryptedNothing = state.encryptAndHash([], key: key)

        let message = Response(
            sender: localIndex,
            receiver: initiation.sender,
            ephemeral: ephemeralPublic,
            encryptedNothing: encryptedNothing
        )
        let (receive, send) = state.split()
        return (message, SessionKeys(send: send, receive: receive))
    }

    /// 초기자: response를 열어 응답자를 인증하고 전송 키를 유도한다. 실패하면 `nil`.
    static func consumeResponse(
        _ message: Response,
        pending: PendingHandshake,
        localStatic: Curve25519.KeyAgreement.PrivateKey
    ) -> SessionKeys? {
        var state = pending.state
        state.mixHash(message.ephemeral)
        state.mixKey(message.ephemeral)

        guard let ee = sharedSecret(pending.ephemeral, message.ephemeral),
              let se = sharedSecret(localStatic, message.ephemeral)
        else { return nil }
        state.mixKey(ee)
        state.mixKey(se)

        let key = state.mixPresharedKey(presharedKey)
        guard state.decryptAndHash(message.encryptedNothing, key: key) != nil else { return nil }
        let (send, receive) = state.split()
        return SessionKeys(send: send, receive: receive)
    }
}

/// 초기자가 response를 기다리는 동안 들고 있는 상태. response를 받거나, 새 initiation으로
/// 바뀌거나, 키 재료를 지울 때 사라진다.
struct PendingHandshake {
    /// initiation의 sender. response의 receiver로 돌아온다.
    let localIndex: UInt32
    let state: SymmetricState
    let ephemeral: Curve25519.KeyAgreement.PrivateKey
}

/// 정적 키만 꺼낸, 아직 인증되지 않은 initiation.
struct OpenedInitiation {
    let initiator: PublicKey
    let message: Initiation
    let state: SymmetricState
}

/// timestamp까지 열어 초기자가 인증된 initiation.
struct AuthenticatedInitiation {
    let initiator: PublicKey
    let sender: UInt32
    let ephemeral: [UInt8]
    let timestamp: TAI64N
    let state: SymmetricState
}

/// 핸드셰이크가 낳은 전송 키 한 쌍.
struct SessionKeys {
    let send: SymmetricKey
    let receive: SymmetricKey
}
