import SwiftailIO

/// 서버의 업그레이드 응답 머리를 읽고 검증한다.
///
/// 성공하면 `101 Switching Protocols`와 `Upgrade: tailscale-control-protocol`이 온다. 그 바로 뒤부터
/// Noise response가 이어지며, 한 번의 TCP 읽기에 HTTP 머리와 Noise 바이트가 함께 들어올 수 있다.
/// 머리 읽기(조각 모으기, 16KiB 한도, 줄 형식)는 `HTTPResponseHead`가 하고, 여기서는 머리 뒤에 이미 도착한
/// 바이트를 돌려줘 `ControlHandshake`에 넘기게 한다.
///
/// 클라이언트는 상태와 `Upgrade` 값만 본다(`Connection`은 검사하지 않는다). `Upgrade` 값은 정확히
/// 같아야 한다.
///
/// `docs/protocol-notes/control-transport.md` 3.6절, 4.4절 2단계 3~4
/// (출처: tailscale.com `control/controlhttp/client.go`).
public struct UpgradeResponseParser: Sendable {
    /// `Upgrade` 헤더 값.
    static let protocolName = "tailscale-control-protocol"

    /// 머리를 읽는 상태. 끝나거나 실패하면 받은 바이트를 비운다.
    private(set) var head = HTTPResponseHead.Parser()

    public init() {}

    /// 머리가 아직 다 오지 않았으면 nil. 다 왔으면 남은 바이트(Noise 계층의 것).
    ///
    /// - Throws: 101이 아니면 `upgradeRejected`, 형식이 틀리거나 `Upgrade` 값이 다르면 `malformed`,
    ///   머리가 16KiB를 넘으면 `messageTooLarge`, 머리를 이미 돌려줬거나 실패한 뒤면 `closed`.
    public mutating func receive(_ bytes: [UInt8]) throws(ControlTransportError) -> [UInt8]? {
        let response: HTTPResponseHead?
        do {
            response = try head.receive(bytes)
        } catch {
            switch error {
            case .malformedStatusLine:
                throw .malformed
            case .malformedHeader(let status):
                // 상태를 먼저 본다: 101이 아니면 나머지 형식과 무관하게 거절이다.
                throw status == 101 ? .malformed : .upgradeRejected(status: status)
            case .tooLarge:
                throw .messageTooLarge
            case .closed:
                throw .closed
            }
        }
        guard let response else { return nil }
        guard response.status == 101 else { throw .upgradeRejected(status: response.status) }
        guard let upgrade = response.firstValue(ofHeader: "upgrade"), upgrade.elementsEqual(Self.protocolName.utf8) else {
            throw .malformed
        }
        return response.remainder
    }
}
