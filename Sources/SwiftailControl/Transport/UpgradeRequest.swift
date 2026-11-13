import Foundation

/// `POST /ts2021` HTTP/1.1 업그레이드 요청.
///
/// 제어 연결은 평범한 HTTP 요청으로 시작해 `101 Switching Protocols` 뒤 같은 소켓에서 Noise로 바뀐다.
/// 왕복 한 번을 아끼려고 Noise initiation을 요청 헤더 `X-Tailscale-Handshake`에 표준 base64로 싣는다.
/// 본문은 없다. `Host`가 없으면 Go 서버는 핸들러에 닿기 전에 400을 준다.
///
/// `docs/protocol-notes/control-transport.md` 3.6절, 4.4절 2단계
/// (출처: tailscale.com `control/controlhttp/client.go`).
public enum UpgradeRequest {
    /// 요청 머리 전체(빈 줄까지)의 바이트.
    ///
    /// - Parameters:
    ///   - host: 업그레이드 URL의 호스트와 포트(예: `127.0.0.1:9911`). 설정에서 오는 값이며
    ///     공백·제어 문자가 있으면 프로그래머 오류다.
    ///   - initiation: `ControlHandshake.initiation`.
    public static func bytes(host: String, initiation: [UInt8]) -> [UInt8] {
        precondition(
            !host.isEmpty && host.utf8.allSatisfy { $0 > 0x20 && $0 != 0x7F },
            "Host 값에 공백이나 제어 문자가 있으면 요청 머리가 깨진다"
        )
        let lines = [
            "POST /ts2021 HTTP/1.1",
            "Host: \(host)",
            "Upgrade: \(UpgradeResponseParser.protocolName)",
            "Connection: upgrade",
            "X-Tailscale-Handshake: \(Data(initiation).base64EncodedString())",
            // Go도 본문 없는 POST에 0을 보낸다.
            "Content-Length: 0",
        ]
        return Array((lines.joined(separator: "\r\n") + "\r\n\r\n").utf8)
    }
}
