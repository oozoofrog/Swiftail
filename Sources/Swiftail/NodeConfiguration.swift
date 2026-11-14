import Foundation

/// `TailnetNode` 하나를 띄우는 데 필요한 설정.
///
/// 인증 키를 담으므로 `description`과 `dump`에서 가린다. 설정 값을 그대로 로그에 찍어도 비밀이 새지 않는다.
/// `docs/contracts/SwiftailEngine.md` "노드 API".
public struct NodeConfiguration: Sendable {
    /// 신원 파일을 둘 디렉터리. 파일 URL이어야 한다.
    public var stateDirectory: URL
    /// 노드의 호스트 이름. 제어 서버가 노드 이름을 지을 때 쓴다.
    public var hostname: String
    /// 제어 서버 URL. `http://` 또는 `https://`.
    public var controlURL: URL
    /// 인증 키. 첫 등록에만 쓴다.
    public var authKey: String?
    /// 오래 비활성이면 제어 서버가 지우는 노드로 등록한다.
    public var ephemeral: Bool

    public init(stateDirectory: URL, hostname: String, controlURL: URL, authKey: String? = nil, ephemeral: Bool = false) {
        self.stateDirectory = stateDirectory
        self.hostname = hostname
        self.controlURL = controlURL
        self.authKey = authKey
        self.ephemeral = ephemeral
    }
}

extension NodeConfiguration: CustomStringConvertible, CustomReflectable {
    /// 인증 키를 가린다.
    public var description: String {
        "NodeConfiguration(hostname: \(hostname), controlURL: \(controlURL), authKey: \(redactedAuthKey), ephemeral: \(ephemeral))"
    }

    /// `dump`는 `description`을 거치지 않으므로 여기서도 인증 키를 가린다.
    public var customMirror: Mirror {
        Mirror(self, children: [
            "stateDirectory": stateDirectory,
            "hostname": hostname,
            "controlURL": controlURL,
            "authKey": redactedAuthKey,
            "ephemeral": ephemeral,
        ])
    }

    private var redactedAuthKey: String { authKey == nil ? "없음" : "<가림>" }
}
