import Foundation

/// `TailnetNode` 하나를 띄우는 데 필요한 설정.
///
/// 인증 키를 담으므로 `description`과 `dump`에서 가린다. 설정 값을 그대로 로그에 찍어도 비밀이 새지 않는다.
/// `docs/contracts/SwiftailEngine.md` "노드 API", `docs/contracts/SwiftailTunnel.md` "공개 API".
public struct NodeConfiguration: Sendable {
    /// Tailscale 제어 서버(Go `ipn.DefaultControlURL`, `ipn/prefs.go`).
    public static let defaultControlURL: URL = {
        guard let url = URL(string: "https://controlplane.tailscale.com") else {
            preconditionFailure("고정된 제어 서버 URL은 올바른 URL이다")
        }
        return url
    }()

    /// 신원 파일(`identity.json`)을 둘 디렉터리. 파일 URL이어야 한다. 같은 프로세스의 노드 둘이 같은 디렉터리로 동시에
    /// 돌지 못한다(`NodeError.stateDirectoryInUse`).
    ///
    /// **다른 사용자가 쓸 수 없는 디렉터리여야 한다.** 노드는 여기서 개인 키(신원)와 tailnet lock의 신뢰 상태를 읽는다.
    /// 이 디렉터리에 쓸 수 있는 쪽은 그 파일을 바꿔 넣어 노드의 신원과 신뢰 상태를 정할 수 있다. 라이브러리는 없는
    /// 디렉터리를 0700으로 만들 뿐, 이미 있는 디렉터리의 주인과 권한은 보지 않는다(앱 샌드박스의 컨테이너, iOS의 앱 그룹
    /// 컨테이너처럼 OS가 지키는 자리를 쓴다).
    public var stateDirectory: URL
    /// 노드의 호스트 이름. 제어 서버가 노드 이름을 지을 때 쓴다. 비어 있으면 안 된다.
    public var hostname: String
    /// 제어 서버 URL. `http://` 또는 `https://`.
    ///
    /// **`http://`는 서버를 인증하지 않는다.** `https://`에서는 TLS가 서버 인증서를 확인한 뒤에 제어 서버의 공개 키를
    /// 받는데, `http://`에서는 그 키를 평문으로 받는다. 경로 위의 상대가 자기 키를 내주고 제어 서버 노릇을 할 수 있고,
    /// 그러면 등록(인증 키 포함)과 netmap이 모두 그 상대의 것이 된다. 시험과 루프백의 서버에만 쓴다.
    public var controlURL: URL
    /// 인증 키. 첫 등록과 node 키를 새로 등록할 때만 쓴다. 저장하지 않는다.
    public var authKey: String?
    /// 오래 비활성이면 제어 서버가 지우는 노드로 등록한다.
    public var ephemeral: Bool

    public init(
        stateDirectory: URL,
        hostname: String,
        controlURL: URL = Self.defaultControlURL,
        authKey: String? = nil,
        ephemeral: Bool = false
    ) {
        self.stateDirectory = stateDirectory
        self.hostname = hostname
        self.controlURL = controlURL
        self.authKey = authKey
        self.ephemeral = ephemeral
    }

    /// 파일·소켓을 만들지 않고 볼 수 있는 것만 검사한다. URL의 세부(포트 범위, 사용자 정보 등)는 제어 클라이언트가
    /// `run()`에서 한 번 더 검사하고 그 실패도 `invalidConfiguration`이다. 메시지에 경로·키를 넣지 않는다.
    func validate() throws(NodeError) {
        guard stateDirectory.isFileURL else { throw .invalidConfiguration("상태 디렉터리는 파일 URL이어야 한다") }
        guard let scheme = controlURL.scheme?.lowercased(), scheme == "http" || scheme == "https" else {
            throw .invalidConfiguration("제어 서버 URL은 http:// 또는 https://여야 한다")
        }
        guard controlURL.host(percentEncoded: false)?.isEmpty == false else {
            throw .invalidConfiguration("제어 서버 URL에 호스트가 없다")
        }
        guard !hostname.isEmpty else { throw .invalidConfiguration("호스트 이름이 비었다") }
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
