import SwiftailControl

/// 서버 쪽 로그아웃. 계약 `docs/contracts/SwiftailHost.md` "로그아웃" 동작 O.
extension TailnetNode {
    /// 제어 서버에 이 노드의 node 키를 만료시키라고 알린다(Go `tailscale logout`의 서버 쪽).
    ///
    /// `run()`이 돌지 않을 때(시작 전이나 끝난 뒤) 부른다. 앱의 순서는 `run()`을 취소하고 끝나기를 기다림 → `logOut()` →
    /// 상태 디렉터리 비우기다. 이 메서드는 로컬 파일(신원·lock 상태·인증서)을 지우지 않는다. 실패해도(망 없음) 앱은 디렉터리를
    /// 지울 수 있고, 그때는 옛 노드가 서버에 남는다.
    ///
    /// 등록한 적이 없으면(저장된 node 키가 없으면) 아무것도 보내지 않고 돌아온다. 보낸 요청은 다시 시도하지 않는다.
    /// `setDefaultInterface`로 알린 인터페이스가 있으면 그 인터페이스로 연결한다.
    ///
    /// - Throws: 같은 상태 디렉터리의 `run()`(이 노드든 다른 노드든)이 도는 중이면 `stateDirectoryInUse`. 서버가 거절하면
    ///   `control(.registrationRejected)`. 10초 안에 끝나지 않거나 연결하지 못하면 `control(.connection)`, 200이 아니면
    ///   `control(.http(status:))`, 신원 파일을 읽지 못하면 `control(.storage)`.
    public func logOut() async throws(NodeError) {
        let directory = configuration.stateDirectory
        // `run()`과 같은 표로 막는다. 이 디렉터리를 쥔 동안 시작하는 `run()`은 `stateDirectoryInUse`로 끝난다.
        guard StateDirectoryClaims.shared.claim(directory) else { throw .stateDirectoryInUse }
        defer { StateDirectoryClaims.shared.release(directory) }

        let control = ControlClient(
            configuration: .init(serverURL: configuration.controlURL, hostname: configuration.hostname, authKey: configuration.authKey),
            identityStore: identityStore
        )
        if let defaultInterface {
            await control.setNetworkInterface(defaultInterface)
        }
        do throws(ControlError) {
            try await control.logOut()
        } catch {
            Self.log.error("로그아웃 실패")
            throw NodeError(error)
        }
        Self.log.info("로그아웃: 서버에 node 키 만료를 알림")
    }
}
