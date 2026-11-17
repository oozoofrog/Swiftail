import Foundation
import Observation
import Swiftail

/// 프로세스 안 tailnet 노드 하나의 수명과 화면에 보일 모습.
///
/// 노드는 `start(authKey:)`에서 만들고 `stop()`이나 `run()`의 실패에서 버린다. 다시 시작하면 새 `TailnetNode`다
/// (`run()`은 노드 하나에 한 번만 부를 수 있다).
@MainActor @Observable
final class NodeModel {
    /// 돌고 있는 노드. 시작 전과 끝난 뒤에는 nil.
    private(set) var node: TailnetNode?
    private(set) var status: NodeStatus?
    /// `run()`이 던진 실패의 안내. 다시 시작하면 지운다.
    private(set) var failure: String?

    private let controlURL: URL
    private let log: EventLog
    private var running: Task<Void, Never>?

    init(controlURL: URL?, log: EventLog) {
        self.controlURL = controlURL ?? NodeConfiguration.defaultControlURL
        self.log = log
    }

    /// 이 기기가 전에 등록한 적이 있는가. 있으면 앱이 뜰 때 인증 없이 노드를 시작한다.
    ///
    /// 우회: 라이브러리에 저장된 신원이 있는지 묻는 API가 없어, `NodeConfiguration.stateDirectory`의 문서가 말하는 파일
    /// 이름(`identity.json`)을 직접 본다.
    var hasSavedIdentity: Bool {
        FileManager.default.fileExists(atPath: Storage.nodeState.appending(path: "identity.json").path)
    }

    /// 노드를 만들고 돌린다. 이미 돌고 있으면 아무 일도 하지 않는다.
    ///
    /// - Parameter authKey: 첫 등록에 쓸 인증 키. 저장하지 않고 노드 설정에 한 번 넘긴다. nil이면 저장된 신원으로 잇고,
    ///   신원이 없으면 노드가 `.needsLogin(url)`로 로그인 URL을 준다.
    func start(authKey: String?) {
        guard node == nil else { return }
        failure = nil
        do throws(NodeError) {
            let node = try TailnetNode(
                configuration: NodeConfiguration(
                    stateDirectory: Storage.nodeState, hostname: Self.hostname, controlURL: controlURL, authKey: authKey),
                device: .inProcess)
            self.node = node
            log.record(.node, "start", authKey == nil ? "저장된 신원 또는 로그인" : "인증 키")
            running = Task { await self.run(node) }
        } catch {
            fail(error)
        }
    }

    func stop() async {
        running?.cancel()
        await running?.value
    }

    /// 노드가 `.running`이 되고 자기 이름을 알 때까지 기다린다. 노드가 끝나거나 호출한 Task가 취소되면 nil.
    func waitUntilRunning() async -> TailnetNode? {
        while let node, !Task.isCancelled {
            if status?.state == .running, status?.fqdn != nil { return node }
            try? await Task.sleep(for: .milliseconds(200))
        }
        return nil
    }

    /// `run()`이 끝날 때까지 돌며 화면의 상태를 맞춘다.
    private func run(_ node: TailnetNode) async {
        await withTaskGroup(of: Void.self) { group in
            group.addTask {
                for await _ in node.events { await self.refresh(from: node) }
            }
            // 우회: netmap이 바뀌어 피어 수나 이름이 달라져도 사건이 오지 않으므로 주기적으로도 읽는다.
            group.addTask {
                while !Task.isCancelled {
                    await self.refresh(from: node)
                    try? await Task.sleep(for: .seconds(2))
                }
            }
            do throws(NodeError) {
                try await node.run()
            } catch {
                fail(error)
            }
            group.cancelAll()
        }
        self.node = nil
        status = nil
        running = nil
        log.record(.node, "stopped", failure == nil ? "중지" : "실패")
    }

    private func refresh(from node: TailnetNode) async {
        let status = await node.status
        guard self.node === node else { return }
        if status.state != self.status?.state { log.record(.node, "state", status.state.label) }
        if status.lockLabel != self.status?.lockLabel { log.record(.node, "tailnet-lock", status.lockLabel) }
        self.status = status
    }

    private func fail(_ error: NodeError) {
        failure = error.guidance
        log.record(.node, "failed", error.logName)
    }

    /// 제어 서버가 노드 이름을 지을 때 쓰는 호스트 이름. 실제 기기 이름을 tailnet에 올리지 않는다.
    private static var hostname: String {
        #if os(macOS)
        "pairing-demo-mac"
        #else
        "pairing-demo-iphone"
        #endif
    }
}

extension NodeState {
    /// 화면과 기록에 쓰는 이름. 로그인 URL은 담지 않는다.
    var label: String {
        switch self {
        case .starting: "시작하는 중"
        case .needsLogin: "로그인 필요"
        case .needsMachineAuth: "관리자 승인 대기"
        case .running: "연결됨"
        }
    }
}

extension NodeStatus {
    var lockLabel: String {
        switch tailnetLock.mode {
        case .disabled: "꺼짐"
        case .enforcing: tailnetLock.signingRequest == nil ? "켜짐 · 이 노드 서명됨" : "켜짐 · 서명을 기다림"
        case .unverified: "확인하지 못함 · 피어를 올리지 않음"
        }
    }
}

extension NodeError {
    /// 사용자가 다음에 할 일.
    var guidance: String {
        switch self {
        case .control(.authKeyRejected):
            "인증 키가 거절됐습니다. 키가 잘못됐거나 만료됐거나 이미 쓰였습니다. 새 키나 새 제안으로 다시 시작하세요."
        case .control(.registrationRejected):
            "제어 서버가 등록을 거절했습니다. tailnet 관리자 정책을 확인하세요."
        case .control(.nodeKeyExpired):
            "노드 키가 만료됐습니다. 노드를 다시 시작해 로그인하세요."
        case .control(.storage):
            "신원 파일을 읽거나 쓰지 못했습니다. 앱의 저장 공간을 확인하세요."
        case .control:
            "제어 서버와의 통신이 실패했습니다. 노드를 다시 시작하세요."
        case .invalidConfiguration(let message):
            "노드 설정이 잘못됐습니다: \(message)"
        case .udpUnavailable(let reason):
            "UDP 소켓을 열지 못했습니다(\(reason)). 네트워크 권한을 확인하세요."
        case .stateDirectoryInUse:
            "다른 노드가 같은 신원으로 돌고 있습니다. 앱을 다시 띄우세요."
        case .tunnelDeviceClosed(let reason):
            "터널 장치가 닫혔습니다(\(reason))."
        }
    }

    /// 기록에 남길 종류. 서버가 준 진단 문자열은 남기지 않는다.
    var logName: String {
        switch self {
        case .control(.authKeyRejected): "authKeyRejected"
        case .control(.registrationRejected): "registrationRejected"
        case .control(.nodeKeyExpired): "nodeKeyExpired"
        case .control(.storage): "storage"
        case .control: "control"
        case .invalidConfiguration: "invalidConfiguration"
        case .udpUnavailable(let reason): "udpUnavailable(\(reason))"
        case .stateDirectoryInUse: "stateDirectoryInUse"
        case .tunnelDeviceClosed: "tunnelDeviceClosed"
        }
    }
}
