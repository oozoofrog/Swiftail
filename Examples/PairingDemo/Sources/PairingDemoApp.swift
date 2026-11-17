import Foundation
import Observation
import SwiftUI

@main
struct PairingDemoApp: App {
    @State private var model = AppModel()

    var body: some Scene {
        WindowGroup {
            ContentView(model: model)
                .task { await model.launch() }
                .onOpenURL { model.open($0) }
        }
    }
}

/// 앱의 뿌리 모델. 노드와 두 역할을 잇는다.
@MainActor @Observable
final class AppModel {
    /// 자동화 모드가 아니면 nil.
    let automation = Automation(arguments: ProcessInfo.processInfo.arguments)
    let log = EventLog()
    let node: NodeModel
    let host: HostModel
    let joiner: JoinerModel
    /// 여는 쪽의 `PairingHost`는 이 역할이 `.host`이고 노드가 있을 때만 돈다.
    var role: Role {
        didSet { Task { await syncHost() } }
    }

    init() {
        node = NodeModel(controlURL: automation?.controlURL, log: log)
        host = HostModel(log: log, automation: automation)
        joiner = JoinerModel(node: node, log: log, automation: automation)
        role = automation?.role ?? .platformDefault
    }

    /// 앱이 뜰 때 한 번 부른다. 전에 등록한 기기면 인증 없이 노드를 잇는다.
    func launch() async {
        if let automation {
            log.record(.app, "launch", "자동화 모드")
            if node.hasSavedIdentity || automation.authKey != nil { await startNode(authKey: automation.authKey) }
            if automation.opensOffer, role == .host, await node.waitUntilRunning() != nil {
                await host.openOffer(lifetime: .seconds(300), authKey: automation.authKey)
            }
        } else {
            log.record(.app, "launch", "시작")
            if node.hasSavedIdentity { await startNode(authKey: nil) }
        }
    }

    func startNode(authKey: String?) async {
        node.start(authKey: authKey)
        await syncHost()
    }

    func stopNode() async {
        await host.stop()
        await node.stop()
    }

    /// OS가 배달한 링크. 들어오는 쪽으로 바꾸고 제안을 보여 준다. 짝 맺기는 사용자가 확인한 뒤에 한다.
    func open(_ url: URL) {
        role = .joiner
        joiner.receive(link: url.absoluteString, source: "url")
    }

    private func syncHost() async {
        if role == .host, let running = node.node {
            await host.start(on: running)
        } else {
            await host.stop()
        }
    }
}
