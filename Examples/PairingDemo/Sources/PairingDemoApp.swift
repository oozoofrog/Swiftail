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

/// The app's root model. Connects the node and the two roles.
@MainActor @Observable
final class AppModel {
    /// Nil outside automation mode.
    let automation = Automation(arguments: ProcessInfo.processInfo.arguments)
    let log = EventLog()
    let node: NodeModel
    let host: HostModel
    let joiner: JoinerModel
    /// The host's `PairingHost` runs only when this role is `.host` and a node exists.
    var role: Role {
        didSet { Task { await syncHost() } }
    }

    init() {
        node = NodeModel(controlURL: automation?.controlURL, log: log)
        host = HostModel(log: log, automation: automation)
        joiner = JoinerModel(node: node, log: log, automation: automation)
        role = automation?.role ?? .platformDefault
    }

    /// Called once at app launch. Connects the node without authentication if the device has registered before.
    func launch() async {
        if let automation {
            log.record(.app, "launch", "Automation mode")
            if node.hasSavedIdentity || automation.authKey != nil { await startNode(authKey: automation.authKey) }
            if automation.opensOffer, role == .host, await node.waitUntilRunning() != nil {
                await host.openOffer(lifetime: .seconds(300), authKey: automation.authKey)
            }
        } else {
            log.record(.app, "launch", "Started")
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

    /// Handles a link delivered by the OS. Switches to the joiner role and shows the offer. Pairing waits for the user to confirm.
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
