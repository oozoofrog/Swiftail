import SwiftUI
import Swiftail

struct ContentView: View {
    @Bindable var model: AppModel

    var body: some View {
        NavigationStack {
            Form {
                if model.automation != nil {
                    Section {
                        Label("Automation Mode", systemImage: "gearshape.2")
                            .foregroundStyle(.orange)
                    }
                }
                Section {
                    Picker("Role", selection: $model.role) {
                        ForEach(Role.allCases) { Text($0.label).tag($0) }
                    }
                    .pickerStyle(.segmented)
                }
                NodeSection(model: model)
                switch model.role {
                case .host: HostSection(host: model.host, nodeIsRunning: model.node.status?.state == .running)
                case .joiner: JoinerSection(joiner: model.joiner)
                }
                EventLogSection(log: model.log)
            }
            .formStyle(.grouped)
            .scrollDismissesKeyboard(.interactively)
            .navigationTitle("Swiftail Pairing")
        }
        .sheet(item: Binding(get: { model.host.approvals.first }, set: { _ in })) { approval in
            ApprovalView(host: model.host, approval: approval)
                .interactiveDismissDisabled()
        }
    }
}

private struct NodeSection: View {
    let model: AppModel
    @State private var authKey = ""
    @Environment(\.openURL) private var openURL

    var body: some View {
        Section("Node") {
            if let status = model.node.status {
                LabeledContent("Status", value: status.state.label)
                if case .needsLogin(let url) = status.state {
                    Button("Sign In in Browser") { openURL(url) }
                }
                LabeledContent("Name", value: status.fqdn ?? "—")
                LabeledContent("Peers", value: "\(status.peerCount)")
                LabeledContent("tailnet lock", value: status.tailnetLock.label)
                if let request = status.tailnetLock.signingRequest {
                    let command = "tailscale lock sign \(request.nodeKey) \(request.lockKey)"
                    Text("This node has not been signed yet and cannot communicate with other devices. Run the command below on a signing device in the tailnet.")
                    Text(command)
                        .font(.caption.monospaced())
                        .textSelection(.enabled)
                    Button("Copy Command") { Pasteboard.copy(command) }
                }
                Button("Stop Node") { Task { await model.stopNode() } }
            } else if model.node.node != nil {
                LabeledContent("Status", value: NodeState.starting.label)
            } else {
                SecureField("Auth key (otherwise use a saved identity or sign in)", text: $authKey)
                Button("Start Node") {
                    let key = authKey.trimmingCharacters(in: .whitespacesAndNewlines)
                    authKey = ""
                    Task { await model.startNode(authKey: key.isEmpty ? nil : key) }
                }
            }
            if let failure = model.node.failure {
                Text(failure).foregroundStyle(.red)
            }
        }
    }
}

private struct ApprovalView: View {
    let host: HostModel
    let approval: HostModel.Approval

    var body: some View {
        VStack(spacing: 16) {
            Text("Approve only if the number matches the one on the joining device's screen.")
                .multilineTextAlignment(.center)
            Text(approval.request.confirmationCode)
                .font(.system(size: 48, weight: .bold).monospacedDigit())
                .accessibilityIdentifier("host-confirmation-code")
            Grid(alignment: .leading, horizontalSpacing: 12, verticalSpacing: 6) {
                GridRow {
                    Text("Device name (reported by the peer)").foregroundStyle(.secondary)
                    Text(approval.request.deviceName)
                }
                GridRow {
                    Text("Node").foregroundStyle(.secondary)
                    Text(approval.request.peer.computedName)
                }
                GridRow {
                    Text("Login").foregroundStyle(.secondary)
                    Text(approval.request.peer.loginName)
                }
            }
            HStack {
                Button("Deny", role: .destructive) { host.deny(approval) }
                Button("Approve") { host.approve(approval) }
                    .keyboardShortcut(.defaultAction)
            }
        }
        .padding(24)
    }
}

private struct EventLogSection: View {
    let log: EventLog

    var body: some View {
        Section("Log") {
            if log.entries.isEmpty {
                Text("No events yet.").foregroundStyle(.secondary)
            }
            ForEach(log.entries) { entry in
                VStack(alignment: .leading, spacing: 2) {
                    Text("\(entry.role.rawValue) · \(entry.event)").font(.caption.monospaced())
                    Text(entry.result).font(.caption)
                    Text(entry.time, format: .dateTime.hour().minute().second())
                        .font(.caption2)
                        .foregroundStyle(.secondary)
                }
            }
        }
    }
}

/// Copies text to the system clipboard.
enum Pasteboard {
    static func copy(_ text: String) {
        #if os(macOS)
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(text, forType: .string)
        #else
        UIPasteboard.general.string = text
        #endif
    }
}
