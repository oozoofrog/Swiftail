import SwiftUI
import Swiftail

struct ContentView: View {
    @Bindable var model: AppModel

    var body: some View {
        NavigationStack {
            Form {
                if model.automation != nil {
                    Section {
                        Label("자동화 모드", systemImage: "gearshape.2")
                            .foregroundStyle(.orange)
                    }
                }
                Section {
                    Picker("역할", selection: $model.role) {
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
            .navigationTitle("Swiftail 페어링")
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
        Section("노드") {
            if let status = model.node.status {
                LabeledContent("상태", value: status.state.label)
                if case .needsLogin(let url) = status.state {
                    Button("브라우저에서 로그인") { openURL(url) }
                }
                LabeledContent("이름", value: status.fqdn ?? "—")
                LabeledContent("피어", value: "\(status.peerCount)")
                LabeledContent("tailnet lock", value: status.tailnetLock.label)
                if let request = status.tailnetLock.signingRequest {
                    let command = "tailscale lock sign \(request.nodeKey) \(request.lockKey)"
                    Text("이 노드는 아직 서명되지 않아 다른 기기와 통신할 수 없습니다. tailnet의 서명 기기에서 아래 명령을 실행하세요.")
                    Text(command)
                        .font(.caption.monospaced())
                        .textSelection(.enabled)
                    Button("명령 복사") { Pasteboard.copy(command) }
                }
                Button("노드 중지") { Task { await model.stopNode() } }
            } else if model.node.node != nil {
                LabeledContent("상태", value: NodeState.starting.label)
            } else {
                SecureField("인증 키(없으면 저장된 신원이나 로그인)", text: $authKey)
                Button("노드 시작") {
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
            Text("들어오는 기기 화면의 숫자와 같을 때만 승인하세요.")
                .multilineTextAlignment(.center)
            Text(approval.request.confirmationCode)
                .font(.system(size: 48, weight: .bold).monospacedDigit())
                .accessibilityIdentifier("host-confirmation-code")
            Grid(alignment: .leading, horizontalSpacing: 12, verticalSpacing: 6) {
                GridRow {
                    Text("기기 이름(상대가 밝힌 값)").foregroundStyle(.secondary)
                    Text(approval.request.deviceName)
                }
                GridRow {
                    Text("노드").foregroundStyle(.secondary)
                    Text(approval.request.peer.computedName)
                }
                GridRow {
                    Text("로그인").foregroundStyle(.secondary)
                    Text(approval.request.peer.loginName)
                }
            }
            HStack {
                Button("거절", role: .destructive) { host.deny(approval) }
                Button("승인") { host.approve(approval) }
                    .keyboardShortcut(.defaultAction)
            }
        }
        .padding(24)
    }
}

private struct EventLogSection: View {
    let log: EventLog

    var body: some View {
        Section("기록") {
            if log.entries.isEmpty {
                Text("아직 사건이 없습니다.").foregroundStyle(.secondary)
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

/// 시스템 클립보드에 글을 넣는다.
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
