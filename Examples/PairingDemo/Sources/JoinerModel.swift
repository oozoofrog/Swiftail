import Foundation
import Observation
import Swiftail
import SwiftailPairing

/// 들어오는 쪽: 제안을 읽어 사용자에게 확인받고, 짝을 맺고, 짝이 된 여는 쪽에 걸어 본다.
@MainActor @Observable
final class JoinerModel {
    enum Phase: Equatable {
        case idle
        /// 노드가 tailnet에 들어오고 여는 쪽에 닿기를 기다린다.
        case connecting
        /// 여는 쪽이 확인됐다. 이 숫자를 여는 쪽 화면의 숫자와 견준다.
        case awaitingApproval(confirmationCode: String)
        case paired
        case failed(String)
    }

    /// 여는 쪽의 승인 화면에 보일 이 기기의 이름. 상대에게 그대로 간다.
    var deviceName = JoinerModel.defaultDeviceName
    /// 읽었지만 아직 사용자가 확인하지 않은 제안. 링크는 어디서든 올 수 있으므로 `host`를 보여 주고 묻는다(계약 3절).
    private(set) var pendingOffer: PairingOffer?
    private(set) var phase = Phase.idle
    private(set) var pairedHost: PairedHost?
    /// 마지막 "연결 확인"의 결과.
    private(set) var connectionCheck: String?
    /// 읽지 못한 링크의 안내.
    private(set) var linkMessage: String?

    private let node: NodeModel
    private let log: EventLog
    private let automation: Automation?
    private var pairing: Task<Void, Never>?

    init(node: NodeModel, log: EventLog, automation: Automation?) {
        self.node = node
        self.log = log
        self.automation = automation
        if let data = try? Data(contentsOf: Storage.pairedHost) {
            pairedHost = try? Self.decoder.decode(PairedHost.self, from: data)
        }
    }

    // MARK: 제안 받기

    /// QR에서 읽었거나, 붙여 넣었거나, URL로 받은 문자열을 제안으로 읽는다. 문자열은 기록하지 않는다.
    ///
    /// - Parameter source: 받은 길(`qr`, `paste`, `url`). 기록에 남긴다.
    func receive(link: String, source: String) {
        do throws(PairingOfferError) {
            pendingOffer = try PairingOffer(link: link.trimmingCharacters(in: .whitespacesAndNewlines))
            linkMessage = nil
            log.record(.joiner, "offer-received", "\(source): 읽음")
        } catch {
            linkMessage = error.guidance
            log.record(.joiner, "offer-received", "\(source): 실패(\(error))")
        }
    }

    func discardOffer() {
        pendingOffer = nil
    }

    // MARK: 짝 맺기

    /// 사용자가 제안의 여는 쪽을 보고 진행을 골랐다.
    func confirmOffer() {
        guard let offer = pendingOffer, pairing == nil else { return }
        pendingOffer = nil
        pairing = Task {
            await self.pair(with: offer)
            self.pairing = nil
        }
    }

    func cancelPairing() {
        pairing?.cancel()
    }

    private func pair(with offer: PairingOffer) async {
        phase = .connecting
        connectionCheck = nil
        // 이미 tailnet에 있으면 제안의 인증 키를 쓰지 않는다. 키는 저장하지 않고 노드에 한 번만 넘긴다(계약 3절).
        if node.node == nil { node.start(authKey: offer.authKey) }
        guard let running = await node.waitUntilRunning() else {
            // 등록에 실패했으면 키는 쓰이지 않았을 수 있다. 같은 제안으로 다시 해 볼 수 있게 돌려놓는다.
            pendingOffer = offer
            phase = .failed(node.failure ?? "노드가 tailnet에 연결되기 전에 멈췄습니다.")
            log.record(.joiner, "pair", "실패: 노드가 연결되지 않음")
            return
        }
        let logsCode = automation?.logsConfirmationCode == true
        do throws(PairingError) {
            let paired = try await PairingJoiner.pair(with: offer, deviceName: deviceName, node: running) { code in
                Task { @MainActor in
                    // 승인이 먼저 도착했으면 덮어쓰지 않는다.
                    guard self.phase == .connecting else { return }
                    self.phase = .awaitingApproval(confirmationCode: code)
                    self.log.record(.joiner, "awaiting-approval", logsCode ? "확인 숫자 \(code)" : "여는 쪽의 승인을 기다림")
                }
            }
            pairedHost = paired
            let saved = (try? Self.encoder.encode(paired).write(to: Storage.pairedHost, options: .atomic)) != nil
            phase = .paired
            log.record(.joiner, "pair", saved ? "짝이 됨" : "짝이 됨(저장하지 못함)")
        } catch {
            // 여는 쪽에 닿기 전에 끝난 제안은 쓰이지 않았다. 잠긴 노드가 서명된 뒤 같은 제안으로 다시 시도할 수 있다.
            // 확인 숫자까지 간 제안은 여는 쪽에서 이미 쓰였으므로 돌려놓지 않는다.
            if phase == .connecting, error == .unreachable || error == .cancelled { pendingOffer = offer }
            phase = .failed(error.guidance)
            log.record(.joiner, "pair", "실패: \(error)")
        }
    }

    // MARK: 짝이 된 뒤의 연결

    /// 여는 쪽의 인사 포트에 걸어 한 줄을 받는다. 연결의 상대가 짝인지는 `whoIs`의 `StableID`로 본다.
    func checkConnection() async {
        guard let pairedHost else { return }
        guard let running = node.node else {
            connectionCheck = "노드를 먼저 시작하세요."
            return
        }
        connectionCheck = "연결하는 중"
        do throws(ConnectionError) {
            let connection = try await running.connect(to: pairedHost.host, port: HostModel.greetingPort)
            guard await running.whoIs(connection.remoteEndpoint.address)?.stableID == pairedHost.stableID else {
                await connection.abort()
                finishCheck("상대가 짝이 된 여는 쪽이 아닙니다. 연결을 끊었습니다.", log: "실패: StableID가 다름")
                return
            }
            var greeting: [UInt8] = []
            while greeting.count < 256, let bytes = try await connection.read(upTo: 256) { greeting += bytes }
            await connection.close()
            let text = String(decoding: greeting, as: UTF8.self).trimmingCharacters(in: .whitespacesAndNewlines)
            finishCheck(text.isEmpty ? "여는 쪽이 인사 없이 닫았습니다." : "받은 인사: \(text)", log: text.isEmpty ? "빈 응답" : "인사를 받음(StableID 일치)")
        } catch {
            finishCheck(error.guidance, log: "실패: \(error)")
        }
    }

    private func finishCheck(_ text: String, log result: String) {
        connectionCheck = text
        log.record(.joiner, "connection-check", result)
    }

    private static var defaultDeviceName: String {
        #if os(macOS)
        "Mac"
        #else
        "iPhone"
        #endif
    }

    private static let encoder: JSONEncoder = {
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .iso8601
        return encoder
    }()

    private static let decoder: JSONDecoder = {
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        return decoder
    }()
}
