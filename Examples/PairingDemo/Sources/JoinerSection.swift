import SwiftUI
import SwiftailPairing

struct JoinerSection: View {
    @Bindable var joiner: JoinerModel
    @State private var link = ""
    #if os(iOS)
    @State private var isScanning = false
    @State private var scannerMessage: String?
    #endif

    var body: some View {
        Section("제안 받기") {
            TextField("여는 쪽에 보일 이 기기의 이름", text: $joiner.deviceName)
            #if os(iOS)
            Button("QR 코드 읽기") {
                Task {
                    if await QRScanner.requestAccess() {
                        isScanning = true
                    } else {
                        scannerMessage = "카메라로 읽을 수 없습니다. 설정에서 카메라 접근을 허용하거나 링크를 붙여 넣으세요."
                    }
                }
            }
            .sheet(isPresented: $isScanning) {
                QRScanner { text in
                    isScanning = false
                    joiner.receive(link: text, source: "qr")
                }
                .ignoresSafeArea()
            }
            if let scannerMessage {
                Text(scannerMessage).foregroundStyle(.red)
            }
            #endif
            SecureField("제안 링크 붙여 넣기", text: $link)
            Button("링크 읽기") {
                joiner.receive(link: link, source: "paste")
                link = ""
            }
            .disabled(link.isEmpty)
            if let message = joiner.linkMessage {
                Text(message).foregroundStyle(.red)
            }
        }
        if let offer = joiner.pendingOffer {
            Section("받은 제안") {
                LabeledContent("여는 쪽", value: offer.host)
                LabeledContent("만료") { Text(offer.expires, format: .dateTime.hour().minute().second()) }
                if offer.expires < .now {
                    Text("이 기기의 시계로는 만료가 지났습니다. 여는 쪽이 거절할 수 있습니다.").font(.caption)
                }
                LabeledContent("인증 키", value: offer.authKey == nil ? "없음" : "있음(tailnet에 없을 때만 씁니다)")
                Text("짝을 맺으려던 기기의 이름이 맞을 때만 진행하세요.").font(.caption)
                Button("짝 맺기") { joiner.confirmOffer() }
                Button("버리기", role: .destructive) { joiner.discardOffer() }
            }
        }
        Section("짝 맺기") {
            switch joiner.phase {
            case .idle:
                Text("제안을 읽으면 여기서 진행합니다.").foregroundStyle(.secondary)
            case .connecting:
                ProgressView("tailnet에 들어가 여는 쪽에 연결하는 중")
                Button("취소") { joiner.cancelPairing() }
            case .awaitingApproval(let confirmationCode):
                Text("여는 쪽 화면의 숫자와 같은지 확인하고, 여는 쪽에서 승인하세요.")
                Text(confirmationCode)
                    .font(.system(size: 48, weight: .bold).monospacedDigit())
                    .frame(maxWidth: .infinity)
                    .accessibilityIdentifier("joiner-confirmation-code")
                Button("취소") { joiner.cancelPairing() }
            case .paired:
                Text("짝이 됐습니다.")
            case .failed(let guidance):
                Text(guidance).foregroundStyle(.red)
            }
        }
        if let pairedHost = joiner.pairedHost {
            Section("짝") {
                LabeledContent("이름", value: pairedHost.name)
                LabeledContent("주소", value: pairedHost.host)
                LabeledContent("짝이 된 때") { Text(pairedHost.pairedAt, format: .dateTime) }
                Button("연결 확인") { Task { await joiner.checkConnection() } }
                if let result = joiner.connectionCheck {
                    Text(result)
                }
            }
        }
    }
}
