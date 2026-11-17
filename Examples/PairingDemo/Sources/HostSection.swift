import SwiftUI
import SwiftailPairing

struct HostSection: View {
    @Bindable var host: HostModel
    let nodeIsRunning: Bool
    @State private var lifetimeSeconds = 300
    @State private var carriesAuthKey = false
    @State private var clientID = ""
    @State private var clientSecret = ""
    @State private var clientTags = ""

    var body: some View {
        Section("제안") {
            if !nodeIsRunning || !host.isRunning {
                Text("노드가 연결되면 제안을 열 수 있습니다.").foregroundStyle(.secondary)
            } else {
                Picker("수명", selection: $lifetimeSeconds) {
                    Text("5분").tag(300)
                    Text("15분").tag(900)
                    Text("60분").tag(3600)
                }
                Toggle("인증 키 싣기", isOn: $carriesAuthKey)
                if carriesAuthKey { oauthClient }
                Button("제안 열기") {
                    let lifetime = Duration.seconds(lifetimeSeconds)
                    Task {
                        if carriesAuthKey {
                            await host.openOfferWithIssuedKey(lifetime: lifetime)
                        } else {
                            await host.openOffer(lifetime: lifetime, authKey: nil)
                        }
                    }
                }
                if let offer = host.offer { openOffer(offer) }
            }
            if let message = host.message {
                Text(message).foregroundStyle(.red)
            }
        }
        Section("짝 목록") {
            if host.peers.isEmpty {
                Text("짝이 없습니다.").foregroundStyle(.secondary)
            }
            ForEach(host.peers, id: \.peer.stableID) { peer in
                HStack {
                    VStack(alignment: .leading, spacing: 2) {
                        Text(peer.deviceName)
                        Text("\(peer.peer.computedName) · \(peer.peer.loginName)")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                        Text(peer.pairedAt, format: .dateTime)
                            .font(.caption2)
                            .foregroundStyle(.secondary)
                    }
                    Spacer()
                    Button("지우기", role: .destructive) { Task { await host.remove(peer) } }
                }
            }
        }
    }

    /// 인증 키를 만드는 OAuth 클라이언트. 비밀값은 키체인에만 둔다.
    @ViewBuilder private var oauthClient: some View {
        if let id = host.oauthClientID {
            LabeledContent("OAuth 클라이언트", value: id)
            Button("OAuth 클라이언트 지우기", role: .destructive) { host.removeOAuthClient() }
        } else {
            TextField("OAuth 클라이언트 ID", text: $clientID)
            SecureField("클라이언트 비밀값(tskey-client-…)", text: $clientSecret)
            TextField("태그(tag:이름, 쉼표로 가름)", text: $clientTags)
            Button("키체인에 저장") {
                host.saveOAuthClient(id: clientID, secret: clientSecret, tags: clientTags)
                if host.oauthClientID != nil { (clientID, clientSecret, clientTags) = ("", "", "") }
            }
            Text("이 키로 들어온 기기는 태그 노드가 됩니다. tailnet 정책이 그 태그에서 이 기기의 포트 4747·4748로 가는 연결을 허용해야 합니다.")
                .font(.caption)
                .foregroundStyle(.secondary)
        }
    }

    @ViewBuilder private func openOffer(_ offer: HostModel.OpenOffer) -> some View {
        if let qrCode = offer.qrCode {
            // 모듈 하나가 한 화소인 그림이다. 보간 없이 키워야 읽힌다.
            Image(qrCode, scale: 1, label: Text("페어링 QR 코드"))
                .interpolation(.none)
                .resizable()
                .scaledToFit()
                .frame(maxWidth: 280)
                .frame(maxWidth: .infinity)
        }
        LabeledContent("만료") { Text(offer.expires, format: .dateTime.hour().minute().second()) }
        Text(offer.carriesAuthKey
            ? "이 QR과 링크에는 tailnet에 들어오는 인증 키가 실려 있습니다. 짝을 맺을 기기에만 보여 주세요."
            : "이 QR과 링크는 짝을 맺을 기기에만 보여 주세요.")
            .font(.caption)
        Button("링크 복사") { Pasteboard.copy(offer.url.absoluteString) }
        ShareLink("링크 공유", item: offer.url)
        Button("제안 닫기") { Task { await host.closeOffer() } }
    }
}
