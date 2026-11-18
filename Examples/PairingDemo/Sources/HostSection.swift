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
        Section("Offer") {
            if !nodeIsRunning || !host.isRunning {
                Text("You can open an offer once the node connects.").foregroundStyle(.secondary)
            } else {
                Picker("Lifetime", selection: $lifetimeSeconds) {
                    Text("5 minutes").tag(300)
                    Text("15 minutes").tag(900)
                    Text("60 minutes").tag(3600)
                }
                Toggle("Include Auth Key", isOn: $carriesAuthKey)
                if carriesAuthKey { oauthClient }
                Button("Open Offer") {
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
        Section("Paired Peers") {
            if host.peers.isEmpty {
                Text("No paired peers.").foregroundStyle(.secondary)
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
                    Button("Remove", role: .destructive) { Task { await host.remove(peer) } }
                }
            }
        }
    }

    /// The OAuth client for creating auth keys. Stores the secret only in the keychain.
    @ViewBuilder private var oauthClient: some View {
        if let id = host.oauthClientID {
            LabeledContent("OAuth Client", value: id)
            Button("Remove OAuth Client", role: .destructive) { host.removeOAuthClient() }
        } else {
            TextField("OAuth Client ID", text: $clientID)
            SecureField("Client Secret (tskey-client-…)", text: $clientSecret)
            TextField("Tags (tag:name, comma-separated)", text: $clientTags)
            Button("Save to Keychain") {
                host.saveOAuthClient(id: clientID, secret: clientSecret, tags: clientTags)
                if host.oauthClientID != nil { (clientID, clientSecret, clientTags) = ("", "", "") }
            }
            Text("Devices that join with this key become tagged nodes. The tailnet policy must allow connections from that tag to ports 4747 and 4748 on this device.")
                .font(.caption)
                .foregroundStyle(.secondary)
        }
    }

    @ViewBuilder private func openOffer(_ offer: HostModel.OpenOffer) -> some View {
        if let qrCode = offer.qrCode {
            // Each module is one pixel in the image. Scale without interpolation to keep it readable.
            Image(qrCode, scale: 1, label: Text("Pairing QR Code"))
                .interpolation(.none)
                .resizable()
                .scaledToFit()
                .frame(maxWidth: 280)
                .frame(maxWidth: .infinity)
        }
        LabeledContent("Expires") { Text(offer.expires, format: .dateTime.hour().minute().second()) }
        Text(offer.carriesAuthKey
            ? "This QR code and link include an auth key for joining the tailnet. Show them only to the device you want to pair with."
            : "Show this QR code and link only to the device you want to pair with.")
            .font(.caption)
        Button("Copy Link") { Pasteboard.copy(offer.url.absoluteString) }
        ShareLink("Share Link", item: offer.url)
        Button("Close Offer") { Task { await host.closeOffer() } }
    }
}
