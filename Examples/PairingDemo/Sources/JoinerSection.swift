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
        Section("Receive Offer") {
            TextField("This device's name as shown to the host", text: $joiner.deviceName)
            #if os(iOS)
            Button("Scan QR Code") {
                Task {
                    if await QRScanner.requestAccess() {
                        isScanning = true
                    } else {
                        scannerMessage = "Could not scan with the camera. Allow camera access in Settings or paste the link."
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
            SecureField("Paste offer link", text: $link)
            Button("Read Link") {
                joiner.receive(link: link, source: "paste")
                link = ""
            }
            .disabled(link.isEmpty)
            if let message = joiner.linkMessage {
                Text(message).foregroundStyle(.red)
            }
        }
        if let offer = joiner.pendingOffer {
            Section("Received Offer") {
                LabeledContent("Host", value: offer.host)
                LabeledContent("Expires") { Text(offer.expires, format: .dateTime.hour().minute().second()) }
                if offer.expires < .now {
                    Text("The offer has expired according to this device's clock. The host may reject it.").font(.caption)
                }
                LabeledContent("Auth Key", value: offer.authKey == nil ? "Absent" : "Present (used only when the node is off the tailnet)")
                Text("Proceed only if the name matches the device you intended to pair with.").font(.caption)
                Button("Pair") { joiner.confirmOffer() }
                Button("Discard", role: .destructive) { joiner.discardOffer() }
            }
        }
        Section("Pairing") {
            switch joiner.phase {
            case .idle:
                Text("After you read the offer, pairing continues here.").foregroundStyle(.secondary)
            case .connecting:
                ProgressView("Joining the tailnet and connecting to the host")
                Button("Cancel") { joiner.cancelPairing() }
            case .awaitingApproval(let confirmationCode):
                Text("Check that the number matches the one on the host screen, then approve on the host.")
                Text(confirmationCode)
                    .font(.system(size: 48, weight: .bold).monospacedDigit())
                    .frame(maxWidth: .infinity)
                    .accessibilityIdentifier("joiner-confirmation-code")
                Button("Cancel") { joiner.cancelPairing() }
            case .paired:
                Text("Paired.")
            case .failed(let guidance):
                Text(guidance).foregroundStyle(.red)
            }
        }
        if let pairedHost = joiner.pairedHost {
            Section("Paired Peer") {
                LabeledContent("Name", value: pairedHost.name)
                LabeledContent("Address", value: pairedHost.host)
                LabeledContent("Paired At") { Text(pairedHost.pairedAt, format: .dateTime) }
                Button("Check Connection") { Task { await joiner.checkConnection() } }
                if let result = joiner.connectionCheck {
                    Text(result)
                }
            }
        }
    }
}
