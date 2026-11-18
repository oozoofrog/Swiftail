import Foundation

/// The role this app plays in pairing.
enum Role: String, Sendable, CaseIterable, Identifiable {
    /// Offers pairing and grants approval.
    case host
    /// Reads the offer and joins.
    case joiner

    var id: Self { self }

    var label: String {
        switch self {
        case .host: "Host"
        case .joiner: "Joiner"
        }
    }

    /// Starts as the host on Mac and as the joiner on iPhone.
    static var platformDefault: Role {
        #if os(macOS)
        .host
        #else
        .joiner
        #endif
    }
}

/// Settings for automation mode. Use them only to verify that the app runs without human input.
///
/// Enabled only with both the launch argument `--automation` and a loopback control server (`--control-url=http://127.0.0.1:<port>`). Saved
/// settings and the UI cannot enable it. This keeps automatic approval and the link file within the test control server environment.
struct Automation: Sendable {
    /// The test control server. Accepts only loopback `http://` URLs.
    let controlURL: URL
    var role: Role?
    /// The auth key for registering the node. If the host opens an offer on startup, it includes the key in that offer as well.
    var authKey: String?
    /// Opens an offer as soon as the node connects (`--open-offer`).
    var opensOffer = false
    /// Approves without presenting the approval screen (`--auto-approve`).
    var approvesAutomatically = false
    /// Writes the open offer's link to `offer-link.txt` in the app container (`--write-offer-link`).
    var writesOfferLink = false
    /// Logs the SAS (`--log-confirmation-code`).
    var logsConfirmationCode = false

    /// Returns nil outside automation mode. Reads the other arguments only in automation mode.
    init?(arguments: [String]) {
        guard arguments.contains("--automation"),
            let controlURL = arguments.lazy.compactMap({ Self.value(of: "--control-url=", in: $0) }).first.flatMap(URL.init(string:)),
            controlURL.scheme == "http", let host = controlURL.host(percentEncoded: false),
            ["127.0.0.1", "::1", "localhost"].contains(host)
        else { return nil }
        self.controlURL = controlURL
        for argument in arguments {
            switch argument {
            case "--open-offer": opensOffer = true
            case "--auto-approve": approvesAutomatically = true
            case "--write-offer-link": writesOfferLink = true
            case "--log-confirmation-code": logsConfirmationCode = true
            default:
                if let value = Self.value(of: "--role=", in: argument) { role = Role(rawValue: value) }
                if let value = Self.value(of: "--auth-key=", in: argument) { authKey = value }
            }
        }
    }

    private static func value(of prefix: String, in argument: String) -> String? {
        argument.hasPrefix(prefix) ? String(argument.dropFirst(prefix.count)) : nil
    }
}
