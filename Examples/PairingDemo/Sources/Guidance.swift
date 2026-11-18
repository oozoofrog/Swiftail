import Swiftail
import SwiftailPairing

// Turns library errors into guidance on what the user can do next.

extension PairingError {
    var guidance: String {
        switch self {
        case .invalidConfiguration(let message):
            "Invalid configuration: \(message). The device name must be 1 to 64 bytes and contain no control characters."
        case .invalidAuthKey:
            "This auth key cannot be included in an offer. Use a single-use key starting with tskey-auth- (Tailnet Lock signed keys cannot be included)."
        case .notRunning:
            "The node has not connected to the tailnet yet. Try again when its status is 'Connected'."
        case .storeUnreadable:
            "Could not read the paired peer list file. If it is corrupt, clear the app data and pair again."
        case .storeInUse:
            "The paired peer list is already in use. Relaunch the app."
        case .storeWriteFailed:
            "Could not save the paired peer list. Check your storage space."
        case .unreachable:
            "Could not reach the host within 60 seconds. Check that both devices are on the same tailnet. If Tailnet Lock is enabled, retry with the same offer after this device is signed."
        case .notOnTailnet:
            "The connection did not go through the tailnet. Try again after the node connects."
        case .rejected:
            "The offer was closed, expired, or already used. Open a new offer on the host and read it again."
        case .hostNotVerified:
            "Could not verify the host. It may be a different device from the one that made the offer. Try again with a new offer."
        case .denied:
            "The host denied the request."
        case .timedOut:
            "The host did not approve in time. Try again with a new offer."
        case .protocolViolation:
            "The pairing procedure does not match the host's. Check that both apps are the same version."
        case .cancelled:
            "Canceled."
        }
    }
}

extension PairingOfferError {
    var guidance: String {
        switch self {
        case .notAnOffer:
            "This is not a pairing offer. Scan the QR code or open the link from the host screen again."
        case .wrappedAuthKey:
            "Offers carrying a signed Tailnet Lock auth key are rejected. Open a new offer on the host with a single-use key."
        case .invalidHost, .invalidPort, .invalidSecret, .invalidExpiry, .invalidAuthKey:
            "The offer contents are invalid. Check whether the link was truncated, then read it again."
        }
    }
}

extension AuthKeyIssueError {
    var guidance: String {
        switch self {
        case .invalidClient:
            "The client ID or secret has an invalid format. The secret starts with tskey-client-."
        case .invalidTags:
            "Enter one or more tags in the form tag:name, separated by commas."
        case .invalidLifetime, .invalidBaseURL:
            "These settings do not allow an auth key request."
        case .clientRejected:
            "Tailscale did not accept the OAuth client. Check the ID and secret."
        case .unauthorized:
            "The issued token was rejected. Check whether the OAuth client was deleted."
        case .forbidden:
            "Permission denied. Check that the OAuth client has auth_keys write access and this tag."
        case .http(let status):
            "The Tailscale admin API returned \(status). Try again shortly."
        case .invalidResponse:
            "Could not read the Tailscale admin API response."
        case .network:
            "Could not reach the Tailscale admin API. Check your internet connection."
        case .cancelled:
            "Canceled."
        }
    }
}

extension ConnectionError {
    var guidance: String {
        switch self {
        case .notRunning:
            "The node has not connected to the tailnet. Try again when its status is 'Connected'."
        case .unknownHost:
            "The host is not visible on the tailnet. Check that the host node is running."
        case .refused:
            "The host app is not listening. Run the host app in the 'Host' role."
        case .reset:
            "The host closed the connection. This device is missing from the host's paired peer list. Pair again."
        case .timedOut:
            "The host is not responding. Check that the host device is on and connected to the network."
        case .peerRemoved:
            "The host left the tailnet."
        case .invalidConfiguration, .addressInUse, .limitReached, .closed, .cancelled, .concurrentUse:
            "Could not connect (\(self))."
        }
    }
}
