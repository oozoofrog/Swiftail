import CryptoKit
import Foundation
import SwiftailBase

extension Hostinfo {
    /// The minimal Hostinfo a Swiftail node sends for registration and state reporting.
    ///
    /// - `Hostname`: The configured hostname. testcontrol uses it as the node name.
    /// - `OS` and `OSVersion`: The actual OS (using the same `macOS` and `iOS` names as Go).
    /// - `IPNVersion` and `App`: Identify Swiftail and avoid impersonating an official client version.
    ///   Uses semver syntax (`0.0.0-swiftail`) so the version parser accepts it.
    /// - `BackendLogID`: The Go client rejects an empty value. Since logs are not uploaded, uses a fixed nonsecret value
    ///   derived from the machine public key.
    /// - `Userspace`: Swiftail implements the network stack in userspace. This describes the stack, even when an app uses a packet tunnel device.
    ///
    /// `docs/protocol-notes/control-map.md` §3.3, contract unit 4 behavior 6.
    static func swiftail(hostname: String, machineKey: MachinePublicKey, netInfo: NetInfo?) -> Hostinfo {
        let logID = SHA256.hash(data: Array("swiftail-backend-log-id:\(machineKey)".utf8))
        let version = ProcessInfo.processInfo.operatingSystemVersion
        return Hostinfo(
            ipnVersion: "0.0.0-swiftail",
            backendLogID: [UInt8](logID).hex,
            os: operatingSystemName,
            osVersion: "\(version.majorVersion).\(version.minorVersion).\(version.patchVersion)",
            hostname: hostname,
            app: "swiftail",
            userspace: true,
            netInfo: netInfo
        )
    }

    private static var operatingSystemName: String {
        #if os(iOS)
        "iOS"
        #elseif os(macOS)
        "macOS"
        #else
        "unknown"
        #endif
    }
}
