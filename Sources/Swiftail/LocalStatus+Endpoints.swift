import SwiftailControl
import SwiftailMagicsock

/// Converts the local endpoints selected by `Magicsock` to the form sent to the control server.
///
/// Contract `docs/contracts/SwiftailEngine.md`, “Changes in M4” N4. `ControlClient` sends the disco key and all
/// endpoints with each status update, so no value is lost if testcontrol replaces the entire node value
/// (`disco-magicsock.md` §4.9 item 4).
extension ControlClient.LocalStatus {
    /// Replaces the endpoint list. Stores addresses and kinds in the same order, because order is significant (notes §4.9 item 1).
    mutating func setEndpoints(_ endpoints: [Magicsock.Endpoint]) {
        self.endpoints = endpoints.map(\.address)
        endpointTypes = endpoints.map { endpoint in
            switch endpoint.source {
            case .local: .local
            case .stun: .stun
            }
        }
    }
}
