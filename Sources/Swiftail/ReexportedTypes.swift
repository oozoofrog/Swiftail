import SwiftailBase
import SwiftailControl
import SwiftailEngine
import SwiftailMagicsock

// Types from other modules that appear in `Swiftail`'s public declarations. Re-exports aliases of the same types so an
// app can use their names with only `import Swiftail`. Also exposes types found in their public properties and
// associated values (`IPPrefix`). Nested types (`TailnetLockStatus.Mode`) are available through the alias.
//
// Only selected names are exposed because `@_exported import` is an unofficial underscored feature and would expand
// `Swiftail`'s surface to entire modules (`Netmap` and tailcfg models, key types, and the control client). Swift 6
// `public import` (SE-0409) does not re-export names. An alias is the original type, so code importing that module too
// can exchange values directly.
//
// Input declarations apps will not use (`Netmap` in `TunnelNetworkSettings.init?(netmap:mtu:at:)`) are left out.

/// An IPv4 or IPv6 address. Appears in `NodeStatus.addresses`, `TailnetNode.whoIs(_:)`, and `TunnelNetworkSettings.dnsServers`.
public typealias IPAddress = SwiftailBase.IPAddress

/// An address and port. Appears in `TailnetConnection.remoteEndpoint` and `localEndpoint`, and `PeerPath.direct(_:)`.
public typealias IPEndpoint = SwiftailBase.IPEndpoint

/// An address prefix (CIDR). Appears in `TunnelNetworkSettings.addresses` and `routes`.
public typealias IPPrefix = SwiftailBase.IPPrefix

/// A failure that ended the control client. Carried by `NodeError.control(_:)`.
public typealias ControlError = SwiftailControl.ControlError

/// The tailnet lock state. Appears in `NodeStatus.tailnetLock` and `NodeEvent.tailnetLockChanged(_:)`.
public typealias TailnetLockStatus = SwiftailControl.TailnetLockStatus

/// Tunnel settings for the app to apply to the OS. Appears in `TailnetNode.networkSettings` and `NodeStatus.networkSettings`.
public typealias TunnelNetworkSettings = SwiftailEngine.TunnelNetworkSettings

/// A path to a peer (direct or relayed). Appears in `TailnetNode.path(toPeerNamed:)` and `NodeEvent.peerPathChanged(fqdn:path:)`.
public typealias PeerPath = SwiftailMagicsock.PeerPath
