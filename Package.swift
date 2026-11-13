// swift-tools-version: 6.0
import PackageDescription

let package = Package(
    name: "Swiftail",
    platforms: [.iOS(.v18), .macOS(.v15)],
    products: [
        .library(name: "SwiftailCrypto", targets: ["SwiftailCrypto"]),
        .library(name: "SwiftailBase", targets: ["SwiftailBase"]),
        .library(name: "SwiftailWireGuard", targets: ["SwiftailWireGuard"]),
        .library(name: "SwiftailHTTP2", targets: ["SwiftailHTTP2"]),
        .library(name: "SwiftailControl", targets: ["SwiftailControl"]),
    ],
    targets: [
        .target(name: "SwiftailCrypto"),
        .testTarget(
            name: "SwiftailCryptoTests",
            dependencies: ["SwiftailCrypto"],
            resources: [.copy("Vectors")]
        ),
        .target(name: "SwiftailBase"),
        .testTarget(name: "SwiftailBaseTests", dependencies: ["SwiftailBase"]),
        .target(name: "SwiftailWireGuard", dependencies: ["SwiftailBase", "SwiftailCrypto"]),
        .testTarget(name: "SwiftailWireGuardTests", dependencies: ["SwiftailWireGuard", "SwiftailBase", "SwiftailCrypto"]),
        .testTarget(name: "SwiftailWireGuardInteropTests", dependencies: ["SwiftailWireGuard", "SwiftailBase"]),
        .target(name: "SwiftailHTTP2"),
        .testTarget(name: "SwiftailHTTP2Tests", dependencies: ["SwiftailHTTP2"], resources: [.copy("Fixtures")]),
        .testTarget(name: "SwiftailHTTP2InteropTests", dependencies: ["SwiftailHTTP2"]),
        .target(name: "SwiftailControl", dependencies: ["SwiftailBase", "SwiftailCrypto", "SwiftailHTTP2"]),
        .testTarget(name: "SwiftailControlInteropTests", dependencies: ["SwiftailControl", "SwiftailBase"]),
        .testTarget(
            name: "SwiftailControlTests",
            dependencies: ["SwiftailControl", "SwiftailBase", "SwiftailCrypto", "SwiftailHTTP2"],
            resources: [.copy("Fixtures")]
        ),
    ],
    swiftLanguageModes: [.v6]
)
