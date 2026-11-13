// swift-tools-version: 6.0
import PackageDescription

let package = Package(
    name: "Swiftail",
    platforms: [.iOS(.v18), .macOS(.v15)],
    products: [
        .library(name: "SwiftailCrypto", targets: ["SwiftailCrypto"]),
        .library(name: "SwiftailBase", targets: ["SwiftailBase"]),
        .library(name: "SwiftailWireGuard", targets: ["SwiftailWireGuard"]),
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
    ],
    swiftLanguageModes: [.v6]
)
