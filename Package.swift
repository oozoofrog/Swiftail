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
        .library(name: "SwiftailDERP", targets: ["SwiftailDERP"]),
        .library(name: "SwiftailMagicsock", targets: ["SwiftailMagicsock"]),
        .library(name: "SwiftailEngine", targets: ["SwiftailEngine"]),
        .library(name: "Swiftail", targets: ["Swiftail"]),
        // Optional products (M7) only for apps that act as servers. iOS tunnel extensions do not link them.
        .library(name: "SwiftailCertificates", targets: ["SwiftailCertificates"]),
        .library(name: "SwiftailLoopback", targets: ["SwiftailLoopback"]),

        .library(name: "SwiftailPairing", targets: ["SwiftailPairing"]),
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
        // Tailnet Lock (TKA) data formats and verification, with no sockets, files, or clocks. This target has no library product.
        .target(name: "SwiftailTKA", dependencies: ["SwiftailBase", "SwiftailCrypto"]),
        .testTarget(
            name: "SwiftailTKATests",
            dependencies: ["SwiftailTKA", "SwiftailBase", "SwiftailCrypto"],
            resources: [.copy("Fixtures")]
        ),
        .target(name: "SwiftailControl", dependencies: ["SwiftailBase", "SwiftailCrypto", "SwiftailHTTP2", "SwiftailIO", "SwiftailTKA"]),
        .testTarget(name: "SwiftailControlInteropTests", dependencies: ["SwiftailControl", "SwiftailBase"]),
        .testTarget(
            name: "SwiftailControlTests",
            dependencies: ["SwiftailControl", "SwiftailBase", "SwiftailCrypto", "SwiftailHTTP2", "SwiftailTKA"],
            resources: [.copy("Fixtures")]
        ),
        // Edge I/O for targets that open sockets (Control, DERP, Swiftail). This target has no library product.
        .target(name: "SwiftailIO", dependencies: ["SwiftailBase"]),
        .testTarget(name: "SwiftailIOTests", dependencies: ["SwiftailIO"]),
        .target(name: "SwiftailMagicsock", dependencies: ["SwiftailBase", "SwiftailCrypto"]),
        .testTarget(
            name: "SwiftailMagicsockTests",
            dependencies: ["SwiftailMagicsock", "SwiftailBase", "SwiftailCrypto"],
            resources: [.copy("Fixtures")]
        ),
        .target(name: "SwiftailDERP", dependencies: ["SwiftailBase", "SwiftailCrypto", "SwiftailIO"]),
        .testTarget(name: "SwiftailDERPTests", dependencies: ["SwiftailDERP", "SwiftailBase", "SwiftailCrypto", "SwiftailIO"]),
        .testTarget(name: "SwiftailDERPInteropTests", dependencies: ["SwiftailDERP", "SwiftailBase", "SwiftailIO"]),
        .target(name: "SwiftailEngine", dependencies: ["SwiftailBase", "SwiftailWireGuard", "SwiftailControl"]),
        .testTarget(
            name: "SwiftailEngineTests",
            dependencies: ["SwiftailEngine", "SwiftailBase", "SwiftailWireGuard", "SwiftailControl"],
            resources: [.copy("Fixtures")]
        ),
        .target(name: "SwiftailNetstack", dependencies: ["SwiftailBase"]),
        .testTarget(
            name: "SwiftailNetstackTests",
            dependencies: ["SwiftailNetstack", "SwiftailBase"],
            resources: [.copy("Fixtures")]
        ),
        .target(name: "Swiftail", dependencies: ["SwiftailBase", "SwiftailEngine", "SwiftailControl", "SwiftailDERP", "SwiftailIO", "SwiftailMagicsock", "SwiftailNetstack"]),
        .testTarget(name: "SwiftailTests", dependencies: ["Swiftail", "SwiftailBase", "SwiftailControl", "SwiftailDERP", "SwiftailMagicsock"]),
        .testTarget(
            name: "SwiftailInteropTests",
            dependencies: ["Swiftail", "SwiftailBase", "SwiftailControl", "SwiftailMagicsock", "SwiftailCertificates", "SwiftailLoopback", "SwiftailPairing"]
        ),
        // Issues, stores, and renews ts.net certificates (ACME DNS-01) using CryptoKit, Security, and Foundation's URLSession.
        .target(name: "SwiftailCertificates", dependencies: ["Swiftail", "SwiftailBase", "SwiftailControl"]),
        .testTarget(
            name: "SwiftailCertificatesTests",
            dependencies: ["SwiftailCertificates", "Swiftail", "SwiftailBase"],
            resources: [.copy("Fixtures")]
        ),
        // Bridges tailnet connections to an OS TCP listener on 127.0.0.1.
        .target(name: "SwiftailLoopback", dependencies: ["Swiftail", "SwiftailBase", "SwiftailCrypto", "SwiftailIO"]),
        .testTarget(name: "SwiftailLoopbackTests", dependencies: ["SwiftailLoopback", "Swiftail", "SwiftailBase", "SwiftailIO", "SwiftailControl", "SwiftailEngine"]),
        // Pairs apps by QR code or link and issues single-use auth keys (M9) using CryptoKit, Network, CoreImage, and Foundation's URLSession.
        .target(name: "SwiftailPairing", dependencies: ["Swiftail", "SwiftailBase", "SwiftailCrypto", "SwiftailIO"]),
        .testTarget(
            name: "SwiftailPairingTests",
            dependencies: ["SwiftailPairing", "Swiftail", "SwiftailBase", "SwiftailControl", "SwiftailEngine"],
            resources: [.copy("Fixtures")]
        ),
    ],
    swiftLanguageModes: [.v6]
)
