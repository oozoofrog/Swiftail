// swift-tools-version: 6.0
import PackageDescription

let package = Package(
    name: "Swiftail",
    platforms: [.iOS(.v18), .macOS(.v15)],
    products: [
        .library(name: "SwiftailCrypto", targets: ["SwiftailCrypto"]),
    ],
    targets: [
        .target(name: "SwiftailCrypto"),
        .testTarget(
            name: "SwiftailCryptoTests",
            dependencies: ["SwiftailCrypto"],
            resources: [.copy("Vectors")]
        ),
    ],
    swiftLanguageModes: [.v6]
)
