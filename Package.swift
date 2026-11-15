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
        // 서버 노릇을 하는 앱만 쓰는 선택 제품(M7). iOS 터널 확장은 링크하지 않는다.
        .library(name: "SwiftailCertificates", targets: ["SwiftailCertificates"]),
        .library(name: "SwiftailLoopback", targets: ["SwiftailLoopback"]),
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
        // 제품으로 내보내지 않는다. Tailnet Lock(TKA)의 자료 형식과 검증이다. 소켓·파일·시계가 없다.
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
            dependencies: ["SwiftailControl", "SwiftailBase", "SwiftailCrypto", "SwiftailHTTP2"],
            resources: [.copy("Fixtures")]
        ),
        // 제품으로 내보내지 않는다. 소켓을 여는 타깃(Control, DERP, Swiftail)이 쓰는 가장자리 입출력 부품이다.
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
            dependencies: ["Swiftail", "SwiftailBase", "SwiftailControl", "SwiftailMagicsock", "SwiftailCertificates", "SwiftailLoopback"]
        ),
        // ts.net 인증서의 발급·저장·갱신(ACME DNS-01). CryptoKit, Security, Foundation의 URLSession을 쓴다.
        .target(name: "SwiftailCertificates", dependencies: ["Swiftail", "SwiftailBase", "SwiftailControl"]),
        .testTarget(
            name: "SwiftailCertificatesTests",
            dependencies: ["SwiftailCertificates", "Swiftail", "SwiftailBase"],
            resources: [.copy("Fixtures")]
        ),
        // tailnet 연결을 127.0.0.1의 OS TCP 리스너에 잇는 다리.
        .target(name: "SwiftailLoopback", dependencies: ["Swiftail", "SwiftailBase", "SwiftailCrypto", "SwiftailIO"]),
        .testTarget(name: "SwiftailLoopbackTests", dependencies: ["SwiftailLoopback", "Swiftail", "SwiftailBase", "SwiftailIO", "SwiftailControl", "SwiftailEngine"]),
    ],
    swiftLanguageModes: [.v6]
)
