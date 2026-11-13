import CryptoKit
import Foundation
import SwiftailBase

extension Hostinfo {
    /// Swiftail 노드가 등록·상태 올리기에 보내는 최소 Hostinfo.
    ///
    /// - `Hostname`: 설정의 호스트 이름. testcontrol은 이것을 노드 이름으로 쓴다.
    /// - `OS`·`OSVersion`: 실제 OS(Go와 같은 `macOS`·`iOS` 표기).
    /// - `IPNVersion`·`App`: Swiftail임을 드러낸다. 공식 클라이언트 버전으로 가장하지 않는다.
    ///   버전 해석기가 받도록 semver 모양(`0.0.0-swiftail`)을 쓴다.
    /// - `BackendLogID`: Go 클라이언트는 빈 값을 거부한다. 로그를 올리지 않으므로 machine 공개 키에서 유도한,
    ///   비밀이 아닌 고정값을 쓴다.
    /// - `Userspace`: 커널 장치가 아닌 사용자 공간 구현이다.
    ///
    /// `docs/protocol-notes/control-map.md` 3.3, 계약 단위 4 동작 6.
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
