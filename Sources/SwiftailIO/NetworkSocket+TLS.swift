import Foundation
import Network
import Security

extension NetworkSocket {
    /// 연결에 얹을 TLS.
    package enum TLS: Sendable, Equatable {
        /// 평문 TCP.
        case none
        /// 시스템 신뢰 저장소로 서버 인증서를 검증한다. `serverName`은 SNI이자 검증하는 이름이다.
        case system(serverName: String)
        /// 시스템 신뢰 저장소로 사슬을 검증하되 인증서의 이름은 `certificateName`으로 본다. `serverName`은 SNI로만
        /// 보낸다(DERP 노드의 `CertName`이 `HostName`과 다를 때, Go `SetConfigExpectedCert`).
        case named(serverName: String, certificateName: String)
        /// 서버가 낸 인증서 가운데 meta 인증서를 뺀 하나의 SHA-256이 `sha256Hex`와 같아야 한다. 사슬은 검증하지 않는다
        /// (DERP 노드의 `CertName`이 `sha256-raw:`일 때, Go `SetConfigExpectedCertHash`). 판정은
        /// `ServerCertificate.checkPinned`다.
        case pinned(serverName: String, sha256Hex: String)
        /// 서버 인증서를 검증하지 않는다. **시험 서버 전용이다.** 서버를 알아볼 수 없으므로 실제 서버에 쓰면
        /// 중간자 공격을 막지 못한다. `serverName`은 SNI로만 보낸다.
        case insecureForTests(serverName: String)

        /// `NWParameters`에 넘길 TLS 옵션. 평문이면 nil.
        var options: NWProtocolTLS.Options? {
            switch self {
            case .none:
                return nil
            case .system(let serverName):
                return Self.options(serverName: serverName, verify: nil)
            case .named(let serverName, let certificateName):
                return Self.options(serverName: serverName) { certificates in
                    do throws(ServerCertificate.Failure) {
                        try ServerCertificate.checkNamed(certificates, name: certificateName, at: Date())
                        return true
                    } catch {
                        return false
                    }
                }
            case .pinned(let serverName, let sha256Hex):
                return Self.options(serverName: serverName) { certificates in
                    do throws(ServerCertificate.Failure) {
                        try ServerCertificate.checkPinned(certificates, sha256Hex: sha256Hex, serverName: serverName, at: Date())
                        return true
                    } catch {
                        return false
                    }
                }
            case .insecureForTests(let serverName):
                // 서버가 낸 인증서가 무엇이든 통과시킨다.
                return Self.options(serverName: serverName) { _ in true }
            }
        }

        /// `verify`가 있으면 플랫폼의 검증 대신 그것이 서버가 낸 순서의 DER 인증서들로 판정한다.
        private static func options(
            serverName: String, verify: (@Sendable ([[UInt8]]) -> Bool)?
        ) -> NWProtocolTLS.Options {
            let options = NWProtocolTLS.Options()
            // Network 프레임워크는 끝에 점이 있는 이름에 SNI를 보내지 않는다. Go는 점을 떼고 보낸다(`hostnameInSNI`).
            sec_protocol_options_set_tls_server_name(
                options.securityProtocolOptions, ServerCertificate.sniHostName(serverName) ?? serverName
            )
            if let verify {
                // 재개된 세션에서는 검증 블록이 불리지 않는다(실험으로 확인). 판정이 연결마다 돌게 재개를 끈다.
                sec_protocol_options_set_tls_resumption_enabled(options.securityProtocolOptions, false)
                sec_protocol_options_set_tls_tickets_enabled(options.securityProtocolOptions, false)
                sec_protocol_options_set_verify_block(
                    options.securityProtocolOptions,
                    { metadata, _, complete in
                        var certificates: [[UInt8]] = []
                        let accessed = sec_protocol_metadata_access_peer_certificate_chain(metadata) { certificate in
                            certificates.append([UInt8](SecCertificateCopyData(sec_certificate_copy_ref(certificate).takeRetainedValue()) as Data))
                        }
                        complete(accessed && verify(certificates))
                    },
                    // 판정이 `SecTrustEvaluateWithError`로 큐를 막으므로 연결마다 따로 둔다.
                    DispatchQueue(label: "Swiftail.NetworkSocket.verify")
                )
            }
            return options
        }
    }
}
