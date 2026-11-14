import Network

extension NetworkSocket {
    /// 연결에 얹을 TLS.
    package enum TLS: Sendable, Equatable {
        /// 평문 TCP.
        case none
        /// 시스템 신뢰 저장소로 서버 인증서를 검증한다. `serverName`은 SNI이자 검증하는 이름이다.
        case system(serverName: String)
        /// 서버 인증서를 검증하지 않는다. **시험 서버 전용이다.** 서버를 알아볼 수 없으므로 실제 서버에 쓰면
        /// 중간자 공격을 막지 못한다. `serverName`은 SNI로만 보낸다.
        case insecureForTests(serverName: String)

        /// `NWParameters`에 넘길 TLS 옵션. 평문이면 nil.
        var options: NWProtocolTLS.Options? {
            switch self {
            case .none:
                return nil
            case .system(let serverName):
                let options = NWProtocolTLS.Options()
                sec_protocol_options_set_tls_server_name(options.securityProtocolOptions, serverName)
                return options
            case .insecureForTests(let serverName):
                let options = NWProtocolTLS.Options()
                sec_protocol_options_set_tls_server_name(options.securityProtocolOptions, serverName)
                // 인증서 검사 블록이 무조건 통과시킨다.
                sec_protocol_options_set_verify_block(
                    options.securityProtocolOptions,
                    { _, _, complete in complete(true) },
                    DispatchQueue(label: "Swiftail.NetworkSocket.insecureVerify")
                )
                return options
            }
        }
    }
}
