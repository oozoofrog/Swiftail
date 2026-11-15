// 판정 규칙은 tailscale.com v1.104.6 `net/tlsdial/tlsdial.go`의 `SetConfigExpectedCert`·`SetConfigExpectedCertHash`,
// `derp/derpconst/derpconst.go`, Go 1.27.3 `crypto/tls/handshake_client.go`의 `hostnameInSNI`를 따랐다
// (tailscale: Copyright (c) Tailscale Inc & contributors, BSD-3-Clause. Go: Copyright The Go Authors, BSD-3-Clause).

import CryptoKit
import Foundation
import Security
import SwiftailBase

/// TLS 서버가 낸 인증서 목록의 판정. 연결 없이 DER 목록·이름·시각만으로 본다.
///
/// `NetworkSocket.TLS`의 `.named`·`.pinned`가 TLS 검증 블록에서 부르고, 시험은 고정 인증서로 직접 부른다
/// (계약 `docs/contracts/SwiftailDERP.md` "M8 ③" 동작 V).
package enum ServerCertificate {
    /// 판정이 받지 않은 까닭. 이름·키·해시를 담지 않는다.
    package enum Failure: Error, Sendable, Equatable {
        /// 서버가 인증서를 내지 않았거나, X.509로 읽히지 않는 것이 있다.
        case unparsable
        /// meta 인증서를 뺀 인증서가 하나도 없다.
        case noCandidate
        /// meta 인증서를 뺀 인증서가 둘 이상이다.
        case multipleCandidates
        /// 그 하나가 첫 자리가 아니다. TLS 핸드셰이크가 키 소유를 증명하는 것은 첫 인증서뿐이다.
        case candidateNotLeaf
        /// 그 하나의 SHA-256이 고정 값과 다르다.
        case hashMismatch
        /// `SecTrust`가 받지 않았다: 이름, 유효 기간, 사슬 가운데 하나. `status`는 Security의 오류 코드다.
        case untrusted(status: Int)
    }

    /// DERP 서버가 덧붙이는 meta 인증서의 주체 CN 머리(Go `derpconst.MetaCertCommonNamePrefix`).
    static let metaCommonNamePrefix = "derpkey"

    /// `sha256-raw:` 고정의 판정(Go `SetConfigExpectedCertHash`).
    ///
    /// 주체 CN이 `derpkey`로 시작하는 meta 인증서를 뺀 나머지가 정확히 하나여야 하고, 그 하나는
    /// ⓪ 목록의 첫 자리에 있고 ① DER 전체의 SHA-256을 소문자 16진으로 쓴 것이 `sha256Hex`와 글자 그대로 같고
    /// ② `serverName`이 SNI로 나가는 이름이면(IP 리터럴이 아니면) 그 이름에 유효하고 ③ `now`가 유효 기간 안이어야 한다.
    /// 사슬은 보지 않는다.
    ///
    /// ⓪은 Go에 없는 조건이다. TLS 핸드셰이크는 첫 인증서의 키만 증명하므로, Go처럼 자리를 보지 않으면 누구나 받아 볼 수
    /// 있는 고정 인증서를 자기 키의 `derpkey…` 인증서 뒤에 붙여 낸 서버도 통과한다. derper는 서버 인증서를 첫 자리에,
    /// meta 인증서를 그 뒤에 내므로(`derpserver.ModifyTLSConfigToAddMetaCert`) 정상 서버는 걸리지 않는다.
    ///
    /// ②③은 `SecTrust`가 본다: 그 인증서만 앵커로 두고, 이름이 있으면 SSL 서버 정책으로, 없으면 기본 X.509 정책으로
    /// 평가한다. SSL 서버 정책에는 Go가 보지 않는 Apple의 TLS 서버 인증서 조건이 함께 걸린다(서버 인증 EKU, 825일 이하의
    /// 유효 기간, RSA 2048비트 이상, Ed25519 키 안 됨 등). derper가 IP 주소에 스스로 만드는 인증서는 이 조건을 지킨다.
    // shortcut: 이름으로 붙는 DERP에 운영자가 직접 만든 자체 서명 인증서(EKU 없음, 10년짜리 등)를 고정한 경우 Go는 붙고
    // 여기서는 거절한다. 이름과 기간을 직접 보려면 X.509의 SAN 해석이 필요하다. 필요해지는 시점: 그런 DERP에 붙어야 할 때.
    ///
    /// - Parameters:
    ///   - certificates: 서버가 낸 순서의 DER 인증서들.
    ///   - serverName: TLS 서버 이름(DERP의 `hostName`).
    package static func checkPinned(
        _ certificates: [[UInt8]], sha256Hex: String, serverName: String, at now: Date
    ) throws(Failure) {
        let parsed = try parse(certificates)
        let candidates = parsed.filter { !isMeta($0.ref) }
        guard let candidate = candidates.first else { throw .noCandidate }
        guard candidates.count == 1 else { throw .multipleCandidates }
        guard !isMeta(parsed[0].ref) else { throw .candidateNotLeaf }
        // 공개된 인증서의 해시라 비밀이 아니다. 상수 시간 비교가 필요 없다.
        guard Array(SHA256.hash(data: candidate.der)).hex == sha256Hex else { throw .hashMismatch }
        try evaluate([candidate.ref], name: sniHostName(serverName), at: now, anchors: [candidate.ref], fetch: false)
    }

    /// 이름을 따로 정한 시스템 검증의 판정(Go `SetConfigExpectedCert`).
    ///
    /// 첫 인증서를 leaf로, 나머지를 사슬을 이을 후보로 두고 `name`에 대해 SSL 서버 정책으로 평가한다. Go와 달리 내장
    /// Let's Encrypt 루트로 다시 보지 않는다(시스템 저장소에 그 루트가 있다).
    ///
    /// - Parameter anchors: nil이면 시스템 신뢰 저장소. 시험은 자기 루트만 믿게 DER을 준다.
    package static func checkNamed(
        _ certificates: [[UInt8]], name: String, at now: Date, anchors: [[UInt8]]? = nil
    ) throws(Failure) {
        let parsed = try parse(certificates)
        let anchorRefs = try anchors.map { anchors throws(Failure) in try parse(anchors).map(\.ref) }
        try evaluate(parsed.map(\.ref), name: name, at: now, anchors: anchorRefs, fetch: true)
    }

    /// TLS ClientHello의 SNI로 나가는 이름(Go `hostnameInSNI`). IP 리터럴이면 nil, 끝의 점은 뗀다.
    ///
    /// Go의 `sha256-raw:` 판정은 이 값이 비면 이름을 보지 않는다(IP로 derper에 붙는 경우).
    package static func sniHostName(_ name: String) -> String? {
        var host = Substring(name)
        if host.count > 1, host.first == "[", host.last == "]" { host = host.dropFirst().dropLast() }
        if let zone = host.lastIndex(of: "%"), zone > host.startIndex { host = host[..<zone] }
        if IPAddress(String(host)) != nil { return nil }
        var result = Substring(name)
        while result.last == "." { result = result.dropLast() }
        return result.isEmpty ? nil : String(result)
    }

    /// 주체 CN이 meta 인증서의 머리로 시작하는지. CN이 없으면 meta가 아니다(Go에서도 빈 CN은 머리로 시작하지 않는다).
    private static func isMeta(_ certificate: SecCertificate) -> Bool {
        var commonName: CFString?
        guard SecCertificateCopyCommonName(certificate, &commonName) == errSecSuccess, let commonName else { return false }
        return (commonName as String).hasPrefix(metaCommonNamePrefix)
    }

    private static func parse(_ certificates: [[UInt8]]) throws(Failure) -> [(der: [UInt8], ref: SecCertificate)] {
        guard !certificates.isEmpty else { throw .unparsable }
        return try certificates.map { der throws(Failure) in
            guard let ref = SecCertificateCreateWithData(nil, Data(der) as CFData) else { throw .unparsable }
            return (der, ref)
        }
    }

    /// `SecTrustEvaluateWithError`는 부른 스레드를 막는다. TLS 검증 블록의 큐에서 부른다.
    private static func evaluate(
        _ certificates: [SecCertificate], name: String?, at now: Date, anchors: [SecCertificate]?, fetch: Bool
    ) throws(Failure) {
        var created: SecTrust?
        let policy = name.map { SecPolicyCreateSSL(true, $0 as CFString) } ?? SecPolicyCreateBasicX509()
        try check(SecTrustCreateWithCertificates(certificates as CFArray, policy, &created))
        guard let trust = created else { throw .untrusted(status: Int(errSecParam)) }
        try check(SecTrustSetVerifyDate(trust, now as CFDate))
        if !fetch { try check(SecTrustSetNetworkFetchAllowed(trust, false)) }
        if let anchors {
            try check(SecTrustSetAnchorCertificates(trust, anchors as CFArray))
            try check(SecTrustSetAnchorCertificatesOnly(trust, true))
        }
        var error: CFError?
        guard SecTrustEvaluateWithError(trust, &error) else {
            throw .untrusted(status: error.map { CFErrorGetCode($0) } ?? Int(errSecNotTrusted))
        }
    }

    private static func check(_ status: OSStatus) throws(Failure) {
        guard status == errSecSuccess else { throw .untrusted(status: Int(status)) }
    }
}
