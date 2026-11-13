// 키를 쥔 값이 `print`·`debugPrint`·`dump`로 새지 않는지 본다.
//
// `CustomStringConvertible`만으로는 `dump`를 가리지 못한다(`dump`는 Mirror로 저장 프로퍼티를 훑는다).
// 그래서 키를 쥔 공개 타입은 `CustomReflectable`로 자식을 감춘다.

import CryptoKit
import Foundation
import Testing

@testable import SwiftailControl

@Suite("비밀이 드러나지 않는 출력")
struct SecretReflectionTests {
    private typealias V = TransportVectors

    /// `String(describing:)`, `String(reflecting:)`, `dump`의 출력을 이어 붙인다.
    private func renderings(of value: Any) -> String {
        var dumped = ""
        dump(value, to: &dumped)
        return String(describing: value) + "\n" + String(reflecting: value) + "\n" + dumped
    }

    @Test("핸드셰이크 상태는 키 재료를 드러내지 않는다")
    func handshake() throws {
        let output = renderings(of: try V.handshake())
        // 배열 원소나 키 바이트가 한 줄씩 찍히지 않는다.
        #expect(!output.contains("chainingKey"))
        #expect(!output.contains("machineKey"))
        #expect(!output.contains("ephemeral"))
        #expect(output.split(separator: "\n").count <= 3)
    }

    @Test("전송 세션은 키를 드러내지 않는다")
    func session() throws {
        let output = renderings(of: try V.clientSession())
        #expect(!output.contains("key"))
        #expect(output.split(separator: "\n").count <= 3)
    }

    @Test("설정은 인증 키를 드러내지 않는다")
    func configuration() throws {
        let secret = "tskey-auth-EXAMPLE-0000"
        let configuration = ControlClient.Configuration(
            serverURL: try #require(URL(string: "http://127.0.0.1:9911")),
            hostname: "rd-mac-1a2b3c4d",
            authKey: secret
        )
        let output = renderings(of: configuration)
        #expect(!output.contains(secret))
        #expect(output.contains("rd-mac-1a2b3c4d"))
    }
}
