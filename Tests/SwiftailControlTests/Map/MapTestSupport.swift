import Foundation
import SwiftailBase

@testable import SwiftailControl

/// JSON 문자열을 맵 응답으로 해독한다.
func mapResponse(_ json: String) throws -> MapResponse {
    try JSONDecoder().decode(MapResponse.self, from: Data(json.utf8))
}

/// 시험용 피어 JSON. ID마다 이름·사용자·주소가 다르다. extra는 `,"Key":…`처럼 쉼표로 시작한다.
func peerJSON(_ id: Int64, _ extra: String = "") -> String {
    #"{"ID":\#(id),"Name":"peer\#(id).tail0001.ts.net.","User":\#(100 + id),"Addresses":["100.64.0.\#(id)/32"]\#(extra)}"#
}

/// 시험용 self 노드 JSON.
let selfNodeJSON = #"{"ID":1,"Name":"rd-mac-1a2b3c4d.tail0001.ts.net.","User":100,"Addresses":["100.64.0.1/32"],"MachineAuthorized":true}"#

/// 같은 바이트 32개로 만든 키 텍스트. prefix는 `"nodekey:"` 같은 접두사.
func keyText(_ prefix: String, byte: UInt8) -> String {
    prefix + [UInt8](repeating: byte, count: 32).hex
}

/// 4바이트 리틀엔디언 길이 + 페이로드.
func frame(_ payload: [UInt8]) -> [UInt8] {
    let length = UInt32(payload.count)
    return (0..<4).map { UInt8(truncatingIfNeeded: length >> (8 * $0)) } + payload
}

func frame(_ json: String) -> [UInt8] {
    frame(Array(json.utf8))
}

/// 인코딩 결과를 키 순서와 무관하게 비교하려고 Foundation 객체로 바꾼다.
func jsonObject(_ data: Data) throws -> NSDictionary {
    guard let object = try JSONSerialization.jsonObject(with: data) as? NSDictionary else {
        throw CocoaError(.coderInvalidValue)
    }
    return object
}

func jsonObject(_ text: String) throws -> NSDictionary {
    try jsonObject(Data(text.utf8))
}

/// 고정 시드 의사 난수(SplitMix64). 실패한 입력을 그대로 재현하기 위해 쓴다.
struct SeededRandom: RandomNumberGenerator {
    private var state: UInt64

    init(seed: UInt64) { state = seed }

    mutating func next() -> UInt64 {
        state &+= 0x9E37_79B9_7F4A_7C15
        var value = state
        value = (value ^ (value >> 30)) &* 0xBF58_476D_1CE4_E5B9
        value = (value ^ (value >> 27)) &* 0x94D0_49BB_1331_11EB
        return value ^ (value >> 31)
    }
}
