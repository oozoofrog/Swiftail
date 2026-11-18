import Foundation
import SwiftailBase

@testable import SwiftailControl

/// Decodes a JSON string as a map response.
func mapResponse(_ json: String) throws -> MapResponse {
    try JSONDecoder().decode(MapResponse.self, from: Data(json.utf8))
}

/// Test peer JSON. The name, user, and address differ by ID. extra begins with a comma, as in `,"Key":…`.
func peerJSON(_ id: Int64, _ extra: String = "") -> String {
    #"{"ID":\#(id),"Name":"peer\#(id).tail0001.ts.net.","User":\#(100 + id),"Addresses":["100.64.0.\#(id)/32"]\#(extra)}"#
}

/// Test self-node JSON.
let selfNodeJSON = #"{"ID":1,"Name":"rd-mac-1a2b3c4d.tail0001.ts.net.","User":100,"Addresses":["100.64.0.1/32"],"MachineAuthorized":true}"#

/// Key text made of 32 copies of the same byte. prefix is a prefix such as `"nodekey:"`.
func keyText(_ prefix: String, byte: UInt8) -> String {
    prefix + [UInt8](repeating: byte, count: 32).hex
}

/// 4-byte little-endian length + payload.
func frame(_ payload: [UInt8]) -> [UInt8] {
    let length = UInt32(payload.count)
    return (0..<4).map { UInt8(truncatingIfNeeded: length >> (8 * $0)) } + payload
}

func frame(_ json: String) -> [UInt8] {
    frame(Array(json.utf8))
}

/// Converts the encoded result to a Foundation object for comparison independent of key order.
func jsonObject(_ data: Data) throws -> NSDictionary {
    guard let object = try JSONSerialization.jsonObject(with: data) as? NSDictionary else {
        throw CocoaError(.coderInvalidValue)
    }
    return object
}

func jsonObject(_ text: String) throws -> NSDictionary {
    try jsonObject(Data(text.utf8))
}

/// Fixed-seed pseudorandom generator (SplitMix64). Used to reproduce failing inputs exactly.
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

/// The time the test "received" the response.
let receivedAt = Date(timeIntervalSince1970: 1_800_000_000)
