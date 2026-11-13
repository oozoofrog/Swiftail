// 노트 7.3절의 고정 입력 시험 벡터(Go v1.104.6 controlbase를 실행해 얻은 값).
//
// 아래 키는 전부 공개된 시험 전용 고정 값이다. 실제 연결에 쓰지 않는다.
// 개인 키는 연속 바이트열 00..1f·20..3f·40..5f·60..7f에 X25519 clamp를 적용한 것이다.

import CryptoKit
import Testing

import SwiftailBase
@testable import SwiftailControl

enum TransportVectors {
    static let clientMachinePrivate = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e5f"
    static let clientMachinePublic = "8f40c5adb68f25624ae5b214ea767a6ec94d829d3d7b5e1ad1ba6f3e2138285f"
    static let serverStaticPublic = "358072d6365880d1aeea329adf9121383851ed21a28e3b75e965d0d2cd166254"
    static let clientEphemeralPrivate = "404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f"
    static let clientEphemeralPublic = "79a631eede1bf9c98f12032cdeadd0e7a079398fc786b88cc846ec89af85a51a"
    static let serverEphemeralPublic = "675dd574ed7789310b3d2e7681f3790b466c773b1521fecf36577958371ea52f"

    static let initiation = "009401006079a631eede1bf9c98f12032cdeadd0e7a079398fc786b88cc846ec89af85a51aad5b8febedeb97415be53612205e6bfab385e34cb127dd8854c4f9afb10f9b0e635d32b6eacf64ca7ce3a83fdf2f525f62cda6ef940fef0c11064f09a292d01e"
    static let response = "020030675dd574ed7789310b3d2e7681f3790b466c773b1521fecf36577958371ea52fe938fd4935979fcc3489231f7ef4c9c7"

    /// Split k_a(클라이언트 → 서버)와 k_b(서버 → 클라이언트).
    static let clientToServerKey = "b5a6c358cd51a1fc717517315852e009148ee5480cf70a3caf4d4f9498c9ca8e"
    static let serverToClientKey = "d8ebca0df9236e3c51fcc4e5d506d473b019dd191d7ac7112d1e046898a1e78d"

    /// 클라이언트 → 서버 레코드. 카운터 0, 1, 2, 3(빈 평문), 4.
    static let clientRecords: [(plaintext: String, record: String)] = [
        ("client-0", "0400184d8db142648da2b8ceb16a43dbdb67e57ba92f2c667e173e"),
        ("client-1", "040018848768a068cbdd2364ed56d8293a3f5264a340bdf735bb5a"),
        ("client-2", "0400186f62b5bf6af70eaae2e7bd9d858d139300bdedcb660f97df"),
        ("", "04001002e188736cdfc5af317a26b1fed85ca0"),
        ("after-empty", "04001b8a5c4fe32e73ff64383e91d49bec27571d8e198737eae631cbd94a"),
    ]

    /// 서버 → 클라이언트 레코드. 카운터 0, 1, 2.
    static let serverRecords: [(plaintext: String, record: String)] = [
        ("server-0", "040018775de2b464bfc78e7ed71c2598a5bf25f9c23ad37efcd53e"),
        ("server-1", "040018a0b7204f4127b4280c93761eceed2305f8f1ec9fa93d8760"),
        ("server-2", "0400180096fa0ae79135bea550c3d6d6a63c427e2b5eb1980579f4"),
    ]

    /// 벡터의 키와 임시 키로 만든 초기자.
    static func handshake(protocolVersion: UInt16 = 148) throws -> ControlHandshake {
        try ControlHandshake(
            machineKey: Curve25519.KeyAgreement.PrivateKey(rawRepresentation: bytes(clientMachinePrivate)),
            serverKey: #require(MachinePublicKey(rawValue: bytes(serverStaticPublic))),
            protocolVersion: protocolVersion,
            ephemeral: Curve25519.KeyAgreement.PrivateKey(rawRepresentation: bytes(clientEphemeralPrivate))
        )
    }

    /// 벡터 response로 핸드셰이크를 마친 클라이언트 세션.
    static func clientSession() throws -> ControlSession {
        var handshake = try handshake()
        let result = try handshake.receive(bytes(response))
        return try #require(result).session
    }

    /// 서버 쪽 세션: 클라이언트와 방향이 반대인 키.
    static func serverSession() throws -> ControlSession {
        ControlSession(keys: TransportKeys(
            send: SymmetricKey(data: try bytes(serverToClientKey)),
            receive: SymmetricKey(data: try bytes(clientToServerKey))
        ))
    }

    static func bytes(_ hex: String) throws -> [UInt8] {
        try #require([UInt8](hex: hex))
    }
}
