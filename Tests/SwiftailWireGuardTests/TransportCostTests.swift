// 전송 패킷 경로의 비용 기록. 시간은 단언하지 않는다: 릴리스 빌드에서 돌려 값을 읽는 용도다.
//
//     eyebuild swift <용도> -- test -c release -Xswiftc -enable-testing --filter TransportCostTests

import Foundation
import Testing

import SwiftailBase
@testable import SwiftailWireGuard

struct TransportCostTests {
    /// 메모리에서 이어진 장치 둘 사이로 1,280바이트 IP 패킷의 `send`(seal)와 `receive`(open) 한 번의 평균 시간.
    /// 패딩이 없는 크기이고, 데이터그램은 미리 만들어 두어 두 시간을 따로 잰다.
    @Test func sealAndOpenOf1280ByteDatagrams() throws {
        var pair = Pair()
        try pair.establish()
        let bob = pair.key(.bob)
        let packet = pair.packet(from: .alice, payload: [UInt8](repeating: 0x5A, count: 1280 - 20))
        #expect(packet.count == 1280)

        let count = 4000
        let rounds = 11
        var sealMicroseconds: [Double] = []
        var openMicroseconds: [Double] = []
        for _ in 0..<rounds {
            var alice = pair.alice
            var datagrams: [[UInt8]] = []
            datagrams.reserveCapacity(count)
            let sealed = try ContinuousClock().measure {
                for _ in 0..<count {
                    datagrams += try alice.send(packet, to: bob, at: t0).datagrams
                }
            }
            #expect(datagrams.count == count)

            var receiver = pair.bob
            var delivered = 0
            let opened = try ContinuousClock().measure {
                for datagram in datagrams {
                    delivered += try receiver.receive(datagram, at: t0).ipPackets.count
                }
            }
            #expect(delivered == count)
            sealMicroseconds.append(sealed.microseconds / Double(count))
            openMicroseconds.append(opened.microseconds / Double(count))
        }
        let seals = sealMicroseconds.sorted()
        let opens = openMicroseconds.sorted()
        print(
            "TransportCost 1280B seal(send) 최소 \(String(format: "%.2f", seals[0]))µs 중앙값 \(String(format: "%.2f", seals[rounds / 2]))µs, "
                + "open(receive) 최소 \(String(format: "%.2f", opens[0]))µs 중앙값 \(String(format: "%.2f", opens[rounds / 2]))µs (\(rounds)회 × \(count)개)"
        )
    }

    /// 피어 수만큼의 비용: `nextDeadline`과 기한이 지난 것이 없는 `advance(to:)` 한 번의 평균 시간.
    @Test func deadlineQueriesWithManyPeers() throws {
        var pair = Pair()
        try pair.establish()
        for index in 0..<63 {
            let key = WireGuardDevice(privateKey: .init(), now: t0, wallClock: Date(timeIntervalSince1970: 1_800_000_000)).publicKey
            pair.alice.addPeer(key, allowedIPs: [IPPrefix("100.64.1.\(index + 1)/32")].compactMap { $0 })
        }
        let count = 20000
        var alice = pair.alice
        var sink = 0
        let deadline = ContinuousClock().measure {
            for _ in 0..<count {
                sink &+= alice.nextDeadline == nil ? 0 : 1
            }
        }
        let advance = ContinuousClock().measure {
            for _ in 0..<count {
                sink &+= alice.advance(to: t0).count
            }
        }
        print("TransportCost 피어 64명 nextDeadline \(String(format: "%.3f", deadline.microseconds / Double(count)))µs, advance(만료 없음) \(String(format: "%.3f", advance.microseconds / Double(count)))µs (\(sink))")
    }
}

private extension Duration {
    var microseconds: Double {
        Double(components.seconds) * 1_000_000 + Double(components.attoseconds) / 1_000_000_000_000
    }
}
