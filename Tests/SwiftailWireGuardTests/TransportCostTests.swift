// Records the cost of the transport packet path. There are no timing assertions. Run a release build to read the measurements.
//
//     eyebuild swift <purpose> -- test -c release -Xswiftc -enable-testing --filter TransportCostTests

import Foundation
import Testing

import SwiftailBase
@testable import SwiftailWireGuard

struct TransportCostTests {
    /// Measures the mean time per `send` (seal) and `receive` (open) for a 1,280-byte IP packet between devices connected in memory.
    /// This size needs no padding. Datagrams are prepared in advance to measure the two times separately.
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
            "TransportCost 1280B seal(send) minimum \(String(format: "%.2f", seals[0]))µs median \(String(format: "%.2f", seals[rounds / 2]))µs, "
                + "open(receive) minimum \(String(format: "%.2f", opens[0]))µs median \(String(format: "%.2f", opens[rounds / 2]))µs (\(rounds) rounds × \(count) packets)"
        )
    }

    /// Measures cost at the given peer count as the mean time per `nextDeadline` and `advance(to:)` call when no deadline has expired.
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
        print("TransportCost 64 peers nextDeadline \(String(format: "%.3f", deadline.microseconds / Double(count)))µs, advance(no expiration) \(String(format: "%.3f", advance.microseconds / Double(count)))µs (\(sink))")
    }
}

private extension Duration {
    var microseconds: Double {
        Double(components.seconds) * 1_000_000 + Double(components.attoseconds) / 1_000_000_000_000
    }
}
