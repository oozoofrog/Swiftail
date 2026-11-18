// TAI64N timestamp layout and nanosecond quantization.
//
// The quantization cases originate from wireguard-go `tai64n/tai64n_test.go` `TestMonotonic`
// (github.com/tailscale/wireguard-go v0.0.0-20261106233718-9e0ab45c16ca).
// SPDX-License-Identifier: MIT, Copyright (C) 2017-2023 WireGuard LLC. All Rights Reserved.
// See the header of ReplayFilterTests.swift for the full license text.

import Foundation
import Testing

@testable import SwiftailWireGuard

@Suite("TAI64N")
struct TAI64NTests {
    @Test("Layout is big-endian (0x400000000000000a + seconds) ‖ big-endian nanoseconds (low 24 bits cleared)")
    func layout() {
        let stamp = TAI64N(sinceUnixEpoch: .seconds(1) + .nanoseconds(0x0123_4567))
        #expect(stamp.bytes == [0x40, 0, 0, 0, 0, 0, 0, 0x0b, 0x01, 0, 0, 0])
        #expect(TAI64N(sinceUnixEpoch: .seconds(-5)).bytes == [0x40, 0, 0, 0, 0, 0, 0, 0x0a, 0, 0, 0, 0])
    }

    @Test(
        "20 ms after time.Unix(0, 123456789) satisfies after, while 10 ms or less does not",
        arguments: [
            (Duration.nanoseconds(10), false),
            (.microseconds(10), false),
            (.milliseconds(1), false),
            (.milliseconds(10), false),
            (.milliseconds(20), true),
        ]
    )
    func whitening(offset: Duration, isAfter: Bool) {
        let start = Duration.nanoseconds(123_456_789)
        #expect((TAI64N(sinceUnixEpoch: start + offset) > TAI64N(sinceUnixEpoch: start)) == isAfter)
    }

    @Test("The device timestamp is wall-clock time plus elapsed time")
    func deviceTimestamp() throws {
        let device = WireGuardDevice(privateKey: .init(), now: t0, wallClock: Date(timeIntervalSince1970: 1_800_000_000))
        #expect(device.timestamp(at: t0 + .seconds(10)) == TAI64N(sinceUnixEpoch: .seconds(1_800_000_010)))
        #expect(device.timestamp(at: t0 + .seconds(5)) > device.timestamp(at: t0))
    }
}
