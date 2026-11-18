// Contract test 3 covers the replay protection window.
//
// Origin is wireguard-go `replay/replay_test.go`
// (github.com/tailscale/wireguard-go v0.0.0-20261106233718-9e0ab45c16ca). The original is a port of the Linux kernel implementation's test.
// The 34 fixed cases and 6 bulk cases preserve their original order and expected results.
//
// SPDX-License-Identifier: MIT
// Copyright (C) 2017-2023 WireGuard LLC. All Rights Reserved.
//
// Permission is hereby granted, free of charge, to any person obtaining a copy of this software and
// associated documentation files (the "Software"), to deal in the Software without restriction,
// including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense,
// and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so,
// subject to the following conditions: The above copyright notice and this permission notice shall be
// included in all copies or substantial portions of the Software.
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED.

import Testing

@testable import SwiftailWireGuard

@Suite("Replay protection window")
struct ReplayFilterTests {
    private static let rejectAfterMessages: UInt64 = .max - (1 << 13)
    private static let windowSize = ReplayFilter.windowSize

    @Test("Constants match wireguard-go")
    func constants() {
        #expect(Self.windowSize == 8128)
        #expect(Self.rejectAfterMessages == Constants.rejectAfterMessages)
    }

    @Test("34 fixed cases")
    func fixedSequence() {
        let limit = Self.windowSize + 1 // T_LIM
        let reject = Self.rejectAfterMessages
        let cases: [(counter: UInt64, accepted: Bool)] = [
            (0, true),                        //  1
            (1, true),                        //  2
            (1, false),                       //  3
            (9, true),                        //  4
            (8, true),                        //  5
            (7, true),                        //  6
            (7, false),                       //  7
            (limit, true),                    //  8
            (limit - 1, true),                //  9
            (limit - 1, false),               // 10
            (limit - 2, true),                // 11
            (2, true),                        // 12
            (2, false),                       // 13
            (limit + 16, true),               // 14
            (3, false),                       // 15
            (limit + 16, false),              // 16
            (limit * 4, true),                // 17
            (limit * 4 - (limit - 1), true),  // 18
            (10, false),                      // 19
            (limit * 4 - limit, false),       // 20
            (limit * 4 - (limit + 1), false), // 21
            (limit * 4 - (limit - 2), true),  // 22
            (limit * 4 + 1 - limit, false),   // 23
            (0, false),                       // 24
            (reject, false),                  // 25
            (reject - 1, true),               // 26
            (reject, false),                  // 27
            (reject - 1, false),              // 28
            (reject - 2, true),               // 29
            (reject + 1, false),              // 30
            (reject + 2, false),              // 31
            (reject - 2, false),              // 32
            (reject - 3, true),               // 33
            (0, false),                       // 34
        ]
        var filter = ReplayFilter()
        for (number, testCase) in cases.enumerated() {
            let accepted = filter.accept(testCase.counter, limit: reject)
            #expect(accepted == testCase.accepted, "Case \(number + 1): counter \(testCase.counter)")
        }
    }

    @Test("bulk 1: 1 through window size in order, then 0")
    func bulk1() {
        var filter = ReplayFilter()
        expectAll(&filter, 1...Self.windowSize)
        #expect(accept(&filter, 0))
        #expect(!accept(&filter, 0))
    }

    @Test("bulk 2: 2 through window+1 in order, then 1 and 0")
    func bulk2() {
        var filter = ReplayFilter()
        expectAll(&filter, 2...(Self.windowSize + 1))
        #expect(accept(&filter, 1))
        #expect(!accept(&filter, 0))
    }

    @Test("bulk 3: window+1 down to 1")
    func bulk3() {
        var filter = ReplayFilter()
        expectAll(&filter, (1...(Self.windowSize + 1)).reversed())
    }

    @Test("bulk 4: window+2 down to 2, then 0")
    func bulk4() {
        var filter = ReplayFilter()
        expectAll(&filter, (2...(Self.windowSize + 2)).reversed())
        #expect(!accept(&filter, 0))
    }

    @Test("bulk 5: window down to 1, window+1, then 0")
    func bulk5() {
        var filter = ReplayFilter()
        expectAll(&filter, (1...Self.windowSize).reversed())
        #expect(accept(&filter, Self.windowSize + 1))
        #expect(!accept(&filter, 0))
    }

    @Test("bulk 6: window down to 1, 0, then window+1")
    func bulk6() {
        var filter = ReplayFilter()
        expectAll(&filter, (1...Self.windowSize).reversed())
        #expect(accept(&filter, 0))
        #expect(accept(&filter, Self.windowSize + 1))
    }

    /// Extracts the result because #expect cannot use a mutating call.
    private func accept(_ filter: inout ReplayFilter, _ counter: UInt64) -> Bool {
        filter.accept(counter, limit: Self.rejectAfterMessages)
    }

    /// Requires acceptance of every counter and reports only the first rejected counter on failure.
    private func expectAll(_ filter: inout ReplayFilter, _ counters: some Sequence<UInt64>) {
        let rejected = counters.first { !filter.accept($0, limit: Self.rejectAfterMessages) }
        #expect(rejected == nil, "Rejected counter: \(String(describing: rejected))")
    }
}
