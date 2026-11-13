// 계약 시험 3: 재전송 방지 창.
//
// 출처: wireguard-go `replay/replay_test.go`
// (github.com/tailscale/wireguard-go v0.0.0-20261106233718-9e0ab45c16ca). 원본은 Linux 커널 구현의 시험을 옮긴 것이다.
// 34개 고정 사례와 bulk 사례 6개를 순서와 기대값 그대로 옮겼다.
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

@Suite("재전송 방지 창")
struct ReplayFilterTests {
    private static let rejectAfterMessages: UInt64 = .max - (1 << 13)
    private static let windowSize = ReplayFilter.windowSize

    @Test("상수는 wireguard-go와 같다")
    func constants() {
        #expect(Self.windowSize == 8128)
        #expect(Self.rejectAfterMessages == Constants.rejectAfterMessages)
    }

    @Test("고정 사례 34개")
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
            #expect(accepted == testCase.accepted, "사례 \(number + 1): counter \(testCase.counter)")
        }
    }

    @Test("bulk 1: 1...창 크기를 차례로, 그다음 0")
    func bulk1() {
        var filter = ReplayFilter()
        expectAll(&filter, 1...Self.windowSize)
        #expect(accept(&filter, 0))
        #expect(!accept(&filter, 0))
    }

    @Test("bulk 2: 2...창+1을 차례로, 그다음 1과 0")
    func bulk2() {
        var filter = ReplayFilter()
        expectAll(&filter, 2...(Self.windowSize + 1))
        #expect(accept(&filter, 1))
        #expect(!accept(&filter, 0))
    }

    @Test("bulk 3: 창+1에서 1까지 거꾸로")
    func bulk3() {
        var filter = ReplayFilter()
        expectAll(&filter, (1...(Self.windowSize + 1)).reversed())
    }

    @Test("bulk 4: 창+2에서 2까지 거꾸로, 그다음 0")
    func bulk4() {
        var filter = ReplayFilter()
        expectAll(&filter, (2...(Self.windowSize + 2)).reversed())
        #expect(!accept(&filter, 0))
    }

    @Test("bulk 5: 창에서 1까지 거꾸로, 창+1, 그다음 0")
    func bulk5() {
        var filter = ReplayFilter()
        expectAll(&filter, (1...Self.windowSize).reversed())
        #expect(accept(&filter, Self.windowSize + 1))
        #expect(!accept(&filter, 0))
    }

    @Test("bulk 6: 창에서 1까지 거꾸로, 0, 그다음 창+1")
    func bulk6() {
        var filter = ReplayFilter()
        expectAll(&filter, (1...Self.windowSize).reversed())
        #expect(accept(&filter, 0))
        #expect(accept(&filter, Self.windowSize + 1))
    }

    /// #expect 안에서는 mutating 호출을 쓸 수 없어 결과만 꺼낸다.
    private func accept(_ filter: inout ReplayFilter, _ counter: UInt64) -> Bool {
        filter.accept(counter, limit: Self.rejectAfterMessages)
    }

    /// 모든 counter가 받아들여져야 한다. 실패하면 첫 counter만 알린다.
    private func expectAll(_ filter: inout ReplayFilter, _ counters: some Sequence<UInt64>) {
        let rejected = counters.first { !filter.accept($0, limit: Self.rejectAfterMessages) }
        #expect(rejected == nil, "거절된 counter: \(String(describing: rejected))")
    }
}
