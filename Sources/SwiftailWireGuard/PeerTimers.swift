// 타이머를 걸고 푸는 규칙은 wireguard-go `device/timers.go`
// (github.com/tailscale/wireguard-go v0.0.0-20261106233718-9e0ab45c16ca)를 옮긴 것이다.
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

/// 한 피어의 타이머 넷과 그 보조 상태.
///
/// 실제 타이머는 없다. 각 타이머는 만료 시각(`ContinuousClock.Instant?`)일 뿐이고, 장치가
/// `advance(to:)`에서 기한이 지난 것을 처리한다. 아래 `…Sent`·`…Received` 함수는 wireguard-go의
/// 같은 이름 함수(`timers*`)를 옮긴 것으로, 패킷이 오갈 때 타이머를 걸고 푼다.
///
/// | 타이머 | 만료 시 |
/// | --- | --- |
/// | retransmitHandshake | initiation 재시도. 18회를 넘으면 포기 |
/// | sendKeepalive | 받은 데이터에 답할 것이 없었으면 keepalive |
/// | newHandshake | 보낸 뒤 답이 없으면 새 핸드셰이크 |
/// | zeroKeyMaterial | 키 재료 전부 삭제 |
///
/// 백서 §6.2–§6.5, `docs/protocol-notes/wireguard.md` "타이머"
/// (출처: wireguard-go `device/timers.go`).
///
/// shortcut: 세션 만료 통지(포크의 sessionExpired)와 persistentKeepalive는 없다. Tailscale은 persistentKeepalive를 끄고, 세션 상태 통지는 M3 엔진이 필요로 할 때 올린다.
struct PeerTimers {
    enum Kind: CaseIterable {
        case retransmitHandshake, sendKeepalive, newHandshake, zeroKeyMaterial
    }

    // 타이머가 넷뿐이라 사전 대신 필드로 둔다. 패킷마다 값을 바꾸므로 할당이 없어야 한다.
    private var retransmitHandshake: ContinuousClock.Instant?
    private var sendKeepalive: ContinuousClock.Instant?
    private var newHandshake: ContinuousClock.Instant?
    private var zeroKeyMaterial: ContinuousClock.Instant?
    /// 이번 핸드셰이크의 재시도 횟수.
    var handshakeAttempts = 0
    /// sendKeepalive가 걸려 있는 동안 데이터를 또 받았다. 만료 뒤 한 번 더 건다.
    var needAnotherKeepalive = false
    /// 만료 직전(165초) rekey initiation을 이미 보냈다.
    var sentLastMinuteHandshake = false

    subscript(kind: Kind) -> ContinuousClock.Instant? {
        get {
            switch kind {
            case .retransmitHandshake: retransmitHandshake
            case .sendKeepalive: sendKeepalive
            case .newHandshake: newHandshake
            case .zeroKeyMaterial: zeroKeyMaterial
            }
        }
        set {
            switch kind {
            case .retransmitHandshake: retransmitHandshake = newValue
            case .sendKeepalive: sendKeepalive = newValue
            case .newHandshake: newHandshake = newValue
            case .zeroKeyMaterial: zeroKeyMaterial = newValue
            }
        }
    }

    /// 가장 이른 만료 시각과 그 타이머. 같은 시각이면 `Kind`의 선언 순서가 앞선 것.
    var earliest: (kind: Kind, deadline: ContinuousClock.Instant)? {
        var result: (kind: Kind, deadline: ContinuousClock.Instant)?
        func consider(_ kind: Kind, _ deadline: ContinuousClock.Instant?) {
            guard let deadline else { return }
            if let best = result, best.deadline <= deadline { return }
            result = (kind, deadline)
        }
        consider(.retransmitHandshake, retransmitHandshake)
        consider(.sendKeepalive, sendKeepalive)
        consider(.newHandshake, newHandshake)
        consider(.zeroKeyMaterial, zeroKeyMaterial)
        return result
    }

    /// 인증된 데이터 패킷(keepalive 아님)을 보낸 뒤.
    mutating func dataSent(at now: ContinuousClock.Instant) {
        if self[.newHandshake] == nil {
            self[.newHandshake] = now + Constants.keepaliveTimeout + Constants.rekeyTimeout + Self.jitter()
        }
    }

    /// 인증된 데이터 패킷(keepalive 아님)을 받은 뒤.
    mutating func dataReceived(at now: ContinuousClock.Instant) {
        if self[.sendKeepalive] == nil {
            self[.sendKeepalive] = now + Constants.keepaliveTimeout
        } else {
            needAnotherKeepalive = true
        }
    }

    /// 인증된 패킷(핸드셰이크·keepalive·데이터)을 보낸 뒤. 보냈으니 keepalive를 따로 보낼 필요가 없다.
    mutating func anyAuthenticatedPacketSent() {
        self[.sendKeepalive] = nil
    }

    /// 인증된 패킷(핸드셰이크·keepalive·데이터)을 받은 뒤. 상대가 살아 있으니 새 핸드셰이크가 필요 없다.
    mutating func anyAuthenticatedPacketReceived() {
        self[.newHandshake] = nil
    }

    /// initiation을 보낸 뒤.
    mutating func handshakeInitiated(at now: ContinuousClock.Instant) {
        self[.retransmitHandshake] = now + Constants.rekeyTimeout + Self.jitter()
    }

    /// 초기자는 response를 처리한 뒤, 응답자는 next를 확인한 뒤.
    mutating func handshakeComplete() {
        self[.retransmitHandshake] = nil
        handshakeAttempts = 0
        sentLastMinuteHandshake = false
    }

    /// 새 keypair를 유도한 뒤. 이후 540초 동안 새 키가 없으면 키 재료를 지운다.
    mutating func sessionDerived(at now: ContinuousClock.Instant) {
        self[.zeroKeyMaterial] = now + Constants.rejectAfterTime * 3
    }

    /// 0–333ms. 양쪽이 동시에 재시도해 계속 엇갈리는 일을 막는다.
    private static func jitter() -> Duration {
        .milliseconds(Int.random(in: 0..<Constants.rekeyTimeoutJitterMaxMilliseconds))
    }
}
