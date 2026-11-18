// The rules for arming and disarming timers are ported from wireguard-go `device/timers.go`
// (github.com/tailscale/wireguard-go v0.0.0-20261106233718-9e0ab45c16ca).
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

/// The four timers and supporting state for one peer.
///
/// Each timer is only a deadline (`ContinuousClock.Instant?`). There are no actual timers. The device
/// processes expired deadlines in `advance(to:)`. The `…Sent` and `…Received` methods below are ports of the corresponding wireguard-go
/// functions (`timers*`) and arm and disarm timers as packets are sent and received.
///
/// | Timer | On expiration |
/// | --- | --- |
/// | retransmitHandshake | Retry initiation. Give up after more than 18 attempts |
/// | sendKeepalive | Send a keepalive if there was nothing to send in reply to received data |
/// | newHandshake | Start a new handshake if nothing came back after sending |
/// | zeroKeyMaterial | Delete all key material |
///
/// Whitepaper §6.2–§6.5, `docs/protocol-notes/wireguard.md` "Timers"
/// (origin: wireguard-go `device/timers.go`).
///
/// shortcut: There is no session expiration notification (sessionExpired in the fork) or persistentKeepalive. Tailscale disables persistentKeepalive, and session state notifications can be added when the M3 engine needs them.
struct PeerTimers {
    enum Kind: CaseIterable {
        case retransmitHandshake, sendKeepalive, newHandshake, zeroKeyMaterial
    }

    // There are only four timers, so store them in fields instead of a dictionary. Updating them on every packet must be allocation-free.
    private var retransmitHandshake: ContinuousClock.Instant?
    private var sendKeepalive: ContinuousClock.Instant?
    private var newHandshake: ContinuousClock.Instant?
    private var zeroKeyMaterial: ContinuousClock.Instant?
    /// The retry count for this handshake.
    var handshakeAttempts = 0
    /// Data arrived again while sendKeepalive was armed. Arm it once more after it expires.
    var needAnotherKeepalive = false
    /// A rekey initiation was already sent just before expiration (165 seconds).
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

    /// The earliest deadline and its timer. Ties go to the earlier declaration in `Kind`.
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

    /// After sending an authenticated data packet (excluding keepalives).
    mutating func dataSent(at now: ContinuousClock.Instant) {
        if self[.newHandshake] == nil {
            self[.newHandshake] = now + Constants.keepaliveTimeout + Constants.rekeyTimeout + Self.jitter()
        }
    }

    /// After receiving an authenticated data packet (excluding keepalives).
    mutating func dataReceived(at now: ContinuousClock.Instant) {
        if self[.sendKeepalive] == nil {
            self[.sendKeepalive] = now + Constants.keepaliveTimeout
        } else {
            needAnotherKeepalive = true
        }
    }

    /// After sending an authenticated packet (handshake, keepalive, or data). The send makes a separate keepalive unnecessary.
    mutating func anyAuthenticatedPacketSent() {
        self[.sendKeepalive] = nil
    }

    /// After receiving an authenticated packet (handshake, keepalive, or data). The peer is alive, so no new handshake is needed.
    mutating func anyAuthenticatedPacketReceived() {
        self[.newHandshake] = nil
    }

    /// After sending an initiation.
    mutating func handshakeInitiated(at now: ContinuousClock.Instant) {
        self[.retransmitHandshake] = now + Constants.rekeyTimeout + Self.jitter()
    }

    /// After the initiator processes the response or the responder confirms next.
    mutating func handshakeComplete() {
        self[.retransmitHandshake] = nil
        handshakeAttempts = 0
        sentLastMinuteHandshake = false
    }

    /// After deriving a new keypair. Erases key material if no new keys arrive in the next 540 seconds.
    mutating func sessionDerived(at now: ContinuousClock.Instant) {
        self[.zeroKeyMaterial] = now + Constants.rejectAfterTime * 3
    }

    /// 0–333ms. Prevents both sides from repeatedly missing each other by retrying simultaneously.
    private static func jitter() -> Duration {
        .milliseconds(Int.random(in: 0..<Constants.rekeyTimeoutJitterMaxMilliseconds))
    }
}
