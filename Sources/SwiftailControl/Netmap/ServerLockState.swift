import SwiftailTKA

/// The tailnet lock state reported by the control server in this map session (Go `netmap.TKAEnabled` and `TKAHead`).
///
/// This is only the server's claim. An enabled claim triggers bootstrap, and a disabled claim is acted on only after verifying the disablement secret
/// (`TailnetLockPlan`, contract `docs/contracts/SwiftailTailnetLock.md` behaviors N1 and O1, §5 TL-11b item 3).
///
/// `docs/protocol-notes/tailnet-lock.md` §4.7 and §4.10 (origin: `netmap` in tailscale.com `control/controlclient/map.go`,
/// BSD-3-Clause).
package struct ServerLockState: Sendable, Equatable {
    /// Whether the server reported that the lock is enabled.
    package var isEnabled = false
    /// The head reported by the server. Nil if absent or unreadable ("enabled, head unknown" if enabled).
    package var head: AUMHash?

    package init(isEnabled: Bool = false, head: AUMHash? = nil) {
        self.isEnabled = isEnabled
        self.head = head
    }

    /// Computes from the last `TKAInfo` received in this map session. If none has arrived (nil), the lock is disabled.
    ///
    /// Even if `Head` cannot be read as an AUM hash, absence of `Disabled` means "enabled, head unknown" (contract §5 TL-11b item 3,
    /// which changes "disabled" in behavior N1). This prevents an unreadable response announcing the lock from being treated as no lock. Go treats an unreadable head
    /// as disabled. For text accepted by Go and rejected by Swiftail (behavior D10), that would leave Swiftail unfiltered while Go filters.
    /// Reads the head regardless of `Disabled`. If an incorrect disablement secret leaves the lock enabled, compares this head with the local head to decide whether to synchronize.
    init(_ info: TKAInfo?) {
        guard let info else { return }
        isEnabled = !info.disabled
        guard !info.head.isEmpty else { return }
        head = AUMHash(text: info.head)
    }
}
