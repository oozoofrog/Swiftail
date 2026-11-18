import SwiftailTKA

/// The two parts of an auth key: the portion sent to the control server and the tailnet lock signature material.
///
/// A signed auth key for a tailnet using tailnet lock appends lock material as `<key>--TL<credential>-<wrapped private key>`.
/// Sends only the part before `--TL` to the server. The suffix signs the new node key and contains private key material, so it is excluded from every request.
/// If the suffix cannot be parsed, stops with a configuration error before sending anything to the server. Go sends the entire original text as the auth key in this case (decision L12).
///
/// `docs/protocol-notes/tailnet-lock.md` §3.8, §4.6 item 2, `docs/contracts/SwiftailTailnetLock.md` behaviors R3 and R4
/// (origin: `DecodeWrappedAuthkey` in tailscale.com `tka/sig.go`, BSD-3-Clause).
enum AuthKey {
    /// The portion to send to the server (before the first `--TL`). Uses the full value if `--TL` is absent.
    static func controlValue(of authKey: String) -> String {
        guard let marker = authKey.range(of: "--TL") else { return authKey }
        return String(authKey[..<marker.lowerBound])
    }

    /// Parses a signed auth key. Returns nil if the auth key or `--TL` is absent.
    ///
    /// - Throws: `invalidConfiguration` if the part after `--TL` violates behavior R3. The message omits the key contents.
    static func wrapped(in authKey: String?) throws(ControlError) -> WrappedAuthKey? {
        guard let authKey else { return nil }
        do {
            return try WrappedAuthKey(parsing: authKey)
        } catch {
            throw .invalidConfiguration("Could not parse the tailnet lock portion of the auth key (after --TL)")
        }
    }
}
