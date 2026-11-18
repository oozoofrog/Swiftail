// Disablement secret verification. Notes §4.5 and §5, contract behavior X.
// Origin: tailscale.com v1.104.7 `tka/state.go` (`DisablementKDF`, `checkDisablement`). The parameters were ported.
// Copyright (c) Tailscale Inc & contributors. BSD-3-Clause.

import SwiftailCrypto

extension Authority {
    /// Checks the disablement secret (Go `ValidDisablement`, behaviors X1 and X2). On true, the caller removes the lock state.
    ///
    /// Returns true when the Argon2i result (salt "tailscale network-lock disablement salt", 4 passes, 16MiB, parallelism 4, 32 bytes) matches one
    /// of the state's disablement values in constant time. Feeds even an empty secret to the KDF as is. Allocates 16MiB once and releases it on completion.
    /// Does not retain the secret or KDF output.
    package func isValidDisablement(secret: [UInt8]) -> Bool {
        let derived: [UInt8]
        do {
            derived = try Argon2i.derive(
                password: secret, salt: Self.disablementSalt, iterations: 4, memoryKiB: 16 * 1_024, parallelism: 4,
                outputByteCount: AuthorityState.disablementValueByteCount
            )
        } catch {
            // With fixed parameters this is reachable only if the secret exceeds 4GiB. An unverified secret is invalid.
            return false
        }
        return state.disablementValues.contains { constantTimeEqual(derived, $0) }
    }

    /// The disablement secret KDF salt (39 ASCII bytes).
    static let disablementSalt = Array("tailscale network-lock disablement salt".utf8)
}
