// The tag rules are ported from Go's `tailcfg.CheckTag`.
// Origin: tailscale.com v1.104.7 `tailcfg/tailcfg.go` (`CheckTag`, `isAlpha`, `isNum`).
// Copyright (c) Tailscale Inc & contributors. SPDX-License-Identifier: BSD-3-Clause.

/// An OAuth client created in the Tailscale admin console and the tags to attach to keys it creates.
///
/// Used only to create auth keys (`AuthKeyIssuer`). Keys from an OAuth client must have at least one tag, and nodes that join with them
/// become tagged nodes (contract `docs/contracts/SwiftailPairing.md` §4 K7). Values are checked when creating `AuthKeyIssuer`
/// (K4).
///
/// This type holds a secret, so `description` and `dump` redact it. Logging the value as is does not reveal the secret. The app is responsible
/// for storing the secret (Keychain). This type only uses the value it receives.
public struct TailscaleOAuthClient: Sendable {
    /// The OAuth client ID, 1–512 bytes using only `A-Z` `a-z` `0-9` `-` `_` `.` `~`.
    public var id: String
    /// The OAuth client secret (`tskey-client-…`). The same rules apply.
    public var secret: String
    /// The tags for generated keys (`tag:…`). At least one is required. The client must have permission to manage them.
    public var tags: [String]

    /// Stores values without validation. `AuthKeyIssuer.init(client:baseURL:)` validates them.
    public init(id: String, secret: String, tags: [String]) {
        self.id = id
        self.secret = secret
        self.tags = tags
    }
}

extension TailscaleOAuthClient: CustomStringConvertible, CustomReflectable {
    /// Redacts the secret.
    public var description: String {
        "TailscaleOAuthClient(id: \(id), secret: <redacted>, tags: \(tags))"
    }

    /// `dump` bypasses `description`, so redact the secret here too.
    public var customMirror: Mirror {
        Mirror(self, children: ["id": id, "secret": "<redacted>", "tags": tags])
    }
}

extension TailscaleOAuthClient {
    /// The byte limit for one ID or secret.
    static let maximumCredentialByteCount = 512
    /// The secret prefix.
    static let secretPrefix = "tskey-client-"

    /// The contract K4 check.
    func validate() throws(AuthKeyIssueError) {
        guard Self.isCredential(id), Self.isCredential(secret), secret.hasPrefix(Self.secretPrefix) else {
            throw .invalidClient
        }
        guard !tags.isEmpty, tags.allSatisfy(Self.isValidTag) else { throw .invalidTags }
    }

    /// Accepts nonempty values within the limit using only characters Go's `url.QueryEscape` leaves unchanged (`A-Z` `a-z` `0-9` `-` `_` `.` `~`).
    /// Escaping therefore preserves the value in both the Basic header and the form body.
    static func isCredential(_ value: String) -> Bool {
        let bytes = value.utf8
        return !bytes.isEmpty && bytes.count <= maximumCredentialByteCount && bytes.allSatisfy(AuthKeyExchange.isUnreserved)
    }

    /// Go's `tailcfg.CheckTag` requires a nonempty value after `tag:` that starts with an ASCII letter and uses only ASCII letters, digits, and `-`.
    /// Go imposes no length limit either.
    static func isValidTag(_ tag: String) -> Bool {
        guard tag.hasPrefix("tag:") else { return false }
        let name = tag.utf8.dropFirst(4)
        guard let first = name.first, isASCIILetter(first) else { return false }
        return name.allSatisfy { isASCIILetter($0) || (UInt8(ascii: "0")...UInt8(ascii: "9")).contains($0) || $0 == UInt8(ascii: "-") }
    }

    private static func isASCIILetter(_ byte: UInt8) -> Bool {
        (UInt8(ascii: "A")...UInt8(ascii: "Z")).contains(byte) || (UInt8(ascii: "a")...UInt8(ascii: "z")).contains(byte)
    }
}
