import Foundation
import Security
import SwiftailPairing

/// Stores the Tailscale OAuth client used to create auth keys in a single generic password item in the keychain.
///
/// The library receives and uses the client secret without storing it (contract §1). The app is responsible for storage.
enum OAuthClientKeychain {
    private struct Stored: Codable {
        var id: String
        var secret: String
        var tags: [String]
    }

    private static var item: [CFString: Any] {
        [
            kSecClass: kSecClassGenericPassword,
            kSecAttrService: "swiftail-demo.oauth-client",
            kSecAttrAccount: "default",
        ]
    }

    static func load() -> TailscaleOAuthClient? {
        var query = item
        query[kSecReturnData] = true
        var result: CFTypeRef?
        guard SecItemCopyMatching(query as CFDictionary, &result) == errSecSuccess, let data = result as? Data,
            let stored = try? JSONDecoder().decode(Stored.self, from: data)
        else { return nil }
        return TailscaleOAuthClient(id: stored.id, secret: stored.secret, tags: stored.tags)
    }

    /// Replaces the existing item. Returns true if saved.
    static func save(_ client: TailscaleOAuthClient) -> Bool {
        guard let data = try? JSONEncoder().encode(Stored(id: client.id, secret: client.secret, tags: client.tags))
        else { return false }
        remove()
        var attributes = item
        attributes[kSecValueData] = data
        return SecItemAdd(attributes as CFDictionary, nil) == errSecSuccess
    }

    static func remove() {
        SecItemDelete(item as CFDictionary)
    }
}
