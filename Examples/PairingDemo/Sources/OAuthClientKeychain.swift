import Foundation
import Security
import SwiftailPairing

/// 인증 키를 만드는 데 쓰는 Tailscale OAuth 클라이언트의 보관. 키체인의 일반 암호 항목 하나에 둔다.
///
/// 라이브러리는 클라이언트 비밀을 받아 쓰기만 하고 저장하지 않는다(계약 1절). 보관은 앱의 몫이다.
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

    /// 있던 항목을 바꾼다. 저장했으면 true.
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
