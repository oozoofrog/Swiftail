// 태그 규칙은 Go `tailcfg.CheckTag`를 옮겼다.
// 출처: tailscale.com v1.104.7 `tailcfg/tailcfg.go` (`CheckTag`, `isAlpha`, `isNum`).
// Copyright (c) Tailscale Inc & contributors. SPDX-License-Identifier: BSD-3-Clause.

/// Tailscale 관리 콘솔에서 만든 OAuth 클라이언트 하나와, 그 클라이언트로 만들 키에 붙일 태그.
///
/// 인증 키를 만드는 데만 쓴다(`AuthKeyIssuer`). OAuth 클라이언트로 만든 키에는 태그가 하나 이상 있어야 하고, 그 키로
/// 들어온 노드는 태그 노드가 된다(계약 `docs/contracts/SwiftailPairing.md` 4절 K7). 값의 검사는 `AuthKeyIssuer`를
/// 만들 때 한다(K4).
///
/// 비밀을 담으므로 `description`과 `dump`에서 가린다. 값을 그대로 로그에 찍어도 비밀이 새지 않는다. 비밀의 보관은 앱의
/// 몫이다(키체인). 이 타입은 받은 값을 쓰기만 한다.
public struct TailscaleOAuthClient: Sendable {
    /// OAuth 클라이언트 ID. `A-Z` `a-z` `0-9` `-` `_` `.` `~`만, 1~512바이트.
    public var id: String
    /// OAuth 클라이언트 비밀(`tskey-client-…`). 같은 규칙.
    public var secret: String
    /// 만들 키에 붙일 태그(`tag:…`). 하나 이상. 클라이언트가 그 태그를 다룰 권한이 있어야 한다.
    public var tags: [String]

    /// 검사하지 않고 값을 담는다. 검사는 `AuthKeyIssuer.init(client:baseURL:)`가 한다.
    public init(id: String, secret: String, tags: [String]) {
        self.id = id
        self.secret = secret
        self.tags = tags
    }
}

extension TailscaleOAuthClient: CustomStringConvertible, CustomReflectable {
    /// 비밀을 가린다.
    public var description: String {
        "TailscaleOAuthClient(id: \(id), secret: <가림>, tags: \(tags))"
    }

    /// `dump`는 `description`을 거치지 않으므로 여기서도 비밀을 가린다.
    public var customMirror: Mirror {
        Mirror(self, children: ["id": id, "secret": "<가림>", "tags": tags])
    }
}

extension TailscaleOAuthClient {
    /// ID·비밀 한 값의 바이트 한도.
    static let maximumCredentialByteCount = 512
    /// 비밀의 머리.
    static let secretPrefix = "tskey-client-"

    /// 계약 K4의 검사.
    func validate() throws(AuthKeyIssueError) {
        guard Self.isCredential(id), Self.isCredential(secret), secret.hasPrefix(Self.secretPrefix) else {
            throw .invalidClient
        }
        guard !tags.isEmpty, tags.allSatisfy(Self.isValidTag) else { throw .invalidTags }
    }

    /// 비지 않고 한도 이하이며 Go `url.QueryEscape`가 그대로 두는 글자(`A-Z` `a-z` `0-9` `-` `_` `.` `~`)만 쓴다.
    /// 그래서 Basic 머리에서든 폼 본문에서든 이스케이프해도 값이 바뀌지 않는다.
    static func isCredential(_ value: String) -> Bool {
        let bytes = value.utf8
        return !bytes.isEmpty && bytes.count <= maximumCredentialByteCount && bytes.allSatisfy(AuthKeyExchange.isUnreserved)
    }

    /// Go `tailcfg.CheckTag`: `tag:` 뒤가 비지 않고, ASCII 영문자로 시작하며, ASCII 영문자·숫자·`-`만 쓴다.
    /// 길이 한도는 Go에도 없다.
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
