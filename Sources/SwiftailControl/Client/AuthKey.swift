import SwiftailTKA

/// 인증 키의 두 부분: 제어 서버에 보낼 부분과 tailnet lock 서명의 재료.
///
/// tailnet lock을 쓰는 tailnet의 서명된 인증 키는 `<키>--TL<credential>-<감싼 개인 키>`처럼 lock 재료를 뒤에 붙여 온다.
/// 서버에는 `--TL` 앞부분만 보낸다. 뒷부분은 새 node 키에 서명하는 재료이고 개인 키가 들어 있으므로 어떤 요청에도 싣지 않는다.
/// 뒷부분이 해석되지 않으면 서버에 아무것도 보내기 전에 설정 오류로 끝낸다. Go는 그때 원문 전체를 인증 키로 보낸다(결정 L12).
///
/// `docs/protocol-notes/tailnet-lock.md` 3.8·4.6 2, `docs/contracts/SwiftailTailnetLock.md` 동작 R3·R4
/// (출처: tailscale.com `tka/sig.go` `DecodeWrappedAuthkey`, BSD-3-Clause).
enum AuthKey {
    /// 서버에 보낼 부분(첫 `--TL` 앞). `--TL`이 없으면 그대로다.
    static func controlValue(of authKey: String) -> String {
        guard let marker = authKey.range(of: "--TL") else { return authKey }
        return String(authKey[..<marker.lowerBound])
    }

    /// 서명된 인증 키를 해석한다. 인증 키가 없거나 `--TL`이 없으면 nil.
    ///
    /// - Throws: `invalidConfiguration` — `--TL` 뒤가 동작 R3에 어긋난다. 메시지에 키 내용은 담지 않는다.
    static func wrapped(in authKey: String?) throws(ControlError) -> WrappedAuthKey? {
        guard let authKey else { return nil }
        do {
            return try WrappedAuthKey(parsing: authKey)
        } catch {
            throw .invalidConfiguration("인증 키의 tailnet lock 부분(--TL 뒤)을 해석하지 못했다")
        }
    }
}
