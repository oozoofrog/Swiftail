/// 인증 키 가운데 제어 서버에 보낼 부분.
///
/// tailnet lock을 쓰는 tailnet의 인증 키는 `<키>--TL<서명>-<개인 키>`처럼 lock 재료를 뒤에 붙여 온다.
/// 서버에는 `--TL` 앞부분만 보내야 한다. 뒷부분은 node 키 서명을 만드는 재료이고, 특히 개인 키가 들어 있으므로
/// 서버에 보내면 안 된다. Swiftail은 lock을 지원하지 않으므로 재료는 버린다.
///
/// `docs/protocol-notes/control-map.md` 3.2, 4.1의 2
/// (출처: tailscale.com `tka/sig.go` `DecodeWrappedAuthkey`, BSD-3-Clause).
enum AuthKey {
    static func controlValue(of authKey: String) -> String {
        guard let marker = authKey.range(of: "--TL") else { return authKey }
        return String(authKey[..<marker.lowerBound])
    }
}
