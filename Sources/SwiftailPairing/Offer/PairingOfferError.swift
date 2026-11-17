/// 링크나 QR의 문자열을 제안으로 읽지 못한 까닭(`PairingOffer.init(link:)`). 계약 동작 O2·O3.
///
/// 값을 싣지 않는다. 링크는 비밀이라, 오류를 로그에 남겨도 새는 것이 없어야 한다.
public enum PairingOfferError: Error, Sendable, Equatable {
    /// 제안의 링크가 아니다: 조각(`#` 뒤)이 없거나 2048바이트를 넘거나 `%`가 있다, `키=값`의 모양이 아니다, 판(`v`)이 `1`이
    /// 아니다, 모르는 키나 겹친 키가 있다.
    case notAnOffer
    /// `h`가 없거나 올바른 DNS 이름이 아니다(소문자·숫자·`-`의 라벨 둘 이상, 전체 253자 이하).
    case invalidHost
    /// `p`가 없거나 앞자리 0 없는 1~65535의 10진수가 아니다.
    case invalidPort
    /// `s`가 없거나 32바이트를 적은 채움 없는 base64url 43자가 아니다.
    case invalidSecret
    /// `e`가 없거나 부호와 앞자리 0이 없는 1~11자리 10진수가 아니다.
    case invalidExpiry
    /// `k`가 `tskey-auth-`로 시작하지 않거나, `A-Za-z0-9-` 밖의 글자가 있거나, 256바이트를 넘는다.
    case invalidAuthKey
    /// `k`가 tailnet lock의 서명된(감싼) 인증 키다(`--TL`). 그 뒤쪽의 개인 키는 1회용이 아니어서 링크에 싣지 않는다.
    case wrappedAuthKey
}
