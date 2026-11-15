import CryptoKit

/// CryptoKit이 서명을 만들지 못했다. P-256 서명은 정상적인 키로는 실패하지 않지만 CryptoKit의 선언이
/// 실패를 허용하므로 종류로 드러낸다. 키나 입력은 싣지 않는다(계약 동작 K3).
struct SigningFailure: Error, Sendable, Equatable {}

/// ACME 요청 본문인 JWS(RFC 7515), Flattened JSON 직렬화(RFC 7515 7.2.2), ES256 서명.
///
/// RFC 8555 6.2의 조건을 타입으로 지킨다: 보호 머리만 쓰고(보호되지 않는 머리 없음), 서명은 하나이고,
/// 머리에는 `alg`·`nonce`·`url`과 함께 `jwk`와 `kid` 가운데 **정확히 하나**가 들어간다(`KeyReference`).
/// `jwk`는 서명한 키의 공개 키에서 만들므로 다른 키를 실을 수 없다.
///
/// 보호 머리의 JSON은 Go `jwsEncodeJSON`과 같은 바이트로 적는다: 멤버 순서 `alg`, `kid` 또는 `jwk`, `nonce`,
/// `url`, 공백 없음, 문자열은 Go `json.Marshal`의 이스케이프(`JSONString`). RFC 7515 5.1은 멤버 순서를 정하지
/// 않으므로 이 일치는 규격이 아니라 Go 기준값과의 바이트 대조를 위한 선택이다(노트 7장 1).
///
/// ECDSA 서명은 CryptoKit이 안에서 난수를 뽑으므로 같은 입력이어도 실행마다 다르다. 시험은 서명을 바이트로
/// 견주지 않고 공개 키로 검증한다(계약 동작 C 머리말).
struct JWS: Sendable, Equatable {
    /// 보호 머리가 서명 키를 가리키는 방식(RFC 8555 6.2).
    enum KeyReference: Sendable, Equatable {
        /// `jwk`: 서명 키의 공개 키를 그대로 싣는다. newAccount 요청에만 쓴다.
        case publicKey
        /// `kid`: newAccount 응답의 `Location`으로 받은 계정 URL. 그 밖의 모든 요청에 쓴다.
        case accountURL(String)
    }

    /// base64url(보호 머리 JSON).
    let protected: String
    /// base64url(본문). POST-as-GET이면 빈 문자열이다(RFC 8555 6.3).
    let payload: String
    /// base64url(R ‖ S). 64바이트를 풀어 적은 86자다(RFC 7518 3.4).
    let signature: String

    /// 요청 하나의 JWS를 만들고 서명한다.
    ///
    /// - Parameters:
    ///   - payload: 본문 JSON의 바이트. **빈 배열이면 POST-as-GET**이다: base64url(빈 바이트)는 빈 문자열이므로
    ///     `payload`가 `""`가 된다(RFC 8555 6.3. `"{}"`의 인코딩과 다르다).
    ///   - url: 이 요청을 보낼 URL. 서버가 준 문자열을 다시 인코딩하지 않고 그대로 넣는다(RFC 8555 6.4, 계약 동작 X1).
    ///   - nonce: 서버가 `Replay-Nonce`로 준 값(RFC 8555 6.5). 형식 검사는 응답을 읽는 쪽의 몫이다(계약 동작 X2).
    ///   - keyReference: `jwk` 또는 `kid`.
    ///   - key: 계정 개인 키.
    init(
        payload: [UInt8],
        url: String,
        nonce: String,
        keyReference: KeyReference,
        signedWith key: P256.Signing.PrivateKey
    ) throws(SigningFailure) {
        protected = Base64URL.encode(Self.protectedHeader(url: url, nonce: nonce, keyReference: keyReference, publicKey: key.publicKey).utf8)
        self.payload = Base64URL.encode(payload)
        do {
            // RFC 7515 5.1: 서명 입력은 ASCII(BASE64URL(머리) ‖ "." ‖ BASE64URL(본문)). CryptoKit이 SHA-256을 적용한다.
            let signingInput = Array((protected + "." + self.payload).utf8)
            signature = Base64URL.encode(try key.signature(for: signingInput).rawRepresentation)
        } catch {
            throw SigningFailure()
        }
    }

    /// HTTP 본문: `{"protected":…,"payload":…,"signature":…}`(RFC 7515 7.2.2, Go `jsonWebSignature`와 같은 순서).
    /// `Content-Type`은 `application/jose+json`이다(RFC 8555 6.2). 세 값은 base64url 알파벳뿐이라 그대로 적는다.
    var flattenedJSON: [UInt8] {
        Array(#"{"protected":"\#(protected)","payload":"\#(payload)","signature":"\#(signature)"}"#.utf8)
    }

    /// 보호 머리 JSON(Go `jwsEncodeJSON`의 `headers`와 같은 멤버 순서).
    private static func protectedHeader(url: String, nonce: String, keyReference: KeyReference, publicKey: P256.Signing.PublicKey) -> String {
        let key = switch keyReference {
        case .publicKey: #""jwk":"# + JWK(publicKey).canonicalJSON
        case .accountURL(let accountURL): #""kid":"# + JSONString.quoted(accountURL)
        }
        return #"{"alg":"ES256","# + key + #","nonce":"# + JSONString.quoted(nonce) + #","url":"# + JSONString.quoted(url) + "}"
    }
}
