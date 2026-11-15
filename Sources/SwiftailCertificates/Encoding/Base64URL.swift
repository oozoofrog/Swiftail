/// 채움 문자 없는 base64url(RFC 4648 5절, RFC 7515 2절의 `BASE64URL`).
///
/// JOSE(JWS의 세 부분, JWK의 좌표, JWK 지문)와 ACME(키 인가, DNS-01 TXT 값, finalize의 CSR)가 이 형식을
/// 쓴다. 알파벳은 표준 base64의 `+`·`/` 대신 `-`·`_`이고, 끝의 `=`를 적지 않는다(RFC 7515 2절).
///
/// 읽기는 엄격하다: `=`, 공백·줄바꿈, 표준 알파벳의 `+`·`/`, 남는 비트가 0이 아닌 끝(RFC 4648 3.5의
/// 정규 인코딩이 아님)을 모두 거절한다. 같은 바이트가 두 가지 글로 읽히지 않게 하기 위해서다.
enum Base64URL {
    /// 바이트를 base64url 글로 적는다.
    static func encode(_ bytes: some Sequence<UInt8>) -> String {
        var text: [UInt8] = []
        var buffer: UInt32 = 0
        var bitCount = 0
        for byte in bytes {
            buffer = buffer << 8 | UInt32(byte)
            bitCount += 8
            while bitCount >= 6 {
                bitCount -= 6
                text.append(alphabet[Int(buffer >> UInt32(bitCount) & 0x3F)])
            }
        }
        // 남은 1~5비트는 오른쪽을 0으로 채워 한 글자로 적는다(RFC 4648 4절의 끝 처리, 채움 문자는 없다).
        if bitCount > 0 {
            text.append(alphabet[Int(buffer << UInt32(6 - bitCount) & 0x3F)])
        }
        return String(decoding: text, as: UTF8.self)
    }

    /// base64url 글을 바이트로 읽는다. 알파벳 밖의 문자, 채움 문자, 길이가 4로 나눠 1이 남는 글,
    /// 남는 비트가 0이 아닌 글이면 `nil`.
    static func decode(_ text: some StringProtocol) -> [UInt8]? {
        var bytes: [UInt8] = []
        var buffer: UInt32 = 0
        var bitCount = 0
        for character in text.utf8 {
            guard let value = sextet(character) else { return nil }
            buffer = buffer << 6 | UInt32(value)
            bitCount += 6
            if bitCount >= 8 {
                bitCount -= 8
                bytes.append(UInt8(truncatingIfNeeded: buffer >> UInt32(bitCount)))
            }
        }
        // 끝에 남을 수 있는 것은 0비트(4글자 묶음), 4비트(2글자), 2비트(3글자)뿐이다. 6비트(1글자)는 바이트를
        // 이루지 못하는 잘린 글이고, 남은 비트가 0이 아니면 정규 인코딩이 아니다(RFC 4648 3.5).
        guard bitCount != 6, buffer & (1 << UInt32(bitCount) - 1) == 0 else { return nil }
        return bytes
    }

    private static let alphabet = Array("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_".utf8)

    private static func sextet(_ character: UInt8) -> UInt8? {
        switch character {
        case UInt8(ascii: "A")...UInt8(ascii: "Z"): character - UInt8(ascii: "A")
        case UInt8(ascii: "a")...UInt8(ascii: "z"): character - UInt8(ascii: "a") + 26
        case UInt8(ascii: "0")...UInt8(ascii: "9"): character - UInt8(ascii: "0") + 52
        case UInt8(ascii: "-"): 62
        case UInt8(ascii: "_"): 63
        default: nil
        }
    }
}
