/// 상대가 보낸 표시용 글(기기 이름, 여는 쪽의 표시 이름)의 규칙(계약 동작 P8·J5).
///
/// 이 글은 상대가 스스로 밝힌 값이고 승인 화면에 그대로 나온다. 제어 문자(Cc)는 화면을 흐트러뜨리고, 서식 문자(Cf)에는
/// 글의 방향을 뒤집어 다른 이름처럼 보이게 하는 것(U+202E 등)이 있다. 둘 다 받지 않는다. 서식 문자 가운데 글자를 잇는
/// 둘(U+200C, U+200D)만은 받는다. 이은 이모지와 페르시아어·인도계 문자의 이름에 들어 있다.
enum PairingText {
    /// 올바른 UTF-8이고 Cc와 (U+200C·U+200D를 뺀) Cf가 없으면 그 문자열, 아니면 nil.
    static func displayable(_ bytes: some Collection<UInt8>) -> String? {
        guard let text = String(validating: Array(bytes), as: UTF8.self),
              text.unicodeScalars.allSatisfy({ scalar in
                  switch scalar.properties.generalCategory {
                  case .control: false
                  case .format: scalar == "\u{200C}" || scalar == "\u{200D}"
                  default: true
                  }
              })
        else { return nil }
        return text
    }
}

/// 검증된 기기 이름: 1~64바이트의 표시할 수 있는 글(`hello`의 이름 칸).
struct DeviceName: Sendable, Equatable {
    /// 이름의 한도(바이트).
    static let maximumLength = 64

    let text: String

    /// 선 위에 적는 바이트.
    var bytes: [UInt8] { Array(text.utf8) }

    init?(_ text: String) {
        self.init(bytes: Array(text.utf8))
    }

    init?(bytes: some Collection<UInt8>) {
        guard (1...Self.maximumLength).contains(bytes.count), let text = PairingText.displayable(bytes) else {
            return nil
        }
        self.text = text
    }
}
