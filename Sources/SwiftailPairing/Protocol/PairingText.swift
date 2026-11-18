/// Rules for display text sent by the peer (device name and host display name, contract behaviors P8 and J5).
///
/// The peer supplies this text, and the approval screen displays it verbatim. Control characters (Cc) disrupt the screen, and some format characters (Cf)
/// can reverse text direction to make a name look different (such as U+202E). Both categories are rejected except for two joining format characters
/// (U+200C and U+200D) used in joined emoji and in names written in Persian and Indic scripts.
enum PairingText {
    /// Returns the string if it is valid UTF-8 with no Cc or Cf other than U+200C and U+200D, or nil otherwise.
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

/// A validated device name of 1–64 bytes of displayable text (the name field in `hello`).
struct DeviceName: Sendable, Equatable {
    /// The name limit in bytes.
    static let maximumLength = 64

    let text: String

    /// The bytes written on the wire.
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
