import Foundation

/// 짝 맺기에서 이 앱이 맡는 쪽.
enum Role: String, Sendable, CaseIterable, Identifiable {
    /// 제안을 내고 승인하는 쪽.
    case host
    /// 제안을 읽고 들어오는 쪽.
    case joiner

    var id: Self { self }

    var label: String {
        switch self {
        case .host: "여는 쪽"
        case .joiner: "들어오는 쪽"
        }
    }

    /// Mac은 여는 쪽, iPhone은 들어오는 쪽에서 시작한다.
    static var platformDefault: Role {
        #if os(macOS)
        .host
        #else
        .joiner
        #endif
    }
}

/// 자동화 모드의 설정. 사람 손 없이 앱을 돌려 보는 검증에만 쓴다.
///
/// 실행 인자 `--automation`과 루프백 제어 서버(`--control-url=http://127.0.0.1:<포트>`)가 함께 있을 때만 켜진다. 저장된
/// 설정이나 화면에서는 켤 수 없다. 그래서 자동 승인과 링크 파일은 시험 제어 서버 밖에서 쓰이지 않는다.
struct Automation: Sendable {
    /// 시험 제어 서버. 루프백의 `http://`만 받는다.
    let controlURL: URL
    var role: Role?
    /// 노드를 등록할 인증 키. 여는 쪽이 시작하면서 제안을 열 때는 그 제안에도 싣는다.
    var authKey: String?
    /// 노드가 연결되면 곧바로 제안을 연다(`--open-offer`).
    var opensOffer = false
    /// 승인 화면을 띄우지 않고 승인한다(`--auto-approve`).
    var approvesAutomatically = false
    /// 연 제안의 링크를 앱 컨테이너의 `offer-link.txt`에 쓴다(`--write-offer-link`).
    var writesOfferLink = false
    /// 확인 숫자를 기록에 남긴다(`--log-confirmation-code`).
    var logsConfirmationCode = false

    /// 자동화 모드가 아니면 nil. 다른 인자는 자동화 모드일 때만 읽는다.
    init?(arguments: [String]) {
        guard arguments.contains("--automation"),
            let controlURL = arguments.lazy.compactMap({ Self.value(of: "--control-url=", in: $0) }).first.flatMap(URL.init(string:)),
            controlURL.scheme == "http", let host = controlURL.host(percentEncoded: false),
            ["127.0.0.1", "::1", "localhost"].contains(host)
        else { return nil }
        self.controlURL = controlURL
        for argument in arguments {
            switch argument {
            case "--open-offer": opensOffer = true
            case "--auto-approve": approvesAutomatically = true
            case "--write-offer-link": writesOfferLink = true
            case "--log-confirmation-code": logsConfirmationCode = true
            default:
                if let value = Self.value(of: "--role=", in: argument) { role = Role(rawValue: value) }
                if let value = Self.value(of: "--auth-key=", in: argument) { authKey = value }
            }
        }
    }

    private static func value(of prefix: String, in argument: String) -> String? {
        argument.hasPrefix(prefix) ? String(argument.dropFirst(prefix.count)) : nil
    }
}
