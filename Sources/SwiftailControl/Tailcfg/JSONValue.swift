/// 해석하지 않고 보관하는 JSON 값. Go `tailcfg.RawMessage`에 대응한다.
///
/// 노드 속성(`CapMap`)과 애플리케이션 권한(`CapGrant.CapMap`)의 인자는 속성마다 형식이 다르다.
/// 이 계층은 형식을 모르므로 값 그대로 두고, 그 속성을 쓰는 쪽이 해석한다.
/// 숫자는 `Double`로 담으므로 2^53을 넘는 정수는 정밀도를 잃는다.
public enum JSONValue: Sendable, Hashable {
    case null
    case bool(Bool)
    case number(Double)
    case string(String)
    case array([JSONValue])
    case object([String: JSONValue])
}

extension JSONValue: Decodable {
    public init(from decoder: any Decoder) throws {
        let container = try decoder.singleValueContainer()
        if container.decodeNil() {
            self = .null
        } else if let value = try? container.decode(Bool.self) {
            self = .bool(value)
        } else if let value = try? container.decode(Double.self) {
            self = .number(value)
        } else if let value = try? container.decode(String.self) {
            self = .string(value)
        } else if let value = try? container.decode([JSONValue].self) {
            self = .array(value)
        } else {
            self = .object(try container.decode([String: JSONValue].self))
        }
    }
}
