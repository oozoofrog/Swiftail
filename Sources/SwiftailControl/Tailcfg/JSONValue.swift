/// 해석하지 않고 보관하는 JSON 값. Go `tailcfg.RawMessage`에 대응한다.
///
/// 노드 속성(`CapMap`)과 애플리케이션 권한(`CapGrant.CapMap`)의 인자는 속성마다 형식이 다르다.
/// 이 계층은 형식을 모르므로 값 그대로 두고, 그 속성을 쓰는 쪽이 해석한다.
///
/// 숫자는 `Int64` → `UInt64` → `Double` 순으로 담는다. 64비트 정수 범위의 정수는 그대로 보존되어
/// `9007199254740992`와 `9007199254740993`이 다른 값이다(Go의 `RawMessage`도 구분한다).
/// 한계: 그 범위를 넘는 정수와 `Double`이 담지 못하는 고정밀 소수는 `Double`로 반올림되어 서로 같아질 수 있다.
/// 또 `1.0`처럼 소수 구문으로 쓴 정수는 `integer(1)`이 된다(바이트를 보존하는 Go와 다른 점).
public enum JSONValue: Sendable, Hashable {
    case null
    case bool(Bool)
    /// `Int64` 범위의 정수.
    case integer(Int64)
    /// `Int64.max`보다 큰 `UInt64` 범위의 정수.
    case unsignedInteger(UInt64)
    /// 그 밖의 수. 정밀도를 잃을 수 있다.
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
        } else if let value = try? container.decode(Int64.self) {
            self = .integer(value)
        } else if let value = try? container.decode(UInt64.self) {
            self = .unsignedInteger(value)
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
