import SwiftailBase

/// 봉하기 전의 disco 메시지: Ping, Pong, CallMeMaybe.
///
/// 평문의 부호화와 해석만 맡는다(`DiscoPacket`이 겉 형식과 암호를 맡는다). 상대가 보낸 바이트는 `init(parsing:)`
/// 하나에서 길이·종류를 검사해 이 타입으로 바꾸고, 어떤 바이트열로도 멈추지 않는다.
///
/// 평문은 `type(1) ‖ version(1) ‖ 본문`이고 보낼 때 version은 0이다. 본문 배치는 노트 3.3·3.4다.
/// 해석은 Go와 같이 느슨하다: Ping과 Pong은 version을 보지 않고 본문 뒤의 바이트를 허용한다.
///
/// `docs/protocol-notes/disco-magicsock.md` 3.3·3.4절 (출처: tailscale.com `disco/disco.go`, BSD-3-Clause).
enum DiscoMessage: Sendable, Equatable {
    /// - nodeKey: 보낸 쪽 node 공개 키. 없거나 0이면 nil. 경로 MTU 측정용 패딩은 버린다.
    case ping(TransactionID, nodeKey: NodePublicKey?)
    /// - source: Ping의 관측 출발 주소. 선에서는 IPv4도 IPv4-mapped IPv6(16바이트)로 오는데 풀어서 담는다.
    case pong(TransactionID, source: IPEndpoint)
    /// 상대가 알려 준 주소 목록. version ≠ 0, 0바이트, 18의 배수가 아닌 본문은 오류가 아니라 빈 목록이다(Go와 같다).
    case callMeMaybe([IPEndpoint])

    private enum Kind: UInt8 {
        case ping = 0x01
        case pong = 0x02
        case callMeMaybe = 0x03
    }

    private static let headerLength = 2
    private static let transactionIDLength = TransactionID.byteCount
    private static let pongBodyLength = transactionIDLength + endpointLength
    /// 선 위의 주소 하나: IP 16바이트 ‖ 포트 2바이트(BE).
    private static let endpointLength = 18

    /// 복호화한 평문을 해석한다.
    ///
    /// - Throws: 2바이트 미만이거나 본문이 종류별 최소 길이보다 짧으면 `malformed`. type이 `0x01`–`0x03`이 아니면
    ///   `unknownType`(peer relay 종류 `0x04`–`0x09` 포함: Go는 해석하지만 M4는 버린다).
    init(parsing plaintext: [UInt8]) throws(DiscoError) {
        guard plaintext.count >= Self.headerLength else { throw .malformed }
        guard let kind = Kind(rawValue: plaintext[0]) else { throw .unknownType(plaintext[0]) }
        let version = plaintext[1]
        let body = plaintext[Self.headerLength...]

        switch kind {
        case .ping:
            guard let txID = TransactionID(body.prefix(Self.transactionIDLength)) else { throw .malformed }
            // TxID 뒤가 32바이트 이상이고 전부 0이 아니면 NodeKey, 아니면 모두 패딩이다.
            let extra = body.dropFirst(Self.transactionIDLength)
            let nodeKey = NodePublicKey(rawValue: extra.prefix(NodePublicKey.byteCount)).flatMap { $0.isZero ? nil : $0 }
            self = .ping(txID, nodeKey: nodeKey)

        case .pong:
            guard body.count >= Self.pongBodyLength,
                  let txID = TransactionID(body.prefix(Self.transactionIDLength)),
                  let source = Self.endpoint(from: body.dropFirst(Self.transactionIDLength).prefix(Self.endpointLength))
            else { throw .malformed }
            self = .pong(txID, source: source)

        case .callMeMaybe:
            guard version == 0, !body.isEmpty, body.count.isMultiple(of: Self.endpointLength) else {
                self = .callMeMaybe([])
                return
            }
            var endpoints: [IPEndpoint] = []
            endpoints.reserveCapacity(body.count / Self.endpointLength)
            var offset = body.startIndex
            while offset < body.endIndex {
                let end = offset + Self.endpointLength
                guard let endpoint = Self.endpoint(from: body[offset..<end]) else { throw .malformed }
                endpoints.append(endpoint)
                offset = end
            }
            self = .callMeMaybe(endpoints)
        }
    }

    /// 평문(type ‖ version 0 ‖ 본문). Ping은 패딩 없이 보내고, `nodeKey`가 nil이거나 0이면 12바이트 본문이다.
    var plaintext: [UInt8] {
        switch self {
        case .ping(let txID, let nodeKey):
            let key = nodeKey.flatMap { $0.isZero ? nil : $0.rawValue } ?? []
            return Self.header(.ping) + txID.bytes + key
        case .pong(let txID, let source):
            return Self.header(.pong) + txID.bytes + Self.wireBytes(of: source)
        case .callMeMaybe(let endpoints):
            return Self.header(.callMeMaybe) + endpoints.flatMap(Self.wireBytes(of:))
        }
    }

    private static func header(_ kind: Kind) -> [UInt8] {
        [kind.rawValue, 0]
    }

    /// 선 위의 주소 18바이트를 푼다. IPv4-mapped(`::ffff:a.b.c.d`)는 IPv4로 돌린다.
    private static func endpoint(from bytes: ArraySlice<UInt8>) -> IPEndpoint? {
        guard bytes.count == endpointLength else { return nil }
        let ip = bytes.prefix(16)
        let isMapped = ip.prefix(10).allSatisfy { $0 == 0 } && ip.dropFirst(10).prefix(2).allSatisfy { $0 == 0xFF }
        guard let address = IPAddress(bytes: isMapped ? ip.suffix(4) : ip) else { return nil }
        let port = UInt16(bytes[bytes.startIndex + 16]) << 8 | UInt16(bytes[bytes.startIndex + 17])
        return IPEndpoint(address: address, port: port)
    }

    /// 주소를 선 위의 18바이트로 만든다. IPv4는 IPv4-mapped IPv6로 넣는다.
    private static func wireBytes(of endpoint: IPEndpoint) -> [UInt8] {
        let ip = endpoint.address.isIPv4
            ? [UInt8](repeating: 0, count: 10) + [0xFF, 0xFF] + endpoint.address.bytes
            : endpoint.address.bytes
        return ip + [UInt8(endpoint.port >> 8), UInt8(endpoint.port & 0xFF)]
    }
}
