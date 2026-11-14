// 응답 해석은 Tailscale의 `net/stun/stun.go`(BSD-3-Clause, Copyright (c) Tailscale Inc & contributors)의
// `ParseResponse`와 같은 규칙이다. 코드는 Swift로 새로 썼다.

import SwiftailBase

extension STUNMessage {
    private static let mappedAddress: UInt16 = 0x0001
    private static let xorMappedAddress: UInt16 = 0x0020
    /// RFC에 없지만 서버가 보내는 XOR-MAPPED-ADDRESS의 대체 번호. 같게 처리한다(DERP 노트 3.9).
    private static let xorMappedAddressAlternate: UInt16 = 0x8020

    /// DERP 노트 4.10 3의 응답 해석. 실패하면 `nil`.
    ///
    /// 받는 것: 헤더 판정(`hasSTUNHeader`)을 통과하고, 종류가 `01 01`(성공 응답)이고, 선언한 본문 길이가 남은 바이트 이하이고
    /// (초과 바이트는 버린다), 모든 속성의 길이와 4바이트 패딩이 본문 안에 들어가고, 주소 속성이 있는 응답이다.
    /// XOR-MAPPED-ADDRESS(`0x0020`, 대체 `0x8020`)가 있으면 그 주소를, 없으면 MAPPED-ADDRESS를 쓴다. 주소 속성의
    /// family가 IPv4(1)·IPv6(2)가 아니거나 값이 짧으면 응답 전체가 오류다. 응답의 FINGERPRINT는 검사하지 않는다(Go도 같다).
    /// IPv4-mapped IPv6 주소는 IPv4로 푼다.
    static func parseBindingResponse(_ bytes: [UInt8]) -> (TransactionID, IPEndpoint)? {
        guard hasSTUNHeader(bytes), bytes[0] == 0x01, bytes[1] == 0x01,
              let txID = TransactionID(bytes[8..<headerLength])
        else { return nil }
        let declared = Int(bytes[2]) << 8 | Int(bytes[3])
        guard declared <= bytes.count - headerLength else { return nil }
        let end = headerLength + declared

        var xor: IPEndpoint?
        var mapped: IPEndpoint?
        var offset = headerLength
        while offset < end {
            guard end - offset >= 4 else { return nil }
            let type = UInt16(bytes[offset]) << 8 | UInt16(bytes[offset + 1])
            let length = Int(bytes[offset + 2]) << 8 | Int(bytes[offset + 3])
            let paddedLength = (length + 3) & ~3
            let value = offset + 4
            guard paddedLength <= end - value else { return nil }
            let attribute = bytes[value..<value + length]
            switch type {
            case xorMappedAddress, xorMappedAddressAlternate:
                guard let endpoint = address(in: attribute, xoring: txID) else { return nil }
                xor = endpoint
            case mappedAddress:
                guard let endpoint = address(in: attribute, xoring: nil) else { return nil }
                mapped = endpoint
            default:
                break
            }
            offset = value + paddedLength
        }
        guard let endpoint = xor ?? mapped else { return nil }
        return (txID, endpoint)
    }

    /// 주소 속성의 값(예약 1, family 1, 포트 2, 주소 4 또는 16)을 읽는다. `txID`가 있으면 XOR 속성이다.
    private static func address(in attribute: ArraySlice<UInt8>, xoring txID: TransactionID?) -> IPEndpoint? {
        let base = attribute.startIndex
        guard attribute.count >= 4 else { return nil }
        let addressLength: Int
        switch attribute[base + 1] {
        case 0x01: addressLength = 4
        case 0x02: addressLength = 16
        default: return nil
        }
        guard attribute.count - 4 >= addressLength else { return nil }
        var port = UInt16(attribute[base + 2]) << 8 | UInt16(attribute[base + 3])
        var address = Array(attribute[base + 4..<base + 4 + addressLength])
        if let txID {
            // 포트는 cookie의 앞 2바이트와, 주소는 앞 4바이트가 cookie와 나머지가 TxID와 XOR된다(RFC 5389 15.2).
            port ^= UInt16(magicCookie[0]) << 8 | UInt16(magicCookie[1])
            let mask = magicCookie + txID.bytes
            for index in address.indices {
                address[index] ^= mask[index]
            }
        }
        guard let ip = IPAddress(bytes: unmapped(address)) else { return nil }
        return IPEndpoint(address: ip, port: port)
    }

    /// `::ffff:a.b.c.d` 형태의 16바이트를 IPv4 4바이트로 푼다. 그 밖의 주소는 그대로 둔다(Go `Addr.Unmap`).
    private static func unmapped(_ address: [UInt8]) -> [UInt8] {
        let prefix = [UInt8](repeating: 0, count: 10) + [0xff, 0xff]
        guard address.count == 16, address.starts(with: prefix) else { return address }
        return Array(address[12...])
    }
}
