// Response parsing follows Tailscale's `net/stun/stun.go` (BSD-3-Clause, Copyright (c) Tailscale Inc & contributors)
// `ParseResponse` rules. The code was written from scratch in Swift.

import SwiftailBase

extension STUNMessage {
    private static let mappedAddress: UInt16 = 0x0001
    private static let xorMappedAddress: UInt16 = 0x0020
    /// An alternate XOR-MAPPED-ADDRESS number that servers send even though it is absent from the RFC. Handles both identically (DERP notes 3.9).
    private static let xorMappedAddressAlternate: UInt16 = 0x8020

    /// Parses a response per DERP notes 4.10 3. Returns `nil` on failure.
    ///
    /// Accepts a response that passes the header check (`hasSTUNHeader`), has type `01 01` (success response), and declares a body no longer than the remaining bytes
    /// (discarding extra bytes), with all attribute lengths and 4-byte padding within the body and an address attribute present.
    /// Uses the address from XOR-MAPPED-ADDRESS (`0x0020`, alternate `0x8020`) if present, or MAPPED-ADDRESS otherwise. If the address attribute's
    /// family is neither IPv4 (1) nor IPv6 (2), or its value is too short, rejects the entire response. Does not check the response FINGERPRINT (as in Go).
    /// Unmaps IPv4-mapped IPv6 addresses to IPv4.
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

    /// Reads an address attribute value (reserved 1, family 1, port 2, address 4 or 16). A present `txID` denotes an XOR attribute.
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
            // The port is XORed with the first 2 bytes of the cookie, and the address's first 4 bytes with the cookie and the rest with the TxID (RFC 5389 15.2).
            port ^= UInt16(magicCookie[0]) << 8 | UInt16(magicCookie[1])
            let mask = magicCookie + txID.bytes
            for index in address.indices {
                address[index] ^= mask[index]
            }
        }
        guard let ip = IPAddress(bytes: unmapped(address)) else { return nil }
        return IPEndpoint(address: ip, port: port)
    }

    /// Unmaps the 16-byte `::ffff:a.b.c.d` form to 4 IPv4 bytes. Leaves other addresses as is (Go `Addr.Unmap`).
    private static func unmapped(_ address: [UInt8]) -> [UInt8] {
        let prefix = [UInt8](repeating: 0, count: 10) + [0xff, 0xff]
        guard address.count == 16, address.starts(with: prefix) else { return address }
        return Array(address[12...])
    }
}
