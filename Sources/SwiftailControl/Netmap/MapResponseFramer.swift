import Foundation

/// Splits the map stream's HTTP body into map responses.
///
/// A frame consists of a 4-byte little-endian length N and N bytes of JSON. Frames continue indefinitely in one body,
/// independently of HTTP/2 DATA frame boundaries. Buffer incoming bytes and decode only complete
/// frames. If the length prefix exceeds the limit, fail before buffering that many bytes.
///
/// Before decoding, scans the payload once to check nesting depth (`maximumNestingDepth`) and value count (`maximumValueCount`).
/// A byte limit alone cannot bound recursive decoding stack use or memory use after decoding.
///
/// Leaving the request's `Compress` empty makes the payload uncompressed JSON. `shortcut:` no zstd decoder. Add one if the production
/// server rejects uncompressed responses (see "Framing and Delta Application" in `docs/contracts/SwiftailControl.md`).
/// `docs/protocol-notes/control-map.md` §3.1 and §3.5.
public struct MapResponseFramer: Sendable {
    /// The maximum payload of one frame (8MiB), far below Go's 256MiB. This is due to the iOS packet tunnel extension's memory limit
    /// (about 50MiB, as reported by the first adopter).
    ///
    /// The limit is based on peak decoding memory. The entire frame is buffered before decoding, so its byte buffer and decoded values coexist in memory. With normal
    /// data filling the limit, the decoded result for a 64MiB frame occupied about 110MB (the measurement for `maximumValueCount`). At the same ratio, 8MiB would use
    /// about 14MB. This fits within the 50MiB limit even on top of idle resident memory (target at most 20MiB). An uncompressed full map for a tailnet
    /// with 1,000 peers is estimated to be several MB, and this is unverified. A tailnet over this limit cannot receive its map,
    /// so adjust the limit if real device measurements show `frameTooLarge` (`docs/contracts/SwiftailTunnel.md` behavior M and item T5 under "Lead session confirmation needed").
    static let maximumFrameSize = 8 << 20

    /// The maximum payload JSON nesting depth (the top-level object is 1). Exceeding it yields `malformed`.
    ///
    /// `Decodable` decoding is recursive, so deeply nested JSON exhausts the stack and kills the process (the error cannot be caught).
    /// - Actual tailcfg depth: The maximum across 73 responses in the Go data (`map-sessions.json`) is 7. The deepest path is
    ///   `PacketFilter[].CapGrant[].CapMap.<capability>[]` with argument JSON appended, at depth 9 + the argument's depth.
    /// - Stack: Decoding nested `CapMap` argument arrays in a Debug build on a secondary thread with the default stack (512KiB)
    ///   survives depth 210 and overflows at 215 (about 2.4KiB per level). 64 levels use about 155KiB, less than a third
    ///   of the stack, leaving room even when the caller is already using stack space.
    static let maximumNestingDepth = 64

    /// The maximum number of values (array elements + object members) per payload. Exceeding it yields `malformed`.
    ///
    /// Memory occupied by decoded values is not proportional to JSON size. An empty object `{}` plus a separating comma takes 3 bytes and yields one `Node` (392-byte stride),
    /// so a single frame can contain millions of nodes (8MiB ÷ 3 ≈ 2.8 million). The value count bounds memory after decoding.
    /// - Normal size: One node in the Go data has 8~29 values (223~729 bytes). A full map with 10,000 peers contains
    ///   29 × 10,000 = 290,000 node values and 60,000 profile values (about 6 per profile), or about 350,000 values. 1,000,000 is
    ///   about 2.9 times that and fits 10,000 nodes at 100 values per node, before counting profile or other map values.
    /// - Measured memory (Debug, phys_footprint before and after decoding): 100,000 copies of the largest node in the Go data (29 values) used
    ///   about 3.2KB per node (about 110 bytes per value). The empty `Node` `{}` (392-byte stride) has the largest expansion for one value, and
    ///   100,000 copies used about 1.3KB per node. These measurements include the decoder's intermediate representation and array growth.
    /// - Worst-case memory: 1,000,000 × 1.3KB ≈ 1.3GB (with only a byte limit, 8MiB ÷ 3 × 1.3KB ≈ 3.6GB).
    ///   Normal data filling 64MiB occupied about 110MB, which gives an estimate of about 14MB for 8MiB. Normal data fits within the 50MB extension limit,
    ///   but the worst case exceeds it. This limit bounds the size so decoding can complete without guaranteeing the extension's
    ///   memory usage. Noise authenticates the control server.
    static let maximumValueCount = 1_000_000

    private static let headerSize = 4

    /// Bytes of a frame that has yet to arrive in full.
    private var buffer: [UInt8] = []
    /// The error after failure. If present, returns the same error without buffering more bytes.
    private var failure: MapError?

    public init() {}

    /// Accepts incoming bytes and returns complete responses in order. Keeps incomplete frames buffered.
    /// Discard the stream on error. An error also withholds responses completed earlier in the same call. The new stream
    /// starts with the full map again, so no state is lost. Failure discards buffered bytes, and subsequent calls yield the same error.
    public mutating func receive(_ bytes: [UInt8]) throws(MapError) -> [MapResponse] {
        if let failure { throw failure }
        do {
            return try decodeFrames(appending: bytes)
        } catch {
            failure = error
            buffer = []
            throw error
        }
    }

    private mutating func decodeFrames(appending bytes: [UInt8]) throws(MapError) -> [MapResponse] {
        buffer += bytes
        var responses: [MapResponse] = []
        var start = 0
        while buffer.count - start >= Self.headerSize {
            let length = buffer[start..<start + Self.headerSize].reversed().reduce(0) { $0 << 8 | Int($1) }
            guard length <= Self.maximumFrameSize else { throw .frameTooLarge }
            let payloadStart = start + Self.headerSize
            guard buffer.count - payloadStart >= length else { break }
            let payload = buffer[payloadStart..<payloadStart + length]
            try Self.checkShape(of: payload)
            do {
                responses.append(try JSONDecoder().decode(MapResponse.self, from: Data(payload)))
            } catch {
                throw .malformed
            }
            start = payloadStart + length
        }
        buffer.removeFirst(start)
        return responses
    }

    /// Scans JSON bytes once before decoding to check that nesting depth and value count are within their limits.
    ///
    /// This scan leaves syntax validation to the decoder. Brackets and commas within strings do not count, and an escaped `\"` does
    /// not end a string. UTF-8 multibyte characters use bytes at or above 0x80, which cannot be confused with ASCII delimiters.
    /// Counts values per container as the first value plus the number of commas.
    ///
    /// Rejects input containing a zero byte. `JSONDecoder` also accepts JSON in UTF-16 and UTF-32. Scanning those bytes as UTF-8
    /// would interpret quotes and brackets differently, making this check disagree with the decoder. UTF-16 and UTF-32 JSON contain
    /// zero bytes at every delimiter. UTF-8 JSON cannot contain zero bytes because control characters must be escaped,
    /// so the check leaves only UTF-8.
    static func checkShape(of json: ArraySlice<UInt8>) throws(MapError) {
        var depth = 0
        var values = 0
        var inString = false
        var escaped = false
        var awaitingFirstValue = false
        for byte in json {
            guard byte != 0 else { throw .malformed }
            if inString {
                if escaped {
                    escaped = false
                } else if byte == UInt8(ascii: "\\") {
                    escaped = true
                } else if byte == UInt8(ascii: "\"") {
                    inString = false
                }
                continue
            }
            switch byte {
            case UInt8(ascii: " "), UInt8(ascii: "\t"), UInt8(ascii: "\n"), UInt8(ascii: "\r"):
                continue
            case UInt8(ascii: "]"), UInt8(ascii: "}"):
                awaitingFirstValue = false
                depth -= 1
                continue
            default:
                break
            }
            if awaitingFirstValue {
                awaitingFirstValue = false
                values += 1
            }
            switch byte {
            case UInt8(ascii: "\""):
                inString = true
            case UInt8(ascii: "["), UInt8(ascii: "{"):
                depth += 1
                guard depth <= maximumNestingDepth else { throw .malformed }
                awaitingFirstValue = true
            case UInt8(ascii: ","):
                values += 1
            default:
                break
            }
            guard values <= maximumValueCount else { throw .malformed }
        }
    }
}
