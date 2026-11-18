import CryptoKit

/// The transport phase, converting between a plaintext byte stream and Noise records.
///
/// A record is up to 4,096 bytes including its header, with up to 4,077 bytes of plaintext. Sending splits plaintext into
/// chunks of that size. Receiving opens only complete records from arbitrary byte chunks and concatenates their plaintext. Record
/// boundaries are independent of higher-layer (HTTP/2) data boundaries.
///
/// Each direction's counter starts at 0 and increases by 1 per record. The nonce is big-endian. Even an empty plaintext record
/// verifies the tag and consumes a nonce. Records have no AAD. There is no termination message.
///
/// A malformed or unopenable received record means the nonce is out of sync with the peer, so the session discards the keys and becomes `closed`.
/// Go clears keys only on authentication failure. This session never restarts after any receive error.
///
/// `docs/protocol-notes/control-transport.md` §3.4, §3.5, §4.6
/// (origin: tailscale.com `control/controlbase/conn.go`).
public struct ControlSession: Sendable {
    private var sender: RecordCipher?
    private var receiver: RecordCipher?
    /// Retains only one incomplete record's worth of bytes (at most 4,095 bytes).
    private var buffer: [UInt8] = []

    init(keys: TransportKeys) {
        sender = RecordCipher(key: keys.send)
        receiver = RecordCipher(key: keys.receive)
    }

    /// Converts plaintext into one or more records. The maximum plaintext per record is 4,077 bytes.
    ///
    /// Empty plaintext produces no record, matching Go's `Write([])`.
    ///
    /// - Throws: `closed` if the session is closed or the send counter is exhausted.
    public mutating func seal(_ plaintext: [UInt8]) throws(ControlTransportError) -> [UInt8] {
        guard var sender else { throw .closed }
        var records: [UInt8] = []
        var start = 0
        while start < plaintext.count {
            let end = min(start + NoiseRecord.maximumPlaintextSize, plaintext.count)
            guard let sealed = sender.seal(Array(plaintext[start..<end])) else {
                close()
                throw .closed
            }
            records += [NoiseMessageType.record] + UInt16(sealed.count).bigEndianBytes + sealed
            start = end
        }
        self.sender = sender
        return records
    }

    /// Accepts incoming bytes and returns concatenated plaintext from complete records. Keeps incomplete records buffered.
    ///
    /// - Throws: `malformed` if the type is not a record, `messageTooLarge` if the record exceeds 4,096 bytes,
    ///   or `authenticationFailed` if it cannot open the record. All cases close the session. Subsequent calls throw `closed`.
    public mutating func receive(_ bytes: [UInt8]) throws(ControlTransportError) -> [UInt8] {
        guard var receiver else { throw .closed }
        buffer += bytes

        var plaintext: [UInt8] = []
        var offset = 0
        do throws(ControlTransportError) {
            while buffer.count - offset >= NoiseHeader.size {
                guard buffer[offset] == NoiseMessageType.record else { throw .malformed }
                let length = Int(UInt16(bigEndianBytes: buffer[(offset + 1)..<(offset + 3)]))
                let recordSize = NoiseHeader.size + length
                guard recordSize <= NoiseRecord.maximumSize else { throw .messageTooLarge }
                guard buffer.count - offset >= recordSize else { break }

                plaintext += try receiver.open(buffer[(offset + NoiseHeader.size)..<(offset + recordSize)])
                offset += recordSize
            }
        } catch {
            close()
            throw error
        }

        buffer.removeFirst(offset)
        self.receiver = receiver
        return plaintext
    }

    /// Discards keys and buffered incoming bytes.
    private mutating func close() {
        sender = nil
        receiver = nil
        buffer = []
    }
}

extension ControlSession: CustomReflectable {
    /// Exposes nothing to `dump` or `print` because it holds transport keys.
    public var customMirror: Mirror { Mirror(self, children: [:]) }
}

/// The key and counter for one direction.
private struct RecordCipher: Sendable {
    let key: SymmetricKey
    /// The next record counter. It becomes unusable at 2⁶⁴−1 (Go's `invalidNonce`).
    private var counter: UInt64 = 0

    init(key: SymmetricKey) {
        self.key = key
    }

    /// Returns `nil` if exhausted.
    mutating func seal(_ plaintext: [UInt8]) -> [UInt8]? {
        guard counter != .max else { return nil }
        defer { counter += 1 }
        return NoiseAEAD.seal(plaintext, key: key, counter: counter)
    }

    /// Consume the counter even if opening fails, as in Go. The session closes anyway.
    mutating func open(_ sealed: ArraySlice<UInt8>) throws(ControlTransportError) -> [UInt8] {
        guard counter != .max else { throw .closed }
        defer { counter += 1 }
        guard let plaintext = NoiseAEAD.open(sealed, key: key, counter: counter) else { throw .authenticationFailed }
        return plaintext
    }
}
