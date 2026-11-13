import CryptoKit

/// 전송 단계: 평문 바이트 스트림 ↔ Noise 레코드.
///
/// 레코드 하나는 머리 포함 4,096바이트까지이고 평문은 4,077바이트까지다. 보낼 때는 평문을 그 단위로
/// 자르고, 받을 때는 임의의 조각으로 온 바이트에서 완성된 레코드만 열어 평문을 이어 붙인다. 레코드
/// 경계는 위 계층(HTTP/2) 데이터의 경계와 무관하다.
///
/// 방향마다 카운터가 0에서 시작해 레코드 하나마다 1씩 늘고 nonce는 빅엔디언이다. 빈 평문 레코드도
/// 태그를 검증하고 nonce를 소비한다. 레코드에는 AAD가 없다. 종료 메시지는 없다.
///
/// 받은 레코드가 형식에 맞지 않거나 열리지 않으면 상대와 nonce가 어긋난 것이므로 키를 버리고 `closed`가
/// 된다. Go는 인증 실패에서만 키를 지우지만, 여기서는 어떤 수신 오류 뒤에도 다시 시작하지 않는다.
///
/// `docs/protocol-notes/control-transport.md` 3.4·3.5절, 4.6절
/// (출처: tailscale.com `control/controlbase/conn.go`).
public struct ControlSession: Sendable {
    private var sender: RecordCipher?
    private var receiver: RecordCipher?
    /// 아직 다 오지 않은 레코드 하나 분량(4,095바이트 이하)만 남는다.
    private var buffer: [UInt8] = []

    init(keys: TransportKeys) {
        sender = RecordCipher(key: keys.send)
        receiver = RecordCipher(key: keys.receive)
    }

    /// 평문을 레코드(들)로 만든다. 한 레코드의 평문은 최대 4,077바이트다.
    ///
    /// 빈 평문은 레코드를 만들지 않는다(Go의 `Write([])`와 같다).
    ///
    /// - Throws: 세션이 닫혔거나 송신 카운터가 고갈되면 `closed`.
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

    /// 받은 바이트를 넣고, 완성된 레코드들의 평문을 이어 돌려준다. 덜 온 레코드는 안에 둔다.
    ///
    /// - Throws: type이 레코드가 아니면 `malformed`, 레코드가 4,096바이트를 넘으면 `messageTooLarge`,
    ///   열리지 않으면 `authenticationFailed`. 어느 경우든 세션은 닫힌다. 닫힌 뒤에는 `closed`.
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

    /// 키와 받던 바이트를 버린다.
    private mutating func close() {
        sender = nil
        receiver = nil
        buffer = []
    }
}

/// 한 방향의 키와 카운터.
private struct RecordCipher: Sendable {
    let key: SymmetricKey
    /// 다음 레코드의 카운터. 2⁶⁴−1에 이르면 더 쓰지 못한다(Go의 `invalidNonce`).
    private var counter: UInt64 = 0

    init(key: SymmetricKey) {
        self.key = key
    }

    /// 고갈되었으면 `nil`.
    mutating func seal(_ plaintext: [UInt8]) -> [UInt8]? {
        guard counter != .max else { return nil }
        defer { counter += 1 }
        return NoiseAEAD.seal(plaintext, key: key, counter: counter)
    }

    /// 열지 못해도 카운터는 소비한다(Go와 같다). 어차피 세션은 닫힌다.
    mutating func open(_ sealed: ArraySlice<UInt8>) throws(ControlTransportError) -> [UInt8] {
        guard counter != .max else { throw .closed }
        defer { counter += 1 }
        guard let plaintext = NoiseAEAD.open(sealed, key: key, counter: counter) else { throw .authenticationFailed }
        return plaintext
    }
}
