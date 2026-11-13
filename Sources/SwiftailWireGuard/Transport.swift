/// transport 메시지의 암복호화와 패딩.
///
/// IP 패킷을 16바이트 배수로 0 패딩해 길이 정보를 흐린 뒤 keypair의 송신 키와 counter로 암호화한다.
/// 평문이 빈 transport는 keepalive다.
///
/// 백서 §5.4.6, `docs/protocol-notes/wireguard.md` "전송 데이터: 보내기"·"전송 데이터: 받기"
/// (출처: wireguard-go `device/send.go`, `device/receive.go`).
extension Keypair {
    /// 다음 counter로 패킷을 암호화한다. 호출하는 쪽은 먼저 `canSend(at:)`을 확인한다.
    // shortcut: 패킷마다 패딩·암호문·메시지 배열을 새로 만든다(버퍼 재사용 없음). M5 실기기 처리량·메모리 측정에서 병목으로 확인되면 올린다.
    mutating func seal(_ packet: [UInt8]) -> TransportData {
        let counter = sendNonce
        sendNonce += 1
        let padded = packet + [UInt8](repeating: 0, count: Self.paddingSize(for: packet.count, mtu: Constants.defaultMTU))
        return TransportData(
            receiver: remoteIndex,
            counter: counter,
            encryptedPacket: AEAD.seal(padded, key: sendKey, counter: counter)
        )
    }

    /// 복호화만 한다. 재전송 검사는 인증된 뒤 `replayFilter`로 따로 한다.
    func open(_ message: TransportData) -> [UInt8]? {
        AEAD.open(message.encryptedPacket, key: receiveKey, counter: message.counter)
    }

    /// wireguard-go `calculatePaddingSize`. MTU를 넘는 패킷은 MTU로 나눈 나머지 기준으로 패딩하고,
    /// 패딩한 길이가 MTU를 넘지 않게 한다. keepalive(0바이트)는 패딩하지 않는다.
    static func paddingSize(for packetSize: Int, mtu: Int) -> Int {
        let multiple = Constants.paddingMultiple
        let lastUnit = packetSize > mtu ? packetSize % mtu : packetSize
        let padded = min((lastUnit + multiple - 1) / multiple * multiple, mtu)
        return padded - lastUnit
    }
}
