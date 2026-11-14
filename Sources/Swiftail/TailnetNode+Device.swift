import SwiftailIO

/// 터널 장치와 엔진 사이(`docs/contracts/SwiftailTunnel.md` 동작 U).
///
/// ```
/// utun 읽기 / send(_:) ─► deliverFromDevice ─► engine.send ─┬ .ipPacket(로컬 응답, 되돌린 패킷) ─► deliverToDevice
///                                                          └ .datagram ─► Magicsock …
/// engine.receive ─ .ipPacket(피어가 보낸 것) ─► deliverToDevice ─┬ utun 쓰기
///                                                              └ inboundPackets(메모리 장치)
/// ```
///
/// 메모리 장치는 `send`가 utun 읽기 자리에, `inboundPackets`가 utun 쓰기 자리에 들어간다. 그 사이의 처리는 같다.
/// `.inProcess` 장치는 TCP 스택이 장치다: 스택의 출력이 utun 읽기 자리에, 스택의 입력이 utun 쓰기 자리에 들어간다
/// (`TailnetNode+Netstack.swift`).
extension TailnetNode {
    /// 장치에서 읽은 IP 패킷 하나를 엔진에 넣는다. 등록 전이면 버린다.
    func deliverFromDevice(_ ipPacket: [UInt8]) {
        let now = ContinuousClock.now
        process(engine?.send(ipPacket, at: now) ?? [], at: now)
    }

    /// 엔진이 장치로 쓰라고 낸 IP 패킷 하나를 쓴다. 기다리지 않고 큐도 없다. utun 쓰기 실패(`EAGAIN`, `ENOBUFS`,
    /// `EMSGSIZE` 등)는 그 패킷을 버리고 계속한다(동작 U5. IP는 원래 그렇다).
    func deliverToDevice(_ ipPacket: [UInt8]) {
        switch device {
        case .memory:
            inboundContinuation.yield(ipPacket)
        case .inProcess:
            deliverToNetstack(ipPacket)
        case .utun:
            do {
                try tunnel?.write(ipPacket)
            } catch {
                return
            }
        }
    }

    /// utun에서 읽은 패킷을 엔진에 넣는다. 장치가 닫히면(읽기 오류나 끝) `tunnelDeviceClosed`를 돌려준다. 취소되면 nil.
    func readTunnel(_ tunnel: UTUNDevice) async -> NodeError? {
        for await packet in tunnel.packets {
            deliverFromDevice(packet)
        }
        guard let failure = tunnel.readFailure else { return nil }
        Self.log.error("utun 읽기가 끝남: \(failure.message, privacy: .public)")
        return .tunnelDeviceClosed(failure.message)
    }

    /// 시험 전용(공개 API 아님). 메모리 장치를 utun 읽기 오류와 같은 상태로 만든다. `run()`이 `tunnelDeviceClosed("test")`로
    /// 끝난다. `run()` 전에 부르면 `run()`이 시작하자마자 끝난다. utun 장치면 아무 일도 없다(동작 U7).
    package func failMemoryDevice() {
        guard case .memory = device else { return }
        failureContinuation.yield(.tunnelDeviceClosed("test"))
    }
}
