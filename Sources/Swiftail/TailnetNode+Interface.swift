import Network
import SwiftailBase
import SwiftailIO
import SwiftailMagicsock

/// 기본 인터페이스 전환과 UDP 소켓의 수명(`docs/contracts/SwiftailTunnel.md` 동작 N).
///
/// Swiftail에는 `AF_ROUTE` 감시가 없으므로 앱이 부르는 `setDefaultInterface`가 망 전환의 유일한 통지원이다(결정 D6).
/// 통지마다 로컬 주소를 다시 읽고 `DefaultLink.change(from:tunnelName:)`로 할 일을 정한다.
///
/// 재결속의 순서(Go 엔진의 순서, 노트 dns-state-node 4.6.3 1):
/// 1. 새 인터페이스를 "지금 인터페이스"로 둔다. 이후 여는 모든 소켓과 연결이 여기에 묶인다.
/// 2. DERP: 열린 지역 연결을 모두 닫고 홈 지역을 새 인터페이스로 다시 연다.
/// 3. UDP: 소켓을 닫고 같은 포트로 다시 묶는다(안 되면 포트 0, 그것도 안 되면 인터페이스에 묶지 않은 소켓. 소켓을
///    아예 만들 수 없을 때만 `run()`이 `udpUnavailable`로 끝난다).
///    이어서 `Magicsock.rebind` → 출력을 순서대로 처리 → `nextDeadline`에 맞춘 `advance`(타이머가 한다).
/// 4. 제어: `ControlClient.setNetworkInterface`가 지금 연결을 닫고 새 인터페이스로 곧바로 다시 잇는다.
/// 5. 설정: netmap이 바뀌지 않았으므로 다시 내지 않는다(동작 E 2).
///
/// 옛 소켓의 `close(2)`는 그 소켓의 디스패치 큐에서 뒤늦게 일어나므로 같은 포트를 곧바로 묶으면 `EADDRINUSE`가 난다.
/// 그래서 3은 자식 `rebindUDP()`가 잠깐씩 기다리며 다시 시도한다. 그동안 소켓이 없으므로 UDP로 보낼 것은 버려진다(DERP가
/// 함께 나가거나 WireGuard·disco가 다시 보낸다).
///
/// - `shortcut:` 열린 DERP 연결은 모두 다시 연다. Go는 로컬 주소가 기본 인터페이스 주소인 연결을 남기고 3초 Ping으로
///   확인한다. 비용은 홈이 아닌 연결의 재연결뿐이다. 필요해지는 시점: 실기기 전환에서 재연결 지연이 문제일 때.
/// - `shortcut:` 망이 내려감(만족된 경로 없음)은 다루지 않는다. 앱은 만족된 경로만 알린다. 끊긴 동안 연결은 각자의
///   재시도·물러남으로 버틴다. 필요해지는 시점: 망이 없는 동안의 재시도가 배터리·메모리에 문제일 때.
/// - `shortcut:` UDP 송신 오류(`EPERM`·broken pipe)에 따른 자동 재결속은 없다. 필요해지는 시점: 실기기 전환 시험에서
///   `setDefaultInterface` 없이 소켓이 죽을 때.
extension TailnetNode {
    /// 같은 포트로 다시 묶기를 시도하는 횟수와 간격. 옛 소켓이 닫히기를 기다린다(합쳐 0.5초).
    static let rebindAttempts = 25
    static let rebindRetryInterval = Duration.milliseconds(20)

    /// 기기의 기본 경로가 이 인터페이스로 간다(앱의 `NWPathMonitor`). 노드의 제어·DERP·UDP 소켓을 이 인터페이스에 묶고,
    /// 바뀌었으면 다시 묶는다.
    ///
    /// 만족된 경로를 받을 때마다 거르지 않고 불러도 된다. 같은 인터페이스·같은 주소면 STUN만 다시 한다(같은 Wi-Fi에서
    /// 주소만 바뀐 경우를 노드가 알 길은 이 호출뿐이다). 이 노드의 utun이면 무시한다. `run()` 전이나 끝난 뒤의 호출은
    /// 마지막 값만 기억하고, `run()`이 시작할 때 그 인터페이스로 연다.
    public func setDefaultInterface(_ interface: NWInterface) {
        // 읽지 못하면 주소 없이 판정한다. local 엔드포인트 없이 STUN이 찾은 것만 올라간다.
        let link = DefaultLink(interface, addresses: (try? LocalInterfaceAddresses.current()) ?? ([], []))
        let change = link.change(from: defaultLink, tunnelName: tunnelName)
        guard change != .ignore else { return }
        guard isRunning else {
            defaultInterface = interface
            return
        }
        switch change {
        case .ignore:
            return
        case .restartSTUN:
            Self.log.debug("기본 인터페이스 같음(\(interface.name, privacy: .public)): STUN 다시 시작")
            let now = ContinuousClock.now
            process(magicsock?.restartSTUN(at: now) ?? [], at: now)
        case .rebind:
            Self.log.info("기본 인터페이스 재결속: \(interface.name, privacy: .public)")
            defaultInterface = interface
            defaultLink = link
            interfaceAddresses = (link.addresses, link.loopbackAddresses)
            closeAllDERPLinks()
            if homeRegion != 0 {
                openDERPLink(to: homeRegion)
            }
            rebindContinuation.yield()
        }
    }

    // MARK: UDP 소켓

    /// 지금 인터페이스에 묶은 UDP 소켓을 연다.
    func openSocket(port: UInt16) throws(NodeError) -> DatagramSocket {
        do {
            return try DatagramSocket(port: port, interfaceIndex: defaultInterface.flatMap { UInt32(exactly: $0.index) })
        } catch {
            throw .udpUnavailable(error.message)
        }
    }

    /// OS가 고른 포트로 소켓을 연다. 지금 인터페이스에 묶지 못하면 묶지 않은 소켓으로 대신한다.
    ///
    /// 알려 준 인터페이스가 그사이 사라졌으면(Wi-Fi가 흔들림, 비행기 모드) 묶기가 실패한다. 그것은 다시 켜도 소용없는
    /// 실패가 아니므로 `run()`을 끝내지 않는다. 묶지 않은 소켓으로 버티고, 마지막 링크를 지워 다음
    /// `setDefaultInterface`가 무엇을 알리든 다시 묶게 한다. 소켓을 아예 만들 수 없을 때만 던진다.
    func openSocketOnAnyPort() throws(NodeError) -> DatagramSocket {
        if let bound = try? openSocket(port: 0) { return bound }
        do {
            let unbound = try DatagramSocket(port: 0)
            if defaultInterface != nil {
                Self.log.error("UDP 소켓을 기본 인터페이스에 묶지 못해 묶지 않고 연다")
            }
            defaultLink = nil
            return unbound
        } catch {
            throw .udpUnavailable(error.message)
        }
    }

    /// 새 소켓을 지금 소켓으로 두고 읽기를 시작한다.
    func adopt(_ socket: DatagramSocket) {
        self.socket = socket
        openedSocketContinuation.yield(socket)
    }

    /// 열린 소켓마다 그 데이터그램을 `Magicsock`에 넣는다. 소켓이 닫히면 그 소켓의 일이 끝난다. 취소될 때까지 돈다.
    func receiveUDP() async {
        await withDiscardingTaskGroup { group in
            for await socket in openedSockets {
                group.addTask { await self.receiveUDP(from: socket) }
            }
        }
    }

    private func receiveUDP(from socket: DatagramSocket) async {
        for await (bytes, source) in socket.datagrams {
            guard !blockedUDPPorts.contains(source.port) else { continue }
            let now = ContinuousClock.now
            process(magicsock?.receiveUDP(bytes, from: source, at: now) ?? [], at: now)
        }
        // 닫지도 취소하지도 않았는데 흐름이 끝났다면 소켓의 읽기가 오류로 멈춘 것이다. 그대로 두면 보내기만 하고 받지
        // 못하는 소켓이 남으므로 새로 연다.
        if self.socket === socket, !Task.isCancelled {
            Self.log.error("UDP 수신이 멈춤: 소켓을 다시 연다")
            rebindContinuation.yield()
        }
    }

    /// 재결속 요청마다 소켓을 지금 인터페이스로 다시 연다(3). 겹친 요청은 하나로 합쳐지고, 기다리는 동안 인터페이스가 또
    /// 바뀌면 다음 요청이 그 인터페이스로 다시 연다. 취소될 때까지 돈다.
    func rebindUDP() async {
        for await _ in rebindRequests {
            let port = closeSocket()
            var reopened: DatagramSocket?
            for attempt in 0..<Self.rebindAttempts where reopened == nil {
                if attempt > 0 {
                    do {
                        try await Task.sleep(for: Self.rebindRetryInterval)
                    } catch {
                        return
                    }
                }
                reopened = try? openSocket(port: port)
            }
            do throws(NodeError) {
                if reopened == nil {
                    reopened = try openSocketOnAnyPort()
                }
            } catch {
                Self.log.error("재결속: UDP 소켓을 열지 못함(\(error.kind, privacy: .public))")
                failureContinuation.yield(error)
                return
            }
            if let reopened {
                adoptRebound(reopened)
            }
        }
    }

    /// 지금 소켓을 닫고 그 포트를 돌려준다. 소켓이 없으면 0(OS가 고른다).
    private func closeSocket() -> UInt16 {
        defer {
            socket?.close()
            socket = nil
        }
        return socket?.localPort ?? 0
    }

    /// 다시 연 소켓을 쓰고 `Magicsock`에 알린 뒤(직접 경로를 버리고 STUN을 곧바로 시작) 제어 연결을 다시 잇는다(4).
    private func adoptRebound(_ socket: DatagramSocket) {
        adopt(socket)
        Self.log.info("재결속: UDP 포트 \(socket.localPort, privacy: .public)")
        let now = ContinuousClock.now
        process(
            magicsock?.rebind(
                localPort: socket.localPort,
                localAddresses: interfaceAddresses.regular,
                loopbackAddresses: interfaceAddresses.loopback,
                at: now
            ) ?? [],
            at: now
        )
        if let defaultInterface {
            interfaceContinuation.yield(defaultInterface)
        }
    }
}
