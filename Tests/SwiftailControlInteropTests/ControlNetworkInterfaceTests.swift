import Foundation
import Network
import SwiftailBase
import Testing

@testable import SwiftailControl

/// `ControlClient.setNetworkInterface`를 일부러 어긋나게 구는 제어 서버(`Tools/interop/cmd/controlfaults`) 상대로 본다.
/// 서버가 센 연결·등록·맵 요청 수와 사건으로 확인한다. 서버가 루프백이라 인터페이스로 묶이지는 않는다
/// (`NetworkSocket.bindableInterface`). 다시 잇는 동작만 본다. 묶음 자체는 `SwiftailIOTests`가 확인한다.
@Suite("제어 클라이언트: 인터페이스 변경", .enabled(if: controlFaultsBinary != nil,
    "SWIFTAIL_CONTROLFAULTS가 없어 건너뜁니다"), .timeLimit(.minutes(2)))
struct ControlNetworkInterfaceTests {
    @Test("인터페이스를 바꾸면 지금 연결을 끊고 새 연결로 맵을 다시 받는다. 등록은 다시 하지 않는다")
    func reconnectsOnInterfaceChange() async throws {
        let interface = try #require(await loopbackInterface(), "루프백 인터페이스가 없다")
        try await withFaultClient("basic") { server, client, _ in
            _ = try await client.registered("첫 등록")
            try await client.nextNetmap("첫 netmap")
            #expect(try await server.probe().connections == 1)

            await client.client.setNetworkInterface(interface)
            // 끊긴 연결은 disconnected로 알리고, 새 연결의 맵 스트림이 전체 netmap을 다시 낸다.
            try await client.nextDisconnected("옛 연결의 끊김")
            try await client.nextNetmap("새 연결의 netmap")
            let probe = try await server.wait("두 번째 연결의 맵 스트림", timeout: .seconds(5)) { $0.connections == 2 && $0.maps >= 4 }
            #expect(probe.registers == 1, "등록 상태를 유지하므로 다시 등록하지 않는다")
            #expect(probe.nodeKeys == 1)
        }
    }

    @Test("같은 인터페이스를 다시 알려도 그만큼 다시 잇는다")
    func sameInterfaceReconnectsAgain() async throws {
        let interface = try #require(await loopbackInterface(), "루프백 인터페이스가 없다")
        try await withFaultClient("basic") { server, client, _ in
            try await client.nextNetmap("첫 netmap")
            await client.client.setNetworkInterface(interface)
            _ = try await server.wait("두 번째 연결", timeout: .seconds(5)) { $0.connections == 2 }
            try await client.nextNetmap("두 번째 연결의 netmap")
            await client.client.setNetworkInterface(interface)
            _ = try await server.wait("세 번째 연결", timeout: .seconds(5)) { $0.connections == 3 }
            try await client.nextNetmap("세 번째 연결의 netmap")
        }
    }

    @Test("연달아 여러 번 알려도 마지막 값으로 이어지고 연결이 끝없이 늘지 않는다")
    func burstSettles() async throws {
        let interface = try #require(await loopbackInterface(), "루프백 인터페이스가 없다")
        try await withFaultClient("basic") { server, client, _ in
            try await client.nextNetmap("첫 netmap")
            for _ in 0..<5 { await client.client.setNetworkInterface(interface) }
            try await client.nextNetmap("다시 이은 뒤의 netmap")
            try await Task.sleep(for: .milliseconds(500))
            let connections = try await server.probe().connections
            #expect((2...6).contains(connections), "연결 수 \(connections)")
            // 안정된 뒤에는 더 늘지 않는다.
            try await Task.sleep(for: .milliseconds(500))
            #expect(try await server.probe().connections == connections)
        }
    }

    /// 서버가 등록을 붙잡고 있는 동안(연결 위에서 응답을 기다리는 중)에 바꿔도 새 연결에서 등록이 끝난다.
    @Test("등록 응답을 기다리는 중에 인터페이스가 바뀌어도 새 연결에서 같은 키로 등록이 끝난다")
    func changeDuringRegistration() async throws {
        let interface = try #require(await loopbackInterface(), "루프백 인터페이스가 없다")
        try await withFaultClient("interactiveRace") { server, client, _ in
            _ = try await server.wait("붙잡힌 첫 등록", timeout: .seconds(5)) { $0.registers == 1 }
            await client.client.setNetworkInterface(interface)
            _ = try await server.wait("새 연결의 등록", timeout: .seconds(5)) { $0.connections == 2 && $0.registers == 2 }
            try await server.release()
            _ = try await client.registered("등록 완료")
        }
    }

    @Test("run()을 시작하기 전에 알린 인터페이스는 기억만 하고, 첫 연결을 한 번 더 잇게 하지 않는다")
    func interfaceBeforeRunIsOnlyRemembered() async throws {
        let interface = try #require(await loopbackInterface(), "루프백 인터페이스가 없다")
        try await withFaultServer("basic") { server, directory in
            let client = ControlClient(
                configuration: .init(serverURL: server.url, hostname: "rd-mac-1a2b3c4d"),
                identityStore: NodeIdentityStore(directory: directory)
            )
            await client.setNetworkInterface(interface)
            let running = Task { try await client.run() }
            defer { running.cancel() }
            for await event in client.events {
                if case .netmap = event { break }
            }
            try await Task.sleep(for: .milliseconds(500))
            #expect(try await server.probe().connections == 1)
        }
    }
}

private func loopbackInterface() async -> NWInterface? {
    let monitor = NWPathMonitor(requiredInterfaceType: .loopback)
    defer { monitor.cancel() }
    for await path in monitor { return path.availableInterfaces.first }
    return nil
}

extension FaultClient {
    /// 다음 netmap까지 기다린다. 그 사이의 다른 사건은 건너뛴다.
    func nextNetmap(_ description: String, timeout: Duration = .seconds(5)) async throws {
        let deadline = ContinuousClock.now + timeout
        while true {
            if case .netmap = try await next(description, timeout: ContinuousClock.now.duration(to: deadline)) { return }
        }
    }

    /// 다음 `disconnected`까지 기다린다. 그 사이의 다른 사건은 건너뛴다.
    func nextDisconnected(_ description: String, timeout: Duration = .seconds(5)) async throws {
        let deadline = ContinuousClock.now + timeout
        while true {
            if case .disconnected = try await next(description, timeout: ContinuousClock.now.duration(to: deadline)) { return }
        }
    }
}
