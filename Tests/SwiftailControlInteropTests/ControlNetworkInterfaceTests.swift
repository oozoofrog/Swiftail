import Foundation
import Network
import SwiftailBase
import Testing

@testable import SwiftailControl

/// Tests `ControlClient.setNetworkInterface` against a deliberately misbehaving control server (`Tools/interop/cmd/controlfaults`).
/// Verifies events and the server's counts of connections, registrations, and map requests. The loopback server does not bind to an interface
/// (`NetworkSocket.bindableInterface`). Checks only reconnection behavior. `SwiftailIOTests` verifies binding itself.
@Suite("Control client: Interface change", .enabled(if: controlFaultsBinary != nil,
    "Skipping because SWIFTAIL_CONTROLFAULTS is missing"), .timeLimit(.minutes(2)))
struct ControlNetworkInterfaceTests {
    @Test("Changing the interface closes the current connection and receives the map again on a new connection without re-registering")
    func reconnectsOnInterfaceChange() async throws {
        let interface = try #require(await loopbackInterface(), "No loopback interface")
        try await withFaultClient("basic") { server, client, _ in
            _ = try await client.registered("First registration")
            try await client.nextNetmap("First netmap")
            #expect(try await server.probe().connections == 1)

            await client.client.setNetworkInterface(interface)
            // The dropped connection is reported as disconnected, and the map stream on the new connection emits the full netmap again.
            try await client.nextDisconnected("Old connection dropped")
            try await client.nextNetmap("Netmap on the new connection")
            let probe = try await server.wait("Map stream on the second connection", timeout: .seconds(5)) { $0.connections == 2 && $0.maps >= 4 }
            #expect(probe.registers == 1, "Preserves registration state, so it does not re-register")
            #expect(probe.nodeKeys == 1)
        }
    }

    @Test("Reporting the same interface again reconnects each time")
    func sameInterfaceReconnectsAgain() async throws {
        let interface = try #require(await loopbackInterface(), "No loopback interface")
        try await withFaultClient("basic") { server, client, _ in
            try await client.nextNetmap("First netmap")
            await client.client.setNetworkInterface(interface)
            _ = try await server.wait("Second connection", timeout: .seconds(5)) { $0.connections == 2 }
            try await client.nextNetmap("Netmap on the second connection")
            await client.client.setNetworkInterface(interface)
            _ = try await server.wait("Third connection", timeout: .seconds(5)) { $0.connections == 3 }
            try await client.nextNetmap("Netmap on the third connection")
        }
    }

    @Test("Several consecutive updates connect with the last value without unbounded connection growth")
    func burstSettles() async throws {
        let interface = try #require(await loopbackInterface(), "No loopback interface")
        try await withFaultClient("basic") { server, client, _ in
            try await client.nextNetmap("First netmap")
            for _ in 0..<5 { await client.client.setNetworkInterface(interface) }
            try await client.nextNetmap("Netmap after reconnecting")
            try await Task.sleep(for: .milliseconds(500))
            let connections = try await server.probe().connections
            #expect((2...6).contains(connections), "Connection count \(connections)")
            // Stops growing once stable.
            try await Task.sleep(for: .milliseconds(500))
            #expect(try await server.probe().connections == connections)
        }
    }

    /// Changing the interface while the server holds registration (waiting for a response on the connection) still completes registration on the new connection.
    @Test("Changing interfaces while waiting for a registration response completes registration on the new connection with the same key")
    func changeDuringRegistration() async throws {
        let interface = try #require(await loopbackInterface(), "No loopback interface")
        try await withFaultClient("interactiveRace") { server, client, _ in
            _ = try await server.wait("Held first registration", timeout: .seconds(5)) { $0.registers == 1 }
            await client.client.setNetworkInterface(interface)
            _ = try await server.wait("Registration on the new connection", timeout: .seconds(5)) { $0.connections == 2 && $0.registers == 2 }
            try await server.release()
            _ = try await client.registered("Registration complete")
        }
    }

    @Test("Remembers the interface reported before run() starts without reconnecting the initial connection")
    func interfaceBeforeRunIsOnlyRemembered() async throws {
        let interface = try #require(await loopbackInterface(), "No loopback interface")
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
    /// Waits for the next netmap. Skips other intervening events.
    func nextNetmap(_ description: String, timeout: Duration = .seconds(5)) async throws {
        let deadline = ContinuousClock.now + timeout
        while true {
            if case .netmap = try await next(description, timeout: ContinuousClock.now.duration(to: deadline)) { return }
        }
    }

    /// Waits for the next `disconnected` event. Skips other intervening events.
    func nextDisconnected(_ description: String, timeout: Duration = .seconds(5)) async throws {
        let deadline = ContinuousClock.now + timeout
        while true {
            if case .disconnected = try await next(description, timeout: ContinuousClock.now.duration(to: deadline)) { return }
        }
    }
}
