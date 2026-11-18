import Network
import SwiftailBase
import Testing
@testable import SwiftailPairing

@Suite("Pairing addresses on OS sockets")
struct SocketAddressRegressionTests {
    @Test(
        "Connections in the ChromeOS VM address range are rejected as tailnet connections",
        arguments: ["100.115.92.0:4747", "100.115.93.255:4747", "[::ffff:100.115.92.1]:4747"]
    )
    func rejectsChromeOSRange(host: String) throws {
        let endpoints = try Sample.endpoints(host: host)
        #expect(!PairingEndpoints.isTailnetAddress(endpoints.host.address))
        #expect(!endpoints.isOnTailnet(localAddress: endpoints.joiner.address))
    }

    @Test("Resolves the name with an IPv4-mapped localAddress, reaches the IPv4 listener, and checks the local endpoint", .timeLimit(.minutes(2)))
    func mappedLocalAddressDialsIPv4() async throws {
        let parameters = NWParameters.tcp
        parameters.requiredLocalEndpoint = .hostPort(host: "127.0.0.1", port: .any)
        let listener = try NWListener(using: parameters)
        defer { listener.cancel() }
        let (ports, ready) = AsyncStream.makeStream(of: UInt16.self, bufferingPolicy: .bufferingNewest(1))
        listener.newConnectionHandler = { connection in
            connection.start(queue: .global())
            connection.receive(minimumIncompleteLength: 1, maximumLength: 1) { _, _, _, _ in
                connection.cancel()
            }
        }
        listener.stateUpdateHandler = { state in
            switch state {
            case .ready:
                if let port = listener.port { ready.yield(port.rawValue) }
                ready.finish()
            case .failed, .cancelled:
                ready.finish()
            default:
                break
            }
        }
        listener.start(queue: .global())
        var iterator = ports.makeAsyncIterator()
        let port = try #require(await iterator.next())

        // The connection uses IPv4, but the address supplied by the app differs from the connection's local endpoint.
        let mappedAddress = try #require(IPAddress("::ffff:127.0.0.2"))
        let failure = await pairingError {
            try await PairingJoiner.pair(
                with: Sample.offer(host: "localhost", port: port), deviceName: "rd-phone-5e6f7a8b",
                localAddress: mappedAddress, requiringTunnel: false, awaitingApproval: { _ in })
        }
        #expect(failure == .notOnTailnet)
    }
}
