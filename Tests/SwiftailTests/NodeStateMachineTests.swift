import Foundation
import Testing
@testable import Swiftail

/// The node state machine. Contract `docs/contracts/SwiftailTunnel.md` behavior B, test list 5.
@Suite("Node state machine")
struct NodeStateMachineTests {
    private static let firstURL = URL(string: "https://login.example.com/a/1111")
    private static let secondURL = URL(string: "https://login.example.com/a/2222")

    @Test("Starts in starting and stays there until a netmap arrives, even if a connection comes up (2)")
    func startsInStarting() {
        var machine = NodeStateMachine()
        #expect(machine.state == .starting)
        #expect(machine.connected() == nil)
        #expect(machine.registered() == nil)
        #expect(machine.state == .starting)
    }

    @Test("loginRequired takes precedence over a netmap and a connection, and registered clears the URL (1)")
    func loginRequiredWins() throws {
        let first = try #require(Self.firstURL), second = try #require(Self.secondURL)
        var machine = NodeStateMachine()
        #expect(machine.loginRequired(first) == .needsLogin(first))
        #expect(machine.loginRequired(first) == nil, "Does not emit the same state again")
        #expect(machine.receivedNetmap(machineAuthorized: true) == nil)
        #expect(machine.connected() == nil)
        #expect(machine.loginRequired(second) == .needsLogin(second), "A changed URL means a different state")
        // After registered clears the URL, move down to the next applicable row: netmap present, authorized, connection has come up → running.
        #expect(machine.registered() == .running)
    }

    @Test("When registered clears the URL before a netmap arrives, the state is starting")
    func registeredClearsURL() throws {
        var machine = NodeStateMachine()
        _ = machine.loginRequired(try #require(Self.firstURL))
        #expect(machine.registered() == .starting)
    }

    @Test("An unauthorized local node is needsMachineAuth even when a connection is up (3)")
    func machineAuthBeforeRunning() {
        var machine = NodeStateMachine()
        _ = machine.connected()
        #expect(machine.receivedNetmap(machineAuthorized: false) == .needsMachineAuth)
        #expect(machine.receivedNetmap(machineAuthorized: true) == .running)
    }

    @Test("After the netmap arrives, the state is starting before a connection comes up and running afterward (5·6)")
    func runningNeedsConnection() {
        var machine = NodeStateMachine()
        #expect(machine.receivedNetmap(machineAuthorized: true) == nil)
        #expect(machine.state == .starting)
        #expect(machine.connected() == .running)
        #expect(machine.connected() == nil, "Does not emit the same state again")
    }

    @Test("After running, a new netmap and disconnection leave it running. Revoking authorization changes it to needsMachineAuth (4·3)")
    func runningStays() {
        var machine = NodeStateMachine()
        _ = machine.receivedNetmap(machineAuthorized: true)
        _ = machine.connected()
        // Disconnection is not an input. The state remains running even when a new netmap arrives.
        #expect(machine.receivedNetmap(machineAuthorized: true) == nil)
        #expect(machine.state == .running)
        #expect(machine.receivedNetmap(machineAuthorized: false) == .needsMachineAuth)
        #expect(machine.receivedNetmap(machineAuthorized: true) == .running)
    }

    @Test("After running, key expiration requiring login yields needsLogin, and reregistration yields running")
    func reloginFromRunning() throws {
        let url = try #require(Self.firstURL)
        var machine = NodeStateMachine()
        _ = machine.receivedNetmap(machineAuthorized: true)
        _ = machine.connected()
        #expect(machine.loginRequired(url) == .needsLogin(url))
        #expect(machine.registered() == .running)
    }
}
