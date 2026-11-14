import Foundation
import Testing
@testable import Swiftail

/// 노드 상태 기계. 계약 `docs/contracts/SwiftailTunnel.md` 동작 B, 시험 목록 5.
@Suite("노드 상태 기계")
struct NodeStateMachineTests {
    private static let firstURL = URL(string: "https://login.example.com/a/1111")
    private static let secondURL = URL(string: "https://login.example.com/a/2222")

    @Test("처음은 starting이고, netmap 전에는 연결이 서도 starting이다(2)")
    func startsInStarting() {
        var machine = NodeStateMachine()
        #expect(machine.state == .starting)
        #expect(machine.connected() == nil)
        #expect(machine.registered() == nil)
        #expect(machine.state == .starting)
    }

    @Test("loginRequired는 netmap·연결보다 앞서고, registered가 URL을 지운다(1)")
    func loginRequiredWins() throws {
        let first = try #require(Self.firstURL), second = try #require(Self.secondURL)
        var machine = NodeStateMachine()
        #expect(machine.loginRequired(first) == .needsLogin(first))
        #expect(machine.loginRequired(first) == nil, "같은 상태는 다시 내지 않는다")
        #expect(machine.receivedNetmap(machineAuthorized: true) == nil)
        #expect(machine.connected() == nil)
        #expect(machine.loginRequired(second) == .needsLogin(second), "URL이 바뀌면 다른 상태다")
        // registered가 URL을 지우면 아래 행으로 내려간다: netmap 있음, 승인됨, 연결 선 적 있음 → running.
        #expect(machine.registered() == .running)
    }

    @Test("registered가 URL을 지우면 netmap 전은 starting이다")
    func registeredClearsURL() throws {
        var machine = NodeStateMachine()
        _ = machine.loginRequired(try #require(Self.firstURL))
        #expect(machine.registered() == .starting)
    }

    @Test("승인되지 않은 자기 노드는 연결이 서 있어도 needsMachineAuth다(3)")
    func machineAuthBeforeRunning() {
        var machine = NodeStateMachine()
        _ = machine.connected()
        #expect(machine.receivedNetmap(machineAuthorized: false) == .needsMachineAuth)
        #expect(machine.receivedNetmap(machineAuthorized: true) == .running)
    }

    @Test("netmap 뒤 연결이 서기 전은 starting, 서면 running이다(5·6)")
    func runningNeedsConnection() {
        var machine = NodeStateMachine()
        #expect(machine.receivedNetmap(machineAuthorized: true) == nil)
        #expect(machine.state == .starting)
        #expect(machine.connected() == .running)
        #expect(machine.connected() == nil, "같은 상태는 다시 내지 않는다")
    }

    @Test("running 뒤 새 netmap과 끊김에도 running이고, 승인이 풀리면 needsMachineAuth다(4·3)")
    func runningStays() {
        var machine = NodeStateMachine()
        _ = machine.receivedNetmap(machineAuthorized: true)
        _ = machine.connected()
        // 끊김은 입력이 아니다. 새 netmap이 와도 running 그대로다.
        #expect(machine.receivedNetmap(machineAuthorized: true) == nil)
        #expect(machine.state == .running)
        #expect(machine.receivedNetmap(machineAuthorized: false) == .needsMachineAuth)
        #expect(machine.receivedNetmap(machineAuthorized: true) == .running)
    }

    @Test("running 뒤 키 만료로 로그인이 필요하면 needsLogin, 다시 등록되면 running이다")
    func reloginFromRunning() throws {
        let url = try #require(Self.firstURL)
        var machine = NodeStateMachine()
        _ = machine.receivedNetmap(machineAuthorized: true)
        _ = machine.connected()
        #expect(machine.loginRequired(url) == .needsLogin(url))
        #expect(machine.registered() == .running)
    }
}
