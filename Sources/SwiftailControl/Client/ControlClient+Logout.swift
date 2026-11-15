import Foundation
import SwiftailBase
import SwiftailIO

/// 로그아웃: 제어 서버에 지금의 node 키를 만료시키라고 알린다(Go `tailscale logout`의 서버 쪽).
///
/// 등록과 같은 길(Noise 위 `POST /machine/register`)로 저장된 node 키를 그대로 싣고 `Expiry`를 먼 과거로 둔다. 서버는
/// "과거의 `Expiry`와 지금의 node 키"를 그 키의 만료로 받는다(`tailcfg.RegisterRequest.Expiry`의 주석).
///
/// Go와 같은 것: `NodeKey`(지금 키), `NLKey`, `Hostinfo`, 빈 `Followup`, `Ephemeral` 없음, `Expiry` = 1970-01-01T00:02:03Z.
/// 응답은 `Error`만 실패로 보고 `NodeKeyExpired`·`NodeKeySignature`·`AuthURL`은 따르지 않는다(Go `TryLogout`은
/// `doLogin`의 `mustRegen`·`newURL`을 버린다). 다시 시도하지 않는다.
///
/// Go와 다른 것(계약 `docs/contracts/SwiftailHost.md` "로그아웃" 동작 O):
/// - 인증 키를 싣지 않는다. Go는 제어 클라이언트가 인증 키를 쥐고 있으면 로그아웃 요청에도 `Auth`와 감싼 키의 서명을 싣는다.
/// - `OldNodeKey`는 늘 0 키다. Swiftail은 옛 node 키를 저장하지 않는다. Go는 키를 바꾼 적이 있으면 저장한 옛 키를 싣는다.
/// - 기한이 있다(`Timeouts.logout`, 10초). Go는 부른 쪽의 context만 따르고 CLI·LocalAPI는 기한을 두지 않는다.
/// - 신원 파일을 건드리지 않는다. Go는 응답과 상관없이 메모리의 persist를 비우고 프로필을 지운다. 파일 정리는 앱의 몫이다.
///
/// 출처: tailscale.com `control/controlclient/direct.go` `TryLogout`·`doLogin`(`loginOpt.Logout`),
/// `control/controlclient/auto.go` `Logout`, `ipn/ipnlocal/local.go` `Logout`, BSD-3-Clause.
extension ControlClient {
    /// Go `doLogin`이 로그아웃에 싣는 `Expiry`(`time.Unix(123, 0)`, "far in the past").
    static let logoutExpiry = Date(timeIntervalSince1970: 123)

    /// 저장된 node 키의 만료를 제어 서버에 요청하고 답을 기다린다.
    ///
    /// `run()`과 함께 부르지 않는다. 같은 상태 디렉터리의 `run()`과 겹치지 않게 하는 것은 부르는 쪽(`TailnetNode.logOut()`)의 몫이다.
    /// 신원 파일을 읽기만 한다(없으면 만들지 않는다).
    ///
    /// - Throws: 서버 URL이 잘못되었으면 `invalidConfiguration`. 신원 파일을 읽지 못하면 `storage`. 응답의 `Error`가 비어 있지
    ///   않으면 `registrationRejected`. 200이 아니면 `http(status:)`. 연결하지 못했거나, 기한 안에 답이 없거나, 응답을 해석하지
    ///   못했거나, 취소되었으면 `connection`.
    package func logOut() async throws(ControlError) {
        let endpoint = try ControlEndpoint(serverURL: configuration.serverURL)
        // 등록한 적이 없으면 서버에 알릴 키가 없다(Go `LocalBackend.Logout`의 `hasNodeKeyLocked`).
        guard let identity = try identityStore.load(), let nodeKey = identity.nodePublicKey else { return }
        let request = RegisterRequest(
            nodeKey: nodeKey,
            nlKey: identity.lockPublicKey,
            expiry: Self.logoutExpiry,
            hostinfo: Hostinfo.swiftail(hostname: configuration.hostname, machineKey: identity.machinePublicKey, netInfo: nil)
        )
        guard let body = try? Self.encode(request) else { throw .connection("로그아웃 요청을 JSON으로 만들지 못했다") }
        let interface = networkInterface
        let limit = timeouts.logout
        let response: RegisterResponse
        do {
            response = try await withTimeout(limit) {
                let serverKey = try await ServerKey.fetch(for: endpoint)
                return try await ControlConnection.withConnection(
                    to: endpoint, interface: interface, machineKey: identity.machineKey, serverKey: serverKey
                ) { connection in
                    let reply = try await connection.response(
                        to: connection.jsonRequest("POST", path: "/machine/register", nodeKey: nodeKey),
                        body: body,
                        limit: Self.maximumRegisterResponseSize
                    )
                    guard reply.status == 200 else { throw ControlError.http(status: reply.status) }
                    guard let decoded = try? JSONDecoder().decode(RegisterResponse.self, from: Data(reply.body)) else {
                        throw ControlError.connection("로그아웃 응답을 해석하지 못했다")
                    }
                    return decoded
                }
            }
        } catch let error as ControlError {
            throw error
        } catch is TimeoutError {
            throw .connection("로그아웃이 \(limit) 안에 끝나지 않았다")
        } catch {
            throw .connection(Task.isCancelled ? "로그아웃이 취소되었다" : "로그아웃 요청이 실패했다")
        }
        guard response.error.isEmpty else {
            throw .registrationRejected(Self.rejectionMessage(response.error, authKey: configuration.authKey))
        }
    }
}
