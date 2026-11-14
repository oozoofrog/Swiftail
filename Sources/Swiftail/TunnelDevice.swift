import SwiftailIO

/// 노드가 IP 패킷을 주고받는 장치(`docs/contracts/SwiftailTunnel.md` 동작 U, `docs/contracts/SwiftailNetstack.md` 동작 N).
///
/// 어느 장치든 처리는 같다. 장치에서 읽은 패킷은 엔진의 보내기(로컬 응답, tailnet으로 보내기)를 거치고, 엔진이 장치로
/// 쓰라고 낸 패킷(피어가 보낸 것, MagicDNS 응답 등)은 장치에 쓴다. `.inProcess`에서는 프로세스 안의 TCP 스택이 그 장치다.
public enum TunnelDevice: Sendable {
    /// Network Extension이 만든 utun 제어 소켓. 노드는 이 기술자를 `run()`에서 복제해 쓰고, 원래 기술자는 닫지도 읽지도
    /// 않는다. `TailnetNode.init`은 이것이 utun인지 읽기만 하는 시스템 호출로 확인한다.
    ///
    /// - Parameter mtu: 앱이 `NEPacketTunnelNetworkSettings.mtu`로 적용하는 값. 1280…1420. 노드는 utun의 MTU를 바꾸지
    ///   않고, 이 값을 `TunnelNetworkSettings.mtu`로 돌려준다. 이보다 큰 패킷은 읽을 때 버린다.
    case utun(fileDescriptor: Int32, mtu: Int = 1280)
    /// 메모리 장치. `TailnetNode.send(_:)`로 넣고 `TailnetNode.inboundPackets`로 받는다. 시험과 관문용이며 utun과 같은
    /// 처리를 거친다.
    case memory(mtu: Int = 1280)
    /// 프로세스 안의 TCP 스택. 피어가 이 노드의 주소로 보낸 패킷을 스택이 받고, 스택이 만든 패킷이 tailnet으로 나간다.
    /// `TailnetNode.listen(port:)`과 `TailnetNode.connect(to:port:)`는 이 장치에서만 쓸 수 있다. MTU는 1280으로 고정이다.
    ///
    /// `TailnetNode.inboundPackets`는 아무것도 내지 않고 `TailnetNode.send(_:)`는 버린다. `networkSettings`는 다른 장치와
    /// 같이 나온다(앱이 OS에 적용할 일은 없다). ICMP·UDP는 다루지 않는다(스택이 버린다).
    case inProcess

    /// 앱이 적용하는 MTU.
    var mtu: Int {
        switch self {
        case let .utun(_, mtu), let .memory(mtu): mtu
        // tailnet MTU(계약 M6 결정 D9). 스택의 MSS가 이 값에서 나온다.
        case .inProcess: 1280
        }
    }

    /// 장치를 검사한다. utun이면 그 인터페이스 이름(`utun3` 등)을 돌려준다. 메모리 장치는 nil.
    ///
    /// 파일·소켓을 만들지 않는다. utun 검사는 `getpeername`·`getsockopt`뿐이다(동작 U1).
    func validate() throws(NodeError) -> String? {
        guard UTUNDevice.supportedMTU.contains(mtu) else {
            throw .invalidConfiguration("MTU는 \(UTUNDevice.supportedMTU.lowerBound)…\(UTUNDevice.supportedMTU.upperBound)이어야 한다")
        }
        guard case let .utun(descriptor, _) = self else { return nil }
        do {
            return try UTUNDevice.interfaceName(ofUTUN: descriptor)
        } catch {
            throw .invalidConfiguration("utun 기술자가 아니다")
        }
    }
}
