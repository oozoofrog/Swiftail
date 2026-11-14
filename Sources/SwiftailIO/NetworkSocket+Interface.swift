import Network

extension NetworkSocket {
    /// 이 목적지로 나갈 때 연결을 묶을 인터페이스. 루프백 목적지는 묶지 않으므로 nil이다.
    ///
    /// 루프백 주소는 어떤 물리 인터페이스로도 닿지 않아, 묶으면 연결이 실패한다. Go도 같은 규칙이다
    /// (`net/netns/netns_darwin.go`의 `controlLogf`가 `isLocalhost(address)`이면 묶지 않는다. `net/netns/netns.go`
    /// `isLocalhost`: `localhost`·`localhost6`·`ip6-loopback`·`ip6-localhost`와 루프백 IP). 시험의 로컬 서버가
    /// 이 규칙으로 돈다.
    ///
    /// shortcut: 호스트 이름이 가리키는 주소는 풀어 보지 않고 이름과 IP 리터럴만 본다. Go는 이름을 푼 뒤의 실제 주소로
    /// 판정하므로(`net.Dialer.Control`), 루프백으로 풀리는 다른 이름이나 `::1`의 다른 표기는 여기서만 묶인다. 운영
    /// 서버에는 영향이 없다. 필요해지는 시점: 그런 이름의 로컬 서버로 시험할 때.
    ///
    /// - Parameters:
    ///   - interface: 묶고 싶은 인터페이스. nil이면 묶지 않는다.
    ///   - host: 연결할 호스트 이름 또는 IP 리터럴.
    package static func bindableInterface(_ interface: NWInterface?, forHost host: String) -> NWInterface? {
        isLoopback(host: host) ? nil : interface
    }

    static func isLoopback(host: String) -> Bool {
        let name = host.lowercased()
        if ["localhost", "localhost6", "ip6-loopback", "ip6-localhost"].contains(name) { return true }
        if name == "::1" { return true }
        // IPv4 리터럴 127.0.0.0/8.
        let octets = name.split(separator: ".", omittingEmptySubsequences: false)
        guard octets.count == 4, octets.allSatisfy({ UInt8($0) != nil }) else { return false }
        return octets[0] == "127"
    }
}
