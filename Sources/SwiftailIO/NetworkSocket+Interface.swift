import Network

extension NetworkSocket {
    /// Returns the interface to bind the connection to for this destination. Returns nil for loopback destinations, which are left unbound.
    ///
    /// A loopback address is unreachable through any physical interface, so binding the connection would make it fail.
    /// Go uses the same rule. `controlLogf` in `net/netns/netns_darwin.go` skips binding if `isLocalhost(address)` is
    /// true. `isLocalhost` in `net/netns/netns.go` recognizes `localhost`, `localhost6`, `ip6-loopback`,
    /// `ip6-localhost`, and loopback IPs. The local test servers rely on this rule.
    ///
    /// shortcut: Check only names and IP literals without resolving host names. Go checks the actual address after
    /// resolution (`net.Dialer.Control`), so only this implementation binds other names that resolve to loopback or
    /// other spellings of `::1`. Production servers are unaffected. This needs to change when testing with a local
    /// server that uses such a name.
    ///
    /// - Parameters:
    ///   - interface: The interface to bind to. Nil leaves the connection unbound.
    ///   - host: The hostname or IP literal to connect to.
    package static func bindableInterface(_ interface: NWInterface?, forHost host: String) -> NWInterface? {
        isLoopback(host: host) ? nil : interface
    }

    static func isLoopback(host: String) -> Bool {
        let name = host.lowercased()
        if ["localhost", "localhost6", "ip6-loopback", "ip6-localhost"].contains(name) { return true }
        if name == "::1" { return true }
        // IPv4 literal 127.0.0.0/8.
        let octets = name.split(separator: ".", omittingEmptySubsequences: false)
        guard octets.count == 4, octets.allSatisfy({ UInt8($0) != nil }) else { return false }
        return octets[0] == "127"
    }
}
