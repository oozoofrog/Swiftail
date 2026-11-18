import Foundation
import SwiftailBase
import SwiftailControl
import SwiftailDERP
import SwiftailEngine
import SwiftailMagicsock

/// Routes control events to the data plane, node state machine, and tunnel settings.
///
/// - `loginRequired`: Passes it to the state machine (`.needsLogin(url)`).
/// - `registered`: Reads the private node key from the identity file and creates the engine and `Magicsock`. If the key
///   changed, recreates both and reopens all DERP region connections, keeping the disco key and socket. Clears the
///   state machine's login URL.
/// - `netmap`: Reports a changed lock state first (`tailnetLockChanged`), applies the netmap to the engine, installs
///   peers and home region candidates in `Magicsock`, and closes connections to regions removed from the DERPMap. In
///   `.inProcess`, updates the stack's local addresses and peer address owners. Computes tunnel settings and publishes
///   changes (behavior E), passes the update to the state machine, and reports a changed `status` last
///   (`statusChanged`).
/// - `disconnected`: Logs only. A disconnect after `.running` leaves the state unchanged (behavior B).
///
/// Contract `docs/contracts/SwiftailEngine.md` node API behaviors 1~4 and “Changes in M4” N2, N3, N5, and N6, and
/// `docs/contracts/SwiftailTunnel.md` behaviors B and E.
extension TailnetNode {
    /// Follows control events until the stream ends. Returns a failure if it cannot continue.
    func follow(_ control: ControlClient) async -> NodeError? {
        for await event in control.events {
            do throws(ControlError) {
                try handle(event)
            } catch {
                return NodeError(error)
            }
        }
        return nil
    }

    private func handle(_ event: ControlClient.Event) throws(ControlError) {
        switch event {
        case let .loginRequired(url):
            announce(stateMachine.loginRequired(url))
        case let .registered(key):
            try adoptNodeKey(key)
            Self.log.info("Control: registered")
            announce(stateMachine.registered())
        case let .netmap(netmap):
            if isControlDisconnected {
                isControlDisconnected = false
                Self.log.info("Control: reconnected")
            }
            apply(netmap)
        case .disconnected:
            isControlDisconnected = true
            Self.log.info("Control: disconnected, reconnecting")
        }
    }

    /// Prepares the data plane with the registered node key. `ControlClient` saves the key to the identity file before emitting `registered`.
    private func adoptNodeKey(_ key: NodePublicKey) throws(ControlError) {
        if let nodeKey, NodePublicKey(nodeKey.publicKey) == key { return }
        guard let privateKey = try identityStore.load()?.nodeKey, NodePublicKey(privateKey.publicKey) == key else {
            throw .storage("The registered node key is missing from the identity file")
        }
        // Control events arrive only in `run()`.
        guard isRunning else { return }
        nodeKey = privateKey
        // The new key is a new WireGuard identity. Old sessions, path state, and DERP connections opened with the old
        // key are unusable, so recreate them all.
        let now = ContinuousClock.now
        // Before discarding the old `Magicsock`, clear its peers to withdraw paths reported to the app by publishing
        // nil. The new `Magicsock` starts its peers idle (nil) and emits no event, so otherwise the old path would
        // remain the app's last event.
        process(magicsock?.setPeers([], at: now) ?? [], at: now)
        closeAllDERPLinks()
        engine = TailnetEngine(nodeKey: privateKey, discoKey: DiscoPublicKey(discoKey.publicKey), now: now, wallClock: Date())
        magicsock = Magicsock(
            discoKey: discoKey,
            nodeKey: key,
            // Use 0 if there is no socket during rebinding. When a new socket opens, `rebind` announces its port.
            localPort: socket?.localPort ?? 0,
            localAddresses: interfaceAddresses.regular,
            loopbackAddresses: interfaceAddresses.loopback,
            now: now
        )
        // A new Magicsock has no home region. When one is selected again, connect to that region and upload it.
        homeRegion = 0
        if let lastNetmap {
            configureDataPlane(lastNetmap)
        }
        rearmTimer()
    }

    func apply(_ netmap: Netmap) {
        let previousLock = lastNetmap?.tailnetLock ?? TailnetLockStatus()
        // Update `status` before emitting events. The lock event precedes the other events from this netmap (F2 1).
        lastNetmap = netmap
        if netmap.tailnetLock != previousLock {
            eventQueue.push(.tailnetLockChanged(netmap.tailnetLock))
        }
        configureDataPlane(netmap)
        publishSettings(for: netmap)
        announce(stateMachine.receivedNetmap(machineAuthorized: netmap.selfNode.machineAuthorized))
        // Even with the same state, the name, addresses, peer count, or settings may have changed. This comes last
        // among this netmap's events.
        announceStatusIfChanged()
        publishCertificateFacts()
    }

    /// Computes tunnel settings and publishes them if they differ from the last published settings (behavior E).
    /// Publishes nothing if there are no local addresses.
    private func publishSettings(for netmap: Netmap) {
        let settings = TunnelNetworkSettings(netmap: netmap, mtu: device.mtu, at: Date())
        guard let settings = settingsPublisher.publish(settings) else { return }
        Self.log.info("""
            Generated tunnel settings: \(settings.addresses.count, privacy: .public) addresses, \(settings.routes.count, privacy: .public) routes, \
            \(settings.dnsServers.count, privacy: .public) DNS servers, \(settings.dnsMatchDomains.count, privacy: .public) match domains
            """)
        settingsContinuation.yield(settings)
    }

    /// Installs the netmap in the engine and `Magicsock`. Closes connections to regions removed from the DERPMap or
    /// whose server definitions changed. Finally, retains the address owner table the engine built with the peers
    /// and passes it to the stack (`updateAddressOwners(for:)`).
    ///
    /// When a peer leaves, `Magicsock` emits a path event (nil) for it. Use the name from before the table update for that event (N6).
    private func configureDataPlane(_ netmap: Netmap) {
        let now = ContinuousClock.now
        let wallClock = Date()
        let regions = netmap.derpMap?.regions ?? [:]
        // A connection reconnects using only the server list it was created with, so close connections to regions whose definitions
        // changed so that subsequent connections use the new servers (`derp-region-redefined` in Go `derp.go`). Reopen the home region immediately and
        // the others on the next send.
        for (region, link) in derpLinks where DERPServer.servers(of: regions[region]) != link.servers {
            closeDERPLink(to: region)
            if region == homeRegion {
                openDERPLink(to: region)
            }
        }

        process(engine?.apply(netmap, at: now, wallClock: wallClock) ?? [], at: now)
        let peers = EnginePeer.peers(in: netmap, at: wallClock)
        let directory = PeerDirectory(peers: peers)
        peerDirectory = directory.keepingNames(of: peerDirectory)
        // Ascending node ID order. Determines disco key ownership (magicsock contract B1).
        let sockPeers = peers.map {
            Magicsock.Peer(key: $0.key, discoKey: $0.discoKey, homeDERP: $0.homeDERP, endpoints: $0.endpoints)
        }
        process(magicsock?.setPeers(sockPeers, at: now) ?? [], at: now)
        peerDirectory = directory
        pathEventTally.retainPeers(Set(peers.map(\.key)))
        // shortcut: Peers the engine removes for key expiration in `advance` remain in `Magicsock` until the next
        // netmap. The engine emits no datagrams for them, so heartbeat stops after 45 seconds, and the device drops
        // received WireGuard traffic (contract N5).
        process(magicsock?.setRegions(Magicsock.Region.homeCandidates(in: netmap.derpMap), at: now) ?? [], at: now)
        updateAddressOwners(for: netmap)
    }

    // MARK: Uploading to the Control Server (N4)

    /// Local endpoints changed. Upload the status.
    func endpointsChanged(_ endpoints: [Magicsock.Endpoint]) {
        localStatus.setEndpoints(endpoints)
        statusUploadContinuation.yield(localStatus)
    }

    /// The home region changed. Upload it so Go peers know the DERP region to send to this node (derp-stun notes §4.8
    /// item 4) and connect to it. Keep the old home connection because peers may still send there (magicsock contract
    /// E6).
    func homeRegionChanged(to region: Int64) {
        homeRegion = region
        localStatus.netInfo = NetInfo(preferredDERP: region)
        statusUploadContinuation.yield(localStatus)
        Self.log.info("Home DERP region: \(region, privacy: .public)")
        openDERPLink(to: region)
        if connectedDERPRegions.contains(region) {
            announce(stateMachine.connected())
        }
    }
}
