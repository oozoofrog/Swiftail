# Go packet filter verdict fixtures

The actual `wgengine/filter` from `tailscale.com` v1.104.6 generates `filter-verdicts.json`.
It contains 91 scenarios (46 IPv4 and 45 IPv6) and 2,429 steps (333 inbound, 2,058 outbound,
and 38 rule replacements), with 34 markers for intentional M3 differences.

For the regeneration environment, commands, key meanings, and complete scenario list, see
the [interop tool documentation](../../../Tools/interop/README.md#filterfixtures).
The generator runs every scenario twice with a fresh filter and compares the results byte for byte.
It uses no clock, randomness, sockets, real tailnet, or Swift implementation.

`GoFilterComparisonTests` decodes the raw rules into `[FilterRule]` and replays the steps in order using only
`IPPacket` and `PacketFilter` from the public contract. The test was written in a worktree without the Swift
implementation, so it has yet to be compiled or run. Verify it after the merge.

The fixtures also retain unmarked cases that expose gaps in the contract. Go drops wire protocols 0 and 255
as Unknown, and SCTP (132) supports allowing specific destination ports and caching outbound flows for replies.
The contract's rule for other protocols (matching the protocol number and allowing only full port ranges) and its statement that only UDP is recorded
yield different verdicts. These differences lack M3 approval, so the fixtures leave them visible without using `swiftailDiffers`.

Steps marked TSMP verify only `.tsmp` parsing. Control packet consumption in `TailnetEngine.receive` and
WireGuard authentication and AllowedIPs checks are outside the scope of this filter comparison.

# TSMP disco key advertisement fixtures

`tsmp-vectors.json` is generated with `packet.TSMPDiscoKeyAdvertisement.Marshal` and
`Parsed.AsTSMPDiscoAdvertisement` from `tailscale.com` v1.104.6 (the same code as in v1.104.7). To regenerate it, follow
the [interop tool documentation](../../../Tools/interop/README.md#tsmpvectors). `TSMPVectorTests` reads the file.
The `key` in each parsing case is Go's verdict. The test separately verifies the two IPv6 first-fragment cases as known differences where Swiftail drops the packet.
