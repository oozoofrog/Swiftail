/// The reason the map stream cannot be read further. In every case, discard this stream and receive the full map again in a new stream
/// (`docs/protocol-notes/control-map.md` §3.5, §4.2 item 4).
public enum MapError: Error, Sendable, Equatable {
    /// The frame's length prefix exceeds `MapResponseFramer.maximumFrameSize`.
    case frameTooLarge
    /// The frame is not map response JSON, or its nesting depth or value count exceeds the limits
    /// (`MapResponseFramer.maximumNestingDepth`, `maximumValueCount`).
    case malformed
    /// The first regular (non-KeepAlive) response in the stream lacks the self node (`Node`).
    case missingSelfNode
    /// The retained session state (peers, user profiles, or named packet filters) exceeds a `MapSession` limit.
    case stateTooLarge
}
