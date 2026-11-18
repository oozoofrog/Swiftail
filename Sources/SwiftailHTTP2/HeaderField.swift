/// A header field with a name and value.
///
/// HTTP/2 allows only lowercase header names (RFC 9113 §8.2.1). `HeaderValidation` defines the rules for names and values.
/// `startRequest` applies them to outgoing requests, and the connection applies them to incoming response heads and trailers.
public struct HeaderField: Sendable, Equatable {
    /// The lowercase name. Pseudo-headers begin with `:`.
    public var name: String
    public var value: String

    public init(_ name: String, _ value: String) {
        self.name = name
        self.value = value
    }
}
