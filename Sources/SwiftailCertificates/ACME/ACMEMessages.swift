import Foundation

// Read ACME resource objects (RFC 8555 7.1) from response bodies and construct request bodies.
//
// Reading is the untrusted-input boundary (contract behavior X2). Return nil if the body exceeds 64KiB, is not JSON, omits a required field,
// has an unknown `status`, contains a URL that fails `isAcceptableURL`, or contains more than 8 authorizations. The order flow reports
// nil as `unexpectedResponse`. Ignore unknown fields. Reading does not crash on any input bytes.

/// An ACME directory (RFC 8555 7.1.1). Reads only the three URLs needed for issuance. It does not use `newAuthz`, `revokeCert`, `keyChange`,
/// or `renewalInfo` (contract §1 exclusions table). Go also fails when `newOrder` is missing (`tempfork/acme/acme.go:199-201`).
struct ACMEDirectory: Sendable, Equatable {
    let newNonce: String
    let newAccount: String
    let newOrder: String

    init?(body: [UInt8]) {
        guard let wire = decodeJSON(Wire.self, from: body),
              [wire.newNonce, wire.newAccount, wire.newOrder].allSatisfy(ACMEInputRules.isAcceptableURL)
        else { return nil }
        newNonce = wire.newNonce
        newAccount = wire.newAccount
        newOrder = wire.newOrder
    }

    private struct Wire: Decodable {
        let newNonce: String
        let newAccount: String
        let newOrder: String
    }
}

/// The `status` of an account object (RFC 8555 7.1.2), from the newAccount response body.
enum ACMEAccountStatus: String, Sendable, Decodable {
    case valid, deactivated, revoked

    init?(body: [UInt8]) {
        guard let wire = decodeJSON(Wire.self, from: body) else { return nil }
        self = wire.status
    }

    private struct Wire: Decodable {
        let status: ACMEAccountStatus
    }
}

/// An identifier (RFC 8555 7.1.3 and 7.1.4). This implementation requests a single `dns` identifier.
struct ACMEIdentifier: Sendable, Hashable, Decodable {
    let type: String
    let value: String
}

/// An order object (RFC 8555 7.1.3).
struct ACMEOrder: Sendable, Equatable {
    /// The five statuses in RFC 8555 7.1.6.
    enum Status: String, Sendable, Decodable {
        case pending, ready, processing, valid, invalid
    }

    let status: Status
    let identifiers: [ACMEIdentifier]
    /// Up to 8 authorization URLs. There is no guaranteed 1:1 mapping to identifiers, and order has no meaning (RFC 8555 7.1.3 and 7.4, contract behavior C5).
    let authorizations: [String]
    let finalize: String
    /// The certificate URL for a `valid` order. It may be absent in other statuses.
    let certificate: String?
    /// The order's problem document, if the order failed (RFC 8555 7.1.3).
    let error: ProblemDocument?

    init?(body: [UInt8]) {
        guard let wire = decodeJSON(Wire.self, from: body),
              wire.authorizations.count <= ACMEInputRules.maximumAuthorizationCount,
              wire.authorizations.allSatisfy(ACMEInputRules.isAcceptableURL),
              ACMEInputRules.isAcceptableURL(wire.finalize),
              wire.certificate.map(ACMEInputRules.isAcceptableURL) ?? true
        else { return nil }
        status = wire.status
        identifiers = wire.identifiers
        authorizations = wire.authorizations
        finalize = wire.finalize
        certificate = wire.certificate
        error = wire.error
    }

    private struct Wire: Decodable {
        let status: Status
        let identifiers: [ACMEIdentifier]
        let authorizations: [String]
        let finalize: String
        let certificate: String?
        let error: ProblemDocument?
    }
}

/// An authorization object (RFC 8555 7.1.4).
struct ACMEAuthorization: Sendable, Equatable {
    /// The six statuses in RFC 8555 7.1.6.
    enum Status: String, Sendable, Decodable {
        case pending, valid, invalid, deactivated, expired, revoked
    }

    let identifier: ACMEIdentifier
    let status: Status
    /// True if this authorization is for a wildcard name (RFC 8555 7.1.4). Defaults to false if absent.
    let wildcard: Bool
    let challenges: [ACMEChallenge]

    init?(body: [UInt8]) {
        guard let wire = decodeJSON(Wire.self, from: body) else { return nil }
        identifier = wire.identifier
        status = wire.status
        wildcard = wire.wildcard ?? false
        challenges = wire.challenges
    }

    /// The first challenge whose `type` is `dns-01` (RFC 8555 8.4). Only the selected challenge's URL, token, and status are checked.
    var dns01Challenge: ACMEChallenge? {
        challenges.first { $0.type == "dns-01" }
    }

    private struct Wire: Decodable {
        let identifier: ACMEIdentifier
        let status: Status
        let wildcard: Bool?
        let challenges: [ACMEChallenge]
    }
}

/// A challenge object (RFC 8555 7.1.5 and §8). The structure varies by `type`, so read every field except `type` as optional and use
/// `validated` only on challenges that will be used. This keeps the shape of unused types (such as http-01) from invalidating the entire authorization.
struct ACMEChallenge: Sendable, Equatable, Decodable {
    /// The four statuses in RFC 8555 7.1.6.
    enum Status: String, Sendable {
        case pending, processing, valid, invalid
    }

    let type: String
    let url: String?
    let status: String?
    let token: String?
    let error: ProblemDocument?

    /// A validated DNS-01 challenge with an `https` URL of at most 2,048 bytes, a base64url token of 1–512 bytes, and one of four statuses.
    var validated: (url: String, token: String, status: Status)? {
        guard let url, ACMEInputRules.isAcceptableURL(url), let token, ACMEInputRules.isAcceptableToken(token),
              let status = status.flatMap(Status.init(rawValue:))
        else { return nil }
        return (url, token, status)
    }
}

/// The request body JSON (JWS payload). This implementation generates every value, so there are no characters to escape.
enum ACMERequestBody {
    /// Looks up the account (RFC 8555 7.3.1).
    static let findAccount = Array(#"{"onlyReturnExisting":true}"#.utf8)
    /// Creates an account (RFC 8555 7.3). No contact information is sent (contract §1 exclusions table). Go sends `termsOfServiceAgreed` only when the
    /// directory has a terms URL (`tempfork/acme/rfc8555.go:49-61`). This implementation always sends the field because it has no meaning for servers without terms.
    static let createAccount = Array(#"{"termsOfServiceAgreed":true}"#.utf8)
    /// A challenge response (RFC 8555 7.5.1). DNS-01 has no response fields.
    static let respondToChallenge = Array("{}".utf8)
    /// An empty payload for POST-as-GET (RFC 8555 6.3).
    static let postAsGet: [UInt8] = []

    /// An order (RFC 8555 7.4). A validated name contains only lowercase letters, digits, hyphens, and periods.
    static func newOrder(_ domain: CertificateDomain) -> [UInt8] {
        Array(#"{"identifiers":[{"type":"dns","value":"\#(domain.name)"}]}"#.utf8)
    }

    /// A finalize payload (RFC 8555 7.4) containing the base64url-encoded CSR DER.
    static func finalize(_ csr: CertificateSigningRequest) -> [UInt8] {
        Array(#"{"csr":"\#(Base64URL.encode(csr.der))"}"#.utf8)
    }
}

/// Reads a JSON body of up to 64KiB. Returns nil for oversized or malformed bodies.
private func decodeJSON<T: Decodable>(_ type: T.Type, from body: [UInt8]) -> T? {
    guard body.count <= ACMEInputRules.maximumJSONByteCount else { return nil }
    return try? JSONDecoder().decode(type, from: Data(body))
}
