/// The reason a link or QR string could not be parsed as an offer (`PairingOffer.init(link:)`). See contract behaviors O2 and O3.
///
/// Omits values. The link is a secret, so logging the error must reveal nothing.
public enum PairingOfferError: Error, Sendable, Equatable {
    /// An invalid offer link. The fragment (after `#`) is missing, exceeds 2048 bytes, or contains `%`. The shape is not `key=value`, the version (`v`) is
    /// not 1, or there are unknown or duplicate keys.
    case notAnOffer
    /// `h` is missing or is not a valid DNS name (at least two labels using lowercase letters, digits, or `-`, at most 253 characters total). This also covers an
    /// IP-address form with an all-digit final label.
    case invalidHost
    /// `p` is missing or is not a decimal number from 1 to 65535 without leading zeros.
    case invalidPort
    /// `s` is missing or is not 43 unpadded base64url characters encoding 32 bytes.
    case invalidSecret
    /// `e` is missing or is not a decimal number of 1–11 digits without a sign or leading zeros.
    case invalidExpiry
    /// `k` does not begin with `tskey-auth-`, contains a character outside `A-Za-z0-9-`, or exceeds 256 bytes.
    case invalidAuthKey
    /// `k` is a tailnet lock signed (wrapped) auth key (`--TL`). Its trailing private key is reusable, so it is omitted from links.
    case wrappedAuthKey
}
