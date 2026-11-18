import CryptoKit

extension P256.Signing.PrivateKey {
    /// Reads a key file's PEM as a P-256 private key (`acme-account.key.pem` for the account key or `<name>.key` for a certificate key).
    ///
    /// The entire file must be **one** `PRIVATE KEY` block (PKCS#8, used by Swiftail and CryptoKit) or `EC PRIVATE KEY` block (SEC1, used by Go,
    /// notes §3.7). Rejects text outside the block, multiple blocks, any other label, or a key other than P-256.
    /// The caller must distinguish a rejected account key from an absent one (contract behavior C4).
    ///
    /// - Parameter maximumByteCount: The maximum file size in bytes (64KiB in contract behavior M).
    init(pemFile input: [UInt8], maximumByteCount: Int) throws(PEMError) {
        let blocks = try PEM.decode(input, maximumByteCount: maximumByteCount)
        guard blocks.count == 1, let block = blocks.first else { throw .wrongBlockCount }
        guard block.label == .privateKey || block.label == .ecPrivateKey else { throw .unexpectedLabel }
        do {
            // CryptoKit's DER decoder accepts both PKCS#8 and SEC1 (`PrivateKeyPEMTests` covers both).
            try self.init(derRepresentation: block.der)
        } catch {
            throw .malformed
        }
    }
}
