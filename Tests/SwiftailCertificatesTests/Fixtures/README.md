# Certificate test fixtures

`acme-fixtures.json` is a reference fixture generated with `tailscale.com/tempfork/acme` and the Go standard library without reading or running the Swift sources. The complete instructions for generation and the verification commands are in **ACME reference fixture generation (`acmefixtures`)** in `Tools/interop/README.md`.

The header contains `reference` (the `go` and `tailscale` versions) and `caseCount: 22`. All hex is lowercase and base64url is unpadded.

| Array | Count | Fields and meanings |
| --- | --- | --- |
| `keys` | 3 | Other arrays refer to each key by `id`. `testOnly: true`, public seed `seed`, 32-byte private scalar `scalarHex`, public-coordinate JWK `publicKey`, RFC 7638 canonical string `jwkJSON`, `thumbprint`, `sec1PEM`, `pkcs8PEM` |
| `challenges` | 9 | `keyID`, `token`, `keyAuthorization`, `dns01TXT`. Three tokens per key |
| `jws` | 6 | `keyID`, `mode` (`jwk` or `kid`), `protectedJSON`, `payloadJSON`, `signingInput`, `verifiedExample` (`protected`, `payload`, `signature`). One account registration and one POST-as-GET example per key |
| `csrs` | 4 | `name`, `keyID`, `domain`, full DER `derHex`, signing input DER `certificationRequestInfoHex`, CN string tag `cnStringTag` (19) |

In `keys`, `account`, `leading-zero-x`, and `leading-zero-y` are a regular key, a key whose first X coordinate byte is 0, and a key whose first Y coordinate byte is 0, respectively. Each coordinate is 32 bytes including the leading 0. **The private keys are test-only values derived from public fixed seeds and must never be used in production.** There are no real tailnets, devices, or auth keys.

The CSRs use the `account` key with `a.ts.net`, `rd-mac-1a2b3c4d.tail0001.ts.net`, a 63-character label, and a 253-character name. The last case tests the DER length boundary. Adding `_acme-challenge.` exceeds the DNS name limit, so this case is unsuitable as an actual DNS-01 issuance example. The template has one CN, one SAN with the same name, and `ExtraExtensions: nil`.

JWK strings, thumbprints, key authorization, and TXT values are compared byte for byte. CSR Info is also compared byte for byte when using the same key, one SAN in extensionRequest, PrintableString, and DER rules. JWS JSON is compared by its decoded meaning and by verifying the signature over the actual `protected + "." + payload`. Both `payloadJSON` and the JWS `payload` are empty strings for POST-as-GET.

Signature examples are reproducible with RFC 6979 in Go and verified by Go at generation time. **Signature bytes are excluded from the Swift comparison baseline.** Verify Swift-generated JWS with `verify-jws`, CSR with `verify-csr`, and SEC1 and PKCS#8 keys with `parse-key`. This tool work does not include `Tests/**/*.swift` or package resource registration.
