import Foundation

/// Fixed certificates for `ServerCertificateTests`. Copied verbatim from the output of `tailnet certificate-fixtures` (`Tools/interop/cmd/tailnet/derpcert.go`)
/// (README "Certificate fixtures"). Keys and signatures are random, so regenerating them changes the bytes.
///
/// The self-signed certificates are valid from 2026-01-01T00:00:00Z ..< 2027-01-01T00:00:00Z (except `meta`).
enum ServerCertificateFixtures {
    /// A self-signed certificate in the same form as derper's manual certificate mode. The CN and IP SAN are both `100.64.0.1`.
    static let ipLeaf = der("MIIBcDCCARWgAwIBAgIRAIOhrq5TR7aQdpNr/+tzjOcwCgYIKoZIzj0EAwIwFTETMBEGA1UEAxMKMTAwLjY0LjAuMTAeFw0yNjAxMDEwMDAwMDBaFw0yNzAxMDEwMDAwMDBaMBUxEzARBgNVBAMTCjEwMC42NC4wLjEwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAQx1X5GcuZB+gCbxHtIFGNahMKrUdlkn6XiG6rUwq44mnQk5eRHElNTgrwmpy2kJt7IQNh04yOAQZ6xj72/TpN2o0YwRDAOBgNVHQ8BAf8EBAMCBaAwEwYDVR0lBAwwCgYIKwYBBQUHAwEwDAYDVR0TAQH/BAIwADAPBgNVHREECDAGhwRkQAABMAoGCCqGSM49BAMCA0kAMEYCIQDMl33/cTUHNIJMcUjJEp7tC5UL4Lc+QfFR0lHe/A9pEgIhAIjn39Hh2tllibgq4xmjdCzeRvLLY7ulwFFAhnYobvsh")
    /// A certificate of the same form as `ipLeaf` with a different key.
    static let otherIPLeaf = der("MIIBbjCCARSgAwIBAgIQUcgX2y8Rh+t17629lVzrdjAKBggqhkjOPQQDAjAVMRMwEQYDVQQDEwoxMDAuNjQuMC4xMB4XDTI2MDEwMTAwMDAwMFoXDTI3MDEwMTAwMDAwMFowFTETMBEGA1UEAxMKMTAwLjY0LjAuMTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABI2vd3chND9Rsvs6VyKFNJ0IXw9QiCcTgKCXj9X86WfeCQpb5cdFNXy81QOpk5KIMd6/cN0gWbA4njO0K/USAeKjRjBEMA4GA1UdDwEB/wQEAwIFoDATBgNVHSUEDDAKBggrBgEFBQcDATAMBgNVHRMBAf8EAjAAMA8GA1UdEQQIMAaHBGRAAAEwCgYIKoZIzj0EAwIDSAAwRQIhAKuS9bR8KwTEBYXWvcgz5FPMT/x0ReDXI5zwcdUqDkL8AiACZrYUGHhjLB2QpWBzyLiA6w7HKEN7Gv5QiaN1v1WyrA==")
    /// A self-signed certificate of the same form with its SAN set to the DNS name `derp1a.example.test`.
    static let dnsLeaf = der("MIIBjzCCATWgAwIBAgIQWLKBO8AIbjwOK6cV3Kgc1zAKBggqhkjOPQQDAjAeMRwwGgYDVQQDExNkZXJwMWEuZXhhbXBsZS50ZXN0MB4XDTI2MDEwMTAwMDAwMFoXDTI3MDEwMTAwMDAwMFowHjEcMBoGA1UEAxMTZGVycDFhLmV4YW1wbGUudGVzdDBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABHU+ANZ8lV3W3vX4Mkd9ujLSDNxj+c9a1zYSdp2qZ+OgbhIqQHneq6NkoDCOqSkrcbIBG3mzp/o/+6QpiA52ME2jVTBTMA4GA1UdDwEB/wQEAwIFoDATBgNVHSUEDDAKBggrBgEFBQcDATAMBgNVHRMBAf8EAjAAMB4GA1UdEQQXMBWCE2RlcnAxYS5leGFtcGxlLnRlc3QwCgYIKoZIzj0EAwIDSAAwRQIgEQ5hepajEP8HhffRrpPQUVQyVOUDSxa3rpxuc4KVar4CIQCR7nvrrHM4Mf0uw58ttbRL9yaksnGA3aqW14l43lbkLA==")
    /// The test root (CA) that issued `namedLeaf`.
    static let root = der("MIIBfDCCASGgAwIBAgIRAMlel3d33sGL9eZRO9QsPdMwCgYIKoZIzj0EAwIwHTEbMBkGA1UEAxMSU3dpZnRhaWwgVGVzdCBSb290MB4XDTI2MDEwMTAwMDAwMFoXDTI3MDEwMTAwMDAwMFowHTEbMBkGA1UEAxMSU3dpZnRhaWwgVGVzdCBSb290MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEyR52FmxKmzdzQ2CdhLi/fyn1X98tXB67NfncRYqEm5rkINhYHn0YjCRV2/XWKSsm7rZdJW/mMiBKRdctulMV5aNCMEAwDgYDVR0PAQH/BAQDAgKEMA8GA1UdEwEB/wQFMAMBAf8wHQYDVR0OBBYEFMiENnEh8R0FrmJguReWJnvMStryMAoGCCqGSM49BAMCA0kAMEYCIQCFYesPEZqk0QzW+bjwvA45cGRkbfnCraB0U2FripiIEAIhAJdYRZ7MvgG/03C6Rsio2RGPDy4SUD28vDzql4mmtZOs")
    /// The `derp-cert.example.test` certificate issued by `root`.
    static let namedLeaf = der("MIIBtDCCAVugAwIBAgIQKI/60bSgjI80vE/gqz7VHTAKBggqhkjOPQQDAjAdMRswGQYDVQQDExJTd2lmdGFpbCBUZXN0IFJvb3QwHhcNMjYwMTAxMDAwMDAwWhcNMjcwMTAxMDAwMDAwWjAhMR8wHQYDVQQDExZkZXJwLWNlcnQuZXhhbXBsZS50ZXN0MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEUhiB5LvrTIlYgFoZeWFVUAo51c6UR7ZH0DsB0+fZcR57nupkHSyQe5J61mKfTVoPCwBX7GTiavyF0EhsGdt5a6N5MHcwDgYDVR0PAQH/BAQDAgWgMBMGA1UdJQQMMAoGCCsGAQUFBwMBMAwGA1UdEwEB/wQCMAAwHwYDVR0jBBgwFoAUyIQ2cSHxHQWuYmC5F5Yme8xK2vIwIQYDVR0RBBowGIIWZGVycC1jZXJ0LmV4YW1wbGUudGVzdDAKBggqhkjOPQQDAgNHADBEAiBV2rC4yzx02JehYsvFbvEcrSVP8XzpL27skG96OUnCLQIgILEexedz1xJ4DJDwRn8ieB+wDxSFEtpXykhqdyIr7/M=")
    /// An actual `derpserver.Server.MetaCert()`. An Ed25519 self-signed certificate with subject CN `derpkey<hex server public key>`.
    static let meta = der("MIIBYzCCARWgAwIBAgIBAjAFBgMrZXAwUjFQME4GA1UEAxNHZGVycGtleTZhNDZiMjRiMDNhYTk1YmI3OGI1MDFiZGJjMTQ3M2MyZDAxY2I3MDlkYmVhNjY4NTY0Y2NhZDk4ZTMyNTE2NGMwHhcNMjYxMDE2MTE1NTMyWhcNMjYxMjE1MTE1NTMyWjBSMVAwTgYDVQQDE0dkZXJwa2V5NmE0NmIyNGIwM2FhOTViYjc4YjUwMWJkYmMxNDczYzJkMDFjYjcwOWRiZWE2Njg1NjRjY2FkOThlMzI1MTY0YzAqMAUGAytlcAMhAGyzjklzwCDQ8luNei+/YEJUMWoSzNWNt4mN2B++YbjeoxAwDjAMBgNVHRMBAf8EAjAAMAUGAytlcANBAPfj6mCcEmDGN2r2IfdYpOoS7kGaBUhk8t0oFXJNtjuENgZMcA8sBwg10/Lv95P/u3+I4QRxM2PTt4F6VomGtAA=")
    /// SHA-256 of the `ipLeaf` DER (Go `fmt.Sprintf("%02x", sha256.Sum256(der))`).
    static let ipLeafSHA256 = "784f7cbb4b718afea8f9a6185505830fc85631cf7b6acc4945e62b4476e9af6d"
    /// SHA-256 of the `dnsLeaf` DER.
    static let dnsLeafSHA256 = "853a422f459bc838706d4fc27eb6415ac6acc805d09aead3972eff0618fd048e"
    /// SHA-256 of the `meta` DER.
    static let metaSHA256 = "f56196d35a64cf272d58f316004c412c08c03e63d5168fa1f12f9921a8a8de5c"

    private static func der(_ base64: String) -> [UInt8] {
        guard let data = Data(base64Encoded: base64) else { preconditionFailure("Invalid base64 in certificate fixture") }
        return [UInt8](data)
    }
}
