# TKA test fixtures

Contains fixtures from the Go reference values (`tkafixtures` under `Tools/interop`) and the execution records in note §8.1. This document gives the origin of each file.

## `cbor-vectors.json`(TL-1)

63 CBOR item-level outcome vectors. Sources are the decoding acceptance and rejection tables in §8.1 of `docs/protocol-notes/tailnet-lock.md`, the verification session's map key type, `Meta` map, and other decoding rows, and the limits from §3.1 (16/17 levels, 4,096/4,097 elements, and 1,024/1,025 pairs). The `Genesis checkpoint` vector decodes the base64 from `tailscale.com/tka/aum_test.go:181` (v1.104.7) to hex (note §7.1).

This unit constructed the input bytes to match the note's descriptions (usually a NoOp AUM of `{1: 3, 2: null}` with one pair added). The note does not record running Go on these exact bytes. TL-5's `tkafixtures` confirms the outcomes with Go.

| Field | Meaning |
| --- | --- |
| `section` | Section and table in the note where the outcome was recorded |
| `cbor` | `CBOR.decode` outcome: `accept` or the `CBORError` case name |
| `aum` | Go `AUM` decode (`Unmarshal`) outcome recorded in the note, `accept` or `reject`. If `cbor` is `accept` and this is `reject`, rejection is at the structure level (TL-2). Static validation is excluded |
| `canonical` | Accepted value rewritten canonically (map keys in lexicographic order by encoded bytes and equal keys in received order). This is a generic CBOR rewrite that retains unknown fields rather than the re-encoded AUM bytes. Absent for values containing negative integers, simple values, or floats |
| `note` | Additional information about the outcome |

## `tka-fixtures.json` (`tkafixtures`)

Origin: Go outcomes produced by `Tools/interop/cmd/tkafixtures` with the `tka` public API from `tailscale.com` v1.104.6 (only peer sets use an overlay for `tkaFilterNetmapLocked` in `ipn/ipnlocal`). Go 1.27.3. Keys are public test-only values derived from `SHA-256("swiftail-fixtures/tka/<role>/<number>")`. The `bootstrap/go-test-genesis` and `go-test-string` in `authKeys` use values from Go test files (`tka/aum_test.go:181` and `tka/sig_test.go:479`). The JSON shape and scenario list are in the TKA reference fixture generation section in `Tools/interop/README.md`. Of the 523 outcomes (`caseCount`), the TL-5 comparison tests added 60 (`unorderedPeerSets`, `limits`, `padded`, `openedStates`, and rows added to other arrays) to settle unresolved inputs in contract §5, and the TL-11a review added 37 (`reviewChains` 22 and `reviewSignatures` 15). `TKAReviewTests.swift` compares the `review*` arrays, and `GoComparisonTests.swift` compares the rest.

Regenerate from the repository root using the environment variables from that section:

```sh
fixture_tool="$(sh Scripts/build-interop-tools.sh tkafixtures)"
(cd Tools/interop && "$fixture_tool" ../../Tests/SwiftailTKATests/Fixtures)
(cd Tools/interop && go test -count=1 ./cmd/tkafixtures)
# Swift test that regenerates and compares against the saved fixture (keep the Go environment variables above)
SWIFTAIL_TKAFIXTURES="$fixture_tool" eyebuild swift tl5 -- test --filter GoComparisonTests
```
