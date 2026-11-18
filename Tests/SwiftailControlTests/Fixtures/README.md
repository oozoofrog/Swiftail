# Test fixtures

For each file, list its origin (document and section, or generation tool and command) and license.

| File | Origin | Generation command | License |
| --- | --- | --- | --- |
| `map-sessions.json` | mapSession from the actual `control/controlclient/map.go` in `tailscale.com` v1.104.6, Go 1.27.3 | Command below | Reference implementation BSD-3-Clause, generated test fixture |
| `requests.json` | `encoding/json.Marshal` of `tailcfg.RegisterRequest` and `MapRequest` from the same version | Command below | Reference implementation BSD-3-Clause, generated test fixture |
| `tka-peer-sets.json` | Copies all `peerSets` from `Tests/SwiftailTKATests/Fixtures/tka-fixtures.json` (Go `tka` and `ipnlocal` decisions, `tkafixtures` tool) and the `name` and `aums` of the referenced `authorities` verbatim. The keys are public test-only values | Last command below | Reference implementation BSD-3-Clause, generated test fixture |

Run from the repository root.

```sh
export GOCACHE="$(eyebuild dir interop-tools)/gocache"
export GOMODCACHE="$(eyebuild dir ref-src)/gomod"
export GOFLAGS=-modcacherw GOPROXY=off GOSUMDB=off
(cd Tools/interop && go run ./cmd/mapfixtures ../../Tests/SwiftailControlTests/Fixtures)
```

There are 10 scenarios, 73 steps, and 10 request cases. Create a fresh session for each scenario. `response` is the original JSON **string** and preserves omitted keys, null, and empty arrays. `netmap` is null if the normalized state matches the previous step. To call the actual Go mapSession, apply `go -overlay` only to the temporary copy of the reference module in the build folder. The application logic is never duplicated, and the module cache stays intact. The reference time for `PeerSeenChange` is `2026-01-02T03:04:05.123456789Z`.

The mapfixtures section of the [test tool README](../../../Tools/interop/README.md) defines the normalized field names and formats, the zero defaults for request input, and the notes for each scenario. Swift comparisons do not convert 64-bit IDs to floating point.

Reference `control/controlclient/map.go` SHA-256: `96aea2fa89b642ea0679e78b50a0133c7780b7ed787792542187a20c76fbee1e`.

`tka-peer-sets.json` is copied here because fixtures in another test target cannot be read. Regenerate this file when regenerating `tka-fixtures.json`.

```sh
python3 - <<'PY'
import json
source = json.load(open('Tests/SwiftailTKATests/Fixtures/tka-fixtures.json'))
names = {peerSet['authority'] for peerSet in source['peerSets']}
json.dump({
    'reference': source['reference'],
    'authorities': [{'name': a['name'], 'aums': a['aums']} for a in source['authorities'] if a['name'] in names],
    'peerSets': source['peerSets'],
}, open('Tests/SwiftailControlTests/Fixtures/tka-peer-sets.json', 'w'), indent=2)
PY
```
