# Test fixtures

For each file, list its origin (document and section, or generation tool and command) and license.

| File | Origin | Generation command | License |
| --- | --- | --- | --- |
| `hpack.json` | Go 1.27.3, `golang.org/x/net/http2/hpack` v0.60.0 Encoder | Command below | Reference implementation BSD-3-Clause, generated test fixture |

Run from the repository root.

```sh
export GOCACHE="$(eyebuild dir interop-tools)/gocache"
export GOMODCACHE="$(eyebuild dir ref-src)/gomod"
export GOFLAGS=-modcacherw GOPROXY=off GOSUMDB=off
(cd Tools/interop && go run ./cmd/h2server -hpack-fixtures ../../Tests/SwiftailHTTP2Tests/Fixtures/hpack.json)
```

There are 2 connections and 10 blocks. Create a separate HPACK decoder for each connection and maintain the dynamic table in `blocks` order. Each block contains `hex` and the expected `headers` (`name`, `value`, `sensitive`). The maximum allowed table size is 4096. The detailed format follows the HPACK section of the [test tool README](../../../Tools/interop/README.md).

Reference `http2/hpack/encode.go` SHA-256: `b39a13dcfd94e03231ab39fe0cfdde3695a6674a481575385237f34dc669d846`.
