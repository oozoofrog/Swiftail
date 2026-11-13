#!/bin/sh
# 프로토콜 노트와 구현이 참고하는 Go 소스를 내려받는다. 저장소에는 넣지 않는다.
# 출력: 소스 루트 경로(이 아래에 tailscale.com@<버전>, github.com/tailscale/wireguard-go@<버전>).
set -eu

TAILSCALE_VERSION=v1.104.6
WIREGUARD_GO_VERSION=v0.0.0-20261106233718-9e0ab45c16ca

ref=$(eyebuild dir ref-src)
mkdir -p "$ref/gomod" "$ref/gocache"
cd "$ref"
GOMODCACHE="$ref/gomod" GOCACHE="$ref/gocache" GOFLAGS=-modcacherw \
    go mod download "tailscale.com@$TAILSCALE_VERSION" "github.com/tailscale/wireguard-go@$WIREGUARD_GO_VERSION"
echo "$ref/gomod"
