#!/bin/sh
# Download the Go sources that the protocol notes and implementation refer to. Keep them out of the repository.
# Output: the source root path (containing tailscale.com@<version> and github.com/tailscale/wireguard-go@<version>).
set -eu

TAILSCALE_VERSION=v1.104.6
WIREGUARD_GO_VERSION=v0.0.0-20261106233718-9e0ab45c16ca

ref=$(eyebuild dir ref-src)
mkdir -p "$ref/gomod" "$ref/gocache"
cd "$ref"
GOMODCACHE="$ref/gomod" GOCACHE="$ref/gocache" GOFLAGS=-modcacherw \
    go mod download "tailscale.com@$TAILSCALE_VERSION" "github.com/tailscale/wireguard-go@$WIREGUARD_GO_VERSION"
echo "$ref/gomod"
