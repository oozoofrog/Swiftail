#!/bin/sh
set -eu
root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
build_dir=$(eyebuild dir interop-tools)
GOCACHE="$build_dir/gocache"
GOMODCACHE="$(eyebuild dir ref-src)/gomod"
GOFLAGS=-modcacherw
export GOCACHE GOMODCACHE GOFLAGS
mkdir -p "$build_dir/bin"
cd "$root/Tools/interop"
go build -o "$build_dir/bin/wgpeer" ./cmd/wgpeer
printf '%s\n' "$build_dir/bin/wgpeer"
