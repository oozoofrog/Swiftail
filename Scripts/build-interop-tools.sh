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
tool=${1:-wgpeer}
case "$tool" in wgpeer|tailnet|h2server|mapfixtures|filterfixtures|dnsfixtures|tunnelfixtures|tcpfixtures|acmefixtures|controlfaults|ed25519fixtures|argon2fixtures) ;; *) printf '알 수 없는 도구입니다\n' >&2; exit 1 ;; esac
[ "$#" -le 1 ] || exit 1
go build -o "$build_dir/bin/$tool" "./cmd/$tool"
printf '%s\n' "$build_dir/bin/$tool"
