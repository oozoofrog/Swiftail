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
# argon2fixtures(Argon2i 기준값). 아래 도구 목록 줄과 따로 둔다.
if [ "${1:-}" = argon2fixtures ] && [ "$#" -eq 1 ]; then go build -o "$build_dir/bin/$1" "./cmd/$1"; printf '%s\n' "$build_dir/bin/$1"; exit 0; fi
tool=${1:-wgpeer}
case "$tool" in wgpeer|tailnet|h2server|mapfixtures|filterfixtures|dnsfixtures|tunnelfixtures|tcpfixtures|acmefixtures|controlfaults|ed25519fixtures) ;; *) printf '알 수 없는 도구입니다\n' >&2; exit 1 ;; esac
[ "$#" -le 1 ] || exit 1
go build -o "$build_dir/bin/$tool" "./cmd/$tool"
printf '%s\n' "$build_dir/bin/$tool"
