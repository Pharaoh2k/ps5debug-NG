#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-only

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

SDK_SRC="$SCRIPT_DIR/ps5-payload-sdk"
SDK_INSTALL="$SDK_SRC/install"
ARTIFACT="$SCRIPT_DIR/ps5debug-NG.elf"
WRITE_DIAG_MODE="${WRITE_DIAG:-0}"
WRITE_PATH_MODE="${WRITE_PATH:-0}"

compute_build_fingerprint() {
    local manifest source_fingerprint
    manifest="$(mktemp)"
    if git -C "$SCRIPT_DIR" rev-parse --is-inside-work-tree \
            >/dev/null 2>&1; then
        (
            cd "$SCRIPT_DIR"
            git ls-files -co --exclude-standard -z -- \
                build.sh common debugger installer |
                LC_ALL=C sort -z
        ) > "$manifest"
    else
        (
            cd "$SCRIPT_DIR"
            find build.sh common debugger installer -type f \
                ! -path '*/build/*' -print0 |
                LC_ALL=C sort -z
        ) > "$manifest"
    fi
    if [ ! -s "$manifest" ]; then
        rm -f "$manifest"
        echo "ERROR: no payload sources found for build fingerprint." >&2
        return 1
    fi
    source_fingerprint="$(
        (cd "$SCRIPT_DIR"; xargs -0 sha256sum < "$manifest") |
        sha256sum | cut -c1-64
    )"
    rm -f "$manifest"
    printf '%s diag=%s path=%s\n' \
        "$source_fingerprint" "$WRITE_DIAG_MODE" "$WRITE_PATH_MODE" |
        sha256sum | cut -c1-16
}

validate_write_build_mode() {
    case "$WRITE_DIAG_MODE" in
        0|1) ;;
        *) echo "ERROR: WRITE_DIAG must be 0 or 1." >&2; exit 1 ;;
    esac
    case "$WRITE_PATH_MODE" in
        0|1|2) ;;
        *) echo "ERROR: WRITE_PATH must be 0 (auto), 1 (DMAP), or 2 (mdbg)." >&2; exit 1 ;;
    esac
}

require_build_host() {
    # This payload's release bytes are toolchain-sensitive.  Keep the supported
    # build host explicit so invoking build.sh from the default WSL distro cannot
    # silently publish an Ubuntu 24 / LLVM 19 artifact.
    . /etc/os-release
    if [ "${ID:-}" != "ubuntu" ] || [ "${VERSION_ID:-}" != "22.04" ]; then
        echo "ERROR: ps5debug-NG must be built in WSL Ubuntu-22.04 (found ${ID:-unknown} ${VERSION_ID:-unknown})." >&2
        exit 1
    fi
}

verify_sdk_links() {
    # Git tracks these FreeBSD forwarding headers as symlinks.  A checkout made
    # with core.symlinks=false turns them into one-line regular files that the C
    # compiler then parses as source text.
    local rel target
    if ! git -C "$SCRIPT_DIR" rev-parse --is-inside-work-tree \
            >/dev/null 2>&1; then
        while IFS= read -r -d '' rel; do
            if [ ! -e "$SCRIPT_DIR/$rel" ]; then
                echo "ERROR: required SDK symlink is broken: $rel" >&2
                exit 1
            fi
        done < <(
            cd "$SCRIPT_DIR"
            find ps5-payload-sdk/include/freebsd -type l -print0
        )
        return
    fi
    while IFS= read -r rel; do
        [ -z "$rel" ] && continue
        if [ ! -L "$SCRIPT_DIR/$rel" ]; then
            echo "ERROR: required SDK symlink is not materialized: $rel" >&2
            echo "       Enable Git symlinks and restore the tracked link before building." >&2
            exit 1
        fi
        target="$(git show ":$rel")"
        if [ "$(readlink "$SCRIPT_DIR/$rel")" != "$target" ]; then
            echo "ERROR: SDK symlink has the wrong target: $rel" >&2
            exit 1
        fi
    done < <(git ls-files -s ps5-payload-sdk/include/freebsd | awk '$1 == 120000 { print $4 }')
}

verify_toolchain() {
    local clang_line lld_line
    clang_line="$($SDK_INSTALL/bin/prospero-clang --version | head -n 1)"
    lld_line="$($SDK_INSTALL/bin/prospero-lld --version | head -n 1)"
    if [[ "$clang_line" != *"version 18.1.8"* ]] || [[ "$lld_line" != *"LLD 18.1.8"* ]]; then
        echo "ERROR: ps5debug-NG release builds require Clang/LLD 18.1.8." >&2
        echo "       clang: $clang_line" >&2
        echo "       lld:   $lld_line" >&2
        exit 1
    fi
}

build_sdk() {
    if [ ! -f "$SDK_INSTALL/toolchain/prospero.mk" ]; then
        echo "==> building SDK (one-time, ~30s)"
        mkdir -p "$SDK_INSTALL"
        make -C "$SDK_SRC" DESTDIR="$SDK_INSTALL" -j"$(nproc)" install
    else
        echo "==> SDK already built at $SDK_INSTALL"
    fi
}

build_debugger() {
    local fingerprint="$1"
    echo "==> building debugger (fingerprint $fingerprint)"
    make -B -C debugger \
        BUILD_FINGERPRINT="$fingerprint" \
        WRITE_DIAG="$WRITE_DIAG_MODE" \
        WRITE_PATH="$WRITE_PATH_MODE"
}

build_installer() {
    local fingerprint="$1"
    echo "==> building installer (embeds debugger)"
    make -B -C installer \
        BUILD_FINGERPRINT="$fingerprint" \
        WRITE_DIAG=0 \
        WRITE_PATH="$WRITE_PATH_MODE"
}

publish_artifact() {
    cp installer/build/ps5debug-NG.elf "$ARTIFACT"
    echo "==> ps5debug-NG.elf ready ($(stat -c %s "$ARTIFACT") bytes)"
}

if [ "${1:-}" = "clean" ]; then
    echo "ERROR: './build.sh clean' is intentionally disabled; it destroys the preserved release SDK install." >&2
    echo "       Clean debugger/ and installer/ independently when a clean payload rebuild is required." >&2
    exit 1
fi

require_build_host
validate_write_build_mode
verify_sdk_links
build_sdk
verify_toolchain
BUILD_FINGERPRINT="$(compute_build_fingerprint)"
build_debugger "$BUILD_FINGERPRINT"
build_installer "$BUILD_FINGERPRINT"
publish_artifact
