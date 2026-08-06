#!/bin/bash
# Builds the zcash_signer native library for the platforms cupcake ships.
#
#   ./build_zcash_signer.sh android   -> android/app/src/main/jniLibs/<abi>/
#   ./build_zcash_signer.sh ios       -> ios/libzcash_signer.a (device+sim xcframework)
#   ./build_zcash_signer.sh host      -> a dylib for running the Dart tests locally
#   ./build_zcash_signer.sh all
#
# Android needs an NDK; set ANDROID_NDK_HOME, or it takes the newest one
# under $ANDROID_HOME/ndk (default ~/Library/Android/sdk on macOS).
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CRATE="$HERE/zcash_signer"
# Matches minSdkVersion in android/app/build.gradle.
ANDROID_API=23

build_android() {
    local ndk="${ANDROID_NDK_HOME:-}"
    if [[ -z "$ndk" ]]; then
        local sdk="${ANDROID_HOME:-$HOME/Library/Android/sdk}"
        ndk="$(ls -d "$sdk"/ndk/* 2>/dev/null | sort -V | tail -1 || true)"
    fi
    if [[ -z "$ndk" || ! -d "$ndk" ]]; then
        echo "error: no Android NDK found; set ANDROID_NDK_HOME" >&2
        exit 1
    fi

    local host_tag
    case "$(uname -s)" in
        Darwin) host_tag=darwin-x86_64 ;;
        Linux)  host_tag=linux-x86_64 ;;
        *) echo "error: unsupported host $(uname -s)" >&2; exit 1 ;;
    esac
    local tc="$ndk/toolchains/llvm/prebuilt/$host_tag/bin"
    echo "NDK: $ndk"

    export AR="$tc/llvm-ar"
    # triple:abi-dir:clang-prefix
    local specs=(
        "aarch64-linux-android:arm64-v8a:aarch64-linux-android"
        "armv7-linux-androideabi:armeabi-v7a:armv7a-linux-androideabi"
        "x86_64-linux-android:x86_64:x86_64-linux-android"
    )
    for spec in "${specs[@]}"; do
        IFS=: read -r triple abi prefix <<< "$spec"
        local clang="$tc/${prefix}${ANDROID_API}-clang"
        [[ -x "$clang" ]] || { echo "error: missing $clang" >&2; exit 1; }

        # Cargo reads the linker from an env var keyed by the upper-snake triple.
        # Spelled with tr so this still runs under the bash 3.2 macOS ships.
        local key
        key="$(printf '%s' "$triple" | tr '[:lower:]-' '[:upper:]_')"
        local cc_key
        cc_key="$(printf '%s' "$triple" | tr '-' '_')"
        echo "--- $triple ($abi) ---"
        env "CARGO_TARGET_${key}_LINKER=$clang" "CC_${cc_key}=$clang" \
            cargo build --release --manifest-path "$CRATE/Cargo.toml" --target "$triple"

        local dest="$HERE/android/app/src/main/jniLibs/$abi"
        mkdir -p "$dest"
        cp "$CRATE/target/$triple/release/libzcash_signer.so" "$dest/"
        echo "-> $dest/libzcash_signer.so"
    done
}

build_ios() {
    for triple in aarch64-apple-ios aarch64-apple-ios-sim; do
        echo "--- $triple ---"
        cargo build --release --manifest-path "$CRATE/Cargo.toml" --target "$triple"
    done

    # An xcframework keeps device and simulator slices apart; both are arm64,
    # so a fat archive is not an option.
    local out="$HERE/ios/ZcashSigner.xcframework"
    rm -rf "$out"
    xcodebuild -create-xcframework \
        -library "$CRATE/target/aarch64-apple-ios/release/libzcash_signer.a" \
        -library "$CRATE/target/aarch64-apple-ios-sim/release/libzcash_signer.a" \
        -output "$out"
    echo "-> $out"
}

build_host() {
    echo "--- host ---"
    cargo build --release --manifest-path "$CRATE/Cargo.toml"
    echo "-> $CRATE/target/release/ (dylib for flutter test)"
}

case "${1:-all}" in
    android) build_android ;;
    ios)     build_ios ;;
    host)    build_host ;;
    all)     build_host; build_ios; build_android ;;
    *) echo "usage: $0 [android|ios|host|all]" >&2; exit 1 ;;
esac
