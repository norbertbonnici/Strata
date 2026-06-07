#!/usr/bin/env bash
#
# Build tsk_loaddb (and friends) from source, statically linked against libewf
# (E01) and libvhdi (VHD/VHDX). Output: Vendor/tsk/bin/<arch>/.
#
# Requires: Xcode Command Line Tools. No Homebrew at runtime.
# Build-time tools used: curl, tar, make, clang (all in CLT).
#
# Usage:
#   scripts/build-tsk.sh                 # host arch
#   scripts/build-tsk.sh arm64
#   scripts/build-tsk.sh x86_64
#   scripts/build-tsk.sh universal       # build both, lipo into universal/
#
# Versions are pinned but overridable via env vars. If a download 404s, the
# libyal "experimental" tags rotate by date; bump LIBEWF_VERSION /
# LIBVHDI_VERSION to a current tag from the respective GitHub Releases page.

set -euo pipefail

TSK_VERSION="${TSK_VERSION:-4.15.0}"
LIBEWF_VERSION="${LIBEWF_VERSION:-20240506}"
LIBVHDI_VERSION="${LIBVHDI_VERSION:-20240509}"
LIBVMDK_VERSION="${LIBVMDK_VERSION:-20240510}"
LIBEVTX_VERSION="${LIBEVTX_VERSION:-20240504}"
LIBREGF_VERSION="${LIBREGF_VERSION:-20240421}"
LIBLNK_VERSION="${LIBLNK_VERSION:-20240423}"

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BUILD="$ROOT/.build-tsk"
OUT="$ROOT/Vendor/tsk"
SDKROOT="$(xcrun --sdk macosx --show-sdk-path)"
DEPLOYMENT_TARGET="${MACOSX_DEPLOYMENT_TARGET:-13.0}"

TOOLS=(tsk_loaddb fls icat mmls fsstat blkstat istat evtxexport evtxinfo regfexport regfinfo lnkinfo ewfinfo ewfverify)

download() {
    local url="$1" dest="$2"
    if [ ! -f "$dest" ]; then
        echo ">>> Downloading $(basename "$dest")"
        curl -fL --retry 3 -o "$dest" "$url"
    fi
}

extract() {
    local tarball="$1" dest="$2"
    if [ ! -d "$dest" ]; then
        mkdir -p "$dest"
        tar -xzf "$tarball" -C "$dest" --strip-components=1
    fi
}

build_arch() {
    local arch="$1"
    case "$arch" in
        arm64)  local host="aarch64-apple-darwin" ;;
        x86_64) local host="x86_64-apple-darwin" ;;
        *) echo "Unsupported arch: $arch" >&2; return 1 ;;
    esac

    local prefix="$BUILD/prefix-$arch"
    local arch_out="$OUT/bin/$arch"
    mkdir -p "$prefix" "$arch_out"

    local flags="-arch $arch -isysroot $SDKROOT -mmacosx-version-min=$DEPLOYMENT_TARGET -O2"
    export CFLAGS="$flags"
    export CXXFLAGS="$flags"
    export LDFLAGS="$flags -Wl,-search_paths_first"
    export MACOSX_DEPLOYMENT_TARGET="$DEPLOYMENT_TARGET"
    export PKG_CONFIG_PATH="$prefix/lib/pkgconfig"

    # libewf
    download "https://github.com/libyal/libewf/releases/download/$LIBEWF_VERSION/libewf-experimental-$LIBEWF_VERSION.tar.gz" \
             "$BUILD/libewf.tar.gz"
    extract "$BUILD/libewf.tar.gz" "$BUILD/libewf-$arch"
    if [ ! -f "$prefix/lib/libewf.a" ]; then
        (cd "$BUILD/libewf-$arch" && \
            ./configure --host="$host" --prefix="$prefix" \
                --enable-static --disable-shared \
                --disable-python --without-libfuse && \
            make -j"$(sysctl -n hw.ncpu)" && \
            make install)
    fi

    # libvhdi
    download "https://github.com/libyal/libvhdi/releases/download/$LIBVHDI_VERSION/libvhdi-alpha-$LIBVHDI_VERSION.tar.gz" \
             "$BUILD/libvhdi.tar.gz"
    extract "$BUILD/libvhdi.tar.gz" "$BUILD/libvhdi-$arch"
    if [ ! -f "$prefix/lib/libvhdi.a" ]; then
        (cd "$BUILD/libvhdi-$arch" && \
            ./configure --host="$host" --prefix="$prefix" \
                --enable-static --disable-shared \
                --disable-python --without-libfuse && \
            make -j"$(sysctl -n hw.ncpu)" && \
            make install)
    fi

    # libvmdk
    download "https://github.com/libyal/libvmdk/releases/download/$LIBVMDK_VERSION/libvmdk-alpha-$LIBVMDK_VERSION.tar.gz" \
             "$BUILD/libvmdk.tar.gz"
    extract "$BUILD/libvmdk.tar.gz" "$BUILD/libvmdk-$arch"
    if [ ! -f "$prefix/lib/libvmdk.a" ]; then
        (cd "$BUILD/libvmdk-$arch" && \
            ./configure --host="$host" --prefix="$prefix" \
                --enable-static --disable-shared \
                --disable-python --without-libfuse && \
            make -j"$(sysctl -n hw.ncpu)" && \
            make install)
    fi

    # libevtx (Windows Event Log parsing)
    download "https://github.com/libyal/libevtx/releases/download/$LIBEVTX_VERSION/libevtx-alpha-$LIBEVTX_VERSION.tar.gz" \
             "$BUILD/libevtx.tar.gz"
    extract "$BUILD/libevtx.tar.gz" "$BUILD/libevtx-$arch"
    if [ ! -f "$prefix/bin/evtxexport" ]; then
        (cd "$BUILD/libevtx-$arch" && \
            ./configure --host="$host" --prefix="$prefix" \
                --enable-static --disable-shared \
                --disable-python --without-libfuse && \
            make -j"$(sysctl -n hw.ncpu)" && \
            make install)
    fi

    # libregf (Windows Registry hive parsing)
    download "https://github.com/libyal/libregf/releases/download/$LIBREGF_VERSION/libregf-alpha-$LIBREGF_VERSION.tar.gz" \
             "$BUILD/libregf.tar.gz"
    extract "$BUILD/libregf.tar.gz" "$BUILD/libregf-$arch"
    if [ ! -f "$prefix/bin/regfexport" ]; then
        (cd "$BUILD/libregf-$arch" && \
            ./configure --host="$host" --prefix="$prefix" \
                --enable-static --disable-shared \
                --disable-python --without-libfuse && \
            make -j"$(sysctl -n hw.ncpu)" && \
            make install)
    fi

    # liblnk (Windows Shell Link / .lnk parsing). 2024-era libyal tag, so its
    # configure tolerates a missing pkg-config the same way libevtx/libregf do
    # (no shim needed, unlike the newer libscca).
    download "https://github.com/libyal/liblnk/releases/download/$LIBLNK_VERSION/liblnk-alpha-$LIBLNK_VERSION.tar.gz" \
             "$BUILD/liblnk.tar.gz"
    extract "$BUILD/liblnk.tar.gz" "$BUILD/liblnk-$arch"
    if [ ! -f "$prefix/bin/lnkinfo" ]; then
        (cd "$BUILD/liblnk-$arch" && \
            ./configure --host="$host" --prefix="$prefix" \
                --enable-static --disable-shared \
                --disable-python --without-libfuse && \
            make -j"$(sysctl -n hw.ncpu)" && \
            make install)
    fi

    # sleuthkit
    # TSK's configure uses pkg-config to detect libewf/libvhdi; on stock macOS
    # there's no pkg-config, so detection silently disables both. We feed the
    # include/lib paths directly via CPPFLAGS/LDFLAGS so the fallback link
    # tests succeed. Verify by checking the configure summary - it must say
    # "afflib support: no" and "libewf support: yes".
    download "https://github.com/sleuthkit/sleuthkit/releases/download/sleuthkit-$TSK_VERSION/sleuthkit-$TSK_VERSION.tar.gz" \
             "$BUILD/sleuthkit.tar.gz"
    extract "$BUILD/sleuthkit.tar.gz" "$BUILD/sleuthkit-$arch"
    # TSK 4.15.0 calls libewf_handle_read_random, which current libewf-
    # experimental has renamed to libewf_handle_read_buffer_at_offset (same
    # signature). The rename is fixed in TSK's main branch but not in any
    # release yet, so we apply it ourselves.
    if grep -q "libewf_handle_read_random" "$BUILD/sleuthkit-$arch/tsk/img/ewf.cpp"; then
        sed -i.bak 's/libewf_handle_read_random/libewf_handle_read_buffer_at_offset/g' \
            "$BUILD/sleuthkit-$arch/tsk/img/ewf.cpp"
    fi

    # tsk_loaddb aborts the whole partition walk the first time it can't
    # determine a filesystem type - so on every modern Windows GPT disk it
    # dies on the Microsoft Reserved Partition before reaching the main NTFS
    # volume. Patch the partition-walk callback to skip the few well-known
    # no-FS partition types up-front so the walker reaches data partitions.
    if ! grep -q "Strata patch" "$BUILD/sleuthkit-$arch/tsk/auto/auto.cpp"; then
        # Anchor on setCurVsPart, which is unique to vsWalkCb (the volume
        # system walker callback). The generic "see if the super class..."
        # comment also appears in a pool callback that has no a_vs_part.
        perl -i.bak -pe 's{(tsk->setCurVsPart\(a_vs_part\);)}{$1\n\n    // Strata patch: pre-skip partitions that are known to carry no\n    // filesystem so the walker does not abort on them.\n    if (a_vs_part->desc != NULL) {\n        const char *_strata_d = a_vs_part->desc;\n        if (strstr(_strata_d, "Microsoft reserved") != NULL ||\n            strstr(_strata_d, "Safety Table") != NULL ||\n            strstr(_strata_d, "GPT Header") != NULL ||\n            strstr(_strata_d, "Partition Table") != NULL) {\n            return TSK_WALK_CONT;\n        }\n    }}' "$BUILD/sleuthkit-$arch/tsk/auto/auto.cpp"
    fi
    if [ ! -f "$prefix/bin/tsk_loaddb" ]; then
        (cd "$BUILD/sleuthkit-$arch" && \
            CPPFLAGS="-I$prefix/include ${CPPFLAGS:-}" \
            LDFLAGS="-L$prefix/lib ${LDFLAGS:-}" \
            LIBS="-lz -lbz2" \
            ./configure --host="$host" --prefix="$prefix" \
                --disable-java --disable-shared \
                --with-libewf="$prefix" --with-libvhdi="$prefix" \
                --with-libvmdk="$prefix" && \
            make -j"$(sysctl -n hw.ncpu)" && \
            make install)
    fi

    for tool in "${TOOLS[@]}"; do
        if [ -f "$prefix/bin/$tool" ]; then
            cp "$prefix/bin/$tool" "$arch_out/$tool"
        fi
    done
    echo ">>> $arch tools in $arch_out"
}

lipo_universal() {
    local universal_out="$OUT/bin/universal"
    mkdir -p "$universal_out"
    for tool in "${TOOLS[@]}"; do
        local arm="$OUT/bin/arm64/$tool"
        local x86="$OUT/bin/x86_64/$tool"
        if [ -f "$arm" ] && [ -f "$x86" ]; then
            lipo -create "$arm" "$x86" -output "$universal_out/$tool"
            echo ">>> universal $tool"
        fi
    done
}

target="${1:-$(uname -m)}"
case "$target" in
    universal)
        build_arch arm64
        build_arch x86_64
        lipo_universal
        ;;
    arm64|x86_64)
        build_arch "$target"
        ;;
    *)
        echo "Unknown target: $target (use arm64, x86_64, or universal)" >&2
        exit 1
        ;;
esac

echo ">>> Done."
