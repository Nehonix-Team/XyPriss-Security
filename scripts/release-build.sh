#!/bin/bash
############################################################################
# XyPriss Security - Advanced Cross-Platform Build System (via Zig)
#
# This script uses Zig as a cross-compiler to build the Go security core
# for all targets without requiring separate toolchains for each OS.
############################################################################

set -e

# Path configuration
ROOT_DIR="$(pwd)"
CORE_DIR="$ROOT_DIR/lib/security-core"
DIST_DIR="$ROOT_DIR/releases/binaries"

mkdir -p "$DIST_DIR"

echo "�️  Starting XyPriss Security Enterprise Build Pipeline..."
echo "🔍 Using $(zig version) for cross-compilation"

# Enter Go source directory
cd "$CORE_DIR"

# Universal Build function
# Arguments: $1:GOOS, $2:GOARCH, $3:ZigTarget, $4:Extension
build_target() {
    local OS=$1
    local ARCH=$2
    local ZIG_TARGET=$3
    local EXT=$4
    local LABEL="${OS}-${ARCH}"
    local OUT_FILE="libxypriss_core-${LABEL}${EXT}"

    echo -e "\n📦 Building for $LABEL ($ZIG_TARGET)..."

    # Use Zig as the C compiler for CGO
    CGO_ENABLED=1 \
    GOOS=$OS \
    GOARCH=$ARCH \
    CC="zig cc -target $ZIG_TARGET" \
    go build \
        -o "$DIST_DIR/$OUT_FILE" \
        -buildmode=c-shared \
        main.go

    echo "✅ Successfully generated: $OUT_FILE"
}

# --- Target Matrix ---

# 🐧 Linux
build_target "linux" "amd64" "x86_64-linux-gnu" ".so"
build_target "linux" "arm64" "aarch64-linux-gnu" ".so"

# 🍎 macOS (Darwin)
build_target "darwin" "amd64" "x86_64-macos" ".dylib"
build_target "darwin" "arm64" "aarch64-macos" ".dylib"

# 🪟 Windows
build_target "windows" "amd64" "x86_64-windows-gnu" ".dll"

cd "$ROOT_DIR"
echo -e "\n🏁 Build complete! All enterprise binaries are located in: $DIST_DIR"
ls -lh "$DIST_DIR"
