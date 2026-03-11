#!/bin/bash
############################################################################
# XyPriss Security - Ultra-Portable Cross-Platform Build System
#
# Builds the pure Go security core for all targets.
# Since we removed CGO, these are statically linked, 
# zero-dependency binaries.
############################################################################

set -e

# Path configuration
ROOT_DIR="$(pwd)"
CORE_DIR="$ROOT_DIR/lib/security-core"
DIST_DIR="$ROOT_DIR/releases/binaries"

mkdir -p "$DIST_DIR"

echo "🛡️  Starting XyPriss Security Enterprise Build Pipeline (Static CLI)..."
echo "🔍 Using $(go version) for compilation"

# Enter Go source directory
cd "$CORE_DIR"

# Universal Build function
# Arguments: $1:GOOS, $2:GOARCH, $3:Extension
build_target() {
    local OS=$1
    local ARCH=$2
    local EXT=$3
    local LABEL="${OS}-${ARCH}"
    local OUT_FILE="libxypriss_core-${LABEL}${EXT}"

    echo -e "\n📦 Building for $LABEL..."

    # Pure Go build (No CGO = Absolute Portability)
    CGO_ENABLED=0 \
    GOOS=$OS \
    GOARCH=$ARCH \
    go build \
        -ldflags="-s -w" \
        -o "$DIST_DIR/$OUT_FILE" \
        main.go

    echo "✅ Successfully generated: $OUT_FILE"
}

# --- Target Matrix ---

# 🐧 Linux
build_target "linux" "amd64" ""
build_target "linux" "arm64" ""

# 🍎 macOS (Darwin)
build_target "darwin" "amd64" ""
build_target "darwin" "arm64" ""

# 🪟 Windows
build_target "windows" "amd64" ".exe"
build_target "windows" "arm64" ".exe"

cd "$ROOT_DIR"
echo -e "\n🏁 Build complete! All enterprise binaries are located in: $DIST_DIR"
ls -lh "$DIST_DIR"

