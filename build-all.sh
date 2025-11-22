#!/usr/bin/env bash
# R-Map Cross-Platform Build Script
# Builds standalone executables for Windows, Linux, macOS (x64 + ARM64)

set -euo pipefail

echo "🔥 R-Map Cross-Platform Build System"
echo "======================================"
echo ""

# Version
VERSION="1.0.0"
BUILD_DATE=$(date +%Y-%m-%d)
GIT_HASH=$(git rev-parse --short HEAD 2>/dev/null || echo "unknown")

echo "Version: $VERSION"
echo "Build Date: $BUILD_DATE"
echo "Git Hash: $GIT_HASH"
echo ""

# Create dist directory
DIST_DIR="dist"
rm -rf "$DIST_DIR"
mkdir -p "$DIST_DIR"

# Build targets
declare -a TARGETS=(
    "x86_64-unknown-linux-gnu"      # Linux x64
    "aarch64-unknown-linux-gnu"     # Linux ARM64
    "x86_64-apple-darwin"           # macOS x64
    "aarch64-apple-darwin"          # macOS ARM64 (M1/M2)
    "x86_64-pc-windows-gnu"         # Windows x64
)

# Binaries to build
declare -a BINARIES=(
    "rmap"                # Standalone network scanner
    "rmap-mcp-server"     # MCP server for AI integration
)

echo "📦 Building for platforms:"
for target in "${TARGETS[@]}"; do
    echo "  - $target"
done
echo ""

echo "🔧 Building binaries:"
for binary in "${BINARIES[@]}"; do
    echo "  - $binary"
done
echo ""

# Function to build for a target
build_target() {
    local target=$1
    local binary=$2

    echo "🚀 Building $binary for $target..."

    # Determine binary extension
    local ext=""
    if [[ $target == *"windows"* ]]; then
        ext=".exe"
    fi

    # Build
    if cargo build --release --target "$target" --bin "$binary" 2>/dev/null; then
        # Create target directory
        local target_dir="$DIST_DIR/$target"
        mkdir -p "$target_dir"

        # Copy binary
        local src="target/$target/release/$binary$ext"
        local dst="$target_dir/$binary$ext"

        if [ -f "$src" ]; then
            cp "$src" "$dst"

            # Strip if not Windows
            if [[ $target != *"windows"* ]] && command -v strip &> /dev/null; then
                strip "$dst" 2>/dev/null || true
            fi

            # Calculate size and hash
            local size=$(du -h "$dst" | cut -f1)
            local hash=$(sha256sum "$dst" | cut -d' ' -f1)

            echo "  ✅ Built: $dst ($size)"
            echo "     SHA256: $hash"

            # Create checksum file
            echo "$hash  $binary$ext" > "$target_dir/$binary.sha256"
        else
            echo "  ❌ Binary not found: $src"
        fi
    else
        echo "  ⚠️  Target $target not available (install with: rustup target add $target)"
    fi
    echo ""
}

# Install required targets
echo "📥 Checking required Rust targets..."
for target in "${TARGETS[@]}"; do
    if ! rustup target list | grep -q "$target (installed)"; then
        echo "  Installing $target..."
        rustup target add "$target" 2>/dev/null || echo "  ⚠️  Could not install $target (skipping)"
    fi
done
echo ""

# Build all combinations
for target in "${TARGETS[@]}"; do
    for binary in "${BINARIES[@]}"; do
        build_target "$target" "$binary"
    done
done

# Create package archives
echo "📦 Creating distribution packages..."
echo ""

cd "$DIST_DIR"
for target_dir in */; do
    target=$(basename "$target_dir")
    archive_name="rmap-$VERSION-$target"

    # Determine archive format
    if [[ $target == *"windows"* ]]; then
        # ZIP for Windows
        if command -v zip &> /dev/null; then
            zip -r "../$archive_name.zip" "$target" > /dev/null
            echo "  ✅ Created: $archive_name.zip"
        fi
    else
        # tar.gz for Unix
        if command -v tar &> /dev/null; then
            tar -czf "../$archive_name.tar.gz" "$target"
            echo "  ✅ Created: $archive_name.tar.gz"
        fi
    fi
done
cd ..

echo ""
echo "🎉 Build Complete!"
echo ""
echo "📂 Distribution directory: $DIST_DIR/"
ls -lh "$DIST_DIR" | tail -n +2
echo ""
echo "📦 Release packages:"
ls -lh rmap-$VERSION-*.{tar.gz,zip} 2>/dev/null | tail -n +2 || echo "  (No packages created)"
echo ""
