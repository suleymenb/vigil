#!/bin/sh
# vigil installer
#
#   curl -fsSL https://raw.githubusercontent.com/suleymenb/vigil/master/install.sh | sh
#
# Options (environment variables):
#   VIGIL_VERSION=v0.3.0          install a specific release (default: latest)
#   VIGIL_INSTALL_DIR=~/.local/bin  install somewhere else (default: /usr/local/bin)
#
# Downloads the static binary for your OS/CPU from GitHub Releases, verifies
# its SHA-256 checksum and installs it. Uses sudo only when the target
# directory isn't writable.
set -eu

REPO="suleymenb/vigil"
BIN_DIR="${VIGIL_INSTALL_DIR:-/usr/local/bin}"
VERSION="${VIGIL_VERSION:-latest}"

os=$(uname -s)
arch=$(uname -m)
case "$os-$arch" in
  Linux-x86_64 | Linux-amd64) target=x86_64-unknown-linux-musl ;;
  Linux-aarch64 | Linux-arm64) target=aarch64-unknown-linux-musl ;;
  Darwin-arm64) target=aarch64-apple-darwin ;;
  Darwin-x86_64) target=x86_64-apple-darwin ;;
  *)
    echo "vigil: no prebuilt binary for $os/$arch." >&2
    echo "Build from source instead: cargo install --git https://github.com/$REPO" >&2
    exit 1
    ;;
esac

if [ "$VERSION" = "latest" ]; then
  base="https://github.com/$REPO/releases/latest/download"
else
  base="https://github.com/$REPO/releases/download/$VERSION"
fi

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
asset="vigil-$target.tar.gz"

echo "→ downloading $asset ($VERSION)"
curl -fsSL "$base/$asset" -o "$tmp/$asset"
curl -fsSL "$base/$asset.sha256" -o "$tmp/$asset.sha256"

echo "→ verifying checksum"
if command -v sha256sum >/dev/null 2>&1; then
  (cd "$tmp" && sha256sum -c "$asset.sha256" >/dev/null)
else
  (cd "$tmp" && shasum -a 256 -c "$asset.sha256" >/dev/null)
fi

tar -xzf "$tmp/$asset" -C "$tmp"
src="$tmp/vigil-$target/vigil"

if [ -d "$BIN_DIR" ] && [ -w "$BIN_DIR" ] || mkdir -p "$BIN_DIR" 2>/dev/null && [ -w "$BIN_DIR" ]; then
  install -m 755 "$src" "$BIN_DIR/vigil"
else
  echo "→ installing to $BIN_DIR (needs sudo)"
  sudo mkdir -p "$BIN_DIR"
  sudo install -m 755 "$src" "$BIN_DIR/vigil"
fi

if [ "$os" = "Darwin" ]; then
  xattr -d com.apple.quarantine "$BIN_DIR/vigil" 2>/dev/null || true
fi

echo "✓ $("$BIN_DIR/vigil" --version) installed to $BIN_DIR/vigil"
case ":$PATH:" in
  *":$BIN_DIR:"*) ;;
  *) echo "  note: $BIN_DIR is not in your PATH" ;;
esac
echo "  run it with: sudo vigil"
