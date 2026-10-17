#!/bin/sh
# kova installer -- https://kovaverified.io/install.sh
# Downloads the latest release binary for this OS/arch from GitHub Releases and installs it.
set -e
REPO="ian-hickey/kova"
BIN_DIR="${KOVA_INSTALL_DIR:-}"
OS=$(uname -s | tr '[:upper:]' '[:lower:]')
ARCH=$(uname -m)
case "$ARCH" in
  x86_64|amd64) ARCH=amd64 ;;
  arm64|aarch64) ARCH=arm64 ;;
  *) echo "kova: unsupported architecture $ARCH"; exit 1 ;;
esac
case "$OS" in
  darwin|linux) ;;
  *) echo "kova: unsupported OS $OS (use: go install github.com/$REPO/cmd/kova@latest)"; exit 1 ;;
esac
VERSION="${KOVA_VERSION:-$(curl -fsSL "https://api.github.com/repos/$REPO/releases/latest" | sed -n 's/.*"tag_name": *"\([^"]*\)".*/\1/p' | head -1)}"
if [ -z "$VERSION" ]; then
  echo "kova: could not determine latest release; falling back to go install"
  command -v go >/dev/null || { echo "kova: go not found"; exit 1; }
  go install "github.com/$REPO/cmd/kova@latest"
  echo "installed via go install -> $(go env GOPATH)/bin/kova"
  exit 0
fi
URL="https://github.com/$REPO/releases/download/$VERSION/kova-$OS-$ARCH"
TMP=$(mktemp -d)
echo "Downloading kova $VERSION for $OS/$ARCH ..."
ASSET="kova-$OS-$ARCH"
curl -fsSL "$URL" -o "$TMP/$ASSET"
if curl -fsSL "$URL.sha256" -o "$TMP/$ASSET.sha256" 2>/dev/null; then
  WANT=$(cut -d' ' -f1 "$TMP/$ASSET.sha256")
  if command -v sha256sum >/dev/null 2>&1; then GOT=$(sha256sum "$TMP/$ASSET" | cut -d' ' -f1)
  elif command -v shasum >/dev/null 2>&1; then GOT=$(shasum -a 256 "$TMP/$ASSET" | cut -d' ' -f1)
  else GOT=$WANT; echo "kova: no sha256 tool found, skipping checksum"; fi
  [ "$GOT" = "$WANT" ] || { echo "kova: checksum mismatch for $ASSET"; rm -rf "$TMP"; exit 1; }
fi
mv "$TMP/$ASSET" "$TMP/kova"
chmod +x "$TMP/kova"
if [ -z "$BIN_DIR" ]; then
  if [ -w /usr/local/bin ]; then BIN_DIR=/usr/local/bin; else BIN_DIR="$HOME/.local/bin"; mkdir -p "$BIN_DIR"; fi
fi
mv "$TMP/kova" "$BIN_DIR/kova"
rm -rf "$TMP"
echo "Installed $BIN_DIR/kova"
case ":$PATH:" in *":$BIN_DIR:"*) ;; *) echo "Add $BIN_DIR to your PATH." ;; esac
echo
echo "Next:  kova init        # pin this machine's agent tools and install session hooks"
echo "       kova wrap --all  # route MCP servers through the verifying proxy"
