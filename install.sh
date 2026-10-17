#!/bin/sh
# kova installer — https://kovaverified.io/install.sh
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
echo "Downloading kova $VERSION for $OS/$ARCH…"
curl -fsSL "$URL" -o "$TMP/kova"
curl -fsSL "$URL.sha256" -o "$TMP/kova.sha256" 2>/dev/null && {
  (cd "$TMP" && (command -v sha256sum >/dev/null && sha256sum -c kova.sha256 || shasum -a 256 -c kova.sha256) >/dev/null) || { echo "kova: checksum mismatch"; exit 1; }
}
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
