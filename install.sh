#!/bin/sh
# Installs the LZ Legacy TLS native helper for Chrome, Chromium, Brave, Edge and Vivaldi.
# Usage: ./install.sh [extension-id]      (default: the fixed ID from manifest.json)
#        ./install.sh --uninstall
set -eu

NAME="de.zumpelars.legacy_tls"
EXT_ID="${1:-ldjkmfibbeaepcpekmkjefgieohjlcef}"
HERE="$(cd "$(dirname "$0")" && pwd)"

case "$(uname -s)" in
  Darwin)
    APP="$HOME/Library/Application Support/LZ Legacy TLS"
    BASES="$HOME/Library/Application Support/Google/Chrome
$HOME/Library/Application Support/Google/Chrome Beta
$HOME/Library/Application Support/Chromium
$HOME/Library/Application Support/BraveSoftware/Brave-Browser
$HOME/Library/Application Support/Microsoft Edge
$HOME/Library/Application Support/Vivaldi" ;;
  Linux)
    APP="$HOME/.local/share/lz-legacy-tls"
    BASES="$HOME/.config/google-chrome
$HOME/.config/chromium
$HOME/.config/BraveSoftware/Brave-Browser
$HOME/.config/microsoft-edge
$HOME/.config/vivaldi" ;;
  *) echo "Unsupported OS. On Windows run install.ps1."; exit 1 ;;
esac

if [ "${1:-}" = "--uninstall" ]; then
  echo "$BASES" | while IFS= read -r b; do rm -f "$b/NativeMessagingHosts/$NAME.json"; done
  rm -rf "$APP"
  echo "Removed."
  exit 0
fi

# Python 3 with TLS 1.0 support. Prefer the system Python on macOS (LibreSSL still speaks TLS 1.0).
PY=""
for c in /usr/bin/python3 /opt/homebrew/bin/python3 /usr/local/bin/python3 "$(command -v python3 || true)"; do
  [ -n "$c" ] && [ -x "$c" ] && "$c" -c 'import ssl' 2>/dev/null && { PY="$c"; break; }
done
[ -n "$PY" ] || { echo "python3 not found"; exit 1; }

mkdir -p "$APP"
cp "$HERE/host/legacy_tls_bridge.py" "$APP/legacy_tls_bridge.py"
cat > "$APP/run-host.sh" <<EOF
#!/bin/sh
exec "$PY" -I "$APP/legacy_tls_bridge.py" "\$@"
EOF
chmod 755 "$APP/run-host.sh" "$APP/legacy_tls_bridge.py"

MANIFEST="{
  \"name\": \"$NAME\",
  \"description\": \"LZ Legacy TLS local bridge\",
  \"path\": \"$APP/run-host.sh\",
  \"type\": \"stdio\",
  \"allowed_origins\": [\"chrome-extension://$EXT_ID/\"]
}"

n=0
echo "$BASES" | while IFS= read -r b; do
  [ -d "$b" ] || continue
  mkdir -p "$b/NativeMessagingHosts"
  printf '%s\n' "$MANIFEST" > "$b/NativeMessagingHosts/$NAME.json"
  echo "registered: $b"
done

echo "Helper: $APP (python: $PY)"
"$PY" -I -c "import ssl; print('ssl:', ssl.OPENSSL_VERSION)"
echo "Done. Restart the browser, then load extension/ via chrome://extensions (developer mode)."
