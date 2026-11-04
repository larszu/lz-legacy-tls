# LZ Legacy TLS

**Open old device web interfaces that modern browsers refuse.**

Encoders, KVMs, switches, cameras and UPS cards often still speak only TLS 1.0/1.1 with CBC-SHA1 ciphers. Chrome answers with `ERR_SSL_VERSION_OR_CIPHER_MISMATCH` and there is no flag left to allow it. LZ Legacy TLS puts a tiny local bridge in between: the browser talks plain HTTP to `127.0.0.1`, the bridge talks whatever TLS the device still accepts.

```
Chrome ──http──▶ 127.0.0.1:<port> ──TLS 1.0 / AES-SHA──▶ device:443
```

## Parts

| Part | What it does |
|---|---|
| `extension/` | Chrome extension (Manifest V3). Detects the TLS error on a tab, offers “open via bridge”, keeps a device list. |
| `host/legacy_tls_bridge.py` | The bridge. Python 3 standard library only. Runs as Native Messaging host for the extension **or** standalone from the command line. |
| `install.sh` | Registers the host for Chrome, Chromium, Brave, Edge and Vivaldi (macOS, Linux). |

A browser extension cannot open raw TLS sockets itself, so the helper is required.

## Install

```sh
git clone https://github.com/larszu/lz-legacy-tls.git
cd lz-legacy-tls
./install.sh
```

Then in Chrome: `chrome://extensions` → enable *Developer mode* → *Load unpacked* → choose `extension/`. Restart Chrome once so it picks up the helper.

The extension has a fixed ID (`ldjkmfibbeaepcpekmkjefgieohjlcef`), so `install.sh` needs no arguments. If you repack it under another ID, run `./install.sh <your-id>`.

Remove everything with `./install.sh --uninstall`.

## Use

- Open the device as usual (`https://192.168.1.20`). When Chrome shows the TLS error, click the extension icon (badge **TLS**) → **Open via bridge**. The page reloads through the bridge, same path.
- Or type the address in the popup. Devices are remembered with their local port, so bookmarks keep working.

Without the extension:

```sh
python3 host/legacy_tls_bridge.py 192.168.1.20          # → http://127.0.0.1:8443/
python3 host/legacy_tls_bridge.py https://encoder:8443 --listen 9000
```

## What the bridge rewrites

- `Host`, `Origin`, `Referer` → the device's own address, so CSRF checks pass.
- `Location` redirects pointing at the device → back to the bridge.
- `Set-Cookie`: drops `Domain=` so the cookie sticks to `127.0.0.1`.
- Removes `Strict-Transport-Security`.
- WebSocket upgrades are passed through.

## Security

- Listens on `127.0.0.1` only. Nothing is exposed to the network.
- Device certificates are **not verified** – these devices almost always use self-signed certificates. Use it on networks you trust.
- The traffic to the device uses obsolete encryption. That is the point; it is not better than what the device offers.

## Requirements

- Python 3.8+. macOS: the system `/usr/bin/python3` (LibreSSL) works; Homebrew Python with OpenSSL 3 works as well (`@SECLEVEL=0`).
- Chrome 116+ or another Chromium browser.
- Windows: the bridge runs (`python legacy_tls_bridge.py <host>`); the installer for the extension helper is not written yet.

## Tests

```sh
python3 -m unittest discover -s tests -v
```

The tests start a real TLS-1.0-only HTTPS server and drive it through the bridge and the Native Messaging protocol.

---

## Deutsch (kurz)

Öffnet Weboberflächen alter Geräte, die nur noch TLS 1.0/1.1 sprechen und von Chrome mit `ERR_SSL_VERSION_OR_CIPHER_MISMATCH` abgelehnt werden. Ein lokaler Helfer übersetzt zwischen Browser (HTTP auf 127.0.0.1) und Gerät (altes TLS).

1. `./install.sh` ausführen.
2. In `chrome://extensions` den Entwicklermodus einschalten und `extension/` als entpackte Erweiterung laden, Chrome einmal neu starten.
3. Beim TLS-Fehler auf das Symbol klicken → **Über die Brücke öffnen**.

Der Helfer lauscht nur auf 127.0.0.1 und prüft keine Gerätezertifikate.

License: MIT
