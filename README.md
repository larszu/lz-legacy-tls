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

- Open the device as usual (`https://192.168.1.20`). When Chrome shows the TLS error, click the extension icon (badge **TLS**) → **Open via bridge**. The page reloads through the bridge, same path and hash.
- Or type the address in the popup.
- Devices in the list are redirected automatically next time. With *Redirect automatically* (settings) every TLS error is redirected without a click.
- Each device gets its own name, e.g. `http://192-168-2-3.localhost:<port>/`. Browsers resolve every `*.localhost` name to the loopback address; separate names keep the cookies (logins) of different devices apart.
- Devices keep their local port. If the helper was restarted (Chrome restart, bookmark), opening the old bridge address starts the bridge again on that port.

### Popup

- Header: helper status (*Helfer bereit* / *Helfer fehlt*) and settings.
- Device list with live counters (requests, data, errors); double-click a name to rename, delete with undo.
- Activity log: every request through the bridge with status and time, plus TLS errors and helper problems (updates every second).
- Settings: *Redirect automatically*, theme Auto/Light/Dark, diagnostics (helper version, Python, TLS library, running bridges, last error, extension ID), *Reconnect helper*, *Stop all bridges*.

Without the extension:

```sh
python3 host/legacy_tls_bridge.py 192.168.1.20          # → http://127.0.0.1:8443/
python3 host/legacy_tls_bridge.py https://encoder:8443 --listen 9000
```

## What the bridge rewrites

- `Host`, `Origin`, `Referer` → the device's own address, so CSRF checks pass.
- `Location`, `Content-Location`, `Refresh` pointing at the device (also with `:443`) → back to the bridge, under the name the browser used.
- `Set-Cookie`: drops `Domain=` and `Secure` (the browser talks plain HTTP to the bridge); `SameSite=None` becomes `Lax`. `__Secure-`/`__Host-` cookies stay untouched.
- Removes `Strict-Transport-Security`.
- WebSocket upgrades are passed through.

## Security

- Listens on `127.0.0.1` only. Nothing is exposed to the network.
- Refuses requests whose `Origin` is another site (a web page cannot use the bridge to reach the device) and requests with a non-loopback `Host` (DNS rebinding).
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

Das Popup zeigt oben den Status des Helfers, darunter die Geräte mit Live-Zählern (Anfragen, Datenmenge, Fehler) und ein Aktivitätsprotokoll. Über das Zahnrad: *Automatisch umleiten*, Darstellung Auto/Hell/Dunkel, Diagnose, *Helfer neu verbinden*, *Alle Brücken beenden*. Bekannte Geräte werden beim nächsten TLS-Fehler direkt umgeleitet; jedes Gerät bekommt einen eigenen Namen (`192-168-2-3.localhost`), damit sich die Anmeldungen verschiedener Geräte nicht stören.

Der Helfer lauscht nur auf 127.0.0.1, lehnt Anfragen fremder Webseiten ab und prüft keine Gerätezertifikate.

License: MIT
