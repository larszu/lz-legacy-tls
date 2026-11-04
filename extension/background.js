// LZ Legacy TLS - service worker.
// Holds the Native Messaging port to the local helper and remembers devices.
// An open native port keeps the service worker alive (Chrome 105+), and the
// helper process lives exactly as long as that port: when it goes, all bridges go.

const HOST_NAME = "de.zumpelars.legacy_tls";
// Errors Chrome reports when a device only offers TLS 1.0/1.1 or old ciphers.
const TLS_ERRORS = new Set([
  "net::ERR_SSL_VERSION_OR_CIPHER_MISMATCH",
  "net::ERR_SSL_OBSOLETE_VERSION",
  "net::ERR_SSL_OBSOLETE_VERSION_OR_CIPHER",
  "net::ERR_SSL_PROTOCOL_ERROR",
  "net::ERR_SSL_VERSION_INTERFERENCE",
  "net::ERR_SSL_UNSAFE_NEGOTIATION",
  "net::ERR_SSL_BAD_RECORD_MAC_ALERT",
]);
// A bridge URL that nobody answers: helper was restarted, Chrome restarted, bookmark.
const BRIDGE_DOWN = new Set(["net::ERR_CONNECTION_REFUSED", "net::ERR_EMPTY_RESPONSE", "net::ERR_CONNECTION_RESET"]);
const DEFAULT_SETTINGS = { autoOpen: false };

let port = null;
let nextId = 1;
const pending = new Map();
let helperError = null; // last reason the helper could not be reached
const ui = []; // extension-side events (TLS errors, helper problems)
const reviving = new Set(); // tabs currently being brought back to a restarted bridge

function note(kind, text) {
  ui.push({ t: Date.now() / 1000, kind, text });
  if (ui.length > 40) ui.shift();
}

// Chrome's own wording is English and technical; say what to do instead.
export function explainHelperError(error) {
  if (/not found/i.test(error)) return "Helfer nicht installiert. Im Repo ./install.sh ausführen, dann Chrome neu starten.";
  if (/forbidden/i.test(error)) return "Helfer ist für eine andere Erweiterungs-ID registriert. ./install.sh <Erweiterungs-ID> ausführen.";
  if (/exited|crashed|disconnected/i.test(error)) return "Helfer wurde beendet. „Helfer neu verbinden“ versuchen; sonst python3 prüfen.";
  return error;
}

function failPending(error) {
  for (const done of pending.values()) done({ ok: false, error, helperMissing: true });
  pending.clear();
}

function connect() {
  if (port) return port;
  const p = chrome.runtime.connectNative(HOST_NAME);
  port = p;
  p.onMessage.addListener((msg) => {
    helperError = null;
    const done = pending.get(msg.id);
    if (done) {
      pending.delete(msg.id);
      done(msg);
    }
  });
  p.onDisconnect.addListener(() => {
    if (port !== p) return; // an old port we dropped on purpose
    const error = explainHelperError(chrome.runtime.lastError?.message || "Helper disconnected");
    helperError = error;
    note("error", `Helfer getrennt: ${error}`);
    failPending(error);
    port = null;
  });
  return p;
}

function disconnect() {
  const p = port;
  port = null;
  try {
    p?.disconnect();
  } catch {}
  failPending("Helfer neu verbunden");
}

function call(msg, timeoutMs = 12000) {
  return new Promise((resolve) => {
    const id = nextId++;
    const timer = setTimeout(() => {
      pending.delete(id);
      resolve({ ok: false, error: "Helfer antwortet nicht" });
    }, timeoutMs);
    pending.set(id, (reply) => {
      clearTimeout(timer);
      resolve(reply);
    });
    try {
      connect().postMessage({ ...msg, id });
    } catch (e) {
      clearTimeout(timer);
      pending.delete(id);
      helperError = explainHelperError(String(e.message || e));
      port = null;
      resolve({ ok: false, error: helperError, helperMissing: true });
    }
  });
}

async function getSettings() {
  const { settings = {} } = await chrome.storage.local.get("settings");
  return { ...DEFAULT_SETTINGS, ...settings };
}

async function getDevices() {
  const { devices = [] } = await chrome.storage.local.get("devices");
  return devices;
}

async function saveDevice(device) {
  const devices = await getDevices();
  const i = devices.findIndex((d) => d.target === device.target);
  if (i >= 0) devices[i] = { ...devices[i], ...device };
  else devices.unshift(device);
  await chrome.storage.local.set({ devices });
  return devices;
}

// "192.168.1.20" or "encoder:8443" - port 443 is left out, like the popup does.
export function targetOf(url) {
  return url.port && url.port !== "443" ? `${url.hostname}:${url.port}` : url.hostname;
}

async function openDevice(target, { newTab = true, tabId, path = "/" } = {}) {
  const devices = await getDevices();
  const known = devices.find((d) => d.target === target);
  const reply = await call({ cmd: "open", target, localPort: known?.localPort || 0 });
  if (!reply.url) {
    note("error", `${target}: ${reply.error || "Brücke nicht gestartet"}`);
    return reply;
  }
  await saveDevice({
    target,
    name: known?.name || target,
    localPort: reply.localPort,
    origin: new URL(reply.url).origin,
    tls: reply.tls || known?.tls || null,
    cipher: reply.cipher || known?.cipher || null,
    lastOpened: Date.now(),
  });
  const url = reply.url.replace(/\/$/, "") + (path || "/");
  if (tabId != null && !newTab) await chrome.tabs.update(tabId, { url });
  else await chrome.tabs.create({ url });
  return { ...reply, opened: url };
}

async function clearFailed(tabId) {
  await chrome.storage.session.remove(`failed:${tabId}`);
  chrome.action.setBadgeText({ tabId, text: "" }).catch(() => {});
}

chrome.webNavigation.onErrorOccurred.addListener(async (d) => {
  if (d.frameId !== 0) return;
  let url;
  try {
    url = new URL(d.url);
  } catch {
    return;
  }

  // 1. A bridge address that nobody answers: start the bridge again on the same port.
  if (url.protocol === "http:" && BRIDGE_DOWN.has(d.error) && !reviving.has(d.tabId)) {
    const device = (await getDevices()).find(
      (x) => x.localPort && String(x.localPort) === url.port && (x.origin ? x.origin === url.origin : /^(127\.0\.0\.1|localhost)$/.test(url.hostname)),
    );
    if (!device) return;
    reviving.add(d.tabId);
    note("info", `${device.target}: Brücke neu gestartet`);
    try {
      await openDevice(device.target, { newTab: false, tabId: d.tabId, path: url.pathname + url.search + url.hash });
    } finally {
      setTimeout(() => reviving.delete(d.tabId), 5000); // no reload loop if it fails again
    }
    return;
  }

  // 2. The device itself, refused by Chrome because of old TLS.
  if (url.protocol !== "https:" || !TLS_ERRORS.has(d.error)) return;
  const target = targetOf(url);
  const path = url.pathname + url.search + url.hash;
  note("tls", `${target}: ${d.error.replace("net::", "")}`);
  const settings = await getSettings();
  const known = (await getDevices()).some((x) => x.target === target);
  // Known devices were opened through the bridge before - send them there straight away.
  if (settings.autoOpen || known) {
    const r = await openDevice(target, { newTab: false, tabId: d.tabId, path });
    if (r.url) return;
  }
  await chrome.storage.session.set({ [`failed:${d.tabId}`]: { target, path } });
  chrome.action.setBadgeText({ tabId: d.tabId, text: "TLS" });
  chrome.action.setBadgeBackgroundColor({ tabId: d.tabId, color: "#D6402E" });
  chrome.action.setBadgeTextColor?.({ tabId: d.tabId, color: "#FFFFFF" });
});

// The tab loaded something successfully: the hint no longer applies.
// (onCompleted never fires for error pages, unlike onCommitted.)
chrome.webNavigation.onCompleted.addListener((d) => {
  if (d.frameId === 0) clearFailed(d.tabId);
});

chrome.tabs.onRemoved.addListener((tabId) => chrome.storage.session.remove(`failed:${tabId}`));

const handlers = {
  async hello() {
    const r = await call({ cmd: "hello" }, 5000);
    return { ...r, helperError, extensionId: chrome.runtime.id };
  },
  async devices() {
    return { ok: true, devices: await getDevices() };
  },
  async failed(msg) {
    const key = `failed:${msg.tabId}`;
    return { ok: true, failed: (await chrome.storage.session.get(key))[key] || null };
  },
  async open(msg) {
    const reply = await openDevice(msg.target, { newTab: !msg.replaceTab, tabId: msg.tabId, path: msg.path });
    if (reply.url && msg.tabId != null) await clearFailed(msg.tabId);
    return reply;
  },
  async activity(msg) {
    const since = msg.since || 0;
    const mine = ui.filter((e) => e.t > since);
    if (!port) return { ok: true, bridges: [], events: mine, helperError };
    const r = await call({ cmd: "log", since }, 3000);
    const events = [...(r.events || []), ...mine].sort((a, b) => a.t - b.t);
    return { ok: r.ok, bridges: r.bridges || [], events, helperError };
  },
  async settings() {
    return { ok: true, settings: await getSettings() };
  },
  async saveSettings(msg) {
    const settings = { ...(await getSettings()), ...msg.settings };
    await chrome.storage.local.set({ settings });
    return { ok: true, settings };
  },
  async stopAll() {
    const r = await call({ cmd: "list" }, 3000);
    for (const b of r.bridges || []) await call({ cmd: "close", target: `${b.host}:${b.port}` }, 3000);
    note("info", "Alle Brücken beendet");
    return { ok: true };
  },
  async reconnect() {
    disconnect();
    helperError = null;
    return handlers.hello();
  },
  async rename(msg) {
    return { ok: true, devices: await saveDevice({ target: msg.target, name: msg.name }) };
  },
  async restore(msg) {
    const devices = (await getDevices()).filter((d) => d.target !== msg.device.target);
    devices.splice(Math.min(msg.index ?? 0, devices.length), 0, msg.device);
    await chrome.storage.local.set({ devices });
    return { ok: true, devices };
  },
  async remove(msg) {
    const devices = (await getDevices()).filter((d) => d.target !== msg.target);
    await chrome.storage.local.set({ devices });
    if (port) await call({ cmd: "close", target: msg.target }, 3000);
    return { ok: true, devices };
  },
};

chrome.runtime.onMessage.addListener((msg, _sender, respond) => {
  const h = handlers[msg?.type];
  if (!h) {
    respond({ ok: false, error: "unknown message" });
    return false;
  }
  h(msg)
    .catch((e) => ({ ok: false, error: String(e?.message || e) }))
    .then(respond);
  return true;
});
