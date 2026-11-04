// LZ Legacy TLS - service worker.
// Holds the Native Messaging port to the local helper and remembers devices.

const HOST_NAME = "de.zumpelars.legacy_tls";
const TLS_ERRORS = new Set([
  "net::ERR_SSL_VERSION_OR_CIPHER_MISMATCH",
  "net::ERR_SSL_OBSOLETE_VERSION",
  "net::ERR_SSL_OBSOLETE_VERSION_OR_CIPHER",
  "net::ERR_SSL_PROTOCOL_ERROR",
]);

let port = null;
let nextId = 1;
const pending = new Map();

function connect() {
  if (port) return port;
  port = chrome.runtime.connectNative(HOST_NAME);
  port.onMessage.addListener((msg) => {
    const done = pending.get(msg.id);
    if (done) {
      pending.delete(msg.id);
      done(msg);
    }
  });
  port.onDisconnect.addListener(() => {
    const error = chrome.runtime.lastError?.message || "Helper disconnected";
    for (const done of pending.values()) done({ ok: false, error, helperMissing: true });
    pending.clear();
    port = null;
  });
  return port;
}

function call(msg, timeoutMs = 12000) {
  return new Promise((resolve) => {
    const id = nextId++;
    const timer = setTimeout(() => {
      pending.delete(id);
      resolve({ ok: false, error: "Helper did not answer" });
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
      resolve({ ok: false, error: String(e.message || e), helperMissing: true });
    }
  });
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

async function openDevice(target, { newTab = true, tabId, path = "/" } = {}) {
  const devices = await getDevices();
  const known = devices.find((d) => d.target === target);
  const reply = await call({ cmd: "open", target, localPort: known?.localPort || 0 });
  if (!reply.url) return reply;
  await saveDevice({
    target,
    name: known?.name || target,
    localPort: reply.localPort,
    tls: reply.tls || known?.tls || null,
    lastOpened: Date.now(),
  });
  const url = reply.url.replace(/\/$/, "") + (path || "/");
  if (tabId != null && !newTab) await chrome.tabs.update(tabId, { url });
  else await chrome.tabs.create({ url });
  return reply;
}

// Remember tabs that just failed because of old TLS, so the popup can offer the fix.
chrome.webNavigation.onErrorOccurred.addListener(async (d) => {
  if (d.frameId !== 0 || !TLS_ERRORS.has(d.error)) return;
  let url;
  try {
    url = new URL(d.url);
  } catch {
    return;
  }
  if (url.protocol !== "https:") return;
  const target = url.port ? `${url.hostname}:${url.port}` : url.hostname;
  await chrome.storage.session.set({ [`failed:${d.tabId}`]: { target, path: url.pathname + url.search } });
  chrome.action.setBadgeText({ tabId: d.tabId, text: "TLS" });
  chrome.action.setBadgeBackgroundColor({ tabId: d.tabId, color: "#D6402E" });
});

chrome.tabs.onRemoved.addListener((tabId) => chrome.storage.session.remove(`failed:${tabId}`));

chrome.runtime.onMessage.addListener((msg, _sender, respond) => {
  (async () => {
    switch (msg.type) {
      case "hello":
        return call({ cmd: "hello" }, 5000);
      case "devices":
        return { ok: true, devices: await getDevices() };
      case "failed": {
        const key = `failed:${msg.tabId}`;
        return { ok: true, failed: (await chrome.storage.session.get(key))[key] || null };
      }
      case "open": {
        const reply = await openDevice(msg.target, { newTab: !msg.replaceTab, tabId: msg.tabId, path: msg.path });
        if (reply.url && msg.tabId != null) {
          chrome.storage.session.remove(`failed:${msg.tabId}`);
          chrome.action.setBadgeText({ tabId: msg.tabId, text: "" });
        }
        return reply;
      }
      case "rename":
        return { ok: true, devices: await saveDevice({ target: msg.target, name: msg.name }) };
      case "remove": {
        const devices = (await getDevices()).filter((d) => d.target !== msg.target);
        await chrome.storage.local.set({ devices });
        await call({ cmd: "close", target: msg.target }, 3000);
        return { ok: true, devices };
      }
      default:
        return { ok: false, error: "unknown message" };
    }
  })().then(respond);
  return true;
});
