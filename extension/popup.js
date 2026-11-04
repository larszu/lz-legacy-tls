// LZ Legacy TLS - popup
const $ = (id) => document.getElementById(id);
// The service worker may be restarting; never let one failed message break the popup.
const send = async (msg) => {
  try {
    return (await chrome.runtime.sendMessage(msg)) || { ok: false, error: "Keine Antwort von der Erweiterung" };
  } catch (e) {
    return { ok: false, error: String(e?.message || e) };
  }
};

// ---- theme: Auto · Hell · Dunkel ------------------------------------------
function applyTheme(mode) {
  if (mode === "auto") delete document.documentElement.dataset.theme;
  else document.documentElement.dataset.theme = mode;
  for (const b of document.querySelectorAll("[data-theme-set]")) b.setAttribute("aria-checked", String(b.dataset.themeSet === mode));
}
chrome.storage.local.get("theme").then(({ theme = "auto" }) => applyTheme(theme));
for (const b of document.querySelectorAll("[data-theme-set]")) {
  b.addEventListener("click", () => {
    applyTheme(b.dataset.themeSet);
    chrome.storage.local.set({ theme: b.dataset.themeSet });
  });
}

// ---- helpers ----------------------------------------------------------------
const num = new Intl.NumberFormat("de-DE", { maximumFractionDigits: 1 });
const fmtBytes = (n) => (n < 1024 ? `${n} B` : n < 1048576 ? `${num.format(Math.round(n / 1024))} KB` : `${num.format(n / 1048576)} MB`);
const fmtTime = (t) => new Date(t * 1000).toLocaleTimeString("de-DE");

function normalize(text) {
  let t = text.trim();
  if (!t) return "";
  if (!t.includes("://")) t = "https://" + t;
  try {
    const u = new URL(t);
    return u.port && u.port !== "443" ? `${u.hostname}:${u.port}` : u.hostname;
  } catch {
    return "";
  }
}
function busy(button, on) {
  button.disabled = on;
  button.classList.toggle("busy", on);
}
function explain(reply) {
  const e = reply.error || "Unbekannter Fehler";
  if (reply.helperMissing) return `Helfer nicht erreichbar: ${e}`;
  if (/timed out|timeout/i.test(e)) return "Gerät antwortet nicht. Adresse und Netzwerk prüfen.";
  if (/refused/i.test(e)) return "Verbindung abgelehnt. Läuft dort ein HTTPS-Dienst auf diesem Port?";
  if (/nodename|not known|getaddrinfo/i.test(e)) return "Name nicht auflösbar. IP-Adresse eingeben.";
  if (/wrong version|unsupported protocol|handshake/i.test(e)) return `Gerät lehnt auch die Brücke ab: ${e}`;
  return e;
}

// ---- helper status ------------------------------------------------------------
function showHelper(reply) {
  const ok = !!reply?.ok;
  $("status").className = "status " + (ok ? "ok" : "bad");
  $("status-text").textContent = ok ? "Helfer bereit" : "Helfer fehlt";
  $("helper").hidden = ok;
  $("helper-reason").textContent = reply?.error || reply?.helperError || "";
  $("d-helper").textContent = ok ? `verbunden, Version ${reply.version}` : `nicht erreichbar${reply?.error ? ` (${reply.error})` : ""}`;
  $("d-python").textContent = reply?.python || "–";
  $("d-ssl").textContent = reply?.ssl || "–";
  $("d-id").textContent = reply?.extensionId || chrome.runtime.id;
}

async function open(target, button, extra = {}) {
  $("add-error").hidden = true;
  busy(button, true);
  const reply = await send({ type: "open", target, ...extra });
  busy(button, false);
  if (!reply.url) {
    if (reply.helperMissing) showHelper(reply);
    $("add-error").textContent = explain(reply);
    $("add-error").hidden = false;
    poll();
    return;
  }
  window.close();
}

// ---- devices ------------------------------------------------------------------
let devices = [];
let bridges = [];
let removed = null;
let toastTimer = 0;
let editing = false;
let lastKey = "";

function bridgeFor(d) {
  return bridges.find((b) => (b.port === 443 ? b.host : `${b.host}:${b.port}`) === d.target);
}

function stats(b) {
  const parts = [`${num.format(b.requests)} Anfragen`, fmtBytes(b.bytesIn)];
  if (b.failures) parts.push(`${num.format(b.failures)} Fehler`);
  return parts.map((p) => p.replace(/ /g, "\u00a0")).join(" · "); // wrap between parts, never inside
}

// Rebuild the list only when something visible changed. Polling runs every second;
// rebuilding each time would swallow clicks that land between two polls.
function updateLive() {
  for (const li of $("devices").children) {
    const d = devices.find((x) => x.target === li.dataset.target);
    const b = d && bridgeFor(d);
    li.classList.toggle("busy-now", !!b?.active);
    li.querySelector(".stats").textContent = b ? stats(b) : "Brücke aus";
  }
  $("d-bridges").textContent = bridges.length ? bridges.map((b) => `${b.host}:${b.port} → :${b.localPort}`).join(", ") : "keine";
}

function render(force = false) {
  // structure only; counters are patched in place by updateLive()
  const key = JSON.stringify([devices, bridges.map((b) => [b.host, b.port, b.tls, b.cipher])]);
  if (editing || (!force && key === lastKey)) return updateLive();
  lastKey = key;
  const list = $("devices");
  const focused = document.activeElement?.closest?.(".device")?.dataset.target;
  list.replaceChildren();
  $("empty").hidden = devices.length > 0;
  const tpl = $("device-tpl");
  for (const d of devices) {
    const li = tpl.content.firstElementChild.cloneNode(true);
    li.dataset.target = d.target;
    const b = bridgeFor(d);
    li.classList.toggle("running", !!b);
    li.classList.toggle("busy-now", !!b?.active);
    li.querySelector(".state").title = b ? "Brücke läuft" : "Brücke aus";
    li.querySelector(".name").textContent = d.name || d.target;
    const sub = d.name && d.name !== d.target ? d.target : "";
    li.querySelector(".target").textContent = sub;
    li.querySelector(".target").hidden = !sub;
    li.querySelector(".tls").textContent = b?.tls || d.tls || "";
    li.querySelector(".tls").title = b?.cipher || d.cipher || "";
    li.querySelector(".stats").textContent = b ? stats(b) : "Brücke aus";
    const btn = li.querySelector(".open");
    btn.setAttribute("aria-label", `${d.name || d.target} öffnen`);
    btn.addEventListener("click", () => open(d.target, btn));
    li.querySelector(".remove").addEventListener("click", async () => {
      removed = { device: d, index: devices.indexOf(d) };
      const r = await send({ type: "remove", target: d.target });
      if (r.devices) devices = r.devices;
      render(true);
      toast(`${d.name || d.target} entfernt`);
    });
    li.querySelector(".name").addEventListener("dblclick", () => rename(li, d));
    list.append(li);
    if (focused === d.target) li.querySelector(".open").focus();
  }
  updateLive();
}

// Inline rename (prompt() is unreliable in extension popups).
function rename(li, d) {
  editing = true;
  const span = li.querySelector(".name");
  const input = document.createElement("input");
  input.className = "rename";
  input.value = d.name || d.target;
  input.setAttribute("aria-label", "Name für dieses Gerät");
  span.replaceWith(input);
  input.focus();
  input.select();
  let done = false;
  const finish = async (save) => {
    if (done) return;
    done = true;
    editing = false;
    if (save) {
      const r = await send({ type: "rename", target: d.target, name: input.value.trim() || d.target });
      if (r.devices) devices = r.devices;
    }
    render(true);
  };
  input.addEventListener("keydown", (e) => {
    if (e.key === "Enter") finish(true);
    if (e.key === "Escape") {
      e.preventDefault();
      finish(false);
    }
  });
  input.addEventListener("blur", () => finish(true));
}

function toast(text) {
  $("toast-text").textContent = text;
  $("toast").hidden = false;
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => ($("toast").hidden = true), 8000);
}
$("toast-undo").addEventListener("click", async () => {
  if (!removed) return;
  const r = await send({ type: "restore", ...removed });
  removed = null;
  $("toast").hidden = true;
  if (r.devices) devices = r.devices;
  render(true);
});

// ---- activity log -------------------------------------------------------------
let since = 0;
const shown = [];
function addEvents(events) {
  for (const e of events) {
    shown.unshift(e);
    since = Math.max(since, e.t);
  }
  shown.splice(30);
  const ol = $("log");
  ol.replaceChildren();
  for (const e of shown) {
    const li = document.createElement("li");
    const st = String(e.status || "");
    li.className = `ev ${e.kind} ${/^[45]|ERR/.test(st) ? "bad" : /^3/.test(st) ? "redir" : ""}`;
    const time = document.createElement("time");
    time.textContent = fmtTime(e.t);
    const text = document.createElement("span");
    text.className = "txt";
    text.textContent = e.kind === "request" ? e.text : `${e.target ? e.target + ": " : ""}${e.text}`;
    text.title = text.textContent;
    li.append(time, text);
    if (e.kind === "request") {
      const s = document.createElement("span");
      s.className = "code";
      s.textContent = `${st} · ${e.ms} ms`;
      li.append(s);
    }
    ol.append(li);
  }
  $("log-empty").hidden = shown.length > 0;
}

let polling = false;
async function poll() {
  if (polling) return; // a slow answer must not pile up requests
  polling = true;
  try {
    const r = await send({ type: "activity", since });
    bridges = r.bridges || [];
    $("live").hidden = bridges.length === 0;
    if (r.events?.length) addEvents(r.events);
    $("d-error").textContent = r.helperError || (r.ok ? "–" : r.error || "–");
    render();
  } finally {
    polling = false;
  }
}

// ---- settings -----------------------------------------------------------------
function showSettings(on) {
  $("view-main").hidden = on;
  $("view-settings").hidden = !on;
  $("title").textContent = on ? "Einstellungen" : "Legacy TLS";
  $("settings-toggle").setAttribute("aria-expanded", String(on));
}
$("settings-toggle").addEventListener("click", () => showSettings($("view-settings").hidden));
$("settings-back").addEventListener("click", () => showSettings(false));
$("opt-auto").addEventListener("change", (e) => send({ type: "saveSettings", settings: { autoOpen: e.target.checked } }));
$("reconnect").addEventListener("click", async () => {
  busy($("reconnect"), true);
  showHelper(await send({ type: "reconnect" }));
  busy($("reconnect"), false);
  poll();
});
$("stop-all").addEventListener("click", async () => {
  await send({ type: "stopAll" });
  toast("Alle Brücken beendet");
  poll();
});

// ---- add form -----------------------------------------------------------------
$("add").addEventListener("submit", (e) => {
  e.preventDefault();
  const target = normalize($("target").value);
  if (!target) {
    $("add-error").textContent = "Bitte eine IP-Adresse oder einen Hostnamen eingeben.";
    $("add-error").hidden = false;
    return;
  }
  open(target, $("add-open"));
});

// ---- start --------------------------------------------------------------------
(async () => {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  const [hello, dev, failed, settings] = await Promise.all([
    send({ type: "hello" }),
    send({ type: "devices" }),
    tab ? send({ type: "failed", tabId: tab.id }) : { failed: null },
    send({ type: "settings" }),
  ]);
  showHelper(hello);
  devices = dev.devices || [];
  $("opt-auto").checked = !!settings.settings?.autoOpen;
  render(true);
  if (failed.failed) {
    const f = failed.failed;
    $("failed").hidden = false;
    $("failed-target").textContent = f.target;
    $("failed-open").addEventListener("click", () => open(f.target, $("failed-open"), { tabId: tab.id, replaceTab: true, path: f.path }));
    $("add-open").classList.replace("primary", "secondary");
    $("failed-open").focus();
  }
  await poll();
  setInterval(poll, 1000);
})();
