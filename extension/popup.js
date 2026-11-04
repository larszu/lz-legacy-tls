// LZ Legacy TLS - popup
const $ = (id) => document.getElementById(id);
const send = (msg) => chrome.runtime.sendMessage(msg);

// ---- theme: Auto · Hell · Dunkel ------------------------------------------
function applyTheme(mode) {
  if (mode === "auto") delete document.documentElement.dataset.theme;
  else document.documentElement.dataset.theme = mode;
  for (const b of document.querySelectorAll("[data-theme-set]")) {
    b.setAttribute("aria-checked", String(b.dataset.themeSet === mode));
  }
}
chrome.storage.local.get("theme").then(({ theme = "auto" }) => applyTheme(theme));
for (const b of document.querySelectorAll("[data-theme-set]")) {
  b.addEventListener("click", () => {
    applyTheme(b.dataset.themeSet);
    chrome.storage.local.set({ theme: b.dataset.themeSet });
  });
}

// ---- helpers ----------------------------------------------------------------
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

let helperOk = false;
function showHelper(reply) {
  helperOk = !!reply?.ok;
  $("status").className = "status " + (helperOk ? "ok" : "bad");
  $("status-text").textContent = helperOk
    ? `Helfer ${reply.version} bereit · ${reply.ssl}`
    : "Helfer nicht erreichbar";
  $("helper").hidden = helperOk;
  if (!helperOk) {
    $("ext-id").textContent = chrome.runtime.id;
    $("helper-error").textContent = reply?.error ? `(${reply.error})` : "";
  }
}

function explain(reply) {
  if (reply.helperMissing) return "Der lokale Helfer ist nicht installiert oder startet nicht.";
  const e = reply.error || "Unbekannter Fehler";
  if (/timed out|timeout/i.test(e)) return "Gerät antwortet nicht. Adresse und Netzwerk prüfen.";
  if (/refused/i.test(e)) return "Verbindung abgelehnt. Läuft dort ein HTTPS-Dienst auf diesem Port?";
  if (/nodename|not known|getaddrinfo/i.test(e)) return "Name nicht auflösbar. IP-Adresse eingeben.";
  return e;
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
    return;
  }
  window.close();
}

// ---- device list ------------------------------------------------------------
let removed = null;
let toastTimer = 0;

function render(devices) {
  const list = $("devices");
  list.replaceChildren();
  $("empty").hidden = devices.length > 0;
  const tpl = $("device-tpl");
  for (const d of devices) {
    const li = tpl.content.firstElementChild.cloneNode(true);
    li.querySelector(".name").textContent = d.name || d.target;
    li.querySelector(".target").textContent = d.localPort ? `${d.target} → :${d.localPort}` : d.target;
    li.querySelector(".tls").textContent = d.tls || "";
    if (!d.name || d.name === d.target) li.querySelector(".target").textContent = d.localPort ? `lokal :${d.localPort}` : "";
    const btn = li.querySelector(".open");
    btn.setAttribute("aria-label", `${d.name || d.target} öffnen`);
    btn.addEventListener("click", () => open(d.target, btn));
    li.querySelector(".remove").addEventListener("click", async () => {
      removed = d;
      const reply = await send({ type: "remove", target: d.target });
      render(reply.devices);
      toast(`${d.name || d.target} entfernt`);
    });
    li.querySelector(".name").addEventListener("dblclick", async () => {
      const name = prompt("Name für dieses Gerät", d.name || d.target);
      if (name == null) return;
      const reply = await send({ type: "rename", target: d.target, name: name.trim() || d.target });
      render(reply.devices);
    });
    list.append(li);
  }
}

function toast(text) {
  $("toast-text").textContent = text;
  $("toast").hidden = false;
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => ($("toast").hidden = true), 8000);
}
$("toast-undo").addEventListener("click", async () => {
  if (!removed) return;
  await chrome.storage.local.get("devices").then(({ devices = [] }) =>
    chrome.storage.local.set({ devices: [removed, ...devices] }));
  removed = null;
  $("toast").hidden = true;
  render((await send({ type: "devices" })).devices);
});

// ---- add form ---------------------------------------------------------------
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
  const [hello, devices, failed] = await Promise.all([
    send({ type: "hello" }),
    send({ type: "devices" }),
    tab ? send({ type: "failed", tabId: tab.id }) : { failed: null },
  ]);
  showHelper(hello);
  render(devices.devices);
  if (failed.failed) {
    const f = failed.failed;
    $("failed").hidden = false;
    $("failed-target").textContent = f.target;
    $("failed-open").addEventListener("click", () =>
      open(f.target, $("failed-open"), { tabId: tab.id, replaceTab: true, path: f.path }));
    $("add-open").classList.replace("primary", "secondary");
  }
})();
