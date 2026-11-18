// app.js - asks the Python server for data every 2 seconds and draws it on the page

// Friendly names for common ports. Any port NOT in this list gets highlighted amber.
const PORT_NAMES = {
  21: "FTP", 22: "SSH", 53: "DNS", 80: "HTTP", 123: "NTP",
  443: "HTTPS", 993: "IMAP", 3389: "RDP", 5228: "Google push"
};

let paused = false;   // true while the user has frozen the view
let lastData = null;  // most recent data from the server, so filtering works instantly

// Make a <tr> from a list of text values. textContent (not innerHTML) keeps
// hostile domain names from injecting HTML into the page.
function makeRow(values, className) {
  const tr = document.createElement("tr");
  if (className) tr.className = className;
  for (const value of values) {
    const td = document.createElement("td");
    td.textContent = value;
    tr.appendChild(td);
  }
  return tr;
}

// A single message row, shown when a table has nothing to display
function emptyRow(message, columns) {
  const tr = document.createElement("tr");
  const td = document.createElement("td");
  td.colSpan = columns;
  td.className = "empty";
  td.textContent = message;
  tr.appendChild(td);
  return tr;
}

// "5s ago", "3m ago", etc.
function timeAgo(seconds) {
  if (seconds < 60) return seconds + "s ago";
  return Math.floor(seconds / 60) + "m ago";
}

// "2m 05s" style duration for the baseline status line
function duration(seconds) {
  seconds = Math.max(0, Math.floor(seconds));
  const m = Math.floor(seconds / 60);
  const s = String(seconds % 60).padStart(2, "0");
  return m + "m " + s + "s";
}

// Describe the baseline in a sentence and light up the active button
function renderBaseline(b, alertCount) {
  const status = document.getElementById("baseline-status");
  const known = b.destinations + " destinations and " + b.ports + " ports";

  if (b.mode === "learning") {
    const elapsed = Date.now() / 1000 - b.started;
    status.textContent = "LEARNING for " + duration(elapsed) + ": " + known +
      " so far. Use your computer normally, then press watch.";
  } else if (b.mode === "watching") {
    status.textContent = "WATCHING against a baseline of " + known + ". " +
      alertCount + " alert" + (alertCount === 1 ? "" : "s") + " so far.";
  } else if (b.destinations > 0) {
    status.textContent = "OFF. A saved baseline is ready (" + known + ", learned over " +
      duration(b.learned_for) + "). Press watch to use it.";
  } else {
    status.textContent = "OFF. Press learn and use your computer normally for a few minutes.";
  }

  document.getElementById("learn").classList.toggle("active", b.mode === "learning");
  document.getElementById("watch").classList.toggle("active", b.mode === "watching");
  document.getElementById("baseline-off").classList.toggle("active", b.mode === "off");
}

// Draw all the tables from the data we have, applying the filter box text
function render() {
  if (!lastData) return;
  const filter = document.getElementById("filter").value.trim().toLowerCase();

  document.getElementById("status").textContent =
    "sniffing from " + lastData.my_ip + " | " + lastData.connections.length + " destinations seen" +
    (lastData.lookup_enabled ? "" : " | country lookup off") +
    (paused ? " | PAUSED" : "");

  // ---- Connections ----
  const connBody = document.getElementById("connections");
  connBody.replaceChildren();
  let shown = 0;
  for (const c of lastData.connections) {
    // Keep the row only if the filter text appears in any of these fields
    const haystack = [c.name, c.ip, c.port, c.process, c.country, c.owner].join(" ").toLowerCase();
    if (filter && !haystack.includes(filter)) continue;

    const known = PORT_NAMES[c.port];
    const portLabel = known ? c.port + " (" + known + ")" : String(c.port);
    connBody.appendChild(makeRow(
      [c.name || "-", c.ip, c.proto + " " + portLabel, c.process || "-",
       c.country || "-", c.owner || "-", c.count, timeAgo(c.ago)],
      known ? "" : "odd"
    ));
    shown++;
  }
  if (shown === 0) {
    connBody.appendChild(emptyRow(
      filter ? "nothing matches your filter" : "waiting for traffic... try opening a website", 8));
  }

  // ---- Baseline and alerts ----
  renderBaseline(lastData.baseline, lastData.alerts.length);
  const alertBody = document.getElementById("alerts");
  alertBody.replaceChildren();
  for (const a of lastData.alerts) {
    alertBody.appendChild(makeRow([a.time, a.level, a.message], "a-" + a.level));
  }
  if (lastData.alerts.length === 0) {
    alertBody.appendChild(emptyRow(
      lastData.baseline.mode === "watching" ? "all quiet: nothing unusual yet" : "no alerts", 3));
  }

  // ---- DNS ----
  const dnsBody = document.getElementById("dns");
  dnsBody.replaceChildren();
  for (const q of lastData.dns) dnsBody.appendChild(makeRow([q.time, q.domain]));
  if (lastData.dns.length === 0) dnsBody.appendChild(emptyRow("no lookups yet", 2));
}

// Fetch fresh data from the server and redraw
async function load() {
  try {
    const response = await fetch("/api/data");
    lastData = await response.json();
    render();
  } catch (err) {
    document.getElementById("status").textContent = "no signal: is sniffer.py running?";
  }
}

// The timer calls this. When paused it does nothing, so the view stays frozen.
function refresh() {
  if (!paused) load();
}

// Ask the server to switch baseline mode; show its error message if it refuses
async function setBaseline(mode) {
  const message = document.getElementById("baseline-message");
  message.textContent = "";
  try {
    const response = await fetch("/api/baseline/" + mode, { method: "POST" });
    const result = await response.json();
    if (!response.ok) message.textContent = result.error || "could not change mode";
  } catch (err) {
    message.textContent = "no signal: is sniffer.py running?";
  }
  load();
}

// ---- Buttons and filter box ----
document.getElementById("filter").addEventListener("input", render);

document.getElementById("pause").addEventListener("click", (event) => {
  paused = !paused;
  event.target.textContent = paused ? "resume" : "pause";
  if (paused) render(); else load();
});

document.getElementById("clear").addEventListener("click", async () => {
  await fetch("/api/clear", { method: "POST" });  // tell Python to forget everything
  paused = false;
  document.getElementById("pause").textContent = "pause";
  load();
});

document.getElementById("learn").addEventListener("click", () => setBaseline("learning"));
document.getElementById("watch").addEventListener("click", () => setBaseline("watching"));
document.getElementById("baseline-off").addEventListener("click", () => setBaseline("off"));

load();
setInterval(refresh, 2000);