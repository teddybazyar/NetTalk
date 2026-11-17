// app.js - asks the Python server for data every 2 seconds and draws it on the page

const PORT_NAMES = {
  21: "FTP", 22: "SSH", 53: "DNS", 80: "HTTP", 123: "NTP",
  443: "HTTPS", 993: "IMAP", 3389: "RDP", 5228: "Google push"
};

let paused = false;  
let lastData = null;  

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

function timeAgo(seconds) {
  if (seconds < 60) return seconds + "s ago";
  return Math.floor(seconds / 60) + "m ago";
}

// Draw both tables from the data we have, applying the filter box text
function render() {
  if (!lastData) return;
  const filter = document.getElementById("filter").value.trim().toLowerCase();

  document.getElementById("status").textContent =
    "sniffing from " + lastData.my_ip + " | " + lastData.connections.length + " destinations seen" +
    (paused ? " | PAUSED" : "");

  const connBody = document.getElementById("connections");
  connBody.replaceChildren();
  let shown = 0;
  for (const c of lastData.connections) {
    const haystack = (c.name + " " + c.ip + " " + c.port).toLowerCase();
    if (filter && !haystack.includes(filter)) continue;

    const known = PORT_NAMES[c.port];
    const portLabel = known ? c.port + " (" + known + ")" : String(c.port);
    connBody.appendChild(makeRow(
      [c.name || "-", c.ip, c.proto + " " + portLabel, c.count, timeAgo(c.ago)],
      known ? "" : "odd"
    ));
    shown++;
  }
  if (shown === 0) {
    connBody.appendChild(emptyRow(
      filter ? "nothing matches your filter" : "waiting for traffic... try opening a website", 5));
  }

  const dnsBody = document.getElementById("dns");
  dnsBody.replaceChildren();
  for (const q of lastData.dns) dnsBody.appendChild(makeRow([q.time, q.domain]));
  if (lastData.dns.length === 0) dnsBody.appendChild(emptyRow("no lookups yet", 2));
}

async function refresh() {
  if (paused) return;  // frozen: don't fetch or redraw
  try {
    const response = await fetch("/api/data");
    lastData = await response.json();
    render();
  } catch (err) {
    document.getElementById("status").textContent = "no signal: is sniffer.py running?";
  }
}

// Buttons and filter box
document.getElementById("filter").addEventListener("input", render);

document.getElementById("pause").addEventListener("click", (event) => {
  paused = !paused;
  event.target.textContent = paused ? "resume" : "pause";
  if (paused) render(); else refresh();
});

document.getElementById("clear").addEventListener("click", async () => {
  await fetch("/api/clear", { method: "POST" });  // tell Python to forget everything
  paused = false;
  document.getElementById("pause").textContent = "pause";
  refresh();
});

refresh();
setInterval(refresh, 2000);