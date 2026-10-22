// app.js - asks the Python server for data every 2 seconds and draws it on the page

const PORT_NAMES = {
  21: "FTP", 22: "SSH", 53: "DNS", 80: "HTTP", 123: "NTP",
  443: "HTTPS", 993: "IMAP", 3389: "RDP", 5228: "Google push"
};

function makeRow(values) {
  const tr = document.createElement("tr");
  for (const value of values) {
    const td = document.createElement("td");
    td.textContent = value;
    tr.appendChild(td);
  }
  return tr;
}

async function refresh() {
  try {
    // Ask the Flask route /api/data for the latest JSON
    const response = await fetch("/api/data");
    const data = await response.json();

    document.getElementById("status").textContent =
      "sniffing from " + data.my_ip + " | " + data.connections.length + " destinations seen";

    // Rebuild the connections table
    const connBody = document.getElementById("connections");
    connBody.replaceChildren();
    for (const c of data.connections) {
      const portLabel = PORT_NAMES[c.port] ? c.port + " (" + PORT_NAMES[c.port] + ")" : c.port;
      // If we never learned a name for this IP, show a dash
      connBody.appendChild(makeRow([c.name || "-", c.ip, c.proto + " " + portLabel, c.count]));
    }

    // Rebuild the DNS table
    const dnsBody = document.getElementById("dns");
    dnsBody.replaceChildren();
    for (const q of data.dns) {
      dnsBody.appendChild(makeRow([q.time, q.domain]));
    }
  } catch (err) {
    // The server probably isn't running
    document.getElementById("status").textContent = "no signal: is sniffer.py running?";
  }
}

refresh();                    
setInterval(refresh, 2000);  