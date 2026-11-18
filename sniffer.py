"""
sniffer.py - "Who is my computer talking to?"

What this file does:
  1. Listens to your network traffic with scapy (a packet sniffing library).
  2. Remembers who your computer talks to (IP, port, how many packets).
  3. Remembers DNS lookups, so IPs can be shown as names like "github.com".
  4. Finds which PROGRAM on your computer owns each connection (psutil).
  5. Looks up the COUNTRY and OWNER of each public IP (a free web lookup).
  6. BASELINE MODE: learns what "normal" looks like, then raises alerts
     when something new or unusual shows up.
  7. Runs a tiny web server (Flask) that hands all of this to the web page.

Setup:   pip install scapy flask psutil
Run:     Mac/Linux:  sudo python3 sniffer.py
         Windows:    run the terminal as Administrator (and install Npcap first)
Then open http://127.0.0.1:5000 in your browser.

Only sniff your own machine or network.
"""

import ipaddress
import json
import os
import queue
import socket
import statistics
import threading
import time
import urllib.request
from collections import deque

import psutil
from flask import Flask, jsonify, send_from_directory
from scapy.all import sniff, IP, TCP, UDP, DNS, DNSQR

# ---------- Settings you can change ----------

# Country/owner lookups send each public IP you contact to a free web service
# (ipwho.is). Set this to False to keep everything on your own computer.
LOOKUP_ENABLED = True

BUCKET_SECONDS = 10      # baseline mode counts packets in chunks of this many seconds
SPIKE_MIN_PACKETS = 50   # ignore "spikes" smaller than this, even if they beat the average

BASE_DIR = os.path.dirname(os.path.abspath(__file__))  # the folder this file lives in
BASELINE_FILE = os.path.join(BASE_DIR, "baseline.json")

# ---------- Shared data (several threads read and write it) ----------

connections = {}                # (ip, port, proto) -> {"count": n, "last": timestamp}
ip_to_name = {}                 # "142.250.80.46" -> "google.com"
ip_info = {}                    # "142.250.80.46" -> {"country": "US", "owner": "Google LLC"}
process_map = {}                # (remote_ip, remote_port) -> "chrome.exe"
dns_queries = deque(maxlen=30)  # the 30 most recent domain lookups
alerts = deque(maxlen=50)       # the 50 most recent baseline alerts
alerted = set()                 # alerts we already raised, so we don't repeat them
packet_counter = 0              # outgoing packets in the current time bucket

# Baseline state. "mode" is "off", "learning" or "watching".
baseline = {"mode": "off", "ips": set(), "ports": set(), "rates": [],
            "started": None, "learned_for": 0}

lock = threading.Lock()         # threads take turns using the data above


def get_my_ip():
    """Find this computer's local IP.
    We "connect" a UDP socket to a public address. UDP sends nothing until you
    write to it, so no traffic is created. We just ask which IP the OS picked."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        return s.getsockname()[0]
    except OSError:
        return "127.0.0.1"  # no network right now
    finally:
        s.close()


MY_IP = get_my_ip()


# ---------- Feature 1: reverse DNS (IP -> name) ----------

def reverse_lookup(ip):
    """Fallback: ask DNS "what name belongs to this IP?".
    This can be slow, so it runs in its own thread so we never miss packets."""
    try:
        name = socket.gethostbyaddr(ip)[0]
    except Exception:
        name = None  # many IPs simply have no name
    with lock:
        ip_to_name.setdefault(ip, name or "")


# ---------- Feature 2: which program owns each connection ----------

def watch_processes():
    """Every 2 seconds, ask the operating system for its list of open network
    connections. Each one includes the ID of the program that owns it.
    We save (remote IP, remote port) -> program name, then the packet table
    can look up who made each connection.

    Limits: very short connections can come and go between checks, and UDP
    traffic often has no entry, so some rows will have no program name."""
    while True:
        found = {}
        names = {}  # process ID -> name (looked up once per round)
        try:
            for c in psutil.net_connections(kind="inet"):
                if not c.raddr or not c.pid:
                    continue
                if c.pid not in names:
                    try:
                        names[c.pid] = psutil.Process(c.pid).name()
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        names[c.pid] = ""
                found[(c.raddr.ip, c.raddr.port)] = names[c.pid]
        except (psutil.AccessDenied, OSError):
            pass  # not enough rights to see connections; the column stays empty
        with lock:
            process_map.update(found)  # update (not replace) so closed connections are remembered
        time.sleep(2)


# ---------- Feature 3: country and owner of each IP ----------

geo_queue = queue.Queue()  # IPs waiting to be looked up


def classify_ip(ip):
    """Return True for public internet addresses. Private ranges (192.168.x.x,
    10.x.x.x), loopback and multicast addresses are not on the public internet,
    so there is nothing to look up for them."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return addr.is_global and not addr.is_multicast


def lookup_ip(ip):
    """Ask the free ipwho.is service about one IP. Returns country and owner.
    If anything goes wrong we return blanks; the page shows a dash."""
    try:
        req = urllib.request.Request(f"https://ipwho.is/{ip}",
                                     headers={"User-Agent": "who-is-my-computer-talking-to"})
        with urllib.request.urlopen(req, timeout=5) as response:
            d = json.load(response)
        if d.get("success"):
            conn = d.get("connection") or {}
            return {"country": d.get("country_code", ""),
                    "owner": conn.get("org") or conn.get("isp") or ""}
    except Exception:
        pass
    return {"country": "", "owner": ""}


def geo_worker():
    """Background thread: look up queued IPs one at a time, with a pause between
    each so we stay polite to the free service."""
    while True:
        ip = geo_queue.get()           # waits here until there is work
        info = lookup_ip(ip)
        with lock:
            ip_info[ip] = info
        time.sleep(1)


def queue_geo(ip):
    """Called (with the lock held) the first time we see an IP."""
    if ip in ip_info:
        return
    if not classify_ip(ip):
        ip_info[ip] = {"country": "LAN", "owner": "local network"}
    elif LOOKUP_ENABLED:
        ip_info[ip] = {"country": "", "owner": ""}  # placeholder until the lookup finishes
        geo_queue.put(ip)
    else:
        ip_info[ip] = {"country": "", "owner": ""}


# ---------- Feature 4: baseline mode ----------

def add_alert(level, message, key):
    """Record an alert once. level is "info", "warn" or "alert" (the page colors them)."""
    if key in alerted:
        return
    alerted.add(key)
    alerts.appendleft({"time": time.strftime("%H:%M:%S"), "level": level, "message": message})


def baseline_check(ip, port, proto):
    """Called (with the lock held) the first time we see a destination.
    While learning, we add it to the baseline. While watching, we compare it."""
    port_key = f"{proto}/{port}"
    mode = baseline["mode"]

    if mode == "learning":
        baseline["ips"].add(ip)
        baseline["ports"].add(port_key)

    elif mode == "watching":
        new_ip = ip not in baseline["ips"]
        new_port = port_key not in baseline["ports"]
        # A new website on a normal port happens all day, so it is only "info".
        # A new port is rarer. Both together is the most unusual of all.
        if new_ip and new_port:
            add_alert("alert", f"New destination {ip} on new port {port_key}", ("both", ip, port_key))
        elif new_port:
            add_alert("warn", f"Known destination {ip} on new port {port_key}", ("port", port_key))
        elif new_ip:
            add_alert("info", f"New destination {ip} ({port_key})", ("ip", ip))


def watch_traffic_rate():
    """Every BUCKET_SECONDS, look at how many packets we sent.
    Learning: remember the number. Watching: compare it with the normal range."""
    global packet_counter
    while True:
        time.sleep(BUCKET_SECONDS)
        with lock:
            count, packet_counter = packet_counter, 0
            rates = baseline["rates"]
            if baseline["mode"] == "learning":
                rates.append(count)
            elif baseline["mode"] == "watching" and len(rates) >= 5:
                average = statistics.mean(rates)
                spread = statistics.pstdev(rates)           # standard deviation
                limit = average + 3 * max(spread, 1)         # "3 sigma" rule of thumb
                if count > limit and count > SPIKE_MIN_PACKETS:
                    add_alert("alert",
                              f"Traffic spike: {count} packets in {BUCKET_SECONDS}s "
                              f"(normal is about {average:.0f})",
                              ("spike", time.time()))


def save_baseline():
    """Save what we learned so it survives a restart. (Call with the lock held.)"""
    data = {"ips": sorted(baseline["ips"]), "ports": sorted(baseline["ports"]),
            "rates": baseline["rates"], "learned_for": baseline["learned_for"]}
    try:
        with open(BASELINE_FILE, "w") as f:
            json.dump(data, f)
    except OSError as err:
        print("Could not save baseline:", err)


def load_baseline():
    """Load a saved baseline at startup (mode stays 'off' until you press a button)."""
    try:
        with open(BASELINE_FILE) as f:
            data = json.load(f)
        baseline["ips"] = set(data.get("ips", []))
        baseline["ports"] = set(data.get("ports", []))
        baseline["rates"] = list(data.get("rates", []))
        baseline["learned_for"] = data.get("learned_for", 0)
    except (OSError, ValueError):
        pass  # no saved baseline yet, or the file is unreadable


# ---------- Packet handler (scapy calls this once per packet) ----------

def handle_packet(pkt):
    global packet_counter
    if not pkt.haslayer(IP):          # ignore anything that isn't IPv4
        return

    with lock:
        # 1) DNS question ("what's the IP of github.com?") -> log the domain
        if pkt.haslayer(DNSQR) and pkt[DNS].qr == 0:
            domain = pkt[DNSQR].qname.decode(errors="ignore").rstrip(".")
            dns_queries.appendleft({"time": time.strftime("%H:%M:%S"), "domain": domain})

        # 2) DNS answer ("github.com is 140.82.x.x") -> remember IP -> name
        if pkt.haslayer(DNS) and pkt[DNS].qr == 1:
            try:
                for i in range(pkt[DNS].ancount):
                    record = pkt[DNS].an[i]
                    if record.type == 1:  # type 1 = "A" record, which holds an IPv4 address
                        ip_to_name[record.rdata] = record.rrname.decode().rstrip(".")
            except Exception:
                pass  # odd or truncated DNS packets are not worth crashing over

        # 3) Outgoing traffic: from us to someone else
        ip = pkt[IP]
        if ip.src != MY_IP:
            return
        if pkt.haslayer(TCP):
            proto, port = "TCP", pkt[TCP].dport
        elif pkt.haslayer(UDP):
            proto, port = "UDP", pkt[UDP].dport
        else:
            return

        packet_counter += 1  # feeds the traffic-spike check

        key = (ip.dst, port, proto)
        if key not in connections:
            connections[key] = {"count": 0, "last": 0}
            baseline_check(ip.dst, port, proto)   # learn it, or compare it
            queue_geo(ip.dst)                     # start the country/owner lookup
            if ip.dst not in ip_to_name:  # never saw a DNS answer for it, so try reverse lookup
                threading.Thread(target=reverse_lookup, args=(ip.dst,), daemon=True).start()
        connections[key]["count"] += 1
        connections[key]["last"] = time.time()


def start_sniffing():
    # store=False means don't keep packets in memory (they'd pile up forever)
    try:
        sniff(prn=handle_packet, store=False)
    except Exception as err:
        print(f"\nCould not capture packets: {err}")
        print("Run as administrator/root (and install Npcap on Windows).\n")


# ---------- Web server ----------

app = Flask(__name__)


@app.route("/")
def index():
    return send_from_directory(BASE_DIR, "index.html")


@app.route("/style.css")
def css():
    return send_from_directory(BASE_DIR, "style.css")


@app.route("/app.js")
def js():
    return send_from_directory(BASE_DIR, "app.js")


@app.route("/api/data")
def data():
    """The page calls this every couple of seconds to get fresh data as JSON."""
    with lock:
        rows = []
        for (ip, port, proto), info in connections.items():
            geo = ip_info.get(ip, {})
            rows.append({
                "ip": ip, "name": ip_to_name.get(ip, ""), "port": port, "proto": proto,
                "process": process_map.get((ip, port), ""),
                "country": geo.get("country", ""), "owner": geo.get("owner", ""),
                "count": info["count"], "ago": int(time.time() - info["last"]),
            })
        rows.sort(key=lambda r: r["count"], reverse=True)  # busiest first
        return jsonify({
            "my_ip": MY_IP,
            "lookup_enabled": LOOKUP_ENABLED,
            "connections": rows[:40],
            "dns": list(dns_queries),
            "alerts": list(alerts),
            "baseline": {
                "mode": baseline["mode"],
                "destinations": len(baseline["ips"]),
                "ports": len(baseline["ports"]),
                "started": baseline["started"],
                "learned_for": baseline["learned_for"],
            },
        })


@app.route("/api/clear", methods=["POST"])
def clear():
    """The 'clear' button calls this to forget everything and start fresh.
    We keep the IP -> name and IP -> country matches (still useful) and the baseline."""
    with lock:
        connections.clear()
        dns_queries.clear()
        alerts.clear()
        alerted.clear()
    return jsonify({"ok": True})


@app.route("/api/baseline/<mode>", methods=["POST"])
def set_baseline_mode(mode):
    """The baseline buttons call this with 'learning', 'watching' or 'off'."""
    if mode not in ("learning", "watching", "off"):
        return jsonify({"error": "unknown mode"}), 400

    with lock:
        previous = baseline["mode"]

        # Leaving learning mode: note how long we learned for, and save it
        if previous == "learning" and mode != "learning":
            baseline["learned_for"] += int(time.time() - baseline["started"])

        if mode == "learning":
            if previous != "learning":
                # Starting a new lesson wipes the old baseline
                baseline.update(ips=set(), ports=set(), rates=[], learned_for=0)
                baseline["started"] = time.time()
                # Count everything already on screen as normal, so the first
                # lookups don't all look new
                for (ip, port, proto) in connections:
                    baseline["ips"].add(ip)
                    baseline["ports"].add(f"{proto}/{port}")
        elif mode == "watching":
            if not baseline["ips"]:
                return jsonify({"error": "Nothing learned yet. Press 'learn' first and "
                                         "browse normally for a few minutes."}), 400
            alerts.clear()
            alerted.clear()

        baseline["mode"] = mode
        if previous == "learning" and mode != "learning":
            save_baseline()
    return jsonify({"ok": True, "mode": mode})


if __name__ == "__main__":
    load_baseline()
    # Each of these runs in its own background thread, alongside the web server
    threading.Thread(target=start_sniffing, daemon=True).start()
    threading.Thread(target=watch_processes, daemon=True).start()
    threading.Thread(target=watch_traffic_rate, daemon=True).start()
    threading.Thread(target=geo_worker, daemon=True).start()
    print(f"Sniffing as {MY_IP} ... open http://127.0.0.1:5000")
    app.run(host="127.0.0.1", port=5000)  # 127.0.0.1 = only your own computer can view it