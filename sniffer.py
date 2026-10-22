"""
sniffer.py - "Who is my computer talking to?"

What this file does:
  1. Listens to your network traffic with scapy (a packet sniffing library).
  2. Remembers who your computer talks to (IP, port, how many packets).
  3. Remembers DNS lookups, so IPs can be shown as names like "github.com".
  4. Runs a tiny web server (Flask) that hands this data to the web page.

Setup:   pip install scapy flask
Then open http://127.0.0.1:5000 in your browser.
"""

import socket
import threading
import time
from collections import deque

from flask import Flask, jsonify, send_from_directory
from scapy.all import sniff, IP, TCP, UDP, DNS, DNSQR

connections = {}              
ip_to_name = {}               
dns_queries = deque(maxlen=30)  
lock = threading.Lock()       


def get_my_ip():
    """Find this computer's local IP."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        return s.getsockname()[0]
    finally:
        s.close()


MY_IP = get_my_ip()


def reverse_lookup(ip):
    """Ask the network for the name of this IP, and store it in ip_to_name."""
    try:
        name = socket.gethostbyaddr(ip)[0]
    except Exception:
        name = None  # many IPs simply have no name
    with lock:
        ip_to_name.setdefault(ip, name or "")


# Packet handler

def handle_packet(pkt):
    if not pkt.haslayer(IP):          # ignore anything that isn't IPv4
        return

    with lock:
        # 1) DNS question 
        if pkt.haslayer(DNSQR) and pkt[DNS].qr == 0:
            domain = pkt[DNSQR].qname.decode(errors="ignore").rstrip(".")
            dns_queries.appendleft({"time": time.strftime("%H:%M:%S"), "domain": domain})

        # 2) DNS answer 
        if pkt.haslayer(DNS) and pkt[DNS].qr == 1:
            try:
                for i in range(pkt[DNS].ancount):
                    record = pkt[DNS].an[i]
                    if record.type == 1:  
                        ip_to_name[record.rdata] = record.rrname.decode().rstrip(".")
            except Exception:
                pass 

        # 3) Outgoing traffic
        ip = pkt[IP]
        if ip.src != MY_IP:
            return
        if pkt.haslayer(TCP):
            proto, port = "TCP", pkt[TCP].dport
        elif pkt.haslayer(UDP):
            proto, port = "UDP", pkt[UDP].dport
        else:
            return

        key = (ip.dst, port, proto)
        if key not in connections:
            connections[key] = {"count": 0, "last": 0}
            if ip.dst not in ip_to_name:  # never saw a DNS answer for it, so try reverse lookup
                threading.Thread(target=reverse_lookup, args=(ip.dst,), daemon=True).start()
        connections[key]["count"] += 1
        connections[key]["last"] = time.time()


def start_sniffing():
    # don't keep packets in memory (theyd pile up forever)
    sniff(prn=handle_packet, store=False)


# Web

app = Flask(__name__)
HERE = "."  # the folder holding index.html, style.css, app.js


@app.route("/")
def index():
    return send_from_directory(HERE, "index.html")


@app.route("/style.css")
def css():
    return send_from_directory(HERE, "style.css")


@app.route("/app.js")
def js():
    return send_from_directory(HERE, "app.js")


@app.route("/api/data")
def data():
    """The page calls this every couple of seconds to get fresh data as JSON."""
    with lock:
        rows = [
            {"ip": ip, "name": ip_to_name.get(ip, ""), "port": port, "proto": proto,
             "count": info["count"]}
            for (ip, port, proto), info in connections.items()
        ]
        rows.sort(key=lambda r: r["count"], reverse=True)  # busiest first
        return jsonify({"my_ip": MY_IP, "connections": rows[:40], "dns": list(dns_queries)})


if __name__ == "__main__":
    # Sniff in a background thread so the web server can run at the same time
    threading.Thread(target=start_sniffing, daemon=True).start()
    print(f"Sniffing as {MY_IP} ... open http://127.0.0.1:5000")
    app.run(host="127.0.0.1", port=5000)