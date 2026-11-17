# Netalk - Who is my computer talking to?
 
A small web dashboard with an old-school black-and-green terminal look that shows which servers your computer is contacting, live.
 
## Brief Description
 
### Goal
 
Most of what your computer does on the network is invisible. This app makes it visible. It watches your outgoing network traffic and shows:
 
- **Outgoing connections:** each destination (host name, IP address, port, protocol), how many packets were sent to it, and when it was last contacted.
- **DNS lookups:** the domain names your computer asks about, as they happen.
It also includes a filter box, pause and clear buttons, and highlights connections that use uncommon ports. A highlight is a hint to take a closer look, not proof that something is wrong.
 
### Tech Stack
 
| Part | Technology | Role |
|------|-----------|------|
| Backend | Python 3 | Runs the sniffer and the web server |
| Packet capture | [Scapy](https://scapy.net/) | Reads network packets and parses IP, TCP, UDP and DNS |
| Web server | [Flask](https://flask.palletsprojects.com/) | Serves the page and a small JSON API |
| Frontend | HTML, CSS, JavaScript | The dashboard (no frameworks or build step) |
 
### Target Users
 
- Students learning networking, DNS and cybersecurity who want to see real traffic.
- Beginner programmers looking for a small project that combines Python and a web frontend.
- Curious home users who want to know what their computer is connecting to.
## Set-Up Instructions
 
### Prerequisites
 
- **Python 3.8 or newer**
- **Administrator/root rights.** Reading raw packets is a privileged operation.
- **Windows only:** install [Npcap](https://npcap.com/) first (needed for Scapy to capture packets).
### 1. Get the files
 
Clone the repo:
 
```bash
git clone https://github.com/teddybazyar/NetTalk.git
```
 
### 2. Install the dependencies
 
Install the libraries:
 
```bash
pip install scapy flask
```
 
### 3. Run it
 
Open a terminal in the project folder.
 
**macOS / Linux:**
 
```bash
sudo python3 sniffer.py
```
 
 
**Windows:** open Command Prompt or PowerShell **as Administrator**, then:
 
```bash
python sniffer.py
```
 
### 4. Open the dashboard
 
Go to **http://127.0.0.1:5000** in your browser. Browse some websites in another tab and rows will start appearing within a couple of seconds.
 
To stop the app, press `Ctrl+C` in the terminal.
 
## How to Use It
 
- **Filter box:** type part of a host, IP or port to narrow the table.
- **pause / resume:** freeze the view so you can read it.
- **clear:** forget everything seen so far and start fresh.
- **Amber rows:** the connection uses a port that isn't on the common list. To change that list, edit `PORT_NAMES` at the top of `app.js`.
- **Host shown as `-`:** no DNS answer or reverse lookup was available for that IP.
## Project Structure
 
```
sniffer.py   Captures packets with Scapy and serves the data through Flask
index.html   Page layout: tables, controls and help section
style.css    Black-and-green terminal theme
app.js       Fetches data every 2 seconds and draws the tables
```
 
## Troubleshooting
 
| Problem | Likely fix |
|---------|-----------|
| `Permission denied` or no packets appear | Run with `sudo` (macOS/Linux) or as Administrator (Windows) |
| Windows error about a missing capture driver | Install Npcap |
| Page says "no signal: is sniffer.py running?" | Make sure the terminal is still running `sniffer.py` |
| `ModuleNotFoundError` with `sudo` | Use the venv's Python: `sudo venv/bin/python sniffer.py` |
| Port 5000 already in use | Change the port in the last line of `sniffer.py` and open that port instead |
 
## Limitations
 
- Only IPv4 traffic is tracked.
- Only outgoing traffic from this computer is counted.
- Data is kept in memory only, so it resets when you stop the app.
## Safety and Ethics
 
Only run this on your own computer and your own network. Capturing other people's traffic without permission is not acceptable and may be illegal. The web page listens on `127.0.0.1` only, so it is visible just to you. Don't change it to `0.0.0.0` unless you understand who could then see your traffic data.
 
