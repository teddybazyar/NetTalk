# Netalk - Who Is My Computer Talking To?

A small web dashboard with an old-school black-and-green terminal look that shows which servers your computer is contacting, live.

## Brief Description

### Goal

Most of what your computer does on the network is invisible. This app makes it visible. It watches your outgoing network traffic and shows:

- **Outgoing connections:** each destination (host name, IP address, port, protocol), how many packets were sent to it, and when it was last contacted.
- **Program:** which app on your computer made each connection (Chrome, Slack, etc.).
- **Country and owner:** where each public IP is registered and which company owns it.
- **DNS lookups:** the domain names your computer asks about, as they happen.
- **Baseline mode:** the app learns what "normal" looks like for your computer, then raises alerts when something new or unusual shows up.

It also includes a filter box, pause and clear buttons, and highlights connections that use uncommon ports. A highlight or an alert is a hint to take a closer look, not proof that something is wrong.

### Tech Stack

| Part | Technology | Role |
|------|-----------|------|
| Backend | Python 3 | Runs the sniffer and the web server |
| Packet capture | [Scapy](https://scapy.net/) | Reads network packets and parses IP, TCP, UDP and DNS |
| Program names | [psutil](https://github.com/giampaolo/psutil) | Asks the operating system which program owns each connection |
| Web server | [Flask](https://flask.palletsprojects.com/) | Serves the page and a small JSON API |
| Country / owner | [ipwho.is](https://ipwho.is/) (free web service) | Looks up where an IP is registered and who owns it |
| Frontend | HTML, CSS, JavaScript | The dashboard (no frameworks or build step) |

### Target Users

- Students learning networking, DNS and cybersecurity who want to see real traffic.
- Beginner programmers looking for a small project that combines Python and a web frontend.
- Curious home users who want to know what their computer is connecting to.

## Set-Up Instructions

### Prerequisites

- **Python 3.8 or newer**
- **Administrator/root rights.** Reading raw packets is a privileged operation, and it is also needed to see which program owns a connection.
- **Windows only:** install [Npcap](https://npcap.com/) first (needed for Scapy to capture packets).
- **Internet access** for the country/owner lookup (optional, see [Privacy](#privacy-and-safety)).

### 1. Get the files

Clone the repo:
 
```bash
git clone https://github.com/teddybazyar/NetTalk.git
```

### 2. Install the dependencies

Install the libraries:
 
```bash
pip install scapy flask psutil
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

### The basics

- **Filter box:** type part of a host, IP, port, program, country or owner to narrow the table.
- **pause / resume:** freeze the view so you can read it.
- **clear:** forget the connections, DNS lookups and alerts so far and start fresh. Your baseline is kept.
- **Amber rows:** the connection uses a port that isn't on the common list. To change that list, edit `PORT_NAMES` at the top of `app.js`.
- **Host shown as `-`:** no DNS answer or reverse lookup was available for that IP.
- **Program shown as `-`:** the connection was too short-lived to catch, or it is UDP traffic (which often has no entry in the system's connection list).
- **Country `LAN`:** the address is on your own network, so there is nothing to look up.

### Baseline mode

Baseline mode finds things you didn't think to look for. Instead of fixed rules, it compares what is happening now with what was normal before.

1. Press **learn** and use your computer normally for a few minutes (the longer, the better). The app records the destinations, ports and traffic volume it sees. Pressing learn starts a fresh lesson and replaces any older baseline.
2. Press **watch**. From now on, anything that doesn't match the baseline appears in the alerts table:

| Level | Meaning |
|-------|---------|
| `info` (dim green) | A destination you never contacted while learning, on a port you normally use. Happens whenever you visit a new website. |
| `warn` (amber) | A destination you already know, but on a port you never used with anyone while learning. |
| `alert` (red) | A brand-new destination on a brand-new port, or a **traffic spike**: far more packets than usual in a 10-second window. |

3. Press **off** to stop either mode.

Each alert is raised once, so you won't see the same one repeat. When you stop learning, the baseline is saved to `baseline.json` next to the program and reloaded the next time you start it.

How the spike check works: while learning, the app counts packets every 10 seconds. While watching, a window counts as a spike if it is more than three standard deviations above the average and has at least 50 packets.

**Tips:** if something suspicious is already running while you learn, it becomes part of "normal", so learn on a quiet, clean session. Your habits also change over time, so press learn again now and then.

## Project Structure

```
sniffer.py     Captures packets, finds programs and owners, runs baseline mode, serves the data
index.html     Page layout: tables, controls, baseline panel and help section
style.css      Black-and-green terminal theme
app.js         Fetches data every 2 seconds and draws the tables
baseline.json  (created automatically) your saved baseline
```

## Settings

Near the top of `sniffer.py`:

| Setting | Default | What it does |
|---------|---------|--------------|
| `LOOKUP_ENABLED` | `True` | Turn the country/owner lookup on or off |
| `BUCKET_SECONDS` | `10` | Length of each traffic-volume window used for spike detection |
| `SPIKE_MIN_PACKETS` | `50` | Smallest window that can count as a spike |

## Troubleshooting

| Problem | Likely fix |
|---------|-----------|
| `Permission denied` or no packets appear | Run with `sudo` (macOS/Linux) or as Administrator (Windows) |
| Windows error about a missing capture driver | Install Npcap |
| Page says "no signal: is sniffer.py running?" | Make sure the terminal is still running `sniffer.py` |
| `ModuleNotFoundError` with `sudo` | Use the venv's Python: `sudo venv/bin/python sniffer.py` |
| `No module named psutil` | Run `pip install psutil` (the install command changed when program names were added) |
| Port 5000 already in use | Change the port in the last line of `sniffer.py` and open that port instead |
| Country and owner stay `-` | The lookup needs internet access, and the free service limits how many requests you can make. Wait a bit, or check that `LOOKUP_ENABLED` is `True` |
| Program column is empty | Run with administrator/root rights. Some connections are too short-lived to catch |
| Too many `info` alerts | Learn for longer and browse a wider range of sites first. Most `info` alerts are just new websites |

## Limitations

- Only IPv4 traffic is tracked.
- Only outgoing traffic from this computer is counted.
- Connection data is kept in memory only, so it resets when you stop the app. Only the baseline is saved to disk.
- Program names are matched by remote address and port, so two programs talking to the same server and port may share a name.
- Country and owner come from a free service and can be wrong or missing, especially for cloud and CDN addresses.

## Privacy and Safety

Only run this on your own computer and your own network. Capturing other people's traffic without permission is not acceptable and may be illegal. The web page listens on `127.0.0.1` only, so it is visible just to you. Don't change it to `0.0.0.0` unless you understand who could then see your traffic data.

Two privacy notes:

- **Country/owner lookups send each public IP you contact to ipwho.is.** That reveals which servers you talk to (not what you send). If you don't want that, set `LOOKUP_ENABLED = False`; everything else keeps working.
- **`baseline.json` is a list of the servers you contact.** If you put this project on GitHub, add `baseline.json` to your `.gitignore` so you don't publish it.