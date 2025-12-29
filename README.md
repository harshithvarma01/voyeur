# VOYEUR – Network Packet Sniffer

A minimal, efficient network packet sniffer powered by Scapy.

## Prerequisites (Windows)
- Install Npcap (required for packet capture and BPF filters): https://npcap.com/
- Run Terminal/PowerShell as Administrator when sniffing.
- Python 3.9+ recommended.

## Setup
```powershell
# From the project folder
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

## Usage
```powershell
# Basic (captures all IP packets)
python sniffer.py

# With options
python sniffer.py --iface Ethernet --bpf "tcp" --count 100
python sniffer.py --no-color --clear
```

### Common BPF filters
- `ip` – all IP traffic
- `tcp` – TCP traffic
- `udp` – UDP traffic
- `icmp` – ICMP traffic
- `port 80` – traffic on a specific port
- `host 8.8.8.8` – traffic to/from a specific host

If BPF filtering is unavailable (e.g., missing Npcap), VOYEUR automatically falls back to a Python-side filter so you can still sniff IP packets.

## Notes
- On Windows, ANSI colors are enabled via `colorama`. Use `--no-color` to disable.
- Use `--count` to limit captured packets and exit automatically.
- Press `Ctrl+C` to stop at any time.
