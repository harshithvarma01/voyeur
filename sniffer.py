#!/usr/bin/env python3
import os
import sys
import argparse
import platform
from typing import Optional

from scapy.all import sniff, IP, TCP, UDP, ICMP, get_if_list  # type: ignore
from scapy.config import conf  # type: ignore

# Optional color support (robust on Windows with colorama)
try:
    from colorama import init as colorama_init  # type: ignore
    COLORAMA_AVAILABLE = True
except Exception:
    COLORAMA_AVAILABLE = False


def supports_color(force_disable: bool = False) -> bool:
    if force_disable:
        return False
    if not sys.stdout.isatty():
        return False
    if os.name == 'nt' and COLORAMA_AVAILABLE:
        return True
    return True


def make_colors(enabled: bool):
    if not enabled:
        return "", "", "", ""
    return "\033[92m", "\033[96m", "\033[93m", "\033[0m"


def packet_callback_factory(GREEN: str, CYAN: str, YELLOW: str, RESET: str):
    def packet_callback(packet):
        # Check if the packet has an IP layer
        if packet.haslayer(IP):
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            proto = "OTHER"

            # Identify the protocol
            if packet.haslayer(TCP):
                proto = f"{GREEN}TCP{RESET}" if GREEN else "TCP"
            elif packet.haslayer(UDP):
                proto = f"{YELLOW}UDP{RESET}" if YELLOW else "UDP"
            elif packet.haslayer(ICMP):
                proto = f"{CYAN}ICMP{RESET}" if CYAN else "ICMP"

            print(f"[{proto}] {src_ip}  ──>  {dst_ip}")
    return packet_callback


def parse_args():
    parser = argparse.ArgumentParser(
        prog="voyeur",
        description="VOYEUR | Simple network packet sniffer built on Scapy",
    )
    parser.add_argument("--iface", "-i", help="Network interface to sniff on (optional)")
    parser.add_argument(
        "--bpf", "-f",
        default="ip",
        help="BPF filter (requires Npcap/WinPcap on Windows). Default: ip",
    )
    parser.add_argument("--count", "-c", type=int, default=0, help="Number of packets to capture (0 = unlimited)")
    parser.add_argument("--timeout", type=int, default=None, help="Sniffing timeout in seconds")
    parser.add_argument("--no-color", action="store_true", help="Disable ANSI colors in output")
    parser.add_argument("--clear", action="store_true", help="Clear the screen before start")
    parser.add_argument("--list-ifaces", action="store_true", help="List available interfaces and exit")
    return parser.parse_args()


def check_admin_windows() -> bool:
    if os.name != 'nt':
        return True
    try:
        import ctypes  # lazy import for Windows only
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        # If check fails, don't block; let scapy decide
        return True


def safe_sniff(iface: Optional[str], bpf: Optional[str], count: int, timeout: Optional[int], prn):
    """Prefer BPF for performance; fallback to Python lfilter if BPF fails."""
    try:
        sniff(iface=iface, filter=bpf, count=count, store=False, timeout=timeout, prn=prn)
        return
    except KeyboardInterrupt:
        raise
    except Exception as e:
        # Fallback without BPF using Python-side lfilter for portability
        print(f"[!] BPF filter unavailable or failed ({e}). Falling back to Python filter.")
        sniff(iface=iface, count=count, store=False, timeout=timeout, prn=prn, lfilter=lambda p: p.haslayer(IP))


def main():
    args = parse_args()

    # Initialize color support on Windows
    if os.name == 'nt' and COLORAMA_AVAILABLE:
        colorama_init()

    use_color = supports_color(force_disable=args.no_color)
    GREEN, CYAN, YELLOW, RESET = make_colors(use_color)

    if args.clear:
        os.system('cls' if os.name == 'nt' else 'clear')

    print(f"{CYAN}="*50 if CYAN else "="*50)
    print(" VOYEUR | Network Packet Sniffer")
    print(("="*50) + (RESET if RESET else ""))
    print("[*] Monitoring network traffic... (Press Ctrl+C to stop)")

    if args.list_ifaces:
        print("\nAvailable interfaces:")
        for iface in get_if_list():
            print(f" - {iface}")
        return

    if os.name == 'nt' and not check_admin_windows():
        print("\n[!] Please run PowerShell or Terminal as Administrator for sniffing on Windows.")
        sys.exit(3)

    # Early check for libpcap provider on Windows for best UX
    if os.name == 'nt' and hasattr(conf, 'use_pcap') and not conf.use_pcap:
        print("\n[!] libpcap/Npcap provider is not available.")
        print("   - Install Npcap: https://npcap.com/")
        print("   - Then run your terminal as Administrator")
        sys.exit(2)

    cb = packet_callback_factory(GREEN, CYAN, YELLOW, RESET)

    try:
        safe_sniff(
            iface=args.iface,
            bpf=args.bpf,
            count=args.count,
            timeout=args.timeout,
            prn=cb,
        )
    except KeyboardInterrupt:
        print("\n[!] VOYEUR stopped by user.")
        sys.exit(0)
    except Exception as e:
        print(f"\n[!] ERROR: {e}")
        if os.name == 'nt':
            print("   - Ensure Npcap is installed: https://npcap.com/")
            print("   - Run terminal as Administrator")
        sys.exit(1)


if __name__ == "__main__":
    main()
