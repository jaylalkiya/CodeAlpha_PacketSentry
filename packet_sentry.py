"""PacketSentry - a basic network packet sniffer with security framing.

CodeAlpha Cyber Security Internship - Task 1: Basic Network Sniffer.

Captures live traffic, shows source/destination IPs, ports, protocols and a
payload preview for each packet, and flags the two things a sniffer is most
useful for spotting: plaintext credentials crossing the wire, and traffic on
protocols that were never encrypted to begin with (HTTP, FTP, Telnet).

    python packet_sentry.py                      sniff on the default interface
    python packet_sentry.py --list-interfaces     show interface names
    python packet_sentry.py -i "Wi-Fi" -c 200     capture 200 packets on Wi-Fi
    python packet_sentry.py -f "tcp port 80"      only HTTP traffic
    python packet_sentry.py -w capture.pcap       also save to a pcap file

Needs scapy, and on Windows also Npcap (https://npcap.com - tick 'WinPcap
API-compatible mode' at setup). Needs Administrator / root to open a raw
socket.

ONLY run this on a network you own or are authorised to monitor. Sniffing
traffic you do not have permission to see may be illegal where you live.
"""

import argparse
import ctypes
import os
import re
import sys
from collections import Counter
from datetime import datetime

IS_WIN = sys.platform == "win32"

CREDENTIAL_RE = re.compile(
    rb"(user(name)?|pass(word)?|pwd|login)\s*[:=]\s*\S+", re.IGNORECASE)
PLAINTEXT_PORTS = {21: "FTP", 23: "Telnet", 80: "HTTP", 110: "POP3", 143: "IMAP"}

COLOR = {
    "reset": "\033[0m", "dim": "\033[2m",
    "cyan": "\033[36m", "yellow": "\033[33m", "magenta": "\033[35m",
    "blue": "\033[34m", "green": "\033[32m", "red": "\033[31m\033[1m",
}


def paint(text, color, enabled):
    return f"{COLOR[color]}{text}{COLOR['reset']}" if enabled else text


def is_admin():
    if not IS_WIN:
        return os.geteuid() == 0 if hasattr(os, "geteuid") else False
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def scapy_problem():
    """Why raw capture won't work, so the fix can be specific."""
    try:
        from scapy.all import conf  # noqa: F401
    except Exception:
        return "scapy is not installed. Install it with:  pip install scapy"
    if not IS_WIN:
        return None
    from scapy.all import conf
    if getattr(conf, "use_pcap", False):
        return None
    system32 = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "System32")
    if any(os.path.exists(os.path.join(system32, dll))
           for dll in ("Npcap\\wpcap.dll", "wpcap.dll")):
        return None
    return ("scapy is installed but Npcap is not, so it cannot open a raw "
            "socket. Install Npcap from https://npcap.com and tick "
            "'WinPcap API-compatible mode' during setup.")


def printable_preview(data, limit=80):
    """Payload bytes -> a safe-to-print ASCII preview, non-printable -> '.'."""
    if not data:
        return ""
    snippet = data[:limit]
    text = "".join(chr(b) if 32 <= b < 127 else "." for b in snippet)
    return text + ("..." if len(data) > limit else "")


class Stats:
    def __init__(self):
        self.total = 0
        self.by_protocol = Counter()
        self.by_src = Counter()
        self.flagged = []   # list of (summary_line) for the end-of-run report

    def record(self, protocol, src):
        self.total += 1
        self.by_protocol[protocol] += 1
        if src:
            self.by_src[src] += 1

    def flag(self, line):
        self.flagged.append(line)

    def report(self, color):
        print("\n" + paint("=" * 60, "dim", color))
        print(paint("Capture summary", "cyan", color))
        print(paint("=" * 60, "dim", color))
        print(f"Total packets: {self.total}")
        if self.by_protocol:
            print("\nBy protocol:")
            for proto, count in self.by_protocol.most_common():
                print(f"   {proto:<8} {count}")
        if self.by_src:
            print("\nTop talkers:")
            for ip, count in self.by_src.most_common(5):
                print(f"   {ip:<18} {count} packet(s)")
        if self.flagged:
            print(paint(f"\n{len(self.flagged)} finding(s) flagged:", "red", color))
            for line in self.flagged:
                print("   " + line)
        else:
            print(paint("\nNo plaintext credentials or risky patterns seen "
                         "in this capture.", "green", color))


def describe_packet(pkt, stats, use_color, show_payload):
    from scapy.all import ARP, DNS, DNSQR, ICMP, IP, TCP, UDP

    ts = datetime.now().strftime("%H:%M:%S")

    if pkt.haslayer(ARP):
        arp = pkt[ARP]
        op = "who-has" if arp.op == 1 else "is-at" if arp.op == 2 else str(arp.op)
        stats.record("ARP", arp.psrc)
        line = (f"{paint(ts, 'dim', use_color)} "
                f"{paint('ARP', 'blue', use_color):<18} "
                f"{arp.psrc} {op} {arp.pdst}  (hw {arp.hwsrc})")
        print(line)
        return

    if not pkt.haslayer(IP):
        return

    ip = pkt[IP]
    src, dst = ip.src, ip.dst

    if pkt.haslayer(TCP):
        layer, proto, sport, dport = pkt[TCP], "TCP", pkt[TCP].sport, pkt[TCP].dport
    elif pkt.haslayer(UDP):
        layer, proto, sport, dport = pkt[UDP], "UDP", pkt[UDP].sport, pkt[UDP].dport
    elif pkt.haslayer(ICMP):
        layer, proto, sport, dport = None, "ICMP", None, None
    else:
        layer, proto, sport, dport = None, f"IP-{ip.proto}", None, None

    stats.record(proto, src)

    endpoints = (f"{src}:{sport} -> {dst}:{dport}" if sport is not None
                 else f"{src} -> {dst}")

    color = {"TCP": "cyan", "UDP": "yellow", "ICMP": "magenta"}.get(proto, "reset")
    header = f"{paint(ts, 'dim', use_color)} {paint(proto, color, use_color):<18} {endpoints}"

    payload = bytes(layer.payload) if layer is not None and layer.payload else b""

    # DNS query names are useful even when not showing full payloads.
    if pkt.haslayer(DNS) and pkt.haslayer(DNSQR) and pkt[DNS].qdcount:
        try:
            qname = pkt[DNSQR].qname.decode(errors="replace").rstrip(".")
            header += f"  query={qname}"
        except Exception:
            pass

    risk_bits = []
    if dport in PLAINTEXT_PORTS or sport in PLAINTEXT_PORTS:
        proto_name = PLAINTEXT_PORTS.get(dport) or PLAINTEXT_PORTS.get(sport)
        risk_bits.append(f"unencrypted {proto_name}")

    cred_match = CREDENTIAL_RE.search(payload) if payload else None
    if cred_match:
        risk_bits.append("possible plaintext credential")

    if risk_bits:
        tag = paint(" [" + ", ".join(risk_bits) + "]", "red", use_color)
        header += tag
        stats.flag(f"{ts}  {endpoints}  -> " + ", ".join(risk_bits))

    print(header)
    if show_payload and payload:
        preview = printable_preview(payload)
        if preview.strip():
            print("   " + paint(preview, "dim", use_color))


def list_interfaces():
    from scapy.all import get_if_list
    try:
        from scapy.arch.windows import get_windows_if_list
        for iface in get_windows_if_list():
            print(f"  {iface.get('name')!r:<30} {iface.get('description', '')}")
        return
    except Exception:
        pass
    for name in get_if_list():
        print(f"  {name}")


def main():
    parser = argparse.ArgumentParser(
        description="PacketSentry - basic network sniffer (CodeAlpha Task 1)")
    parser.add_argument("-i", "--iface", help="interface name to sniff on")
    parser.add_argument("-f", "--filter", default="",
                         help="BPF filter, e.g. 'tcp port 80'")
    parser.add_argument("-c", "--count", type=int, default=0,
                         help="stop after N packets (0 = until Ctrl+C)")
    parser.add_argument("-t", "--timeout", type=int, default=0,
                         help="stop after N seconds (0 = no timeout)")
    parser.add_argument("-w", "--pcap", help="also save the capture to this .pcap file")
    parser.add_argument("-p", "--payload", action="store_true",
                         help="show a printable preview of each packet's payload")
    parser.add_argument("--no-color", action="store_true", help="disable colored output")
    parser.add_argument("--list-interfaces", action="store_true",
                         help="list available interfaces and exit")
    args = parser.parse_args()

    problem = scapy_problem()
    if problem:
        print("Cannot capture packets: " + problem)
        return 1

    from scapy.all import sniff, wrpcap

    if args.list_interfaces:
        list_interfaces()
        return 0

    if not is_admin():
        print("Needs Administrator / root to open a raw socket - "
              "re-run elevated.")
        return 1

    use_color = not args.no_color and sys.stdout.isatty()
    stats = Stats()
    captured = []

    def on_packet(pkt):
        describe_packet(pkt, stats, use_color, args.payload)
        if args.pcap:
            captured.append(pkt)

    print(paint("PacketSentry - capturing. Ctrl+C to stop.", "cyan", use_color))
    try:
        sniff(iface=args.iface or None, filter=args.filter or None,
              prn=on_packet, count=args.count or 0,
              timeout=args.timeout or None, store=False)
    except KeyboardInterrupt:
        pass
    except OSError as exc:
        print(f"Capture failed ({exc}). Check the interface name with "
              "--list-interfaces.")
        return 1

    if args.pcap and captured:
        wrpcap(args.pcap, captured)
        print(f"\nSaved {len(captured)} packet(s) to {args.pcap}")

    stats.report(use_color)
    return 0


if __name__ == "__main__":
    sys.exit(main())
