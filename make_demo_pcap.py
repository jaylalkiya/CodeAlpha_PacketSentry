"""Write demo.pcap - a small, fully synthetic capture for trying PacketSentry.

    python make_demo_pcap.py
    python packet_sentry.py -r demo.pcap -v -p
    python packet_sentry_gui.py            (then OPEN PCAP -> demo.pcap)

Every packet is built here from made-up addresses and credentials, so the
demo shows the detections (plaintext FTP / POP3 / IMAP / HTTP logins) without
needing a real server or sniffing anyone's traffic. No admin rights needed.
"""

import sys
import warnings

warnings.filterwarnings("ignore", message=".*Diffie-Hellman.*")

from scapy.all import ARP, DNS, DNSQR, ICMP, IP, TCP, UDP, Ether, Raw, wrpcap

CLIENT = "192.168.1.10"
SERVER = "192.168.1.50"
GATEWAY = "192.168.1.1"


def tcp(dport, data, sport=40000, dst=SERVER):
    return (Ether() / IP(src=CLIENT, dst=dst)
            / TCP(sport=sport, dport=dport, flags="PA") / Raw(data))


def build():
    return [
        Ether() / ARP(op=1, psrc=CLIENT, pdst=GATEWAY, hwsrc="aa:bb:cc:dd:ee:ff"),
        Ether() / IP(src=CLIENT, dst="8.8.8.8") / UDP(sport=5353, dport=53)
        / DNS(rd=1, qd=DNSQR(qname="intranet.example.com")),
        Ether() / IP(src=CLIENT, dst=GATEWAY) / ICMP(),
        # HTTPS - encrypted, so nothing to flag
        tcp(443, bytes(range(48)), sport=40100, dst="93.184.216.34"),
        # FTP login in plaintext
        tcp(21, b"USER demo_user\r\n", sport=40001),
        tcp(21, b"PASS Summer2026!\r\n", sport=40001),
        # HTTP form login
        tcp(80, b"POST /login HTTP/1.1\r\nHost: intranet.example.com\r\n"
                b"Content-Type: application/x-www-form-urlencoded\r\n\r\n"
                b"username=demo_user&password=Summer2026!", sport=40002),
        # HTTP Basic auth (demo_user:Summer2026!)
        tcp(80, b"GET /admin HTTP/1.1\r\nHost: intranet.example.com\r\n"
                b"Authorization: Basic ZGVtb191c2VyOlN1bW1lcjIwMjYh\r\n\r\n",
            sport=40003),
        # POP3 and IMAP logins
        tcp(110, b"USER demo_user\r\n", sport=40004),
        tcp(143, b"a1 LOGIN demo_user Summer2026!\r\n", sport=40005),
        # Plain HTTP with no credentials - flagged only as unencrypted
        tcp(80, b"GET /index.html HTTP/1.1\r\nHost: intranet.example.com\r\n\r\n",
            sport=40006),
    ]


def main():
    path = sys.argv[1] if len(sys.argv) > 1 else "demo.pcap"
    packets = build()
    wrpcap(path, packets)
    print(f"Wrote {len(packets)} synthetic packets to {path}")


if __name__ == "__main__":
    main()
