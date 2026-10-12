# PacketSentry

A basic network packet sniffer — **CodeAlpha Cyber Security Internship, Task 1**.

Captures live traffic and shows source/destination IPs, ports, protocol and a
payload preview for each packet. It also flags the two things a sniffer is
most useful for spotting on a network: **plaintext credentials** crossing the
wire, and traffic on protocols that were **never encrypted to begin with**
(HTTP, FTP, Telnet, POP3, IMAP). The goal isn't just to dump packets — it's to
show *why* visibility into raw traffic matters from a defensive standpoint.

## What it does

- Captures live packets with `scapy`.
- Parses ARP, TCP, UDP, ICMP and DNS queries.
- Prints a one-line summary per packet: timestamp, protocol, source/destination
  IP and port, and (optionally) a printable preview of the payload.
- Flags unencrypted-protocol traffic and anything that looks like a plaintext
  username/password pair.
- Prints an end-of-capture summary: packet counts by protocol, top talkers,
  and every flagged finding in one place.
- Can save the capture to a `.pcap` file for later analysis in Wireshark.

## Usage

```
pip install -r requirements.txt

python packet_sentry.py                      # sniff on the default interface
python packet_sentry.py --list-interfaces     # show interface names
python packet_sentry.py -i "Wi-Fi" -c 200     # capture 200 packets on Wi-Fi
python packet_sentry.py -f "tcp port 80"      # only HTTP traffic (BPF filter)
python packet_sentry.py -p                    # show payload previews too
python packet_sentry.py -w capture.pcap       # also save to a pcap file
```

Needs **Administrator / root** to open a raw socket. On Windows you also need
[Npcap](https://npcap.com) installed (tick "WinPcap API-compatible mode"
during setup) — plain `pip install scapy` is not enough on its own.

## Why it's built this way

- **Flags instead of just dumps.** Two thousand lines of raw packets tells
  you nothing by itself. Marking plaintext credentials and unencrypted
  protocols turns the output into something you'd actually act on.
- **A summary, not just a stream.** The end-of-run report (protocol
  breakdown, top talkers, flagged findings) is what you'd actually hand to
  someone — the live scroll is for watching, the summary is for reporting.
- **Fails loudly, not silently.** If scapy or Npcap is missing, or the
  process isn't elevated, it says exactly what's missing and how to fix it,
  rather than capturing nothing and giving no output.

## Disclaimer

Educational project, built for the CodeAlpha Cyber Security Internship.
**Only run this on a network you own or are authorised to monitor.**
Capturing traffic you don't have permission to see may be illegal where you
live.
