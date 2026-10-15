"""PacketSentry GUI - a desktop front end for the PacketSentry sniffer.

CodeAlpha Cyber Security Internship - Task 1: Basic Network Sniffer.

    python packet_sentry_gui.py

Same capture and detection logic as packet_sentry.py (it imports it), shown
as a live packet table with a detail pane, a running summary and red rows
for anything flagged. Live capture needs Administrator / root and, on
Windows, Npcap; opening a saved .pcap needs neither.

ONLY capture on a network you own or are authorised to monitor.
"""

import queue
import sys
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

import packet_sentry as core

DEFAULT_IFACE = "(default interface)"
POLL_MS = 100
BATCH = 500            # max packets moved from the sniffer thread per poll

PROTO_COLORS = {"TCP": "#0b6e99", "UDP": "#9a6700", "ICMP": "#8250df",
                "ARP": "#1f6feb"}
FLAG_BG = "#ffd7d5"
FLAG_FG = "#a40e26"


def hexdump(data, width=16):
    """bytes -> classic offset / hex / ASCII dump."""
    lines = []
    for off in range(0, len(data), width):
        chunk = data[off:off + width]
        hexpart = " ".join(f"{b:02x}" for b in chunk)
        text = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        lines.append(f"{off:04x}  {hexpart:<{width * 3}} {text}")
    return "\n".join(lines)


class PacketSentryApp:
    def __init__(self, root):
        self.root = root
        root.title("PacketSentry - Network Sniffer")
        root.geometry("1280x780")
        root.minsize(900, 560)

        self.queue = queue.Queue()
        self.sniffer = None
        self.reset_state()

        self.build_toolbar()
        self.build_body()
        self.build_statusbar()
        root.protocol("WM_DELETE_WINDOW", self.on_close)
        self.root.after(POLL_MS, self.poll)

    # ------------------------------------------------------------ state

    def reset_state(self):
        self.packets = []      # raw scapy packets, for saving to pcap
        self.infos = []        # analyse_packet() result per packet
        self.stats = core.Stats()

    # ------------------------------------------------------------ layout

    def build_toolbar(self):
        bar = ttk.Frame(self.root, padding=(8, 8, 8, 4))
        bar.pack(fill="x")

        ttk.Label(bar, text="Interface").pack(side="left")
        self.iface_var = tk.StringVar(value=DEFAULT_IFACE)
        names = [DEFAULT_IFACE]
        try:
            names += [name for name, _ in core.interfaces() if name]
        except Exception:
            pass
        ttk.Combobox(bar, textvariable=self.iface_var, values=names,
                     width=24, state="readonly").pack(side="left", padx=(4, 12))

        ttk.Label(bar, text="BPF filter").pack(side="left")
        self.filter_var = tk.StringVar()
        ttk.Entry(bar, textvariable=self.filter_var, width=18).pack(
            side="left", padx=(4, 12))

        self.start_btn = ttk.Button(bar, text="Start", command=self.start_live)
        self.start_btn.pack(side="left")
        self.stop_btn = ttk.Button(bar, text="Stop", command=self.stop,
                                   state="disabled")
        self.stop_btn.pack(side="left", padx=4)
        ttk.Separator(bar, orient="vertical").pack(side="left", fill="y", padx=8)
        ttk.Button(bar, text="Open pcap...", command=self.open_pcap).pack(side="left")
        ttk.Button(bar, text="Save pcap...", command=self.save_pcap).pack(
            side="left", padx=4)
        ttk.Button(bar, text="Clear", command=self.clear).pack(side="left")

        self.only_flagged = tk.BooleanVar()
        ttk.Checkbutton(bar, text="Only flagged", variable=self.only_flagged,
                        command=self.refill_table).pack(side="right")

    def build_body(self):
        panes = ttk.PanedWindow(self.root, orient="vertical")
        panes.pack(fill="both", expand=True, padx=8)

        # Packet table
        table_frame = ttk.Frame(panes)
        cols = ("no", "time", "proto", "src", "dst", "len", "info")
        heads = ("No.", "Time", "Protocol", "Source", "Destination", "Length", "Info")
        widths = (55, 75, 70, 170, 170, 60, 460)
        self.tree = ttk.Treeview(table_frame, columns=cols, show="headings",
                                 selectmode="browse")
        for col, head, width in zip(cols, heads, widths):
            self.tree.heading(col, text=head)
            anchor = "e" if col in ("no", "len") else "w"
            self.tree.column(col, width=width, anchor=anchor,
                             stretch=(col == "info"))
        for proto, color in PROTO_COLORS.items():
            self.tree.tag_configure(proto, foreground=color)
        self.tree.tag_configure("flagged", background=FLAG_BG, foreground=FLAG_FG)
        scroll = ttk.Scrollbar(table_frame, orient="vertical",
                               command=self.tree.yview)
        self.tree.configure(yscrollcommand=scroll.set)
        self.tree.pack(side="left", fill="both", expand=True)
        scroll.pack(side="right", fill="y")
        self.tree.bind("<<TreeviewSelect>>", self.show_detail)
        panes.add(table_frame, weight=3)

        # Detail + summary side by side
        lower = ttk.PanedWindow(panes, orient="horizontal")
        detail_box = ttk.LabelFrame(lower, text="Packet detail", padding=4)
        self.detail = self.make_text(detail_box, wrap="none")
        lower.add(detail_box, weight=3)
        summary_box = ttk.LabelFrame(lower, text="Capture summary", padding=4)
        self.summary = self.make_text(summary_box, wrap="word")
        lower.add(summary_box, weight=2)
        panes.add(lower, weight=2)

        self.write(self.detail, "Select a packet to see its layers, "
                   "findings and payload.")
        self.update_summary()

    def make_text(self, parent, wrap):
        text = tk.Text(parent, wrap=wrap, font=("Consolas", 10), height=12,
                       relief="flat", borderwidth=0, padx=6, pady=4)
        scroll = ttk.Scrollbar(parent, orient="vertical", command=text.yview)
        text.configure(yscrollcommand=scroll.set, state="disabled")
        if wrap == "none":
            xscroll = ttk.Scrollbar(parent, orient="horizontal",
                                    command=text.xview)
            text.configure(xscrollcommand=xscroll.set)
            xscroll.pack(side="bottom", fill="x")
        text.tag_configure("head", font=("Consolas", 10, "bold"))
        text.tag_configure("risk", foreground=FLAG_FG,
                           font=("Consolas", 10, "bold"))
        text.tag_configure("ok", foreground="#1a7f37")
        text.pack(side="left", fill="both", expand=True)
        scroll.pack(side="right", fill="y")
        return text

    def build_statusbar(self):
        self.status_var = tk.StringVar(
            value="Ready. Start a live capture or open a .pcap file. "
                  "Only capture on networks you are authorised to monitor.")
        ttk.Label(self.root, textvariable=self.status_var, anchor="w",
                  padding=(8, 4)).pack(fill="x", side="bottom")

    # ------------------------------------------------------------ capture

    def start_live(self):
        problem = core.scapy_problem()
        if problem:
            messagebox.showerror("Cannot capture", problem)
            return
        if not core.is_admin():
            messagebox.showerror(
                "Administrator needed",
                "Live capture needs Administrator / root to open a raw socket.\n\n"
                "Re-launch PacketSentry from an elevated terminal, or use "
                "'Open pcap...' to analyse a saved capture.")
            return
        iface = self.iface_var.get()
        self.start_sniffer(iface=None if iface == DEFAULT_IFACE else iface,
                           label=f"Capturing on {iface}")

    def open_pcap(self):
        if self.sniffer:
            return
        path = filedialog.askopenfilename(
            title="Open capture",
            filetypes=[("Packet captures", "*.pcap *.pcapng *.cap"),
                       ("All files", "*.*")])
        if not path:
            return
        self.clear()
        self.start_sniffer(offline=path, label=f"Reading {path}")

    def start_sniffer(self, label, **source):
        from scapy.all import AsyncSniffer
        if self.sniffer:
            return
        bpf = self.filter_var.get().strip() or None
        try:
            self.sniffer = AsyncSniffer(prn=self.queue.put, store=False,
                                        filter=bpf, **source)
            self.sniffer.start()
        except Exception as exc:
            self.sniffer = None
            messagebox.showerror("Capture failed", str(exc))
            return
        self.start_btn.configure(state="disabled")
        self.stop_btn.configure(state="normal")
        self.status_var.set(label + " ...")

    def stop(self):
        if not self.sniffer:
            return
        try:
            if self.sniffer.running:
                self.sniffer.stop()
        except Exception:
            pass
        self.finish_capture()

    def finish_capture(self):
        error = getattr(self.sniffer, "exception", None)
        self.sniffer = None
        self.drain_queue(limit=None)
        self.start_btn.configure(state="normal")
        self.stop_btn.configure(state="disabled")
        if error:
            messagebox.showerror("Capture failed",
                                 f"{error}\n\nCheck the interface and BPF filter.")
        self.status_var.set(f"Stopped. {len(self.packets)} packet(s), "
                            f"{len(self.stats.flagged)} flagged.")

    def poll(self):
        added = self.drain_queue(limit=BATCH)
        if added:
            self.update_summary()
            if self.sniffer:
                self.status_var.set(
                    f"Capturing ... {len(self.packets)} packet(s), "
                    f"{len(self.stats.flagged)} flagged.")
        # An offline read (or a crashed capture) ends on its own.
        if self.sniffer and not self.sniffer.running and self.queue.empty():
            self.finish_capture()
            self.update_summary()
        self.root.after(POLL_MS, self.poll)

    def drain_queue(self, limit):
        added = 0
        while limit is None or added < limit:
            try:
                pkt = self.queue.get_nowait()
            except queue.Empty:
                break
            self.add_packet(pkt)
            added += 1
        return added

    def add_packet(self, pkt):
        info = core.analyse_packet(pkt)
        if info is None:
            return
        self.packets.append(pkt)
        self.infos.append(info)
        self.stats.record(info["proto"], info["src"])
        if info["risks"]:
            self.stats.flag(f"#{len(self.infos)}  {info['time']}  "
                            f"{info['endpoints']}  -> {', '.join(info['risks'])}")
        self.insert_row(len(self.infos) - 1)

    # ------------------------------------------------------------ table

    def insert_row(self, index):
        info = self.infos[index]
        if self.only_flagged.get() and not info["risks"]:
            return
        src = info["src"] if info["sport"] is None else f"{info['src']}:{info['sport']}"
        dst = info["dst"] if info["dport"] is None else f"{info['dst']}:{info['dport']}"
        text = info["detail"]
        if info["proto"] == "ARP":
            text = f"{info['endpoints']}  ({info['detail']})"
        if info["risks"]:
            text = f"[{', '.join(info['risks'])}]  {text}".strip()
        tag = "flagged" if info["risks"] else info["proto"]
        self.tree.insert("", "end", iid=str(index), tags=(tag,),
                         values=(index + 1, info["time"], info["proto"], src,
                                 dst, info["length"], text))
        if self.sniffer and not self.tree.selection():
            self.tree.yview_moveto(1.0)

    def refill_table(self):
        self.tree.delete(*self.tree.get_children())
        for index in range(len(self.infos)):
            self.insert_row(index)

    def show_detail(self, _event=None):
        selected = self.tree.selection()
        if not selected:
            return
        index = int(selected[0])
        info, pkt = self.infos[index], self.packets[index]

        self.detail.configure(state="normal")
        self.detail.delete("1.0", "end")
        add = self.detail.insert
        add("end", f"Packet #{index + 1}   {info['time']}   "
                   f"{info['length']} bytes\n", "head")
        add("end", f"{info['proto']}  {info['endpoints']}\n")
        if info["detail"]:
            add("end", f"{info['detail']}\n")
        add("end", "\nLayers (header bytes)\n", "head")
        add("end", f"  {info['layers']}\n")
        add("end", "\nFindings\n", "head")
        if info["risks"]:
            for risk in info["risks"]:
                add("end", f"  ! {risk}\n", "risk")
        else:
            add("end", "  none\n", "ok")
        add("end", f"\nPayload ({len(info['payload'])} bytes)\n", "head")
        add("end", (hexdump(info["payload"]) if info["payload"] else "  (none)") + "\n")
        add("end", "\nFull packet fields\n", "head")
        add("end", pkt.show(dump=True))
        self.detail.configure(state="disabled")

    def update_summary(self):
        s = self.stats
        box = self.summary
        box.configure(state="normal")
        box.delete("1.0", "end")
        box.insert("end", f"Total packets: {s.total}\n", "head")
        if s.by_protocol:
            box.insert("end", "\nBy protocol\n", "head")
            for proto, count in s.by_protocol.most_common():
                box.insert("end", f"  {proto:<8} {count}\n")
        if s.by_src:
            box.insert("end", "\nTop talkers\n", "head")
            for ip, count in s.by_src.most_common(5):
                box.insert("end", f"  {ip:<18} {count}\n")
        if s.flagged:
            box.insert("end", f"\n{len(s.flagged)} finding(s) flagged\n", "risk")
            for line in s.flagged:
                box.insert("end", f"  {line}\n")
        elif s.total:
            box.insert("end", "\nNo plaintext credentials or risky "
                              "patterns seen.\n", "ok")
        box.configure(state="disabled")

    @staticmethod
    def write(widget, text):
        widget.configure(state="normal")
        widget.delete("1.0", "end")
        widget.insert("end", text)
        widget.configure(state="disabled")

    # ------------------------------------------------------------ files

    def save_pcap(self):
        if not self.packets:
            messagebox.showinfo("Nothing to save", "No packets captured yet.")
            return
        path = filedialog.asksaveasfilename(
            title="Save capture", defaultextension=".pcap",
            filetypes=[("Packet capture", "*.pcap")])
        if not path:
            return
        from scapy.all import wrpcap
        try:
            wrpcap(path, self.packets)
        except Exception as exc:
            messagebox.showerror("Save failed", str(exc))
            return
        self.status_var.set(f"Saved {len(self.packets)} packet(s) to {path}")

    def clear(self):
        if self.sniffer:
            self.stop()
        with self.queue.mutex:
            self.queue.queue.clear()
        self.reset_state()
        self.tree.delete(*self.tree.get_children())
        self.write(self.detail, "Select a packet to see its layers, "
                   "findings and payload.")
        self.update_summary()
        self.status_var.set("Cleared.")

    def on_close(self):
        self.stop()
        self.root.destroy()


def main():
    if sys.platform == "win32":
        try:   # crisp text on high-DPI screens
            import ctypes
            ctypes.windll.shcore.SetProcessDpiAwareness(1)
        except Exception:
            pass
    root = tk.Tk()
    try:
        ttk.Style(root).theme_use("vista" if sys.platform == "win32" else "clam")
    except tk.TclError:
        pass
    PacketSentryApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()
