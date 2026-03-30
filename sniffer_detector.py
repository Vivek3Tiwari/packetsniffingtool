#!/usr/bin/env python3
"""
Packet Sniffer + Suspicious Traffic Detector (No ML)
===================================================

A zero-ML, presentation-ready cybersecurity project that:
  • Sniffs live traffic (or reads a .pcap)
  • Applies simple, explainable heuristics to flag suspicious behavior
  • Prints colorized alerts and writes a CSV log

Detections implemented
----------------------
1) Port scan heuristics (SYN storms, many unique ports/hosts in a window)
2) DoS burst (high packets-per-second from a single source)
3) DNS anomalies (very long/fragmented labels, high entropy, high QPS)
4) ARP spoofing (same IP announced by multiple MAC addresses)
5) Odd TCP flags (NULL/XMAS/SYN+FIN)
6) Cleartext credential hints (HTTP Basic, FTP USER/PASS)

No model training. All rules are inline and adjustable via CLI.

Requirements
------------
• Python 3.9+
• scapy
• rich (for prettier console output) — optional but recommended

Install:
    pip install scapy rich

Run (Linux/macOS requires sudo; Windows needs Npcap):
    sudo python sniffer_detector.py --iface eth0

Read from pcap instead of live:
    python sniffer_detector.py --pcap capture.pcap

Export alerts to CSV (default: alerts.csv):
    python sniffer_detector.py --iface eth0 --out alerts.csv

"""
import argparse
import csv
import math
import os
import queue
import re
import signal
import sys
import threading
import time
from collections import defaultdict, deque
from datetime import datetime, timedelta

try:
    from scapy.all import (
        sniff, rdpcap, AsyncSniffer,
        IP, IPv6, TCP, UDP, DNS, DNSQR, ARP, Raw
    )
except Exception as e:
    print("[!] Failed to import scapy. Install with: pip install scapy")
    raise

# Optional pretty printing
try:
    from rich.console import Console
    from rich.table import Table
    from rich import box
    console = Console()
except Exception:
    class _Dummy:
        def print(self, *a, **k):
            print(*a)
    console = _Dummy()

# ------------------------ Utility helpers ------------------------

def now_ts():
    return time.time()


def human_ts(ts=None):
    return datetime.fromtimestamp(ts or now_ts()).strftime('%Y-%m-%d %H:%M:%S')


def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    freq = defaultdict(int)
    for ch in s:
        freq[ch] += 1
    total = len(s)
    ent = 0.0
    for c in freq.values():
        p = c / total
        ent -= p * math.log2(p)
    return ent

# ------------------------ Detector core -------------------------

class Detector:
    def __init__(self, args):
        self.args = args
        # Sliding windows
        self.window_seconds = args.window
        self.window_cut = now_ts() - self.window_seconds

        # Per-source accounting
        self.syn_seen = defaultdict(deque)        # src -> times
        self.syn_dports = defaultdict(lambda: defaultdict(set))  # src -> dst -> set(ports)
        self.pkts_times = defaultdict(deque)      # src -> times for pps
        self.dns_times = defaultdict(deque)       # src -> times for QPS

        # ARP tables: ip -> set(macs)
        self.arp_map = defaultdict(set)

        # CSV logging
        self.csv_path = args.out
        self.csv_file = open(self.csv_path, 'w', newline='')
        self.csv = csv.writer(self.csv_file)
        self.csv.writerow(["time","type","src","dst","detail"])

        # Precompiled regex
        self.re_http_basic = re.compile(rb"\r\nAuthorization:\s*Basic\s+", re.I)
        self.re_http_user_agent_missing = re.compile(rb"\r\nUser-Agent:\s*\r\n", re.I)
        self.re_ftp_user = re.compile(rb"\bUSER\s+([\x20-\x7E]+)", re.I)
        self.re_ftp_pass = re.compile(rb"\bPASS\s+([\x20-\x7E]+)", re.I)

        self.alert_count = 0

    # ---------- housekeeping ----------
    def _evict_old(self, dq: deque):
        cutoff = now_ts() - self.window_seconds
        while dq and dq[0] < cutoff:
            dq.popleft()

    def _evict_nested_ports(self, src):
        cutoff = now_ts() - self.window_seconds
        to_del_dst = []
        for dst, ports in self.syn_dports[src].items():
            # We cannot time-tag ports, so keep set as-is within window by relying on syn_seen timestamp gate
            if not self.syn_seen[src]:
                to_del_dst.append(dst)
        for d in to_del_dst:
            del self.syn_dports[src][d]

    def close(self):
        try:
            self.csv_file.close()
        except Exception:
            pass

    # ---------- emit alert ----------
    def alert(self, atype: str, src: str, dst: str, detail: str):
        self.alert_count += 1
        ts = human_ts()
        self.csv.writerow([ts, atype, src or "-", dst or "-", detail])
        self.csv_file.flush()
        try:
            from rich.panel import Panel
            console.print(Panel(f"[bold]{atype}[/bold]\n[dim]{ts}[/dim]\n[src] {src or '-'} -> [dst] {dst or '-'}\n{detail}", border_style="red"))
        except Exception:
            print(f"[ALERT] {ts} {atype} {src}->{dst}: {detail}")

    # ---------- detectors ----------
    def on_tcp(self, pkt):
        ip = pkt.getlayer(IP) or pkt.getlayer(IPv6)
        src = ip.src if hasattr(ip, 'src') else None
        dst = ip.dst if hasattr(ip, 'dst') else None
        tcp = pkt[TCP]
        flags = tcp.flags
        t = now_ts()

        # DoS burst: packets per second per source
        dq = self.pkts_times[src]
        dq.append(t)
        self._evict_old(dq)
        if len(dq) >= self.args.dos_pps:
            self.alert("DoS burst suspect", src, dst, f">= {self.args.dos_pps} pkts within {self.window_seconds}s window")
            dq.clear()  # dampen repeats

        # Port-scan: SYN tracking
        if flags & 0x02 and not (flags & 0x10):  # SYN without ACK
            self.syn_seen[src].append(t)
            self._evict_old(self.syn_seen[src])
            self.syn_dports[src][dst].add(tcp.dport)
            unique_ports = len(set().union(*self.syn_dports[src].values())) if self.syn_dports[src] else 0
            if len(self.syn_seen[src]) >= self.args.syn_count or unique_ports >= self.args.scan_unique_ports:
                self.alert("Port scan suspect", src, dst,
                           f"SYNs={len(self.syn_seen[src])}, unique_ports~={unique_ports} in {self.window_seconds}s")
                self.syn_seen[src].clear()
                self.syn_dports[src].clear()

        # Weird TCP flags
        if flags == 0:
            self.alert("TCP NULL scan", src, dst, f"No flags set to port {tcp.dport}")
        if flags & 0x29 == 0x29:  # FIN+PSH+URG (XMAS-ish)
            self.alert("TCP XMAS scan", src, dst, f"Flags={flags} to port {tcp.dport}")
        if (flags & 0x03) == 0x03:  # SYN+FIN
            self.alert("TCP odd flags", src, dst, f"SYN+FIN to port {tcp.dport}")

        # Cleartext credential hints in Raw payload
        if pkt.haslayer(Raw):
            payload = bytes(pkt[Raw].load)
            if self.re_http_basic.search(payload):
                self.alert("HTTP Basic Auth in clear", src, dst, f"Authorization: Basic header seen on port {tcp.dport}")
            if self.re_http_user_agent_missing.search(payload):
                self.alert("Suspicious HTTP client", src, dst, "Missing User-Agent header")
            if tcp.dport in (20, 21) or tcp.sport in (20, 21):
                if self.re_ftp_user.search(payload) or self.re_ftp_pass.search(payload):
                    self.alert("FTP credential leak", src, dst, "USER/PASS command observed")

    def on_udp(self, pkt):
        ip = pkt.getlayer(IP) or pkt.getlayer(IPv6)
        src = ip.src if hasattr(ip, 'src') else None
        dst = ip.dst if hasattr(ip, 'dst') else None
        udp = pkt[UDP]

        # DNS anomalies
        if udp.dport == 53 or udp.sport == 53:
            t = now_ts()
            dq = self.dns_times[src]
            dq.append(t)
            self._evict_old(dq)
            # Rate-based check
            if len(dq) >= self.args.dns_qps:
                self.alert("High DNS query rate", src, dst, f">= {self.args.dns_qps} queries within {self.window_seconds}s")
                dq.clear()
            # Content-based checks
            if pkt.haslayer(DNS) and pkt[DNS].qdcount > 0 and pkt.haslayer(DNSQR):
                qname = pkt[DNSQR].qname.decode(errors='ignore').strip('.')
                labels = qname.split('.') if qname else []
                longest = max((len(l) for l in labels), default=0)
                entropy = shannon_entropy(qname)
                if longest >= self.args.dns_long_label or len(labels) >= self.args.dns_label_count or entropy >= self.args.dns_entropy:
                    self.alert("Suspicious DNS name", src, dst,
                               f"qname={qname[:80]}..., longest_label={longest}, labels={len(labels)}, H={entropy:.2f}")

    def on_arp(self, pkt):
        if pkt.op != 2:  # only ARP replies
            return
        ip = pkt.psrc
        mac = pkt.hwsrc
        self.arp_map[ip].add(mac)
        if len(self.arp_map[ip]) > 1:
            self.alert("ARP spoofing suspect", ip, pkt.pdst, f"Multiple MACs for {ip}: {', '.join(self.arp_map[ip])}")

    # ---------- dispatcher ----------
    def handle(self, pkt):
        try:
            if pkt.haslayer(ARP):
                self.on_arp(pkt[ARP])
                return
            ip = pkt.getlayer(IP) or pkt.getlayer(IPv6)
            if not ip:
                return
            if pkt.haslayer(TCP):
                self.on_tcp(pkt)
            elif pkt.haslayer(UDP):
                self.on_udp(pkt)
        except Exception as e:
            console.print(f"[!] Handler error: {e}")


# ------------------------ CLI + Runner --------------------------

def build_argparser():
    p = argparse.ArgumentParser(description="Packet sniffer + suspicious traffic detector (no ML)")
    src = p.add_mutually_exclusive_group(required=True)
    src.add_argument('--iface', help='Interface to sniff (e.g., eth0, en0, Wi-Fi)')
    src.add_argument('--pcap', help='Read from pcap file instead of live capture')

    p.add_argument('--out', default='alerts.csv', help='CSV output path (default: alerts.csv)')
    p.add_argument('--window', type=int, default=10, help='Sliding window seconds (default: 10)')

    # Port-scan / DoS thresholds
    p.add_argument('--syn-count', type=int, default=30, help='SYNs in window to flag scan (default: 30)')
    p.add_argument('--scan-unique-ports', type=int, default=40, help='Unique dest ports in window to flag (default: 40)')
    p.add_argument('--dos-pps', type=int, default=200, help='Packets per window per source (default: 200)')

    # DNS thresholds
    p.add_argument('--dns-qps', type=int, default=50, help='DNS queries per window per source (default: 50)')
    p.add_argument('--dns-long-label', type=int, default=40, help='Longest DNS label length to flag (default: 40)')
    p.add_argument('--dns-label-count', type=int, default=6, help='Number of DNS labels to flag (default: 6)')
    p.add_argument('--dns-entropy', type=float, default=3.8, help='Shannon entropy threshold to flag (default: 3.8)')

    return p


def present_banner(args):
    try:
        from rich.panel import Panel
        from rich.text import Text
        txt = Text()
        txt.append("Network Packet Sniffer + Suspicious Detector\n", style="bold")
        txt.append(f"Source: {'live on ' + args.iface if args.iface else 'pcap ' + args.pcap}\n")
        txt.append(f"Window: {args.window}s | CSV: {args.out}\n")
        txt.append("Detectors: PortScan, DoS burst, DNS anomalies, ARP spoof, Odd TCP flags, Cleartext creds")
        console.print(Panel(txt, border_style="green"))
    except Exception:
        print("Network Packet Sniffer + Suspicious Detector")


def sniff_live(args, det: Detector):
    present_banner(args)
    console.print("[dim]Press Ctrl+C to stop...[/dim]")
    sniffer = AsyncSniffer(iface=args.iface, prn=det.handle, store=False)
    sniffer.start()
    try:
        while True:
            time.sleep(0.3)
    except KeyboardInterrupt:
        sniffer.stop()
        console.print(f"\n[bold]Stopped.[/bold] Alerts written to {args.out}")


def sniff_pcap(args, det: Detector):
    present_banner(args)
    pkts = rdpcap(args.pcap)
    for pkt in pkts:
        det.handle(pkt)
    console.print(f"\n[bold]Done.[/bold] Processed {len(pkts)} packets. Alerts written to {args.out}")


def main():
    args = build_argparser().parse_args()
    det = Detector(args)
    try:
        if args.iface:
            sniff_live(args, det)
        else:
            sniff_pcap(args, det)
    finally:
        det.close()


if __name__ == '__main__':
    main()
