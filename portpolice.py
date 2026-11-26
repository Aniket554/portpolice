#!/usr/bin/env python3
"""PortPolice - watches the ports open on THIS machine and alerts on suspicious ones.

Standard library only (Python 3.8+). Works on Windows, Linux and macOS.

Usage:
    python portpolice.py --once                 # one scan, print results
    python portpolice.py --daemon               # keep scanning in the background loop
    python portpolice.py --gui                  # simple desktop window
    python portpolice.py --once --range 1-10000 # custom port range
"""
import argparse
import json
import platform
import socket
import subprocess
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from pathlib import Path

HERE = Path(__file__).resolve().parent
PORTS_FILE = HERE / "suspicious_ports.json"
LOG_FILE = HERE / "portpolice.log"


# ----------------------------------------------------------------- data
def load_suspicious():
    """Return {port: description} from suspicious_ports.json (edit that file freely)."""
    try:
        with open(PORTS_FILE, encoding="utf-8") as f:
            return {int(k): v for k, v in json.load(f).items()}
    except (OSError, ValueError):
        return {}


# ----------------------------------------------------------------- scanning
def _check(port, host, timeout):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(timeout)
        return port if s.connect_ex((host, port)) == 0 else None


def local_addresses():
    hosts = {"127.0.0.1"}
    try:
        hosts.add(socket.gethostbyname(socket.gethostname()))
    except OSError:
        pass
    return sorted(hosts)


def scan_host(start=1, end=65535, timeout=0.3, workers=400):
    """Connect-scan this machine's own addresses and return sorted open ports."""
    found = set()
    for host in local_addresses():
        with ThreadPoolExecutor(max_workers=workers) as ex:
            results = ex.map(lambda p: _check(p, host, timeout), range(start, end + 1))
            found.update(p for p in results if p)
    return sorted(found)


def process_for_port(port):
    """Name of the process listening on a port (only if the optional psutil is installed)."""
    try:
        import psutil  # optional

        for c in psutil.net_connections(kind="inet"):
            if c.status == "LISTEN" and c.laddr and c.laddr.port == port and c.pid:
                return psutil.Process(c.pid).name()
    except Exception:
        pass
    return ""


# ----------------------------------------------------------------- alerts
def log(line):
    stamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(f"[{stamp}] {line}\n")


def notify(title, message):
    """Best-effort desktop notification, falls back silently to console/log only."""
    system = platform.system()
    try:
        if system == "Linux":
            subprocess.run(["notify-send", title, message], check=False)
        elif system == "Darwin":
            safe = message.replace('"', "'")
            subprocess.run(
                ["osascript", "-e", f'display notification "{safe}" with title "{title}"'],
                check=False,
            )
        elif system == "Windows":
            import ctypes

            threading.Thread(
                target=lambda: ctypes.windll.user32.MessageBoxW(0, message, title, 0x40),
                daemon=True,
            ).start()
    except Exception:
        pass


class Watcher:
    """Keeps a baseline of open ports and classifies every scan against it."""

    def __init__(self, start=1, end=65535):
        self.start, self.end = start, end
        self.baseline = None  # set after the first scan
        self.alerted = set()

    def scan(self):
        suspicious = load_suspicious()
        open_ports = scan_host(self.start, self.end)
        rows, alerts = [], []
        for port in open_ports:
            if port in suspicious:
                status, note = "SUSPICIOUS", suspicious[port]
            elif self.baseline is not None and port not in self.baseline:
                status, note = "NEW", "opened since the first scan"
            else:
                status, note = "known", ""
            rows.append(
                {"port": port, "status": status, "note": note, "process": process_for_port(port)}
            )
            if status != "known" and port not in self.alerted:
                self.alerted.add(port)
                alerts.append(rows[-1])
        if self.baseline is None:
            self.baseline = set(open_ports)
        for a in alerts:
            msg = f"{a['status']} port {a['port']} {a['process']} {a['note']}".strip()
            log(msg)
            notify("PortPolice alert", msg)
        return rows


def print_rows(rows):
    print(f"\n{'PORT':<8}{'STATUS':<12}{'PROCESS':<20}NOTE")
    for r in rows:
        print(f"{r['port']:<8}{r['status']:<12}{r['process']:<20}{r['note']}")
    print(f"\n{len(rows)} open port(s) at {datetime.now():%H:%M:%S}")


# ----------------------------------------------------------------- GUI
def run_gui(watcher, interval):
    import tkinter as tk
    from tkinter import ttk

    root = tk.Tk()
    root.title("PortPolice")
    root.geometry("640x380")
    cols = ("port", "status", "process", "note")
    tree = ttk.Treeview(root, columns=cols, show="headings")
    for c, w in zip(cols, (70, 100, 140, 300)):
        tree.heading(c, text=c.upper())
        tree.column(c, width=w)
    tree.tag_configure("SUSPICIOUS", background="#ffb3b3")
    tree.tag_configure("NEW", background="#fff2b3")
    tree.pack(fill="both", expand=True)
    status = tk.StringVar(value="Ready")
    tk.Label(root, textvariable=status, anchor="w").pack(fill="x")
    busy = threading.Event()

    def refresh(rows):
        tree.delete(*tree.get_children())
        for r in rows:
            tree.insert(
                "", "end", tags=(r["status"],),
                values=(r["port"], r["status"], r["process"], r["note"]),
            )
        status.set(f"{len(rows)} open ports - updated {datetime.now():%H:%M:%S}")
        busy.clear()

    def scan_now():
        if busy.is_set():
            return
        busy.set()
        status.set("Scanning...")
        threading.Thread(
            target=lambda: (lambda rows: root.after(0, refresh, rows))(watcher.scan()),
            daemon=True,
        ).start()

    def auto():
        scan_now()
        root.after(interval * 1000, auto)

    ttk.Button(root, text="Scan now", command=scan_now).pack(pady=4)
    auto()
    root.mainloop()


# ----------------------------------------------------------------- main
def main():
    ap = argparse.ArgumentParser(description="Scan this machine's own open ports.")
    mode = ap.add_mutually_exclusive_group()
    mode.add_argument("--once", action="store_true", help="single scan (default)")
    mode.add_argument("--daemon", action="store_true", help="scan repeatedly, alert on changes")
    mode.add_argument("--gui", action="store_true", help="open a simple window")
    ap.add_argument("--range", default="1-65535", help="port range, e.g. 1-10000")
    ap.add_argument("--interval", type=int, default=60, help="seconds between scans")
    args = ap.parse_args()

    start, end = (int(x) for x in args.range.split("-"))
    watcher = Watcher(start, end)

    if args.gui:
        run_gui(watcher, args.interval)
    elif args.daemon:
        print(f"PortPolice watching ports {start}-{end} every {args.interval}s. Ctrl+C to stop.")
        try:
            while True:
                print_rows(watcher.scan())
                time.sleep(args.interval)
        except KeyboardInterrupt:
            print("\nStopped.")
    else:
        print_rows(watcher.scan())


if __name__ == "__main__":
    main()
