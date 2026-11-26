# PortPolice

Scans the ports open on **your own machine** (not other computers) and flags any that match a list of ports commonly used by malware, plus any port that newly opens after the first scan.

## Run it (Antigravity or any terminal)

1. Open this folder in Antigravity (File > Open Folder).
2. Open the terminal and run one of:

```
python portpolice.py --once              # one scan
python portpolice.py --daemon            # repeat every 60s and alert on changes
python portpolice.py --gui               # desktop window
python portpolice.py --once --range 1-10000
python portpolice.py --daemon --interval 30
```

On macOS/Linux use `python3` if `python` is not found.

No packages needed. Optional: `pip install psutil` to also show the process name behind each port.

## Files

- `portpolice.py` - scanner, daemon loop, alerts and GUI
- `suspicious_ports.json` - the list of flagged ports; edit it to add your own
- `portpolice.log` - created automatically when an alert fires

## Notes

- A flagged port is a hint, not proof of malware. Some legitimate software uses these numbers too.
- "Background" mode keeps running while the terminal stays open. To run it hidden at login, use Task Scheduler (Windows), systemd or cron (Linux), or launchd (macOS).
