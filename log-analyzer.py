import re
from datetime import datetime

LOG_FILE = "sample.log"

SUSPICIOUS_PATTERNS = [
    (r"Failed password for .+ from (\S+)", "SSH Failed Login"),
    (r"Invalid user .+ from (\S+)", "Invalid User Attempt"),
    (r"Connection closed by (\S+)", "Connection Closed"),
    (r"Did not receive identification string from (\S+)", "No Identification"),
    (r"error: maximum authentication attempts exceeded for .+ from (\S+)", "Brute Force Detected"),
]

def analyze_log(filepath):
    print("-" * 60)
    print(f"SOC Log Analyzer — Started at {datetime.now()}")
    print("-" * 60)

    try:
        with open(filepath, "r") as f:
            lines = f.readlines()
    except FileNotFoundError:
        print(f"Log file '{filepath}' not found.")
        return

    alerts = []
    ip_count = {}

    for line in lines:
        for pattern, label in SUSPICIOUS_PATTERNS:
            match = re.search(pattern, line)
            if match:
                ip = match.group(1)
                alerts.append((label, ip, line.strip()))
                ip_count[ip] = ip_count.get(ip, 0) + 1

    if not alerts:
        print("No suspicious activity found.")
    else:
        print(f"ALERTS FOUND: {len(alerts)}\n")
        for label, ip, line in alerts:
            print(f"[ALERT] {label} | IP: {ip}")
            print(f"        Log: {line}")
            print()

    print("-" * 60)
    print("Top Suspicious IPs:")
    sorted_ips = sorted(ip_count.items(), key=lambda x: x[1], reverse=True)
    for ip, count in sorted_ips[:5]:
        print(f"  {ip} — {count} suspicious events")
    print("-" * 60)

if __name__ == "__main__":
    analyze_log(LOG_FILE)
