#!/usr/bin/env python3
"""
Mini IDS — Intrusion Detection System
======================================
Monitors system logs for suspicious activity:
  - Failed SSH/login attempts
  - Brute force detection
  - IP reputation tracking
  - Real-time alerting

Author: Juan Pablo Mendez | github.com/juanpablocode-sudo
"""

import re
import os
import sys
import json
import time
import argparse
from datetime import datetime
from pathlib import Path
from collections import defaultdict


# --- CONFIG ---

DEFAULT_LOG_PATHS = [
    '/var/log/auth.log',
    '/var/log/secure',
    '/var/log/syslog',
]

PATTERNS = {
    "ssh_failed": {
        "regex": r'Failed (password|publickey) for (?:invalid user )?(\S+) from ([\d.]+)',
        "severity": "MEDIUM",
        "description": "Failed SSH authentication"
    },
    "invalid_user": {
        "regex": r'Invalid user (\S+) from ([\d.]+)',
        "severity": "HIGH",
        "description": "SSH login attempt with invalid user"
    },
    "sudo_failed": {
        "regex": r'sudo:.*authentication failure.*user=(\S+)',
        "severity": "HIGH",
        "description": "Failed sudo authentication"
    },
    "accepted_ssh": {
        "regex": r'Accepted (password|publickey) for (\S+) from ([\d.]+)',
        "severity": "INFO",
        "description": "Successful SSH login"
    },
    "connection_closed": {
        "regex": r'Connection closed by authenticating user (\S+) ([\d.]+)',
        "severity": "LOW",
        "description": "Connection closed before authentication"
    },
    "brute_force_disconnect": {
        "regex": r'Disconnecting invalid user (\S+) ([\d.]+)',
        "severity": "HIGH",
        "description": "Disconnected invalid user"
    },
}

SEVERITY_COLORS = {
    "CRITICAL": "\033[91m",  # red
    "HIGH": "\033[91m",
    "MEDIUM": "\033[93m",    # yellow
    "LOW": "\033[94m",       # blue
    "INFO": "\033[92m",      # green
    "RESET": "\033[0m"
}


class Alert:
    def __init__(self, pattern_name, severity, description, ip=None, user=None, raw_line=None):
        self.pattern_name = pattern_name
        self.severity = severity
        self.description = description
        self.ip = ip
        self.user = user
        self.raw_line = raw_line
        self.timestamp = datetime.now().isoformat()

    def to_dict(self):
        return {
            "timestamp": self.timestamp,
            "pattern": self.pattern_name,
            "severity": self.severity,
            "description": self.description,
            "ip": self.ip,
            "user": self.user,
        }


class MiniIDS:
    def __init__(self, log_path: str, threshold: int = 5, window: int = 60, output_file: str = None):
        self.log_path = log_path
        self.threshold = threshold
        self.window = window
        self.output_file = output_file

        self.ip_attempts = defaultdict(list)  # ip -> [timestamps]
        self.user_attempts = defaultdict(int)
        self.alerts = []
        self.blocked_ips = set()
        self.stats = defaultdict(int)

    def parse_line(self, line: str) -> Alert | None:
        """Try to match a log line against all known patterns."""
        for pattern_name, pattern_info in PATTERNS.items():
            match = re.search(pattern_info["regex"], line)
            if match:
                groups = match.groups()
                ip = None
                user = None

                # Extract IP and user depending on pattern
                if pattern_name == "ssh_failed":
                    user, ip = groups[1], groups[2]
                elif pattern_name in ("invalid_user", "connection_closed", "brute_force_disconnect"):
                    user, ip = groups[0], groups[1]
                elif pattern_name == "accepted_ssh":
                    user, ip = groups[1], groups[2]
                elif pattern_name == "sudo_failed":
                    user = groups[0]

                return Alert(
                    pattern_name=pattern_name,
                    severity=pattern_info["severity"],
                    description=pattern_info["description"],
                    ip=ip,
                    user=user,
                    raw_line=line.strip()
                )
        return None

    def check_brute_force(self, ip: str) -> bool:
        """Return True if IP exceeds attempt threshold within time window."""
        if not ip:
            return False

        now = time.time()
        self.ip_attempts[ip].append(now)
        # Keep only attempts within the window
        self.ip_attempts[ip] = [t for t in self.ip_attempts[ip] if now - t <= self.window]

        return len(self.ip_attempts[ip]) >= self.threshold

    def format_alert(self, alert: Alert, brute_force: bool = False) -> str:
        """Format alert for console output."""
        severity = "CRITICAL" if brute_force else alert.severity
        color = SEVERITY_COLORS.get(severity, "")
        reset = SEVERITY_COLORS["RESET"]

        ts = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        line = f"{color}[{severity}]{reset} {ts}"

        if brute_force:
            line += f" 🚨 BRUTE FORCE DETECTED from {alert.ip} ({len(self.ip_attempts.get(alert.ip, []))} attempts in {self.window}s)"
        else:
            line += f" {alert.description}"
            if alert.ip:
                line += f" from {alert.ip}"
            if alert.user:
                line += f" (user: {alert.user})"

        return line

    def process_line(self, line: str):
        """Process a single log line."""
        alert = self.parse_line(line)
        if not alert:
            return

        self.alerts.append(alert)
        self.stats[alert.severity] += 1

        # Check for brute force
        brute_force = False
        if alert.ip and alert.severity in ("MEDIUM", "HIGH"):
            brute_force = self.check_brute_force(alert.ip)
            if brute_force and alert.ip not in self.blocked_ips:
                self.blocked_ips.add(alert.ip)
                self.stats["BRUTE_FORCE"] += 1

        print(self.format_alert(alert, brute_force))

    def tail_log(self):
        """Tail a log file in real-time."""
        print(f"\n[*] Mini IDS started — monitoring: {self.log_path}")
        print(f"[*] Brute force threshold: {self.threshold} attempts / {self.window}s")
        print(f"[*] Press Ctrl+C to stop\n")

        try:
            with open(self.log_path, 'r') as f:
                f.seek(0, 2)  # seek to end
                while True:
                    line = f.readline()
                    if line:
                        self.process_line(line)
                    else:
                        time.sleep(0.1)
        except KeyboardInterrupt:
            self.print_summary()
            if self.output_file:
                self.save_report()

    def analyze_file(self):
        """Analyze an existing log file (non-real-time)."""
        print(f"\n[*] Analyzing log file: {self.log_path}\n")

        with open(self.log_path, 'r', errors='ignore') as f:
            for line in f:
                self.process_line(line)

        self.print_summary()
        if self.output_file:
            self.save_report()

    def print_summary(self):
        """Print detection summary."""
        print("\n" + "="*60)
        print("  MINI IDS — SESSION SUMMARY")
        print("="*60)
        print(f"  Total alerts:     {len(self.alerts)}")
        print(f"  HIGH severity:    {self.stats.get('HIGH', 0)}")
        print(f"  MEDIUM severity:  {self.stats.get('MEDIUM', 0)}")
        print(f"  Brute forces:     {self.stats.get('BRUTE_FORCE', 0)}")

        if self.blocked_ips:
            print(f"\n  IPs with brute force activity:")
            for ip in self.blocked_ips:
                print(f"    • {ip} ({len(self.ip_attempts.get(ip, []))} attempts)")

        if self.user_attempts:
            print(f"\n  Top targeted users:")
            sorted_users = sorted(self.user_attempts.items(), key=lambda x: x[1], reverse=True)[:5]
            for user, count in sorted_users:
                print(f"    • {user}: {count} attempts")

        print("="*60 + "\n")

    def save_report(self):
        """Save all alerts to JSON."""
        report = {
            "session_end": datetime.now().isoformat(),
            "log_file": self.log_path,
            "total_alerts": len(self.alerts),
            "brute_force_ips": list(self.blocked_ips),
            "stats": dict(self.stats),
            "alerts": [a.to_dict() for a in self.alerts]
        }
        with open(self.output_file, 'w') as f:
            json.dump(report, f, indent=2)
        print(f"[+] Report saved: {self.output_file}")


def find_log_file() -> str | None:
    """Auto-detect available log file."""
    for path in DEFAULT_LOG_PATHS:
        if os.path.exists(path):
            return path
    return None


def main():
    parser = argparse.ArgumentParser(
        description="Mini IDS — Real-time intrusion detection for Linux systems",
        epilog="Example: sudo python mini_ids.py --tail --threshold 3 --json session.json"
    )
    parser.add_argument('--log', help='Path to log file (auto-detected if omitted)')
    parser.add_argument('--tail', action='store_true', help='Monitor in real-time (tail mode)')
    parser.add_argument('--analyze', action='store_true', help='Analyze existing log file')
    parser.add_argument('--threshold', type=int, default=5, help='Failed attempts before brute force alert (default: 5)')
    parser.add_argument('--window', type=int, default=60, help='Time window in seconds for brute force detection (default: 60)')
    parser.add_argument('--json', metavar='OUTPUT', help='Save session report as JSON')

    args = parser.parse_args()

    log_path = args.log or find_log_file()
    if not log_path:
        print("[ERROR] No log file found. Specify one with --log /path/to/auth.log")
        print(f"        Tried: {', '.join(DEFAULT_LOG_PATHS)}")
        sys.exit(1)

    if not os.path.exists(log_path):
        print(f"[ERROR] Log file not found: {log_path}")
        sys.exit(1)

    ids = MiniIDS(
        log_path=log_path,
        threshold=args.threshold,
        window=args.window,
        output_file=args.json
    )

    if args.tail:
        ids.tail_log()
    elif args.analyze:
        ids.analyze_file()
    else:
        print("[!] Specify --tail (real-time) or --analyze (existing file)")
        parser.print_help()


if __name__ == "__main__":
    main()
