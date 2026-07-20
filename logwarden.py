#!/usr/bin/env python3
"""
LogWarden — SSH/auth log analyzer.
Scans auth.log for failed login attempts, brute-force patterns, and suspicious IPs.
"""

import argparse
import datetime
import json
import os
import re
import sys
from collections import Counter, defaultdict
from pathlib import Path

# Maximum log file size (CWE-770)
MAX_LOG_SIZE = 500 * 1024 * 1024  # 500MB


def _validate_path(path: str, purpose: str = "input") -> str:
    """Validate a file path — canonicalize and check exists (CWE-20/CWE-22)."""
    resolved = os.path.realpath(path)
    if purpose == "input":
        if not os.path.isfile(resolved):
            raise FileNotFoundError(f"Log file not found: {resolved}")
        file_size = os.path.getsize(resolved)
        if file_size > MAX_LOG_SIZE:
            raise ValueError(f"Log file too large ({file_size} bytes > {MAX_LOG_SIZE} max)")
    elif purpose == "output":
        parent = os.path.dirname(resolved)
        if parent and not os.path.isdir(parent):
            raise FileNotFoundError(f"Output directory does not exist: {parent}")
    return resolved


SSH_FAILED_RE = re.compile(
    r"(Failed password|Connection closed by authenticating user|"
    r"Invalid user|Did not receive identification|"
    r"Connection reset by peer|maximum authentication attempts exceeded)"
)
SSH_INVALID_USER_RE = re.compile(r"Invalid user (\S+) from (\S+)")
SSH_FAILED_PW_RE = re.compile(r"Failed password for (\S+) from (\S+) port")
SSH_ACCEPTED_RE = re.compile(r"Accepted (\S+) for (\S+) from (\S+) port")


def parse_log(logpath: str) -> dict:
    """Parse an auth log file and extract security-relevant events."""
    data = {
        "file": logpath,
        "total_lines": 0,
        "failed_attempts": 0,
        "accepted_logins": 0,
        "invalid_users": 0,
        "unique_ips": set(),
        "users_attacked": Counter(),
        "sources": Counter(),
        "source_details": defaultdict(list),
        "timeline": [],
        "ssh_accepts": [],
    }
    
    if not os.path.exists(logpath):
        print("[-] Log file not found")
        return data

    # CWE-20/CWE-22: Validate path
    validated = _validate_path(logpath)

    with open(validated, "r", errors="replace") as f:
        for line in f:
            data["total_lines"] += 1
            
            # Timestamp extraction
            ts_match = re.match(r"^(\w{3}\s+\d+\s+\d+:\d+:\d+)", line)
            # CWE-476: guard regex match before .group()
            timestamp = ts_match.group(1) if ts_match else "unknown"
            
            if SSH_FAILED_RE.search(line):
                data["failed_attempts"] += 1
                data["timeline"].append((timestamp, "FAILED", line.strip()[:120]))
                
                # Extract username + source IP
                # CWE-476: guard regex match before .group()
                m = SSH_INVALID_USER_RE.search(line)
                if m:
                    data["invalid_users"] += 1
                    user, ip = m.group(1), m.group(2)
                    data["unique_ips"].add(ip)
                    data["users_attacked"][user] += 1
                    data["sources"][ip] += 1
                    data["source_details"][ip].append({
                        "time": timestamp,
                        "user": user,
                        "type": "invalid_user",
                    })
                
                # CWE-476: guard regex match before .group()
                m = SSH_FAILED_PW_RE.search(line)
                if m:
                    user, ip = m.group(1), m.group(2)
                    data["unique_ips"].add(ip)
                    data["users_attacked"][user] += 1
                    data["sources"][ip] += 1
                    data["source_details"][ip].append({
                        "time": timestamp,
                        "user": user,
                        "type": "failed_password",
                    })
            
            # CWE-476: guard regex match before .group()
            m = SSH_ACCEPTED_RE.search(line)
            if m:
                data["accepted_logins"] += 1
                auth_method, user, ip = m.group(1), m.group(2), m.group(3)
                data["ssh_accepts"].append((timestamp, auth_method, user, ip))
    
    data["unique_ip_count"] = len(data["unique_ips"])
    data["unique_ips"] = list(data["unique_ips"])

    # Find brute-force sources
    data["bruteforce_sources"] = []
    for ip, count in data["sources"].most_common(20):
        if count >= 5:
            data["bruteforce_sources"].append({
                "ip": ip,
                "attempts": count,
                "first_seen": data["source_details"][ip][0]["time"] if data["source_details"][ip] else "unknown",
                "last_seen": data["source_details"][ip][-1]["time"] if data["source_details"][ip] else "unknown",
            })
    
    return data


def print_report(data: dict):
    """Pretty-print analysis results."""
    print(f"\n{'='*60}")
    print(f"  LogWarden Analysis Report")
    print(f"  File: {data['file']}")
    print(f"{'='*60}\n")
    
    print(f"  Total lines parsed: {data['total_lines']}")
    print(f"  Failed auth attempts: {data['failed_attempts']}")
    print(f"  Accepted logins: {data['accepted_logins']}")
    print(f"  Invalid user attempts: {data['invalid_users']}")
    print(f"  Unique attacking IPs: {data['unique_ip_count']}\n")
    
    if data["users_attacked"]:
        print(f"  Top attacked usernames:")
        for user, count in data["users_attacked"].most_common(10):
            print(f"    {user:20s} {count} attempts")
        print()
    
    if data["bruteforce_sources"]:
        print(f"  Brute-force sources (>=5 attempts):")
        for src in data["bruteforce_sources"]:
            print(f"    {src['ip']:18s} {src['attempts']:5d} attempts  "
                  f"(first: {src['first_seen']}, last: {src['last_seen']})")
        print()


def main():
    parser = argparse.ArgumentParser(description="LogWarden — auth log analyzer")
    parser.add_argument("logfile", help="Path to auth.log or syslog file")
    parser.add_argument("-o", "--output", help="Export results as JSON")
    parser.add_argument("--top-users", type=int, default=10, help="Number of top users to show")
    parser.add_argument("--min-attempts", type=int, default=5, help="Min attempts for brute-force flag")
    parser.add_argument("--watch", action="store_true", help="Follow mode (tail log)")
    args = parser.parse_args()

    data = parse_log(args.logfile)
    print_report(data)

    if args.output:
        # CWE-20/CWE-22: Validate output path
        out_path = _validate_path(args.output, "output")
        # Convert sets to lists for JSON
        data_serializable = data
        if isinstance(data_serializable.get("unique_ips"), set):
            data_serializable["unique_ips"] = list(data_serializable["unique_ips"])
        with open(out_path, "w") as f:
            json.dump(data_serializable, f, indent=2, default=str)
        print(f"[+] Report saved to {args.output}")


if __name__ == "__main__":
    main()
