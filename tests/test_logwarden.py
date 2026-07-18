"""Tests for LogWarden auth log analyzer."""
import json
import sys
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

sys.path.insert(0, "/home/j-alien/cybersec-portfolio/15-LogWarden")

from logwarden import (
    parse_log,
    print_report,
    SSH_FAILED_RE,
    SSH_INVALID_USER_RE,
    SSH_FAILED_PW_RE,
    SSH_ACCEPTED_RE,
)


TEST_LOG_LINES = [
    "Jan 15 10:00:00 server sshd[1234]: Failed password for root from 192.168.1.100 port 22 ssh2",
    "Jan 15 10:00:05 server sshd[1235]: Failed password for admin from 10.0.0.50 port 22 ssh2",
    "Jan 15 10:00:10 server sshd[1236]: Invalid user test from 192.168.1.100 port 22",
    "Jan 15 10:01:00 server sshd[1237]: Accepted publickey for jdrexler from 10.0.0.10 port 54321 ssh2",
    "Jan 15 10:02:00 server sshd[1238]: Failed password for root from 192.168.1.100 port 22 ssh2",
    "Jan 15 10:02:05 server sshd[1239]: Failed password for root from 192.168.1.100 port 22 ssh2",
    "Jan 15 10:03:00 server sshd[1240]: Connection closed by authenticating user root 192.168.1.100 port 22 [preauth]",
    "Jan 15 10:04:00 server sudo: jdrexler : TTY=pts/0 ; PWD=/home/jdrexler ; USER=root ; COMMAND=/bin/bash",
]


def test_ssh_failed_re_matches():
    """Should match failed password events."""
    line = "Jan 15 10:00:00 server sshd[1234]: Failed password for root from 192.168.1.100 port 22 ssh2"
    assert SSH_FAILED_RE.search(line)


def test_ssh_failed_re_no_match():
    """Should not match non-failed events."""
    line = "Jan 15 10:01:00 server sshd[1237]: Accepted publickey for jdrexler from 10.0.0.10 port 54321 ssh2"
    assert not SSH_FAILED_RE.search(line)


def test_ssh_invalid_user_re():
    """Should extract invalid username and source IP."""
    line = "Jan 15 10:00:10 server sshd[1236]: Invalid user test from 192.168.1.100 port 22"
    m = SSH_INVALID_USER_RE.search(line)
    assert m is not None
    assert m.group(1) == "test"
    assert m.group(2) == "192.168.1.100"


def test_ssh_failed_pw_re():
    """Should extract failed password username and source IP."""
    line = "Jan 15 10:00:00 server sshd[1234]: Failed password for root from 192.168.1.100 port 22 ssh2"
    m = SSH_FAILED_PW_RE.search(line)
    assert m is not None
    assert m.group(1) == "root"
    assert m.group(2) == "192.168.1.100"


def test_ssh_accepted_re():
    """Should extract accepted auth details."""
    line = "Jan 15 10:01:00 server sshd[1237]: Accepted publickey for jdrexler from 10.0.0.10 port 54321 ssh2"
    m = SSH_ACCEPTED_RE.search(line)
    assert m is not None
    assert m.group(1) == "publickey"
    assert m.group(2) == "jdrexler"
    assert m.group(3) == "10.0.0.10"


def test_parse_log_basic():
    """Should parse a log file and return structured data."""
    with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".log") as f:
        f.write("\n".join(TEST_LOG_LINES))
        logpath = f.name

    try:
        result = parse_log(logpath)
        assert result["file"] == logpath
        assert result["total_lines"] == 8
        assert result["failed_attempts"] > 0
    finally:
        Path(logpath).unlink(missing_ok=True)


def test_parse_log_empty():
    """Should handle empty log file."""
    with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".log") as f:
        logpath = f.name

    try:
        result = parse_log(logpath)
        assert result["total_lines"] == 0
        assert result["failed_attempts"] == 0
    finally:
        Path(logpath).unlink(missing_ok=True)


def test_parse_log_nonexistent():
    """Should handle nonexistent log file."""
    result = parse_log("/nonexistent/path/auth.log")
    assert result["total_lines"] == 0


def test_parse_log_counts_failed():
    """Should count failed password events."""
    with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".log") as f:
        f.write("\n".join(TEST_LOG_LINES))
        logpath = f.name

    try:
        result = parse_log(logpath)
        assert result["failed_attempts"] >= 3
    finally:
        Path(logpath).unlink(missing_ok=True)


def test_parse_log_counts_accepted():
    """Should count accepted logins."""
    with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".log") as f:
        f.write("\n".join(TEST_LOG_LINES))
        logpath = f.name

    try:
        result = parse_log(logpath)
        assert result["accepted_logins"] >= 1
    finally:
        Path(logpath).unlink(missing_ok=True)


def test_parse_log_unique_ips():
    """Should extract unique IPs from log."""
    with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".log") as f:
        f.write("\n".join(TEST_LOG_LINES))
        logpath = f.name

    try:
        result = parse_log(logpath)
        assert result["unique_ip_count"] >= 2
        assert "192.168.1.100" in result["unique_ips"]
    finally:
        Path(logpath).unlink(missing_ok=True)


def test_parse_log_bruteforce_detection():
    """Should detect IPs with multiple failed attempts."""
    with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".log") as f:
        f.write("\n".join(TEST_LOG_LINES))
        logpath = f.name

    try:
        result = parse_log(logpath)
        if result["bruteforce_sources"]:
            ips = [s["ip"] for s in result["bruteforce_sources"]]
            assert "192.168.1.100" in ips
    finally:
        Path(logpath).unlink(missing_ok=True)


def test_print_report_handles_data():
    """Should handle structured data without crashing."""
    data = {
        "file": "/var/log/auth.log",
        "total_lines": 100,
        "failed_attempts": 50,
        "accepted_logins": 5,
        "invalid_users": 10,
        "unique_ip_count": 15,
        "unique_ips": ["192.168.1.1"],
        "bruteforce_sources": [],
        "ssh_accepts": [],
        "users_attacked": {},
    }
    import io
    from contextlib import redirect_stdout
    with io.StringIO() as buf, redirect_stdout(buf):
        print_report(data)


def test_connection_closed_preauth_detection():
    """Should detect pre-auth connection closures."""
    line = "Jan 15 10:03:00 server sshd[1240]: Connection closed by authenticating user root 192.168.1.100 port 22 [preauth]"
    assert SSH_FAILED_RE.search(line)


def test_parse_log_timeline():
    """Should build a timeline of events."""
    with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".log") as f:
        f.write("\n".join(TEST_LOG_LINES))
        logpath = f.name

    try:
        result = parse_log(logpath)
        assert len(result["timeline"]) >= 1
        assert "FAILED" in result["timeline"][0]
    finally:
        Path(logpath).unlink(missing_ok=True)
