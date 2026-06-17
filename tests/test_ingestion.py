import pytest
from datetime import datetime
from ingestion.parser import parse_log_line, extract_timestamp



class TestExtractTimestamp:
    def test_syslog_format(self):
        line = "Jun 12 10:30:01 myhost sshd[1234]: Failed password for root from 1.2.3.4"
        ts, msg = extract_timestamp(line)
        assert isinstance(ts, datetime)
        assert ts.month == 6
        assert ts.day == 12
        assert "Failed password" in msg

    def test_iso_format(self):
        line = "2026-06-12T10:30:01 some log message here"
        ts, msg = extract_timestamp(line)
        assert ts.year == 2026
        assert ts.month == 6

    def test_no_timestamp_returns_now(self):
        line = "just a log line with no timestamp"
        ts, msg = extract_timestamp(line)
        assert isinstance(ts, datetime)
        assert msg == line



class TestSSHParsing:
    def test_ssh_failed_login(self):
        line = "Jun 12 10:00:01 host sshd[1]: Failed password for root from 45.33.32.156 port 22 ssh2"
        event = parse_log_line(line, "auth.log")
        assert event is not None
        assert event["event_type"]  == "ssh_failed_login"
        assert event["source_ip"]   == "45.33.32.156"
        assert event["username"]    == "root"
        assert event["category"]    == "authentication"
        assert event["severity"]    == "medium"
        assert event["log_source"]  == "auth.log"

    def test_ssh_failed_invalid_user(self):
        line = "Jun 12 10:00:01 host sshd[1]: Failed password for invalid user nobody from 1.1.1.1 port 22 ssh2"
        event = parse_log_line(line, "auth.log")
        assert event is not None
        assert event["event_type"] == "ssh_failed_login"
        assert event["username"]   == "nobody"
        assert event["source_ip"]  == "1.1.1.1"

    def test_ssh_accepted_login(self):
        line = "Jun 12 10:01:00 host sshd[2]: Accepted password for deploy from 192.168.1.10 port 5555 ssh2"
        event = parse_log_line(line, "auth.log")
        assert event is not None
        assert event["event_type"] == "ssh_accepted_login"
        assert event["username"]   == "deploy"
        assert event["source_ip"]  == "192.168.1.10"
        assert event["severity"]   == "low"

    def test_ssh_invalid_user(self):
        line = "Jun 12 10:05:00 host sshd[3]: Invalid user testuser from 198.51.100.42"
        event = parse_log_line(line, "auth.log")
        assert event is not None
        assert event["event_type"] == "ssh_invalid_user"
        assert event["username"]   == "testuser"
        assert event["source_ip"]  == "198.51.100.42"



class TestSudoParsing:
    def test_sudo_usage(self):
        line = "Jun 12 10:02:00 host sudo: alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/bin/bash"
        event = parse_log_line(line, "auth.log")
        assert event is not None
        assert event["event_type"] == "sudo_usage"
        assert event["username"]   == "alice"
        assert event["category"]   == "privilege_escalation"

    def test_sudo_failed(self):
        line = "Jun 12 10:02:00 host sudo: bob : authentication failure; logname=bob"
        event = parse_log_line(line, "auth.log")
        assert event is not None
        assert event["event_type"] == "sudo_failed"
        assert event["severity"]   == "high"



class TestAccountParsing:
    def test_user_created(self):
        line = "Jun 12 10:03:00 host useradd[1]: new user: name=hacker, UID=1001, GID=1001"
        event = parse_log_line(line, "syslog")
        assert event is not None
        assert event["event_type"] == "user_created"
        assert event["username"]   == "hacker"
        assert event["category"]   == "account_management"

    def test_user_deleted(self):
        line = "Jun 12 10:04:00 host userdel[1]: delete user 'alice'"
        event = parse_log_line(line, "syslog")
        assert event is not None
        assert event["event_type"] == "user_deleted"
        assert event["username"]   == "alice"
        assert event["severity"]   == "high"



class TestNetworkParsing:
    def test_port_scan_kernel(self):
        line = "Jun 12 10:06:00 host kernel: [UFW BLOCK] IN=eth0 SRC=203.0.113.5 DST=10.0.0.1 DPT=4444"
        event = parse_log_line(line, "kern.log")
        assert event is not None
        assert event["event_type"] == "port_scan"
        assert event["source_ip"]  == "203.0.113.5"
        assert event["dest_ip"]    == "10.0.0.1"
        assert event["dest_port"]  == 4444

    def test_fail2ban_ban(self):
        line = "Jun 12 10:07:00 host fail2ban.actions[1]: Ban 1.2.3.4"
        event = parse_log_line(line, "syslog")
        assert event is not None
        assert event["event_type"] == "ip_banned"
        assert event["source_ip"]  == "1.2.3.4"



class TestJSONParsing:
    def test_valid_json_log(self):
        import json
        line = json.dumps({
            "timestamp":  "2026-06-12T10:00:00",
            "event_type": "app_login",
            "severity":   "low",
            "source_ip":  "10.0.0.5",
            "username":   "alice",
            "message":    "User logged in",
        })
        event = parse_log_line(line, "app")
        assert event is not None
        assert event["event_type"] == "app_login"
        assert event["source_ip"]  == "10.0.0.5"
        assert event["username"]   == "alice"

    def test_invalid_json_falls_back(self):
        line = "{not valid json"
        event = parse_log_line(line, "app")
        # Should return a generic event, not crash
        assert event is not None



class TestEdgeCases:
    def test_empty_line_returns_none(self):
        assert parse_log_line("", "test") is None

    def test_whitespace_only_returns_none(self):
        assert parse_log_line("   \n", "test") is None

    def test_unrecognized_line_returns_generic(self):
        event = parse_log_line("This is just some random log line with no pattern", "test")
        assert event is not None
        assert event["event_type"] == "generic"

    def test_raw_log_is_stored(self):
        line = "Jun 12 10:00:01 host sshd[1]: Failed password for root from 1.1.1.1 port 22 ssh2"
        event = parse_log_line(line, "auth.log")
        assert event["raw_log"] is not None
        assert len(event["raw_log"]) > 0

    def test_log_source_preserved(self):
        line = "Jun 12 10:00:01 host sshd[1]: Failed password for root from 1.1.1.1 port 22 ssh2"
        event = parse_log_line(line, "my_custom_source")
        assert event["log_source"] == "my_custom_source"

    def test_message_truncated_at_500_chars(self):
        long_msg = "A" * 1000
        line = f"Jun 12 10:00:00 host sshd[1]: {long_msg}"
        event = parse_log_line(line, "test")
        assert len(event["message"]) <= 500
