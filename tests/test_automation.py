import json
import pytest
from unittest.mock import patch, MagicMock, call
from datetime import datetime


SAMPLE_ALERT = {
    "alert_id":  1,
    "rule_id":   "SSH-001",
    "rule_name": "SSH Brute Force Attack",
    "severity":  "high",
    "source_ip": "45.33.32.156",
    "playbook":  "block_ip_and_notify",
    "event": {
        "event_type": "ssh_failed_login",
        "category":   "authentication",
        "username":   "root",
        "message":    "Failed password for root from 45.33.32.156",
        "raw_log":    "Jun 12 10:00:01 host sshd[1]: Failed password for root from 45.33.32.156",
    },
}



class TestBlockIP:
    def test_dry_run_returns_success(self, monkeypatch):
        monkeypatch.setenv("IPTABLES_DRY_RUN", "true")
        from automation.playbooks import block_ip
        import importlib; importlib.reload(block_ip)

        with patch("automation.playbooks.block_ip._store_blocked_ip"), \
             patch("automation.playbooks.block_ip.notify") as mock_notify:
            mock_notify.return_value = {"status": "success"}
            result = block_ip.execute(SAMPLE_ALERT)

        assert result["status"] in ("success", "partial")
        assert result["ip_blocked"] == "45.33.32.156"
        assert "DRY RUN" in result["iptables"]

    def test_missing_source_ip_skips(self):
        from automation.playbooks import block_ip
        alert = {**SAMPLE_ALERT, "source_ip": None}
        result = block_ip.execute(alert)
        assert result["status"] == "skipped"

    def test_iptables_command_called_in_prod(self, monkeypatch):
        monkeypatch.setenv("IPTABLES_DRY_RUN", "false")
        from automation.playbooks import block_ip
        import importlib; importlib.reload(block_ip)

        with patch("subprocess.run") as mock_run, \
             patch("automation.playbooks.block_ip._store_blocked_ip"), \
             patch("automation.playbooks.block_ip.notify") as mock_notify:
            mock_run.return_value = MagicMock(returncode=1)  # rule doesn't exist yet
            mock_notify.return_value = {"status": "success"}
            block_ip.execute(SAMPLE_ALERT)

        calls = [str(c) for c in mock_run.call_args_list]
        assert any("iptables" in c for c in calls)



class TestNotifySlack:
    def test_skips_when_not_configured(self, monkeypatch):
        monkeypatch.setenv("SLACK_WEBHOOK_URL", "")
        monkeypatch.setenv("ALERT_EMAIL", "")
        from automation.playbooks import notify_slack
        import importlib; importlib.reload(notify_slack)

        result = notify_slack.execute(SAMPLE_ALERT)
        assert result["status"] == "skipped"
        assert result["channels"]["slack"]["status"] == "skipped"
        assert result["channels"]["email"]["status"] == "skipped"

    def test_slack_payload_structure(self):
        from automation.playbooks.notify_slack import _build_slack_payload
        payload = _build_slack_payload(SAMPLE_ALERT)
        assert "text" in payload
        assert "attachments" in payload
        assert len(payload["attachments"]) == 1
        fields = {f["title"]: f["value"] for f in payload["attachments"][0]["fields"]}
        assert "Source IP" in fields
        assert "45.33.32.156" in fields["Source IP"]

    def test_slack_sends_when_configured(self, monkeypatch):
        monkeypatch.setenv("SLACK_WEBHOOK_URL", "https://hooks.slack.com/fake")
        from automation.playbooks import notify_slack
        import importlib; importlib.reload(notify_slack)

        mock_response = MagicMock()
        mock_response.read.return_value = b"ok"
        mock_response.__enter__ = lambda s: s
        mock_response.__exit__ = MagicMock(return_value=False)

        with patch("urllib.request.urlopen", return_value=mock_response):
            ok, msg = notify_slack._send_slack(notify_slack._build_slack_payload(SAMPLE_ALERT))
        assert ok is True

    def test_email_body_contains_key_fields(self):
        from automation.playbooks.notify_slack import _build_email_body
        body = _build_email_body(SAMPLE_ALERT)
        assert "SSH Brute Force" in body
        assert "45.33.32.156" in body
        assert "HIGH" in body



class TestCreateTicket:
    def test_creates_local_ticket(self):
        from automation.playbooks import create_ticket

        mock_engine = MagicMock()
        mock_session = MagicMock()
        mock_session.__enter__ = lambda s: s
        mock_session.__exit__ = MagicMock(return_value=False)

        with patch("automation.playbooks.create_ticket._ensure_table", return_value=mock_engine), \
             patch("automation.playbooks.create_ticket.Session", return_value=mock_session), \
             patch("automation.playbooks.create_ticket._create_local_ticket",
                   return_value={"id": 42, "title": "Test"}) as mock_local, \
             patch("automation.playbooks.create_ticket._create_jira_ticket",
                   return_value=(False, "not configured")), \
             patch("automation.playbooks.create_ticket._create_github_issue",
                   return_value=(False, "not configured")):
            result = create_ticket.execute(SAMPLE_ALERT)

        assert result["status"] == "success"
        assert result["local_id"] == 42

    def test_description_contains_rule_info(self):
        from automation.playbooks.create_ticket import _build_description
        desc = _build_description(SAMPLE_ALERT)
        assert "SSH Brute Force" in desc
        assert "45.33.32.156" in desc
        assert "ssh_failed_login" in desc

    def test_jira_skipped_without_config(self, monkeypatch):
        monkeypatch.setenv("JIRA_URL", "")
        from automation.playbooks import create_ticket
        import importlib; importlib.reload(create_ticket)
        ok, msg = create_ticket._create_jira_ticket(SAMPLE_ALERT)
        assert ok is False
        assert "not configured" in msg



class TestPlaybookRunner:
    def test_known_playbook_dispatches(self):
        from automation.playbook_runner import run_playbook
        with patch("automation.playbooks.block_ip.execute",
                   return_value={"status": "success"}) as mock_exec:
            result = run_playbook("block_ip_and_notify", SAMPLE_ALERT)
        assert result["status"] == "success"

    def test_unknown_playbook_returns_error(self):
        from automation.playbook_runner import run_playbook
        result = run_playbook("nonexistent_playbook", SAMPLE_ALERT)
        assert result["status"] == "error"
        assert "Unknown playbook" in result["message"]
