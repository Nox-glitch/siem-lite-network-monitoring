import pytest
import time
from datetime import datetime
from unittest.mock import MagicMock, patch

from detection.rule_engine import (
    SlidingWindow,
    evaluate_threshold,
    evaluate_pattern,
    load_rules,
)



class TestSlidingWindow:
    def test_count_increases_with_events(self):
        w = SlidingWindow()
        assert w.add("rule1", "1.2.3.4", 60) == 1
        assert w.add("rule1", "1.2.3.4", 60) == 2
        assert w.add("rule1", "1.2.3.4", 60) == 3

    def test_different_ips_are_independent(self):
        w = SlidingWindow()
        w.add("rule1", "1.1.1.1", 60)
        w.add("rule1", "1.1.1.1", 60)
        count = w.add("rule1", "2.2.2.2", 60)
        assert count == 1

    def test_different_rules_are_independent(self):
        w = SlidingWindow()
        w.add("SSH-001", "1.1.1.1", 60)
        w.add("SSH-001", "1.1.1.1", 60)
        count = w.add("NET-001", "1.1.1.1", 60)
        assert count == 1

    def test_window_expires_old_events(self):
        from collections import deque
        from datetime import timedelta
        w = SlidingWindow()
        key = ("rule1", "1.1.1.1")
        old_time = datetime.utcnow() - timedelta(seconds=120)
        w._windows[key] = deque([old_time, old_time, old_time])
        count = w.add("rule1", "1.1.1.1", 60)
        assert count == 1



class TestThresholdEvaluator:
    BASE_RULE = {
        "id":             "SSH-001",
        "condition_type": "threshold",
        "condition": {
            "event_type":     "ssh_failed_login",
            "count":          3,
            "window_seconds": 60,
            "group_by":       "source_ip",
        },
    }

    def setup_method(self):
        import detection.rule_engine as re_module
        re_module.sliding_windows = SlidingWindow()

    def _make_event(self, source_ip="1.2.3.4"):
        return {
            "event_type": "ssh_failed_login",
            "source_ip":  source_ip,
        }

    def test_does_not_fire_below_threshold(self):
        assert evaluate_threshold(self.BASE_RULE, self._make_event()) is False
        assert evaluate_threshold(self.BASE_RULE, self._make_event()) is False

    def test_fires_at_threshold(self):
        evaluate_threshold(self.BASE_RULE, self._make_event())
        evaluate_threshold(self.BASE_RULE, self._make_event())
        assert evaluate_threshold(self.BASE_RULE, self._make_event()) is True

    def test_different_event_type_does_not_count(self):
        for _ in range(5):
            result = evaluate_threshold(self.BASE_RULE, {
                "event_type": "ssh_accepted_login",
                "source_ip":  "1.2.3.4",
            })
        assert result is False

    def test_different_ips_dont_share_count(self):
        evaluate_threshold(self.BASE_RULE, self._make_event("1.1.1.1"))
        evaluate_threshold(self.BASE_RULE, self._make_event("1.1.1.1"))
        # Third event from different IP — should NOT fire
        assert evaluate_threshold(self.BASE_RULE, self._make_event("2.2.2.2")) is False



class TestPatternEvaluator:
    def test_simple_event_type_match(self):
        rule = {
            "id":             "PRIV-001",
            "condition_type": "pattern",
            "condition":      {"event_type": "sudo_failed"},
        }
        event = {"event_type": "sudo_failed", "source_ip": "10.0.0.1"}
        assert evaluate_pattern(rule, event) is True

    def test_event_type_mismatch(self):
        rule = {
            "id":             "PRIV-001",
            "condition_type": "pattern",
            "condition":      {"event_type": "sudo_failed"},
        }
        event = {"event_type": "ssh_failed_login"}
        assert evaluate_pattern(rule, event) is False

    def test_field_value_match(self):
        rule = {
            "id":             "SSH-002",
            "condition_type": "pattern",
            "condition": {
                "event_type": "ssh_accepted_login",
                "field":      "username",
                "value":      "root",
            },
        }
        assert evaluate_pattern(rule, {"event_type": "ssh_accepted_login", "username": "root"})  is True
        assert evaluate_pattern(rule, {"event_type": "ssh_accepted_login", "username": "alice"}) is False

    def test_contains_any_match(self):
        rule = {
            "id":             "PRIV-002",
            "condition_type": "pattern",
            "condition": {
                "event_type":   "sudo_usage",
                "field":        "command",
                "contains_any": ["/bin/bash", "python"],
            },
        }
        event_bash   = {"event_type": "sudo_usage", "command": "/bin/bash"}
        event_python = {"event_type": "sudo_usage", "command": "python3 script.py"}
        event_safe   = {"event_type": "sudo_usage", "command": "/usr/bin/systemctl restart nginx"}

        assert evaluate_pattern(rule, event_bash)   is True
        assert evaluate_pattern(rule, event_python) is True
        assert evaluate_pattern(rule, event_safe)   is False

    def test_field_from_extra(self):
        rule = {
            "id":             "TEST",
            "condition_type": "pattern",
            "condition": {
                "event_type": "generic",
                "field":      "process",
                "value":      "nginx",
            },
        }
        event = {"event_type": "generic", "extra": {"process": "nginx"}}
        assert evaluate_pattern(rule, event) is True



class TestLoadRules:
    def test_loads_without_error(self):
        rules = load_rules()
        assert isinstance(rules, list)
        assert len(rules) > 0

    def test_all_rules_have_required_fields(self):
        rules = load_rules()
        for rule in rules:
            assert "id"             in rule, f"Missing id in {rule}"
            assert "name"           in rule, f"Missing name in {rule}"
            assert "severity"       in rule, f"Missing severity in {rule}"
            assert "condition_type" in rule, f"Missing condition_type in {rule}"
            assert "condition"      in rule, f"Missing condition in {rule}"

    def test_disabled_rules_excluded(self):
        rules = load_rules()
        for rule in rules:
            assert rule.get("enabled", True) is True

    def test_known_rule_ids_present(self):
        rules  = load_rules()
        ids    = {r["id"] for r in rules}
        assert "SSH-001" in ids
        assert "PRIV-001" in ids
        assert "NET-001" in ids

    def test_severities_are_valid(self):
        valid  = {"low", "medium", "high", "critical"}
        rules  = load_rules()
        for rule in rules:
            assert rule["severity"] in valid, f"Invalid severity in rule {rule['id']}"

    def test_condition_types_are_valid(self):
        valid = {"threshold", "pattern", "sequence"}
        rules = load_rules()
        for rule in rules:
            assert rule["condition_type"] in valid, f"Unknown condition_type in {rule['id']}"



class TestAlertCreation:
    def test_store_event_and_create_alert(self):
        from detection.rule_engine import store_event, create_alert

        mock_session = MagicMock()
        mock_session.flush = MagicMock()

        event = {
            "timestamp":  datetime.utcnow().isoformat(),
            "event_type": "ssh_failed_login",
            "category":   "authentication",
            "severity":   "medium",
            "source_ip":  "1.2.3.4",
            "message":    "Failed password for root",
            "raw_log":    "raw",
            "log_source": "auth.log",
            "username":   "root",
            "extra":      {},
        }

        rule = {
            "id":              "SSH-001",
            "name":            "SSH Brute Force",
            "severity":        "high",
            "description":     "Brute force detected",
            "playbook":        "block_ip_and_notify",
            "mitre_tactic":    "TA0006",
            "mitre_technique": "T1110",
            "tags":            ["brute-force"],
        }

        mock_redis = MagicMock()
        db_event   = store_event(mock_session, event)
        mock_session.add.assert_called_once()
        mock_session.flush.assert_called_once()

        create_alert(mock_session, rule, event, db_event, mock_redis)
        mock_redis.publish.assert_called_once()
