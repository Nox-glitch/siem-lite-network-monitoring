import pytest
from unittest.mock import patch
from ingestion.enrichment import (
    lookup_ip, enrich_event, _is_private, _cache, _cache_set
)


class TestPrivateIPDetection:
    def test_loopback(self):
        assert _is_private("127.0.0.1") is True

    def test_class_a_private(self):
        assert _is_private("10.0.0.1") is True
        assert _is_private("10.255.255.255") is True

    def test_class_b_private(self):
        assert _is_private("172.16.0.1") is True
        assert _is_private("172.31.255.255") is True

    def test_class_c_private(self):
        assert _is_private("192.168.1.1") is True

    def test_public_ip(self):
        assert _is_private("8.8.8.8") is False
        assert _is_private("45.33.32.156") is False

    def test_none_is_private(self):
        assert _is_private(None) is True
        assert _is_private("") is True


class TestLookupIP:
    def test_private_ip_returns_empty(self):
        result = lookup_ip("192.168.1.1")
        assert result == {}

    def test_uses_cache(self):
        _cache_set("1.2.3.4", {"country": "US", "threat_score": 10})
        result = lookup_ip("1.2.3.4")
        assert result["country"] == "US"

    def test_geo_and_abuse_merged(self):
        with patch("ingestion.enrichment._fetch_geo_ipapi",
                   return_value={"country": "Russia", "city": "Moscow", "country_code": "RU"}), \
             patch("ingestion.enrichment._fetch_abuse_score",
                   return_value={"abuse_score": 85, "is_tor": False, "total_reports": 10}):
            _cache.pop("5.5.5.5", None)
            result = lookup_ip("5.5.5.5")

        assert result["country"]     == "Russia"
        assert result["abuse_score"] == 85
        assert result["threat_score"] == 85
        assert result["threat_level"] == "malicious"

    def test_tor_escalates_score(self):
        with patch("ingestion.enrichment._fetch_geo_ipapi", return_value={}), \
             patch("ingestion.enrichment._fetch_abuse_score",
                   return_value={"abuse_score": 10, "is_tor": True}):
            _cache.pop("6.6.6.6", None)
            result = lookup_ip("6.6.6.6")

        assert result["threat_score"] >= 60
        assert result["is_tor"] is True

    def test_threat_levels(self):
        cases = [
            (0,  "clean"),
            (5,  "clean"),
            (10, "low_risk"),
            (40, "suspicious"),
            (80, "malicious"),
        ]
        for score, expected_level in cases:
            with patch("ingestion.enrichment._fetch_geo_ipapi", return_value={}), \
                 patch("ingestion.enrichment._fetch_abuse_score",
                       return_value={"abuse_score": score, "is_tor": False}):
                _cache.pop("7.7.7.7", None)
                result = lookup_ip("7.7.7.7")
            assert result["threat_level"] == expected_level, \
                f"score={score} expected {expected_level} got {result['threat_level']}"


class TestEnrichEvent:
    def test_enriches_public_ip(self):
        with patch("ingestion.enrichment.lookup_ip",
                   return_value={"country": "US", "city": "San Jose",
                                 "threat_score": 0.0, "threat_level": "clean"}):
            event = {"source_ip": "8.8.8.8", "severity": "low", "extra": {}}
            result = enrich_event(event)

        assert result["country"] == "US"
        assert result["city"]    == "San Jose"
        assert result["threat_score"] == 0.0

    def test_skips_private_ip(self):
        with patch("ingestion.enrichment.lookup_ip", return_value={}) as mock:
            event = {"source_ip": "192.168.1.1", "extra": {}}
            enrich_event(event)
        mock.assert_called_once()
        assert event.get("country") is None

    def test_escalates_severity_on_high_score(self):
        with patch("ingestion.enrichment.lookup_ip",
                   return_value={"threat_score": 90, "threat_level": "malicious",
                                 "country": "XX", "city": "Unknown"}):
            event = {"source_ip": "9.9.9.9", "severity": "low", "extra": {}}
            result = enrich_event(event)

        assert result["severity"] == "high"
        assert "severity_escalated" in result["extra"]

    def test_does_not_downgrade_severity(self):
        with patch("ingestion.enrichment.lookup_ip",
                   return_value={"threat_score": 90, "country": "XX", "city": "Y"}):
            event = {"source_ip": "9.9.9.9", "severity": "critical", "extra": {}}
            result = enrich_event(event)

        assert result["severity"] == "critical"

    def test_survives_enrichment_failure(self):
        with patch("ingestion.enrichment.lookup_ip", side_effect=Exception("network error")):
            event = {"source_ip": "8.8.8.8", "severity": "medium", "extra": {}}
            result = enrich_event(event)

        assert result["severity"] == "medium"
        assert result is event
