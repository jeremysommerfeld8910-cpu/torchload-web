"""Tests for torchload-web app."""
import pytest
from fastapi.testclient import TestClient
from app import app, validate_github_url, check_rate_limit, rate_limits, scan_stats


client = TestClient(app)


class TestURLValidation:
    def test_valid_owner_repo(self):
        valid, url = validate_github_url("pytorch/pytorch")
        assert valid is True
        assert url == "https://github.com/pytorch/pytorch.git"

    def test_valid_full_url(self):
        valid, url = validate_github_url("https://github.com/pytorch/pytorch")
        assert valid is True
        assert url == "https://github.com/pytorch/pytorch.git"

    def test_valid_http_url(self):
        valid, url = validate_github_url("http://github.com/pytorch/pytorch")
        assert valid is True

    def test_invalid_no_slash(self):
        valid, _ = validate_github_url("invalid")
        assert valid is False

    def test_path_traversal(self):
        valid, _ = validate_github_url("../../../etc/passwd")
        assert valid is False

    def test_empty_string(self):
        valid, _ = validate_github_url("")
        assert valid is False

    def test_trailing_slash(self):
        valid, url = validate_github_url("pytorch/pytorch/")
        assert valid is True

    def test_long_owner(self):
        valid, _ = validate_github_url("a" * 101 + "/repo")
        assert valid is False


class TestRateLimiting:
    def setup_method(self):
        rate_limits.clear()

    def test_first_request_allowed(self):
        assert check_rate_limit("test-ip-1") is True

    def test_within_limit(self):
        for _ in range(3):
            check_rate_limit("test-ip-2")
        assert len(rate_limits.get("test-ip-2", [])) == 3

    def test_exceeds_limit(self):
        for _ in range(3):
            check_rate_limit("test-ip-3")
        assert check_rate_limit("test-ip-3") is False


class TestHealthEndpoint:
    def test_health(self):
        response = client.get("/api/v1/health")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "ok"
        assert data["version"] == "0.5.1"
        assert "scanner" not in data  # Don't leak internal paths


class TestHomePage:
    def test_home_returns_html(self):
        response = client.get("/")
        assert response.status_code == 200
        assert "torchload" in response.text.lower()

    def test_home_has_form(self):
        response = client.get("/")
        assert 'action="/scan"' in response.text


class TestAPIEndpoint:
    def setup_method(self):
        rate_limits.clear()

    def test_missing_repo_url(self):
        response = client.post("/api/v1/scan", json={})
        assert response.status_code == 400

    def test_invalid_repo_url(self):
        response = client.post("/api/v1/scan", json={"repo_url": "invalid"})
        assert response.status_code == 400

    def test_path_traversal_rejected(self):
        response = client.post("/api/v1/scan", json={"repo_url": "../../../etc/passwd"})
        assert response.status_code == 400

    def test_invalid_json(self):
        response = client.post(
            "/api/v1/scan",
            content="not json",
            headers={"Content-Type": "application/json"},
        )
        assert response.status_code == 400


class TestStatsEndpoint:
    def test_stats_returns_data(self):
        response = client.get("/api/v1/stats")
        assert response.status_code == 200
        data = response.json()
        assert "total_scans" in data
        assert data["patterns_detected"] == 22
        assert data["version"] == "0.5.1"


class TestBadgeEndpoint:
    def test_badge_not_scanned(self):
        response = client.get("/api/v1/badge/nonexistent/repo")
        assert response.status_code == 200
        data = response.json()
        assert data["schemaVersion"] == 1
        assert data["label"] == "CWE-502"
        assert data["message"] == "not scanned"
        assert data["color"] == "lightgrey"


class TestCORS:
    def test_cors_headers_present(self):
        response = client.options(
            "/api/v1/health",
            headers={"Origin": "https://example.com", "Access-Control-Request-Method": "GET"},
        )
        assert response.status_code == 200


class TestPatternsEndpoint:
    def test_patterns_returns_all(self):
        response = client.get("/api/v1/patterns")
        assert response.status_code == 200
        data = response.json()
        assert data["total_patterns"] == 22
        assert len(data["patterns"]) == 22

    def test_patterns_have_required_fields(self):
        response = client.get("/api/v1/patterns")
        data = response.json()
        for p in data["patterns"]:
            assert "name" in p
            assert "severity" in p
            assert "cwe" in p
            assert "description" in p
            assert p["severity"] in ("CRITICAL", "HIGH", "MEDIUM", "LOW")

    def test_patterns_severity_breakdown(self):
        response = client.get("/api/v1/patterns")
        data = response.json()
        assert "severity_breakdown" in data
        total = sum(data["severity_breakdown"].values())
        assert total == 22


class TestScanShorthand:
    def test_scan_shorthand_rate_limit(self):
        """GET scan endpoint should respect rate limits."""
        rate_limits.clear()
        # Exhaust rate limit
        for _ in range(3):
            rate_limits.setdefault("testclient", []).append(__import__("time").time())
        response = client.get("/api/v1/scan/pytorch/pytorch")
        assert response.status_code == 429


class TestPricingEndpoint:
    def test_pricing_returns_tiers(self):
        response = client.get("/api/v1/pricing")
        assert response.status_code == 200
        data = response.json()
        assert "tiers" in data
        assert len(data["tiers"]) == 3
        names = [t["name"] for t in data["tiers"]]
        assert "Free" in names
        assert "Pro" in names
        assert "Enterprise" in names

    def test_free_tier_details(self):
        response = client.get("/api/v1/pricing")
        data = response.json()
        free = [t for t in data["tiers"] if t["name"] == "Free"][0]
        assert free["scans_per_day"] == 3
        assert free["price"] == "$0/month"


class TestReportEndpoint:
    def test_report_not_scanned(self):
        response = client.get("/api/v1/report/nonexistent/repo")
        assert response.status_code == 404
        data = response.json()
        assert "not scanned" in data["error"].lower()


class TestAPIDocs:
    def test_openapi_docs(self):
        response = client.get("/api/docs")
        assert response.status_code == 200

    def test_redoc(self):
        response = client.get("/api/redoc")
        assert response.status_code == 200
