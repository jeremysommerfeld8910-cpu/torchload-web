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
        assert data["version"] == "0.5.0"
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
        assert data["patterns_detected"] == 18
        assert data["version"] == "0.5.0"


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


class TestAPIDocs:
    def test_openapi_docs(self):
        response = client.get("/api/docs")
        assert response.status_code == 200

    def test_redoc(self):
        response = client.get("/api/redoc")
        assert response.status_code == 200
