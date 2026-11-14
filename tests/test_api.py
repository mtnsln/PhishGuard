from fastapi.testclient import TestClient

from phishguard.api import app

client = TestClient(app)


def test_health_version():
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json()["version"] == "2.0.0"


def test_api_brand_detection():
    response = client.post("/api/analyze", json={"url": "https://paypal.com.example.org/login"})
    assert response.status_code == 200
    report = response.json()
    assert report["risk_score"] == 35
    assert "brand_in_subdomain" in {item["code"] for item in report["findings"]}


def test_api_rejects_invalid_scheme():
    response = client.post("/api/analyze", json={"url": "javascript:alert(1)"})
    assert response.status_code == 422


def test_api_rejects_oversized_url():
    response = client.post("/api/analyze", json={"url": "https://example.com/" + "a" * 2100})
    assert response.status_code == 422


def test_homepage_is_served():
    response = client.get("/")
    assert response.status_code == 200
    assert "PhishGuard" in response.text
