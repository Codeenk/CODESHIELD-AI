from fastapi.testclient import TestClient

from codeshield import config
from codeshield.api.app import app


def test_register_login_logout(monkeypatch):
    monkeypatch.setattr(config, "AUTH_MODE", "on")
    with TestClient(app) as client:
        registered = client.post(
            "/api/v1/auth/register",
            json={"email": "test@example.com", "password": "supersecret", "name": "Tester"},
        )
        assert registered.status_code == 200, registered.text
        assert registered.json()["user"]["email"] == "test@example.com"

        assert client.get("/api/v1/auth/me").json()["user"]["email"] == "test@example.com"
        assert client.post("/api/v1/auth/logout").status_code == 200
        assert client.get("/api/v1/auth/me").json()["user"] is None

        login = client.post(
            "/api/v1/auth/login",
            json={"email": "test@example.com", "password": "supersecret"},
        )
        assert login.status_code == 200
        assert client.get("/api/v1/auth/me").json()["user"]["email"] == "test@example.com"


def test_login_rejects_bad_password(monkeypatch):
    monkeypatch.setattr(config, "AUTH_MODE", "on")
    with TestClient(app) as client:
        client.post(
            "/api/v1/auth/register",
            json={"email": "other@example.com", "password": "supersecret", "name": "Other"},
        )
        client.post("/api/v1/auth/logout")
        response = client.post(
            "/api/v1/auth/login",
            json={"email": "other@example.com", "password": "wrong-password"},
        )
        assert response.status_code == 401


def test_invalid_email_rejected(monkeypatch):
    monkeypatch.setattr(config, "AUTH_MODE", "on")
    with TestClient(app) as client:
        response = client.post(
            "/api/v1/auth/register",
            json={"email": "not-an-email", "password": "supersecret", "name": "Nope"},
        )
        assert response.status_code == 422
