import time

import pytest
from fastapi.testclient import TestClient

from codeshield.api.app import app


@pytest.fixture(scope="module")
def client():
    with TestClient(app) as test_client:
        yield test_client


def _wait(client, scan_id: str, timeout: float = 60.0) -> dict:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        body = client.get(f"/api/v1/scans/{scan_id}").json()
        if body["status"] in {"completed", "failed", "cancelled"}:
            return body
        time.sleep(0.05)
    raise AssertionError(f"scan {scan_id} did not finish")


def _scan(client, code: str, filename: str = "snippet.py") -> dict:
    response = client.post(
        "/api/v1/scans",
        data={"source_type": "snippet", "filename": filename, "code": code},
    )
    assert response.status_code == 202, response.text
    return _wait(client, response.json()["id"])


def test_health_and_meta(client):
    health = client.get("/api/v1/health")
    assert health.status_code == 200
    assert health.json()["status"] == "ok"
    meta = client.get("/api/v1/meta").json()
    assert meta["app"] == "CodeShield AI"
    assert meta["auth_enabled"] is False
    assert meta["model"]["mode"] == "off"


def test_knowledge_endpoint(client):
    body = client.get("/api/v1/knowledge").json()
    assert body["items"]
    assert all("slug" in item and "cwe" in item for item in body["items"])
    slug = body["items"][0]["slug"]
    item = client.get(f"/api/v1/knowledge/{slug}")
    assert item.status_code == 200 and item.json()["slug"] == slug
    assert client.get("/api/v1/knowledge/../../etc/passwd").status_code == 404


def test_scan_inline_code_and_fetch_results(client):
    scan = _scan(client, 'def f(q):\n    cur.execute("SELECT * FROM t WHERE id = " + q)\n')
    assert scan["summary"]["total_findings"] >= 1
    assert scan["findings"]
    finding = scan["findings"][0]
    assert finding["patch_candidates"]
    detail = client.get(f"/api/v1/findings/{finding['id']}")
    assert detail.status_code == 200 and detail.json()["patch_candidates"]


def test_finding_status_lifecycle(client):
    scan = _scan(client, "def f(d):\n    return pickle.loads(d)\n")
    finding = scan["findings"][0]
    response = client.patch(
        f"/api/v1/findings/{finding['id']}",
        json={"status": "accepted_risk", "note": "tested"},
    )
    assert response.status_code == 200
    assert response.json()["status"] == "accepted_risk"
    events = client.get(f"/api/v1/findings/{finding['id']}/events").json()
    assert events and events[-1]["status"] == "accepted_risk"


def test_report_formats(client):
    scan = _scan(client, "def f(d):\n    return pickle.loads(d)\n")
    scan_id = scan["id"]
    assert client.get(f"/api/v1/scans/{scan_id}/report?format=json").status_code == 200
    sarif = client.get(f"/api/v1/scans/{scan_id}/report?format=sarif")
    assert sarif.status_code == 200 and sarif.json()["version"] == "2.1.0"
    assert client.get(f"/api/v1/scans/{scan_id}/report?format=html").status_code == 200
    pdf = client.get(f"/api/v1/scans/{scan_id}/report?format=pdf")
    assert pdf.status_code == 200 and pdf.content[:4] == b"%PDF"


def test_scan_list_stats_and_not_found(client):
    _scan(client, "def f(d):\n    return pickle.loads(d)\n")
    listing = client.get("/api/v1/scans?limit=5")
    assert listing.status_code == 200 and listing.json()["items"]
    stats = client.get("/api/v1/stats?days=14")
    assert stats.status_code == 200
    projects = client.get("/api/v1/projects")
    assert projects.status_code == 200 and projects.json()
    assert client.get("/api/v1/scans/does-not-exist").status_code == 404


def test_invalid_source_type(client):
    response = client.post("/api/v1/scans", data={"source_type": "ftp"})
    assert response.status_code == 400


def test_me_returns_demo_user(client):
    body = client.get("/api/v1/auth/me").json()
    assert body["user"]["email"] == "demo@codeshield.local"
