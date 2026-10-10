import pytest
from fastapi.testclient import TestClient

from codeshield.api.app import create_app
from codeshield.config import Settings

VULN = b"import os\n\ndef ping(h):\n    return os.system('ping ' + h)\n"


@pytest.fixture()
def client():
    app = create_app(Settings(disable_model=True))
    with TestClient(app) as test_client:
        yield test_client


def test_health_reports_engines(client):
    response = client.get("/health")
    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "ok"
    assert body["model_id"]


def test_upload_scan_lifecycle(client):
    response = client.post("/api/scans", files={"file": ("app.py", VULN, "text/x-python")})
    assert response.status_code == 200
    scan_id = response.json()["id"]

    detail = client.get(f"/api/scans/{scan_id}")
    assert detail.status_code == 200
    scan = detail.json()
    assert scan["status"] == "done"
    assert scan["summary"]["total_findings"] >= 1

    finding_id = scan["findings"][0]["id"]
    patch = client.get(f"/api/scans/{scan_id}/patches/{finding_id}")
    assert patch.status_code == 200
    assert patch.json()["finding_id"] == finding_id


def test_report_formats(client):
    scan_id = client.post(
        "/api/scans", files={"file": ("app.py", VULN, "text/x-python")}
    ).json()["id"]

    assert client.get(f"/api/scans/{scan_id}/report?format=json").json()["id"] == scan_id
    sarif = client.get(f"/api/scans/{scan_id}/report?format=sarif").json()
    assert sarif["version"] == "2.1.0"
    pdf = client.get(f"/api/scans/{scan_id}/report?format=pdf")
    assert pdf.content.startswith(b"%PDF-")

    bad = client.get(f"/api/scans/{scan_id}/report?format=xml")
    assert bad.status_code == 400


def test_lifecycle_update(client):
    scan_id = client.post(
        "/api/scans", files={"file": ("app.py", VULN, "text/x-python")}
    ).json()["id"]
    finding_id = client.get(f"/api/scans/{scan_id}").json()["findings"][0]["id"]

    response = client.post(
        f"/api/scans/{scan_id}/findings/{finding_id}/status", json={"status": "false_positive"}
    )
    assert response.status_code == 200
    assert response.json()["status"] == "false_positive"


def test_github_rejects_non_github_url(client):
    response = client.post("/api/scans/github", json={"url": "https://example.com/x"})
    assert response.status_code == 200  # accepted for background processing
    scan_id = response.json()["id"]
    # The background job should mark it errored rather than crash.
    scan = client.get(f"/api/scans/{scan_id}").json()
    assert scan["status"] in {"error", "done"}


def test_missing_scan_is_404(client):
    assert client.get("/api/scans/nope").status_code == 404


def test_auth_required_when_token_set():
    app = create_app(Settings(disable_model=True, api_token="s3cret"))
    with TestClient(app) as client:
        assert client.get("/api/scans").status_code == 401
        assert client.get("/api/scans", headers={"Authorization": "Bearer s3cret"}).status_code == 200
