from fastapi.testclient import TestClient

from codeshield.api.app import app

client = TestClient(app)


def test_health():
    r = client.get("/health")
    assert r.status_code == 200
    body = r.json()
    assert body["status"] == "ok"
    assert body["knowledge"]["vulnerability_count"] == 29


def test_knowledge_endpoint():
    r = client.get("/api/v1/knowledge")
    assert r.status_code == 200
    body = r.json()
    assert len(body["vulnerabilities"]) == 29
    assert len(body["skills"]) == 4


def test_scan_inline_code_and_fetch_results():
    payload = {
        "filename": "snippet.py",
        "code": 'def f(q):\n    cur.execute("SELECT * FROM t WHERE id = " + q)\n',
    }
    r = client.post("/api/v1/scans", json=payload)
    assert r.status_code == 200, r.text
    scan = r.json()
    assert scan["summary"]["total_findings"] >= 1
    scan_id = scan["id"]

    r2 = client.get(f"/api/v1/scans/{scan_id}")
    assert r2.status_code == 200
    assert r2.json()["findings"]

    finding_id = r2.json()["findings"][0]["id"]
    r3 = client.get(f"/api/v1/findings/{finding_id}/patches")
    assert r3.status_code == 200
    assert r3.json()["candidates"]


def test_report_formats():
    payload = {"filename": "snippet.py", "code": "def f(d):\n    return pickle.loads(d)\n"}
    scan_id = client.post("/api/v1/scans", json=payload).json()["id"]
    assert client.get(f"/api/v1/scans/{scan_id}/report?format=json").status_code == 200
    sarif = client.get(f"/api/v1/scans/{scan_id}/report?format=sarif")
    assert sarif.status_code == 200 and sarif.json()["version"] == "2.1.0"
    assert client.get(f"/api/v1/scans/{scan_id}/report?format=html").status_code == 200
    pdf = client.get(f"/api/v1/scans/{scan_id}/report?format=pdf")
    assert pdf.status_code == 200 and pdf.content[:4] == b"%PDF"


def test_status_update_and_scan_not_found():
    payload = {"filename": "snippet.py", "code": "def f(d):\n    return pickle.loads(d)\n"}
    scan = client.post("/api/v1/scans", json=payload).json()
    fid = scan["findings"][0]["id"]
    r = client.post(f"/api/v1/findings/{fid}/status", json={"status": "accepted_risk"})
    assert r.status_code == 200
    assert client.get("/api/v1/scans/does-not-exist").status_code == 404
