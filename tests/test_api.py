from __future__ import annotations

import hashlib
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from stegolab.app import create_app
from stegolab.config import Settings
from stegolab.store import atomic_json


@pytest.fixture
def app(tmp_path: Path):
    return create_app(Settings(data_dir=tmp_path / "data", max_file_bytes=1024, max_pending=2))


@pytest.fixture
def client(app):
    with TestClient(app) as session:
        yield session
    # Docker is the supported runtime; allow Windows host pytest temp cleanup.
    for path in app.state.settings.jobs_dir.rglob("original.bin"):
        path.chmod(0o600)


def upload(client, value=b"flag{api_evidence}\n", filename="clue.txt", mode="quick"):
    return client.post("/api/jobs", files={"file": (filename, value)}, data={"mode": mode})


def test_upload_preserves_evidence_and_hash_and_uses_generated_paths(client, app):
    value = b"flag{api_evidence}\n<script>never execute this</script>"
    response = upload(client, value=value, filename="../../outside.txt")
    assert response.status_code == 202
    job = response.json()
    assert len(job["id"]) == 32
    assert job["filename"] == "outside.txt"
    assert job["status"] == "queued"
    assert job["sha256"] == hashlib.sha256(value).hexdigest()
    assert job["size"] == len(value)
    evidence = app.state.settings.jobs_dir / job["id"] / "evidence" / "original.bin"
    assert evidence.read_bytes() == value
    assert not (app.state.settings.data_dir.parent / "outside.txt").exists()
    assert client.get(f"/api/jobs/{job['id']}/report").status_code == 409
    assert client.delete(f"/api/jobs/{job['id']}").status_code == 409
    assert client.get("/api/jobs").json()["jobs"][0]["id"] == job["id"]


@pytest.mark.parametrize("value,mode,status", [(b"", "quick", 422), (b"x", "invalid", 422), (b"x" * 1025, "quick", 413)])
def test_bad_upload_releases_queue_and_disk_reservation(client, app, value, mode, status):
    assert upload(client, value=value, mode=mode).status_code == status
    assert client.get("/api/jobs").json()["jobs"] == []
    # A rejected upload must not prevent a subsequent permitted upload.
    assert upload(client).status_code == 202


def test_missing_file_and_multiple_files_are_rejected(client):
    assert client.post("/api/jobs", data={"mode": "quick"}).status_code == 422
    response = client.post("/api/jobs", files=[("file", ("one", b"a")), ("file", ("two", b"b"))])
    assert response.status_code == 400
    assert client.get("/api/jobs").json()["jobs"] == []


def test_queue_capacity_cancel_and_missing_report(client):
    first = upload(client).json()
    second = upload(client).json()
    assert upload(client).status_code == 429
    cancelled = client.post(f"/api/jobs/{first['id']}/cancel")
    assert cancelled.status_code == 200
    assert cancelled.json()["status"] == "cancelled"
    assert client.post(f"/api/jobs/{first['id']}/cancel").json()["status"] == "cancelled"
    assert client.get(f"/api/jobs/{first['id']}/report").status_code == 404
    assert upload(client).status_code == 202
    assert client.get(f"/api/jobs/{second['id']}").json()["status"] == "queued"


def test_origin_host_and_response_headers(client):
    response = client.get("/api/health")
    assert response.status_code == 200
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["x-frame-options"] == "DENY"
    assert "object-src 'none'" in response.headers["content-security-policy"]
    assert response.headers["cache-control"] == "no-store"
    assert client.get("/api/health", headers={"host": "attacker.example"}).status_code == 400
    for origin in ("https://attacker.example", "null", "http://["):
        assert client.post("/api/utilities", headers={"origin": origin}, json={"operation": "rot13", "text": "test"}).status_code == 403
    assert client.post("/api/utilities", headers={"origin": "http://testserver"}, json={"operation": "rot13", "text": "synt{ncv}"}).json()["result"] == "flag{api}"


def test_request_cap_checks_declared_and_streamed_bytes(client):
    assert client.post("/api/jobs", content=b"", headers={"content-length": "2000000"}).status_code == 413
    boundary = "stegolab-test-boundary"
    prefix = (f"--{boundary}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"large.bin\"\r\nContent-Type: application/octet-stream\r\n\r\n").encode()
    chunks = iter([prefix, b"x" * (1024 * 1024 + 2048), f"\r\n--{boundary}--\r\n".encode()])
    response = client.post("/api/jobs", content=chunks, headers={"content-type": f"multipart/form-data; boundary={boundary}"})
    assert response.status_code == 413
    assert client.get("/api/jobs").json()["jobs"] == []


@pytest.mark.parametrize("job_id", ["not-a-job", "0" * 32])
def test_unknown_jobs_cannot_access_reports_or_cancel(client, job_id):
    assert client.get(f"/api/jobs/{job_id}").status_code == 404
    assert client.get(f"/api/jobs/{job_id}/report").status_code == 404
    assert client.post(f"/api/jobs/{job_id}/cancel").status_code == 404


def test_artifact_download_is_an_attachment_and_rejects_path_escape(client, app, tmp_path):
    job = upload(client).json()
    root = app.state.settings.jobs_dir / job["id"]
    artifacts = root / "artifacts"
    artifacts.mkdir()
    (artifacts / "safe.txt").write_bytes(b"flag{downloaded_artifact}")
    outside = tmp_path / "outside-secret.txt"
    outside.write_bytes(b"must not be downloaded")
    report = {"status": "completed", "artifacts": [
        {"id": "safe", "path": "safe.txt", "name": "result.html"},
        {"id": "escape", "path": str(outside), "name": "secret.txt"},
        {"id": "parent", "path": "../upload.json", "name": "upload.json"},
    ]}
    atomic_json(root / "report.json", report)
    app.state.store.finish(job["id"], "completed")
    response = client.get(f"/api/jobs/{job['id']}/artifacts/safe")
    assert response.status_code == 200
    assert response.content == b"flag{downloaded_artifact}"
    assert response.headers["content-type"] == "application/octet-stream"
    assert "attachment;" in response.headers["content-disposition"]
    assert client.get(f"/api/jobs/{job['id']}/artifacts/escape").status_code == 404
    assert client.get(f"/api/jobs/{job['id']}/artifacts/parent").status_code == 404
    assert client.get(f"/api/jobs/{job['id']}/report").json() == report
    assert "attachment;" in client.get(f"/api/jobs/{job['id']}/report?download=true").headers["content-disposition"]


def test_utilities_return_real_results_and_reject_invalid_input(client):
    assert client.post("/api/utilities", json={"operation": "base64_decode", "text": "ZmxhZ3t1dGlsaXR5fQ=="}).json()["result"] == "flag{utility}"
    hashes = client.post("/api/utilities", json={"operation": "hashes", "text": "abc"}).json()["hashes"]
    assert hashes["sha256"] == hashlib.sha256(b"abc").hexdigest()
    assert client.post("/api/utilities", json={"operation": "base64_decode", "text": "invalid!"}).status_code == 422
    assert client.post("/api/utilities", json={"operation": "xor", "text": "ABC", "key": "4b"}).json()["result"] == "0a0908"
    assert client.post("/api/utilities", json={"operation": "rot13", "text": "x" * 65537}).status_code == 422
