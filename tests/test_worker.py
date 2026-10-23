"""Real Linux subprocess lifecycle tests (run in the provided Docker test image)."""
from __future__ import annotations

from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time

import pytest
from fastapi.testclient import TestClient

from stegolab.app import create_app
from stegolab.config import Settings
from stegolab.store import Store, atomic_json, read_json

pytestmark = pytest.mark.skipif(sys.platform != "linux", reason="Restricted worker requires Linux; run Docker tests")


def wait_for(predicate, *, seconds=12, description="condition"):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        value = predicate()
        if value:
            return value
        time.sleep(0.025)
    raise AssertionError(f"Timed out waiting for {description}")


@contextmanager
def worker(settings: Settings, tool_path=''):
    env = dict(os.environ)
    env.update({
        "STEGOLAB_DATA_DIR": str(settings.data_dir),
        "STEGOLAB_CONCURRENCY": str(settings.concurrency),
        "STEGOLAB_QUICK_TIMEOUT": str(settings.quick_timeout),
        "STEGOLAB_DEEP_TIMEOUT": str(settings.deep_timeout),
        "STEGOLAB_JOB_MEMORY_MB": str(settings.memory_mb),
        "STEGOLAB_MAX_FILE_MB": str(settings.max_file_bytes // (1024 * 1024)),
        "PATH": tool_path,  # Default tests exercise native analyzers with optional tools absent.
        "PYTHONPATH": str(Path(__file__).resolve().parents[1]),
    })
    settings.data_dir.mkdir(parents=True, exist_ok=True)
    store = Store(settings)
    with tempfile.TemporaryFile() as output:
        process = subprocess.Popen([sys.executable, "-m", "stegolab.worker"], env=env,
                                   cwd=Path(__file__).resolve().parents[1], stdout=output, stderr=output)
        try:
            wait_for(lambda: store.heartbeat_time() > 0 or process.poll() is not None, description="worker startup")
            if process.poll() is not None:
                output.seek(0)
                pytest.fail(f"Worker exited during startup: {output.read().decode(errors='replace')}")
            yield process, store
        finally:
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=8)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=5)
            output.seek(0)
            logs = output.read().decode(errors="replace")
            assert process.returncode == 0, logs


def enqueue(store: Store, value: bytes, filename="evidence.bin", mode="quick"):
    job_id = store.reserve(filename, mode)
    root = store.settings.jobs_dir / job_id
    evidence = root / "evidence"
    evidence.mkdir(parents=True)
    original = evidence / "original.bin"
    original.write_bytes(value)
    original.chmod(0o444)
    digest = hashlib.sha256(value).hexdigest()
    atomic_json(root / "upload.json", {"filename": filename, "size": len(value), "sha256": digest})
    store.enqueue(job_id, len(value), digest)
    return job_id


def terminal(store, job_id):
    row = store.get(job_id)
    return row if row["status"] in {"completed", "failed", "cancelled", "timeout"} else None


def slow_evidence():
    # Real bounded candidate scanning under CPU pressure. The closing delimiter
    # prevents the scanner's valid fast path for data with no complete candidate.
    # No uploaded programs or test-only executables are run, even with /tmp noexec.
    return b"flag{" * (6 * 1024 * 1024) + b"}"


def test_api_worker_report_artifact_and_delete_complete_flow(tmp_path: Path, corpus):
    settings = Settings(data_dir=tmp_path / "data", concurrency=1, quick_timeout=20, deep_timeout=30)
    app = create_app(settings)
    with TestClient(app) as client, worker(settings):
        value = corpus["image.png"].read_bytes()
        response = client.post("/api/jobs", files={"file": ("challenge.png", value)}, data={"mode": "deep"})
        assert response.status_code == 202
        job_id = response.json()["id"]
        result = wait_for(lambda: terminal(app.state.store, job_id), seconds=20, description="real nested archive scan")
        assert result["status"] == "completed", result
        report = client.get(f"/api/jobs/{job_id}/report").json()
        assert report["file"]["sha256"] == hashlib.sha256(value).hexdigest()
        assert "CTF{nested_zip_flag}" in {finding.get("value") for finding in report["findings"]}
        artifact = next(artifact for artifact in report["artifacts"] if artifact["name"] == "answer.txt")
        download = client.get(f"/api/jobs/{job_id}/artifacts/{artifact['id']}")
        assert download.status_code == 200
        assert b"CTF{nested_zip_flag}" in download.content
        assert client.delete(f"/api/jobs/{job_id}").status_code == 204
        assert client.get(f"/api/jobs/{job_id}").status_code == 404
        assert not (settings.jobs_dir / job_id).exists()


def test_running_cancel_and_bounded_concurrency_preserve_originals(tmp_path: Path):
    settings = Settings(data_dir=tmp_path / "data", concurrency=1, quick_timeout=30, memory_mb=512)
    value = slow_evidence()
    with worker(settings) as (process, store):
        first = enqueue(store, value)
        second = enqueue(store, value)
        wait_for(lambda: store.get(first)["status"] == "running", description="first scan running")
        assert store.get(second)["status"] == "queued"
        assert len([job for job in store.list() if job["status"] == "running"]) == 1
        children = Path(f"/proc/{process.pid}/task/{process.pid}/children")
        child_ids = wait_for(lambda: children.read_text().split(), description="restricted analyzer child")
        assert len(child_ids) == 1
        # /proc exposes the fork before Popen's preexec limits and exec finish.
        # Wait for the analyzer module, rather than inspecting that transient fork.
        child_proc = Path(f"/proc/{child_ids[0]}")
        wait_for(lambda: b"stegolab.analyze" in (child_proc / "cmdline").read_bytes(),
                 description="analyzer exec after resource limits")
        child_limits = (child_proc / "limits").read_text()
        address_limit = next(line for line in child_limits.splitlines() if line.startswith("Max address space"))
        assert str(512 * 1024 * 1024) in address_limit
        cpu_limit = next(line for line in child_limits.splitlines() if line.startswith("Max cpu time"))
        assert "30" in cpu_limit
        store.cancel(first)
        cancelled = wait_for(lambda: terminal(store, first), description="running cancellation")
        assert cancelled["status"] == "cancelled"
        wait_for(lambda: store.get(second)["status"] == "running", description="next queued scan")
        store.cancel(second)
        assert wait_for(lambda: terminal(store, second))["status"] == "cancelled"
        for job_id in (first, second):
            report = read_json(settings.jobs_dir / job_id / "report.json")
            assert report["status"] == "cancelled"
            assert any("cancelled" in error.lower() for error in report["errors"])
            assert (settings.jobs_dir / job_id / "evidence" / "original.bin").read_bytes() == value


def test_wall_or_cpu_timeout_reports_terminal_status_and_worker_survives(tmp_path: Path):
    settings = Settings(data_dir=tmp_path / "data", concurrency=1, quick_timeout=1, deep_timeout=15, memory_mb=512)
    with worker(settings) as (_, store):
        job_id = enqueue(store, slow_evidence())
        result = wait_for(lambda: terminal(store, job_id), seconds=8, description="real analyzer timeout")
        assert result["status"] == "timeout", result
        report = read_json(settings.jobs_dir / job_id / "report.json")
        assert report["status"] == "timeout"
        assert report["errors"]
        # Give the recovery assertion its own ordinary budget: a 1s deadline
        # measures interpreter startup under CI contention rather than recovery.
        following = enqueue(store, b"flag{worker_still_operates}", mode="deep")
        result = wait_for(lambda: terminal(store, following), seconds=18, description="scan after timeout")
        assert result["status"] == "completed", result


def test_graceful_worker_shutdown_marks_active_job_failed(tmp_path: Path):
    settings = Settings(data_dir=tmp_path / "data", concurrency=1, quick_timeout=30, memory_mb=512)
    with worker(settings) as (process, store):
        job_id = enqueue(store, slow_evidence())
        wait_for(lambda: store.get(job_id)["status"] == "running", description="active job before shutdown")
        process.terminate()
        process.wait(timeout=8)
        assert store.get(job_id)["status"] == "failed"
        assert read_json(settings.jobs_dir / job_id / "report.json")["status"] == "failed"
        assert store.heartbeat_time() == 0
