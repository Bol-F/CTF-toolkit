from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest

from stegolab.config import Settings
from stegolab.store import CapacityError, Store


def test_cancel_during_upload_cannot_leave_an_unclaimable_queue_entry(tmp_path: Path):
    store = Store(Settings(data_dir=tmp_path, max_pending=1))
    job_id = store.reserve("evidence.bin", "quick")
    store.cancel(job_id)
    store.enqueue(job_id, 12, "a" * 64)
    assert store.get(job_id)["status"] == "cancelled"
    assert store.claim() is None
    assert store.reserve("next.bin", "quick") != job_id


def test_concurrent_claims_never_run_the_same_job_twice(tmp_path: Path):
    store = Store(Settings(data_dir=tmp_path))
    ids = [store.reserve(f"file-{index}", "quick") for index in range(4)]
    for job_id in ids:
        store.enqueue(job_id, 1, "a" * 64)
    with ThreadPoolExecutor(max_workers=8) as threads:
        results = list(threads.map(lambda _: store.claim(), range(8)))
    claimed = [result["id"] for result in results if result]
    assert sorted(claimed) == sorted(ids)
    assert len(set(claimed)) == 4


def test_storage_and_job_reservations_bound_concurrent_uploads(tmp_path: Path):
    settings = Settings(data_dir=tmp_path, max_file_bytes=1024, max_storage_bytes=90 * 1024 * 1024)
    store = Store(settings)
    job = store.reserve("first", "quick")
    with pytest.raises(CapacityError, match="Storage"):
        store.reserve("second", "quick")
    store.delete(job)
    assert store.reserve("second", "quick")


def test_worker_restart_marks_interrupted_jobs_failed_and_preserves_queued(tmp_path: Path):
    store = Store(Settings(data_dir=tmp_path))
    running = store.reserve("running", "quick")
    queued = store.reserve("queued", "deep")
    store.enqueue(running, 1, "a" * 64)
    store.enqueue(queued, 1, "b" * 64)
    assert store.claim()["id"] == running
    store.recover()
    assert store.get(running)["status"] == "failed"
    assert "interrupted" in store.get(running)["error"]
    assert store.get(queued)["status"] == "queued"
