"""Single supervisor, bounded subprocess jobs, shared SQLite queue; no network needed."""
import logging
import os
from pathlib import Path
import signal
import subprocess
import sys
import time

from .config import Settings
from .store import Store, atomic_json, now, read_json

log = logging.getLogger("stegolab.worker")


def process_limits(settings, timeout):
    import resource
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    resource.setrlimit(resource.RLIMIT_AS, (settings.memory_mb * 1024**2,) * 2)
    resource.setrlimit(resource.RLIMIT_CPU, (timeout, timeout + 1))
    resource.setrlimit(resource.RLIMIT_FSIZE, (80 * 1024**2,) * 2)
    resource.setrlimit(resource.RLIMIT_NOFILE, (128, 128))
    os.umask(0o077)


def kill_group(proc):
    try:
        os.killpg(proc.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    proc.wait(timeout=5)


def failure_report(job_dir, job, status, error):
    for secret_file in ('action.json', 'supplied-wordlist.txt'):
        (job_dir / secret_file).unlink(missing_ok=True)
    # Retain any completed analyzer results, while clearly marking partial execution.
    report = read_json(job_dir / "report.json", {})
    report.update(schema_version="1.0", job_id=job["id"], mode=job["mode"], status=status,
                  started_at=job["started_at"], completed_at=now())
    report.setdefault("file", {"filename": job["filename"], "size": job["size"], "sha256": job["sha256"]})
    for key in ("analyzers", "findings", "artifacts", "recommendations", "errors"):
        report.setdefault(key, [])
    report["errors"].append(error)
    atomic_json(job_dir / "report.json", report)


def main():
    if os.name != "posix":
        raise SystemExit("The restricted worker requires Linux. Run it through Docker Compose.")
    import fcntl
    settings = Settings()
    settings.data_dir.mkdir(parents=True, exist_ok=True)
    lock = (settings.data_dir / "worker.lock").open("w")
    try:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        raise SystemExit("Only one supervisor per data volume is supported")
    store = Store(settings)
    for interrupted in store.recover():
        failure_report(settings.jobs_dir / interrupted["id"], interrupted, "failed", "Worker interrupted; submit a new scan")
    running, stopping = {}, False

    def stop(signum, frame):
        nonlocal stopping
        stopping = True

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    from .analysis.tools import registry_snapshot
    atomic_json(settings.data_dir / "tools.json", registry_snapshot())
    try:
        while not stopping:
            store.heartbeat(time.time())
            for job_id, item in list(running.items()):
                proc, started, timeout, job = item
                current = store.get(job_id)
                status, error = None, None
                if current["cancel_requested"]:
                    status, error = "cancelled", "Analysis cancelled by the user"
                elif time.monotonic() - started >= timeout:
                    status, error = "timeout", f"Job exceeded its {timeout}s wall-clock limit"
                elif proc.poll() is not None:
                    report = read_json(settings.jobs_dir / job_id / "report.json")
                    if proc.returncode == 0 and report and report.get("status") == "completed":
                        status = "completed"
                    elif proc.returncode == -signal.SIGXCPU:
                        status, error = "timeout", "Job exceeded its CPU time limit"
                    else:
                        status, error = "failed", f"Analyzer exited with code {proc.returncode}; see analyzer errors in the report"
                if status:
                    kill_group(proc)
                    if error:
                        failure_report(settings.jobs_dir / job_id, job, status, error)
                    store.finish(job_id, status, error)
                    del running[job_id]
            while len(running) < settings.concurrency and not stopping:
                job = store.claim()
                if not job:
                    break
                timeout = settings.deep_timeout if job["mode"] == "deep" else settings.quick_timeout
                job_dir = settings.jobs_dir / job["id"]
                # Only fixed executable/module and server-generated paths become argv.
                env = {"PATH": os.environ.get("PATH", "/usr/local/bin:/usr/bin:/bin"),
                       "HOME": str(job_dir), "TMPDIR": "/tmp", "LANG": "C.UTF-8",
                       "PYTHONPATH": str(Path(__file__).resolve().parent.parent),
                       "STEGOLAB_TOOL_REGISTRY": str(settings.data_dir / "tools.json"),
                       "STEGOLAB_MAX_FILE_BYTES": str(settings.max_file_bytes),
                       "PYTHONDONTWRITEBYTECODE": "1", "OMP_NUM_THREADS": "1",
                       "MAGICK_THREAD_LIMIT": "1", "MAGICK_MEMORY_LIMIT": "128MiB",
                       "MAGICK_MAP_LIMIT": "128MiB", "MAGICK_DISK_LIMIT": "64MiB"}
                try:
                    proc = subprocess.Popen([sys.executable, "-m", "stegolab.analyze", str(job_dir), job["mode"]],
                                            cwd=job_dir, env=env, stdin=subprocess.DEVNULL,
                                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                            start_new_session=True,
                                            preexec_fn=lambda: process_limits(settings, timeout))
                    running[job["id"]] = (proc, time.monotonic(), timeout, job)
                except Exception as exc:
                    error = f"Could not start analyzer: {exc}"
                    failure_report(job_dir, job, "failed", error)
                    store.finish(job["id"], "failed", error)
            time.sleep(0.25)
    finally:
        for job_id, (proc, _, _, job) in running.items():
            kill_group(proc)
            failure_report(settings.jobs_dir / job_id, job, "failed", "Worker stopped during analysis")
            store.finish(job_id, "failed", "Worker stopped during analysis")
        store.heartbeat(0)


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    main()
