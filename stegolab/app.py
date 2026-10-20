from contextlib import asynccontextmanager
import asyncio
import hashlib
import json
import re
import shutil
import time
from pathlib import Path
from urllib.parse import urlsplit

from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field
from starlette.middleware.trustedhost import TrustedHostMiddleware

from . import __version__
from .config import Settings
from .store import CapacityError, Store, TERMINAL, atomic_json, read_json
from .utilities import transform


class BodyTooLarge(Exception):
    pass


class RequestGuard:
    """Bound bytes before multipart parsing, and reject cross-origin mutation."""
    def __init__(self, app, limit):
        self.app, self.limit = app, limit
        self.upload_slots = asyncio.Semaphore(2)

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)
        headers = dict(scope["headers"])
        if scope["method"] in {"POST", "DELETE", "PUT", "PATCH"}:
            origin = headers.get(b"origin", b"").decode("latin1")
            host = headers.get(b"host", b"").decode("latin1")
            try:
                parsed_origin = urlsplit(origin)
                bad_origin = origin and (parsed_origin.netloc != host or parsed_origin.scheme not in {"http", "https"})
            except ValueError:
                bad_origin = True
            if bad_origin:
                return await JSONResponse({"detail": "Cross-origin writes are not allowed"}, 403)(scope, receive, send)
        try:
            length = int(headers.get(b"content-length", b"0"))
        except ValueError:
            return await JSONResponse({"detail": "Invalid content length"}, 400)(scope, receive, send)
        request_limit = 96 * 1024 if scope["path"] == "/api/utilities" else self.limit
        if length > request_limit:
            return await JSONResponse({"detail": "Request exceeds upload limit"}, 413)(scope, receive, send)
        count = 0

        async def bounded_receive():
            nonlocal count
            message = await receive()
            count += len(message.get("body", b""))
            if count > request_limit:
                raise BodyTooLarge()
            return message

        async def safe_send(message):
            if message["type"] == "http.response.start":
                message.setdefault("headers", []).extend([
                    (b"x-content-type-options", b"nosniff"),
                    (b"x-frame-options", b"DENY"),
                    (b"referrer-policy", b"no-referrer"),
                    (b"content-security-policy", b"default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'"),
                    (b"cache-control", b"no-store"),
                ])
            await send(message)

        try:
            if scope["method"] == "POST" and scope["path"] == "/api/jobs":
                if self.upload_slots.locked():
                    return await JSONResponse({"detail": "Upload capacity reached; retry shortly"}, 429)(scope, receive, safe_send)
                async with self.upload_slots:
                    await self.app(scope, bounded_receive, safe_send)
            else:
                await self.app(scope, bounded_receive, safe_send)
        except BodyTooLarge:
            await JSONResponse({"detail": "Request exceeds upload limit"}, 413)(scope, receive, safe_send)


class UtilityInput(BaseModel):
    operation: str = Field(max_length=40)
    text: str = Field(max_length=65536)
    key: str = Field(default="", max_length=512)


def create_app(settings: Settings | None = None):
    settings = settings or Settings()

    @asynccontextmanager
    async def lifespan(app):
        app.state.store = Store(settings)
        app.state.store.recover_uploads()
        yield

    app = FastAPI(title="StegoLab", version=__version__, lifespan=lifespan)
    app.state.settings = settings
    app.add_middleware(RequestGuard, limit=settings.max_file_bytes + 1024 * 1024)
    app.add_middleware(TrustedHostMiddleware, allowed_hosts=list(settings.allowed_hosts))

    def store():
        return app.state.store

    def get_job(job_id):
        if not re.fullmatch(r"[a-f0-9]{32}", job_id):
            raise HTTPException(404, "Job not found")
        job = store().get(job_id)
        if not job:
            raise HTTPException(404, "Job not found")
        return job

    def public_job(job):
        job = dict(job)
        progress = read_json(settings.jobs_dir / job["id"] / "progress.json", {})
        job.update(progress=progress.get("progress", 0), stage=progress.get("stage", job["status"]))
        if job["status"] in TERMINAL:
            job["stage"] = job["status"]
            if job["status"] == "completed":
                job["progress"] = 100
        job.pop("reserved_bytes", None)
        return job

    @app.get("/api/health")
    def health():
        beat = store().heartbeat_time()
        return {"status": "ok", "version": __version__, "worker": {"online": time.time() - beat < 15, "heartbeat": beat},
                "limits": {"max_file_bytes": settings.max_file_bytes, "max_pending": settings.max_pending,
                           "max_storage_bytes": settings.max_storage_bytes, "concurrency": settings.concurrency,
                           "quick_timeout": settings.quick_timeout, "deep_timeout": settings.deep_timeout}}

    @app.get("/api/tools")
    def tools():
        snapshot = read_json(settings.data_dir / "tools.json")
        if snapshot is None:
            return {"tools": [], "status": "pending", "message": "Waiting for worker tool discovery"}
        return {"tools": snapshot if isinstance(snapshot, list) else snapshot.get("tools", [])}

    @app.get("/api/jobs")
    def jobs(limit: int = Query(100, ge=1, le=100), offset: int = Query(0, ge=0)):
        return {"jobs": [public_job(j) for j in store().list(limit, offset)]}

    @app.post("/api/jobs", status_code=202)
    async def upload(request: Request):
        # Explicit parser limits also cap multipart fields and number of uploads.
        async with request.form(max_files=1, max_fields=1, max_part_size=1024) as form:
            file = form.get("file")
            mode = form.get("mode", "quick")
            if not isinstance(mode, str) or mode not in {"quick", "deep"}:
                raise HTTPException(422, "Mode must be quick or deep")
            if not hasattr(file, "read") or not hasattr(file, "filename"):
                raise HTTPException(422, "Upload one file using the file field")
            filename = re.sub(r"[\x00-\x1f\x7f]", "_", str(file.filename or "evidence.bin").replace("\\", "/").split("/")[-1])[:180] or "evidence.bin"
            try:
                job_id = store().reserve(filename, mode)
            except CapacityError as exc:
                raise HTTPException(429, str(exc)) from exc
            job_dir = settings.jobs_dir / job_id
            size, digest = 0, hashlib.sha256()
            try:
                evidence_dir = job_dir / "evidence"
                evidence_dir.mkdir(parents=True)
                evidence = evidence_dir / "original.bin"
                with evidence.open("xb") as output:
                    while chunk := await file.read(65536):
                        size += len(chunk)
                        if size > settings.max_file_bytes:
                            raise HTTPException(413, "File exceeds upload limit")
                        digest.update(chunk)
                        output.write(chunk)
                if size == 0:
                    raise HTTPException(422, "Empty evidence files are not supported")
                evidence.chmod(0o444)
                atomic_json(job_dir / "upload.json", {"filename": filename, "size": size, "sha256": digest.hexdigest()})
                store().enqueue(job_id, size, digest.hexdigest())
            except BaseException:
                shutil.rmtree(job_dir, ignore_errors=True)
                store().delete(job_id)
                raise
        return public_job(get_job(job_id))

    @app.get("/api/jobs/{job_id}")
    def job(job_id: str):
        return public_job(get_job(job_id))

    @app.post("/api/jobs/{job_id}/cancel")
    def cancel(job_id: str):
        get_job(job_id)
        return public_job(store().cancel(job_id))

    @app.delete("/api/jobs/{job_id}", status_code=204)
    def delete(job_id: str):
        record = get_job(job_id)
        if record["status"] not in TERMINAL:
            raise HTTPException(409, "Cancel the active job and wait for it to finish before deleting")
        shutil.rmtree(settings.jobs_dir / job_id)
        store().delete(job_id)

    @app.get("/api/jobs/{job_id}/report")
    def report(job_id: str, download: bool = False):
        record = get_job(job_id)
        if record["status"] not in TERMINAL:
            raise HTTPException(409, "Report is not ready")
        path = settings.jobs_dir / job_id / "report.json"
        data = read_json(path)
        if data is None:
            raise HTTPException(404, "No report was generated")
        if download:
            return FileResponse(path, media_type="application/json", filename=f"stegolab-{job_id}.json")
        return data

    @app.get("/api/jobs/{job_id}/artifacts/{artifact_id}")
    def artifact(job_id: str, artifact_id: str):
        record = get_job(job_id)
        if record["status"] not in TERMINAL:
            raise HTTPException(409, "Artifacts are available after the job finishes")
        job_dir = settings.jobs_dir / job_id
        data = read_json(job_dir / "report.json", {})
        entry = next((a for a in data.get("artifacts", []) if str(a.get("id")) == artifact_id), None)
        if not entry:
            raise HTTPException(404, "Artifact not found")
        root = (job_dir / "artifacts").resolve()
        candidate = root / entry["path"]
        path = candidate.resolve()
        if not path.is_relative_to(root) or candidate.is_symlink() or not path.is_file():
            raise HTTPException(404, "Artifact not found")
        return FileResponse(path, media_type="application/octet-stream", filename=Path(entry.get("name", path.name)).name)

    @app.post("/api/utilities")
    def utilities(data: UtilityInput):
        try:
            return transform(data.operation, data.text, data.key)
        except ValueError as exc:
            raise HTTPException(422, str(exc)) from exc

    static = Path(__file__).parent / "static"
    @app.get("/", include_in_schema=False)
    def index():
        return FileResponse(static / "index.html", media_type="text/html")

    app.mount("/static", StaticFiles(directory=static, check_dir=False), name="frontend")
    return app


app = create_app()
