from contextlib import asynccontextmanager
import asyncio
import base64
import hashlib
import json
import re
import shutil
import time
from pathlib import Path
from urllib.parse import urlsplit
from typing import Literal

from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.responses import FileResponse, JSONResponse, Response
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field
from starlette.middleware.trustedhost import TrustedHostMiddleware

from . import __version__
from .config import Settings
from .store import CapacityError, Store, TERMINAL, atomic_json, read_json
from .utilities import transform
from .reporting import markdown_report


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
        request_limit = 400 * 1024 if scope['path'].endswith('/actions') or scope['path']=='/api/recipes' else 96 * 1024 if scope["path"] == "/api/utilities" else self.limit
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


class RecipeStep(BaseModel):
    operation: str = Field(max_length=40)
    key: str = Field(default='',max_length=512)
    shift: int = Field(default=13,ge=-100000,le=100000)


class RecipeInput(BaseModel):
    input: str = Field(max_length=131072)
    input_encoding: Literal['utf8','hex','base64'] = 'utf8'
    steps: list[RecipeStep] = Field(default_factory=list,max_length=20)


class LabAction(BaseModel):
    operation: Literal['inspect','image_prepare','image_lsb','audio_analyze','flag_scan','tool_extract','pdf_extract']
    artifact_id: str | None = Field(default=None,max_length=64)
    channels: str = Field(default='RGB',pattern=r'^[RGBA]{1,4}$')
    bits: list[int] = Field(default_factory=lambda:[0],min_length=1,max_length=8)
    bit_order: Literal['msb','lsb'] = 'msb'
    direction: Literal['row','column'] = 'row'
    reverse: bool = False
    frame: int = Field(default=0,ge=0,le=255)
    skip_bits: int = Field(default=0,ge=0,le=8000000)
    max_bytes: int = Field(default=65536,ge=1,le=1048576)
    prefixes: list[str] | None = Field(default=None,max_length=32)
    expression: str = Field(default='',max_length=256)
    tool: Literal['zsteg','steghide','stegseek','stegoveritas','outguess','openstego','stegsnow','stegdetect'] = 'steghide'
    password: str = Field(default='',max_length=256)
    passwords: list[str] = Field(default_factory=list,max_length=1000)
    attachment: int = Field(default=1,ge=1,le=100)


def create_app(settings: Settings | None = None):
    settings = settings or Settings()

    @asynccontextmanager
    async def lifespan(app):
        app.state.store = Store(settings)
        app.state.store.recover_uploads()
        app.state.store.index_missing_reports()
        for record in app.state.store.list(settings.max_jobs):
            if record['status'] in TERMINAL:
                (settings.jobs_dir/record['id']/'action.json').unlink(missing_ok=True)
        yield

    # Default Swagger/ReDoc pages load third-party CDN assets. Keep docs offline.
    app = FastAPI(title="StegoLab", version=__version__, lifespan=lifespan, docs_url=None, redoc_url=None)
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

    def source_file(job_id, artifact_id=None):
        record = get_job(job_id)
        if record['status'] not in TERMINAL:
            raise HTTPException(409,'Wait for the evidence job to finish')
        job_dir = settings.jobs_dir/job_id
        if artifact_id is None:
            return job_dir/'evidence'/'original.bin', record['filename'], None
        report = read_json(job_dir/'report.json',{})
        entry = next((a for a in report.get('artifacts',[]) if a['id']==artifact_id),None)
        if not entry: raise HTTPException(404,'Artifact not found')
        root = (job_dir/'artifacts').resolve()
        candidate = root/entry['path']
        path = candidate.resolve()
        if not path.is_relative_to(root) or candidate.is_symlink() or not path.is_file():
            raise HTTPException(404,'Artifact not found')
        return path, entry['name'], entry

    def enqueue_action(content, filename, options, parent_id=None):
        if len(content)>settings.max_file_bytes: raise HTTPException(413,'Source exceeds evidence size limit')
        try: job_id = store().reserve(filename,'deep',parent_id=parent_id)
        except CapacityError as exc: raise HTTPException(429,str(exc)) from exc
        root = settings.jobs_dir/job_id
        try:
            (root/'evidence').mkdir(parents=True)
            original = root/'evidence'/'original.bin'
            original.write_bytes(content); original.chmod(0o444)
            digest = hashlib.sha256(content).hexdigest()
            atomic_json(root/'upload.json',{'filename':filename,'sha256':digest,'size':len(content),'parent_id':parent_id})
            if parent_id: options['parent_job'] = parent_id
            atomic_json(root/'action.json',options)
            (root/'action.json').chmod(0o600)
            store().enqueue(job_id,len(content),digest)
        except BaseException:
            shutil.rmtree(root,ignore_errors=True); store().delete(job_id); raise
        return public_job(get_job(job_id))

    @app.post('/api/jobs/{job_id}/actions',status_code=202)
    def lab_action(job_id:str, data:LabAction):
        path,filename,_ = source_file(job_id,data.artifact_id)
        options = data.model_dump(exclude={'artifact_id'})
        if data.artifact_id:
            options['source_artifact_id'] = data.artifact_id
        if any(len(p.encode())>256 or '\n' in p or '\x00' in p for p in data.passwords):
            raise HTTPException(422,'Password candidates must contain at most 256 bytes and no NUL/newline')
        if '\x00' in data.password: raise HTTPException(422,'Password cannot contain NUL')
        try:
            content = path.read_bytes()
        except FileNotFoundError as exc:
            raise HTTPException(409, 'Source investigation was deleted; refresh the investigation list') from exc
        return enqueue_action(content,filename,options,parent_id=job_id)

    @app.post('/api/recipes',status_code=202)
    def recipe(data:RecipeInput):
        try:
            raw = base64.b64decode(data.input,validate=True) if data.input_encoding=='base64' else bytes.fromhex(data.input) if data.input_encoding=='hex' else data.input.encode('utf-8')
        except (ValueError,UnicodeError) as exc: raise HTTPException(422,f'Invalid input: {exc}') from exc
        if len(raw)>65536: raise HTTPException(413,'Recipe input exceeds 64 KiB')
        return enqueue_action(raw,'crypto-recipe.bin',{'operation':'crypto','recipe':data.model_dump(exclude={'input'})})

    @app.get('/api/recipes/operations')
    def recipe_operations():
        from .labs.crypto import OPERATIONS
        return {'operations':OPERATIONS,'limits':{'input_bytes':65536,'output_bytes':1048576,'steps':20}}

    @app.get('/api/jobs/{job_id}/bytes')
    def bytes_view(job_id:str, artifact_id:str|None=None, offset:int=Query(0,ge=0), length:int=Query(1024,ge=1,le=4096)):
        path,name,_ = source_file(job_id,artifact_id)
        with path.open('rb') as handle: handle.seek(offset); content=handle.read(length)
        return {'source':name,'size':path.stat().st_size,'offset':offset,'offset_hex':hex(offset),
                'hex':content.hex(),'ascii':''.join(chr(b) if 32<=b<127 else '.' for b in content),
                'bytes':list(content),'next_offset':offset+len(content)}

    @app.get('/api/jobs/{job_id}/preview/{artifact_id}')
    def preview(job_id:str,artifact_id:str):
        path,name,entry = source_file(job_id,artifact_id)
        if not entry.get('preview') or entry['media_type'] not in {'image/png','audio/wav'}:
            raise HTTPException(415,'Only worker-generated sanitized previews may render inline')
        return FileResponse(path,media_type=entry['media_type'])

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

    @app.get('/api/flags')
    def flags(query: str = Query('', max_length=256),
              classification: Literal['all', 'confirmed_pattern_match', 'heuristic_candidate'] = 'all',
              limit: int = Query(100, ge=1, le=100), offset: int = Query(0, ge=0)):
        return store().flags(query, classification, limit, offset)

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
        record = store().cancel(job_id)
        if record['status']=='cancelled':
            (settings.jobs_dir/job_id/'action.json').unlink(missing_ok=True)
            (settings.jobs_dir/job_id/'supplied-wordlist.txt').unlink(missing_ok=True)
        return public_job(record)

    @app.delete("/api/jobs/{job_id}", status_code=204)
    def delete(job_id: str):
        get_job(job_id)
        try:
            store().delete_finished(job_id)
        except ValueError as exc:
            raise HTTPException(409, str(exc)) from exc

    @app.get("/api/jobs/{job_id}/report")
    def report(job_id: str, download: bool = False, format: Literal['json', 'markdown'] = 'json'):
        record = get_job(job_id)
        if record["status"] not in TERMINAL:
            raise HTTPException(409, "Report is not ready")
        path = settings.jobs_dir / job_id / "report.json"
        data = read_json(path)
        if data is None:
            raise HTTPException(404, "No report was generated")
        if format == 'markdown':
            headers = {'Content-Disposition': f'attachment; filename="stegolab-{job_id}.md"'} if download else {}
            return Response(markdown_report(data, record), media_type='text/markdown', headers=headers)
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

    @app.get("/docs", include_in_schema=False)
    def api_docs():
        return FileResponse(static / "api.html", media_type="text/html")

    app.mount("/static", StaticFiles(directory=static, check_dir=False), name="frontend")
    return app


app = create_app()
