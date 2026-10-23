"""SQLite queue shared by the API and the network-isolated worker."""
from contextlib import contextmanager
from datetime import datetime, timezone
import json
from pathlib import Path
import shutil
import sqlite3
import uuid

from .config import Settings

TERMINAL = {"completed", "failed", "cancelled", "timeout"}


def now():
    return datetime.now(timezone.utc).isoformat()


def atomic_json(path: Path, data):
    temp = path.with_suffix(path.suffix + ".tmp")
    temp.write_text(json.dumps(data, ensure_ascii=True), encoding="utf-8")
    temp.replace(path)


def read_json(path: Path, default=None):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return default


class CapacityError(Exception):
    pass


class Store:
    def __init__(self, settings: Settings):
        self.settings = settings
        self.root = settings.data_dir
        self.root.mkdir(parents=True, exist_ok=True)
        settings.jobs_dir.mkdir(exist_ok=True)
        with self.connect() as db:
            db.execute("PRAGMA journal_mode=WAL")
            db.executescript("""
                CREATE TABLE IF NOT EXISTS jobs (
                    id TEXT PRIMARY KEY, filename TEXT NOT NULL, mode TEXT NOT NULL,
                    status TEXT NOT NULL, size INTEGER NOT NULL DEFAULT 0,
                    sha256 TEXT, created_at TEXT NOT NULL, started_at TEXT,
                    completed_at TEXT, error TEXT, cancel_requested INTEGER NOT NULL DEFAULT 0,
                    reserved_bytes INTEGER NOT NULL
                );
                CREATE TABLE IF NOT EXISTS worker_state (id INTEGER PRIMARY KEY, heartbeat REAL NOT NULL);
                CREATE TABLE IF NOT EXISTS flag_index_jobs (job_id TEXT PRIMARY KEY);
                CREATE TABLE IF NOT EXISTS flag_index (
                    job_id TEXT NOT NULL, ordinal INTEGER NOT NULL,
                    classification TEXT NOT NULL, search_text TEXT NOT NULL,
                    candidate_json TEXT NOT NULL, PRIMARY KEY(job_id,ordinal)
                );
                CREATE INDEX IF NOT EXISTS flag_classification ON flag_index(classification);
            """)
            db.execute('BEGIN IMMEDIATE')
            if 'parent_id' not in {row[1] for row in db.execute('PRAGMA table_info(jobs)')}:
                db.execute('ALTER TABLE jobs ADD COLUMN parent_id TEXT')

    @contextmanager
    def connect(self):
        db = sqlite3.connect(self.root / "state.sqlite", timeout=10)
        db.row_factory = sqlite3.Row
        try:
            yield db
            db.commit()
        except Exception:
            db.rollback()
            raise
        finally:
            db.close()

    def reserve(self, filename, mode, parent_id=None):
        settings = self.settings
        with self.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            total, reserved, pending = db.execute("""SELECT COUNT(*), COALESCE(SUM(reserved_bytes),0),
                COALESCE(SUM(CASE WHEN status IN ('uploading','queued','running') THEN 1 ELSE 0 END),0)
                FROM jobs""").fetchone()
            if total >= settings.max_jobs or pending >= settings.max_pending:
                raise CapacityError("Job capacity reached. Delete finished jobs or wait for the queue.")
            if reserved + settings.reservation_bytes > settings.max_storage_bytes:
                raise CapacityError("Storage budget reached. Delete finished jobs before uploading.")
            if parent_id:
                parent = db.execute('SELECT status FROM jobs WHERE id=?', (parent_id,)).fetchone()
                if not parent or parent['status'] not in TERMINAL:
                    raise CapacityError('Source investigation is no longer available; refresh the investigation list')
            job_id = uuid.uuid4().hex
            db.execute("INSERT INTO jobs(id,filename,mode,status,created_at,reserved_bytes,parent_id) VALUES(?,?,?,?,?,?,?)",
                       (job_id, filename, mode, "uploading", now(), settings.reservation_bytes, parent_id))
        return job_id

    def enqueue(self, job_id, size, sha256):
        with self.connect() as db:
            db.execute("""UPDATE jobs SET status=CASE WHEN cancel_requested=1 THEN 'cancelled' ELSE 'queued' END,
                       completed_at=CASE WHEN cancel_requested=1 THEN ? ELSE NULL END,size=?,sha256=?
                       WHERE id=? AND status='uploading'""", (now(), size, sha256, job_id))

    def get(self, job_id):
        with self.connect() as db:
            row = db.execute("SELECT * FROM jobs WHERE id=?", (job_id,)).fetchone()
        return dict(row) if row else None

    def list(self, limit=100, offset=0):
        with self.connect() as db:
            return [dict(row) for row in db.execute("SELECT * FROM jobs ORDER BY created_at DESC LIMIT ? OFFSET ?", (limit, offset))]

    def claim(self):
        with self.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute("SELECT * FROM jobs WHERE status='queued' AND cancel_requested=0 ORDER BY created_at LIMIT 1").fetchone()
            if not row:
                return None
            db.execute("UPDATE jobs SET status='running',started_at=? WHERE id=?", (now(), row["id"]))
        return self.get(row["id"])

    def finish(self, job_id, status, error=None):
        if status not in TERMINAL:
            raise ValueError("Invalid terminal status")
        with self.connect() as db:
            db.execute("UPDATE jobs SET status=?,completed_at=?,error=? WHERE id=?", (status, now(), error, job_id))
            self._index_flags(db, job_id)

    def cancel(self, job_id):
        with self.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute("SELECT status FROM jobs WHERE id=?", (job_id,)).fetchone()
            if row and row["status"] not in TERMINAL:
                db.execute("UPDATE jobs SET cancel_requested=1 WHERE id=?", (job_id,))
                if row["status"] == "queued":
                    db.execute("UPDATE jobs SET status='cancelled',completed_at=? WHERE id=?", (now(), job_id))
        return self.get(job_id)

    def delete(self, job_id):
        with self.connect() as db:
            db.execute('DELETE FROM flag_index WHERE job_id=?', (job_id,))
            db.execute('DELETE FROM flag_index_jobs WHERE job_id=?', (job_id,))
            db.execute("DELETE FROM jobs WHERE id=?", (job_id,))

    def delete_finished(self, job_id):
        """Serialize evidence deletion with child-action admission."""
        with self.connect() as db:
            db.execute('BEGIN IMMEDIATE')
            job = db.execute('SELECT status FROM jobs WHERE id=?', (job_id,)).fetchone()
            if not job:
                return
            if job['status'] not in TERMINAL:
                raise ValueError('Cancel the active job and wait for it to finish before deleting')
            children = db.execute("SELECT COUNT(*) FROM jobs WHERE parent_id=? AND status IN ('uploading','queued','running')", (job_id,)).fetchone()[0]
            if children:
                raise ValueError('This evidence is referenced by an active lab action; finish or cancel it first')
            try:
                shutil.rmtree(self.settings.jobs_dir / job_id)
            except FileNotFoundError:
                pass  # A missing directory must not leave undeletable stale history.
            db.execute('DELETE FROM flag_index WHERE job_id=?', (job_id,))
            db.execute('DELETE FROM flag_index_jobs WHERE job_id=?', (job_id,))
            db.execute('DELETE FROM jobs WHERE id=?', (job_id,))

    def _index_flags(self, db, job_id):
        from .reporting import flag_candidates
        report = read_json(self.settings.jobs_dir / job_id / 'report.json', {})
        candidates = flag_candidates(report)[:500]
        db.execute('DELETE FROM flag_index WHERE job_id=?', (job_id,))
        for index, candidate in enumerate(candidates):
            search = ' '.join(str(candidate.get(key, '')) for key in ('value', 'source_file', 'method', 'evidence'))
            db.execute('INSERT INTO flag_index VALUES(?,?,?,?,?)',
                       (job_id, index, candidate['classification'], search, json.dumps(candidate, ensure_ascii=True)))
        db.execute('INSERT OR IGNORE INTO flag_index_jobs VALUES(?)', (job_id,))

    def index_missing_reports(self):
        """One-time migration of terminal reports from earlier StegoLab releases."""
        with self.connect() as db:
            ids = [row[0] for row in db.execute("SELECT id FROM jobs WHERE status IN ('completed','failed','cancelled','timeout') AND id NOT IN (SELECT job_id FROM flag_index_jobs)")]
        for job_id in ids:
            with self.connect() as db:
                db.execute('BEGIN IMMEDIATE')
                if db.execute('SELECT id FROM jobs WHERE id=?', (job_id,)).fetchone():
                    self._index_flags(db, job_id)

    def flags(self, query='', classification='all', limit=100, offset=0):
        condition = "j.status IN ('completed','failed','cancelled','timeout')"
        parameters = []
        if query:
            condition += ' AND instr(lower(f.search_text || ? || j.filename), lower(?)) > 0'
            parameters.extend([' ', query])
        if classification != 'all':
            condition += ' AND f.classification=?'
            parameters.append(classification)
        base = ' FROM flag_index f JOIN jobs j ON j.id=f.job_id WHERE ' + condition
        with self.connect() as db:
            total = db.execute('SELECT COUNT(*)' + base, parameters).fetchone()[0]
            rows = db.execute('SELECT f.candidate_json,j.id,j.filename,j.status,j.created_at' + base +
                              ' ORDER BY j.created_at DESC,f.ordinal LIMIT ? OFFSET ?', (*parameters, limit, offset)).fetchall()
        candidates = [{**json.loads(row['candidate_json']), 'job_id': row['id'], 'job_filename': row['filename'],
                       'job_status': row['status'], 'created_at': row['created_at']} for row in rows]
        return {'candidates': candidates, 'total': total, 'limit': limit, 'offset': offset}

    def active_children(self, job_id):
        with self.connect() as db:
            return db.execute("SELECT COUNT(*) FROM jobs WHERE parent_id=? AND status IN ('uploading','queued','running')", (job_id,)).fetchone()[0]

    def recover(self):
        with self.connect() as db:
            interrupted = [dict(row) for row in db.execute("SELECT * FROM jobs WHERE status='running'")]
            db.execute("UPDATE jobs SET status='failed',completed_at=?,error='Worker interrupted; submit a new scan' WHERE status='running'", (now(),))
            # Upload requests live only in the API and may be in progress during a worker restart.
        return interrupted

    def recover_uploads(self):
        with self.connect() as db:
            db.execute("UPDATE jobs SET status='failed',completed_at=?,error='API interrupted during upload; submit a new scan' WHERE status='uploading'", (now(),))

    def heartbeat(self, timestamp):
        with self.connect() as db:
            db.execute("INSERT OR REPLACE INTO worker_state VALUES(1,?)", (timestamp,))

    def heartbeat_time(self):
        with self.connect() as db:
            row = db.execute("SELECT heartbeat FROM worker_state WHERE id=1").fetchone()
        return row[0] if row else 0
