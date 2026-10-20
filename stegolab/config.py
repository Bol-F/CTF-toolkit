from dataclasses import dataclass, field
from pathlib import Path
import os


@dataclass(frozen=True)
class Settings:
    data_dir: Path = field(default_factory=lambda: Path(os.getenv("STEGOLAB_DATA_DIR", "/data")))
    max_file_bytes: int = int(os.getenv("STEGOLAB_MAX_FILE_MB", "32")) * 1024 * 1024
    max_storage_bytes: int = int(os.getenv("STEGOLAB_MAX_STORAGE_MB", "2048")) * 1024 * 1024
    max_pending: int = int(os.getenv("STEGOLAB_MAX_PENDING", "32"))
    max_jobs: int = int(os.getenv("STEGOLAB_MAX_JOBS", "1000"))
    concurrency: int = max(1, min(4, int(os.getenv("STEGOLAB_CONCURRENCY", "2"))))
    quick_timeout: int = int(os.getenv("STEGOLAB_QUICK_TIMEOUT", "90"))
    deep_timeout: int = int(os.getenv("STEGOLAB_DEEP_TIMEOUT", "300"))
    memory_mb: int = int(os.getenv("STEGOLAB_JOB_MEMORY_MB", "768"))
    allowed_hosts: tuple[str, ...] = tuple(os.getenv("STEGOLAB_ALLOWED_HOSTS", "localhost,127.0.0.1,[::1],testserver").split(","))

    def __post_init__(self):
        object.__setattr__(self, "data_dir", Path(self.data_dir).resolve())
        if min(self.max_file_bytes, self.max_storage_bytes, self.max_jobs, self.max_pending,
               self.quick_timeout, self.deep_timeout, self.memory_mb) <= 0:
            raise ValueError("Limits must be positive")

    @property
    def reservation_bytes(self):
        # Original + extraction quota + generated text/JSON/log allowance.
        return self.max_file_bytes + 80 * 1024 * 1024

    @property
    def jobs_dir(self):
        return self.data_dir / "jobs"
