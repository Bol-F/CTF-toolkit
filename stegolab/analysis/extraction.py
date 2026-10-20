"""Recursive archive extraction into generated paths with shared hard quotas.

Archive names are display labels only. No archive library extract method is used.
"""
from __future__ import annotations

import gzip
import mimetypes
import os
import re
import stat
import tarfile
import uuid
import zipfile
from dataclasses import dataclass
from pathlib import Path, PurePosixPath, PureWindowsPath


@dataclass(frozen=True)
class Limits:
    max_file_bytes: int = 32 * 1024 * 1024
    max_extracted_bytes: int = 64 * 1024 * 1024
    max_artifacts: int = 100
    max_depth: int = 3
    max_ratio: int = 100
    max_member_bytes: int = 32 * 1024 * 1024

    @classmethod
    def from_environment(cls):
        def value(name, default, maximum):
            return max(1, min(int(os.environ.get(name, default)), maximum))
        return cls(max_file_bytes=value("STEGOLAB_MAX_FILE_BYTES", 32 * 1024 * 1024, 256 * 1024 * 1024),
                   max_extracted_bytes=value("STEGOLAB_MAX_EXTRACTED_BYTES", 64 * 1024 * 1024, 256 * 1024 * 1024),
                   max_artifacts=value("STEGOLAB_MAX_ARTIFACTS", 100, 500),
                   max_depth=value("STEGOLAB_MAX_EXTRACTION_DEPTH", 3, 5),
                   max_ratio=value("STEGOLAB_MAX_COMPRESSION_RATIO", 100, 1000))


def safe_member_name(name: str) -> bool:
    if not name or "\x00" in name or len(name) > 1024:
        return False
    normalized = name.replace("\\", "/")
    posix = PurePosixPath(normalized)
    windows = PureWindowsPath(name)
    return not (posix.is_absolute() or windows.is_absolute() or windows.drive
                or ".." in posix.parts or ":" in normalized)


def display_name(name: str) -> str:
    return re.sub(r"[\x00-\x1f\x7f]", "_", name.replace("\\", "/"))[:240]


class ExtractionLimit(Exception):
    pass


class Extractor:
    def __init__(self, artifacts_dir: Path, limits: Limits):
        self.root = artifacts_dir.resolve()
        self.output = self.root / "extracted"
        self.output.mkdir(parents=True, exist_ok=True)
        self.limits = limits
        self.bytes_written = 0
        self.artifacts: list[dict] = []
        self.findings: list[dict] = []
        self.errors: list[str] = []
        self.inspected_members = 0

    def finding(self, title, detail, kind="extraction", **extra):
        self.findings.append({"type": kind, "title": title, "detail": detail, "offset": None, "confidence": 1.0, **extra})

    def reject(self, name, reason):
        self.finding("Archive member rejected", f"{display_name(name)}: {reason}", "rejected_member", member=display_name(name), reason=reason)

    def check_member(self, name, size, compressed_size=None):
        self.inspected_members += 1
        if self.inspected_members > self.limits.max_artifacts * 4:
            raise ExtractionLimit("Archive member inspection limit reached")
        if not safe_member_name(name):
            self.reject(name, "unsafe path")
            return False
        if len(self.artifacts) >= self.limits.max_artifacts:
            raise ExtractionLimit("Artifact count limit reached")
        if size > self.limits.max_member_bytes:
            self.reject(name, "member size exceeds limit")
            return False
        if size > self.limits.max_extracted_bytes - self.bytes_written:
            self.reject(name, "total extraction byte quota would be exceeded")
            return False
        if compressed_size is not None and size > max(compressed_size, 1) * self.limits.max_ratio:
            self.reject(name, "compression ratio exceeds limit")
            return False
        return True

    def save_stream(self, stream, name, depth, parent, compressed_size=None):
        artifact_id = uuid.uuid4().hex
        suffix = Path(name.replace("\\", "/")).suffix[:12]
        if not re.fullmatch(r"\.[a-zA-Z0-9]{1,10}", suffix):
            suffix = ".bin"
        target = self.output / f"{artifact_id}{suffix}"
        size = 0
        try:
            with target.open("xb") as destination:
                while True:
                    chunk = stream.read(65536)
                    if not chunk:
                        break
                    size += len(chunk)
                    # Count even partial/rejected streams against the job budget.
                    self.bytes_written += len(chunk)
                    if size > self.limits.max_member_bytes or self.bytes_written > self.limits.max_extracted_bytes:
                        raise ExtractionLimit("extraction byte limit reached while streaming")
                    if compressed_size is not None and size > max(compressed_size, 1) * self.limits.max_ratio:
                        raise ExtractionLimit("compression ratio exceeds limit while streaming")
                    destination.write(chunk)
        except Exception:
            target.unlink(missing_ok=True)
            raise
        record = {"id": artifact_id, "path": target.relative_to(self.root).as_posix(), "name": display_name(name), "size": size, "media_type": mimetypes.guess_type(name)[0] or "application/octet-stream", "kind": "extracted", "depth": depth, "parent": parent}
        self.artifacts.append(record)
        self.finding("Archive member extracted", f"{display_name(name)} ({size} bytes)", artifact_id=artifact_id, member=display_name(name), depth=depth)
        return target, record

    def extract(self, source: Path, depth=0, parent="original"):
        if depth >= self.limits.max_depth:
            # Report only if an archive would otherwise be processed at this depth.
            if self.is_archive(source):
                self.finding("Recursion depth limit reached", f"Nested archive {parent} retained without further extraction", "extraction_limit")
            return
        try:
            if zipfile.is_zipfile(source):
                self.extract_zip(source, depth, parent)
                return
            with source.open("rb") as handle:
                head = handle.read(512)
            if len(head) >= 262 and head[257:262] == b"ustar":
                self.extract_tar(source, depth, parent)
            elif head.startswith(b"\x1f\x8b"):
                name = "gzip-content.bin"
                if self.check_member(name, 0):
                    try:
                        with gzip.open(source, "rb") as handle:
                            path, record = self.save_stream(handle, name, depth + 1, parent, source.stat().st_size)
                        self.extract(path, depth + 1, record["id"])
                    except (OSError, EOFError, ExtractionLimit) as exc:
                        self.reject(name, str(exc))
        except (OSError, ValueError, zipfile.BadZipFile, tarfile.TarError, ExtractionLimit, RuntimeError, NotImplementedError) as exc:
            self.errors.append(f"{display_name(parent)}: {str(exc)[:500]}")

    @staticmethod
    def is_archive(source):
        with source.open("rb") as handle:
            head = handle.read(512)
        return head.startswith((b"PK\x03\x04", b"\x1f\x8b")) or head[257:262] == b"ustar" or zipfile.is_zipfile(source)

    def extract_zip(self, source, depth, parent):
        # Read EOCD before ZipFile allocates its full central-directory inventory.
        # ZIP64 is not required for the small bounded uploads accepted here.
        with source.open("rb") as stream:
            stream.seek(max(0, source.stat().st_size - 65557))
            tail = stream.read(65557)
        end = tail.rfind(b"PK\x05\x06")
        if end >= 0 and end + 22 <= len(tail):
            entries = int.from_bytes(tail[end + 10:end + 12], "little")
            central_bytes = int.from_bytes(tail[end + 12:end + 16], "little")
            if entries == 65535 or entries > self.limits.max_artifacts * 4 or central_bytes > 4 * 1024 * 1024:
                raise ExtractionLimit("ZIP central-directory count or size exceeds inspection limit; ZIP64 is not extracted")
        with zipfile.ZipFile(source) as archive:
            for member in archive.infolist():
                if not self.check_member(member.filename, member.file_size, member.compress_size):
                    continue
                mode = member.external_attr >> 16
                if stat.S_ISLNK(mode) or (stat.S_IFMT(mode) and not stat.S_ISREG(mode) and not stat.S_ISDIR(mode)):
                    self.reject(member.filename, "links and special files are not allowed")
                    continue
                if member.is_dir():
                    continue
                if member.flag_bits & 1:
                    self.reject(member.filename, "encrypted ZIP requires a password; no guessing is performed")
                    continue
                try:
                    with archive.open(member) as handle:
                        path, record = self.save_stream(handle, member.filename, depth + 1, parent, member.compress_size)
                    self.extract(path, depth + 1, record["id"])
                except (OSError, ValueError, RuntimeError, zipfile.BadZipFile, NotImplementedError, ExtractionLimit) as exc:
                    self.reject(member.filename, str(exc)[:500])

    def extract_tar(self, source, depth, parent):
        with tarfile.open(source, mode="r:") as archive:
            for member in archive:
                if not self.check_member(member.name, member.size):
                    continue
                if member.isdir():
                    continue
                if not member.isfile() or member.issparse():
                    self.reject(member.name, "links, sparse files and special files are not allowed")
                    continue
                try:
                    stream = archive.extractfile(member)
                    if stream is None:
                        self.reject(member.name, "member has no data")
                        continue
                    with stream:
                        path, record = self.save_stream(stream, member.name, depth + 1, parent)
                    self.extract(path, depth + 1, record["id"])
                except (OSError, ValueError, tarfile.TarError, ExtractionLimit) as exc:
                    self.reject(member.name, str(exc)[:500])
