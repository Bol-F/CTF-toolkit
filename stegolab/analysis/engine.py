"""StegoLab's deterministic local analysis pipeline.

Each stage returns the same JSON envelope; optional programs cannot abort the
pipeline. Native scanners and quota-controlled extraction work without any tools.
"""
from __future__ import annotations

import base64
import hashlib
import itertools
import json
import math
import mimetypes
import os
import re
import struct
import time
import uuid
import zlib
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

from .encoding import decoded_candidates
from .extraction import Extractor, Limits, display_name
from .tools import MAX_OUTPUT, SPECS, registry_snapshot, run_command

FLAG_PREFIX_RE = re.compile(rb"(?i)(?:flag|ctf|picoctf|htb|thm|ictf|ductf|uiuctf|angstromctf|actf|zer0pts|tjctf|corctf|crewctf|(?<![a-z0-9_])[a-z0-9_]{2,24}ctf)\{")
FLAG_BODY_RE = re.compile(rb"[\x20-\x7e]{1,256}")
ASCII_RE = re.compile(rb"[\x20-\x7e\t]{4,}")
UTF16_LE_RE = re.compile(rb"(?:[\x20-\x7e]\x00){4,}")
UTF16_BE_RE = re.compile(rb"(?:\x00[\x20-\x7e]){4,}")
SIGNATURES = [
    ("png", b"\x89PNG\r\n\x1a\n", "image/png"), ("jpeg", b"\xff\xd8\xff", "image/jpeg"),
    ("gif", b"GIF87a", "image/gif"), ("gif", b"GIF89a", "image/gif"),
    ("zip", b"PK\x03\x04", "application/zip"), ("gzip", b"\x1f\x8b\x08", "application/gzip"),
    ("7z", b"7z\xbc\xaf\x27\x1c", "application/x-7z-compressed"),
    ("rar", b"Rar!\x1a\x07", "application/vnd.rar"), ("pdf", b"%PDF-", "application/pdf"),
    ("elf", b"\x7fELF", "application/x-elf"), ("pe", b"MZ", "application/vnd.microsoft.portable-executable"),
    ("sqlite", b"SQLite format 3\x00", "application/vnd.sqlite3"),
    ("ogg", b"OggS", "audio/ogg"), ("flac", b"fLaC", "audio/flac"),
    ("matroska", b"\x1a\x45\xdf\xa3", "video/x-matroska"),
    ("bmp", b"BM", "image/bmp"), ("tiff", b"II*\x00", "image/tiff"), ("tiff", b"MM\x00*", "image/tiff"),
]
RASTER = {"png", "jpeg", "gif", "bmp", "tiff", "webp"}
MEDIA = {"wav", "mp3", "ogg", "flac", "mp4", "webm", "avi", "matroska"}


def utc_now():
    return datetime.now(timezone.utc).isoformat()


def atomic_json(path: Path, value):
    temporary = path.with_name(path.name + ".tmp")
    temporary.write_text(json.dumps(value, ensure_ascii=True, indent=2), encoding="utf-8")
    for attempt in range(5):
        try:
            temporary.replace(path)
            return
        except PermissionError:
            # Windows readers/antivirus can briefly hold an open destination.
            # Docker Linux does not need this compatibility retry.
            if os.name != "nt" or attempt == 4:
                raise
            time.sleep(.02 * (attempt + 1))


def finding(kind, title, detail, offset=None, confidence=1.0, **extra):
    return {"type": kind, "title": title, "detail": str(detail), "offset": offset, "confidence": confidence, **extra}


def stage(name, findings=None, errors=None, artifacts=None, status="completed", **extra):
    return {"name": name, "status": status, "findings": findings or [], "errors": errors or [], "artifacts": artifacts or [], "duration_ms": 0, **extra}


def flag_findings(data: bytes, *, source="original", base_offset=0, maximum=200):
    found = []
    seen = set()
    if b"}" not in data:
        return found
    contents = [("ascii", data, 1, 0)]
    utf_records = []
    for encoding, regex in (("utf-16-le", UTF16_LE_RE), ("utf-16-be", UTF16_BE_RE)):
        for record in itertools.islice(regex.finditer(data), 10000):
            utf_records.append((record.start(), record.end(), encoding))
    # A UTF16 run also resembles the opposite byte order shifted by one byte.
    # Prefer the longest overlapping run to keep the actual source offsets.
    accepted, best, group_end = [], None, -1
    for record in sorted(utf_records):
        start, end, encoding = record
        if start >= group_end:
            if best is not None:
                accepted.append(best)
            best = record
            group_end = end
        else:
            group_end = max(group_end, end)
            if end - start > best[1] - best[0]:
                best = record
    if best is not None:
        accepted.append(best)
    for start, end, encoding in accepted:
        contents.append((encoding, data[start:end].decode(encoding).encode("ascii"), 2, start))
    for encoding, content, multiplier, start_offset in contents:
        next_allowed = 0
        for match in FLAG_PREFIX_RE.finditer(content):
            if match.start() < next_allowed:
                continue
            # Find the bounded delimiter in C, rather than backtracking over a
            # potentially attacker-controlled run of repeated `flag{` prefixes.
            close = content.find(b"}", match.end() + 1, match.end() + 257)
            if close < 0 or FLAG_BODY_RE.fullmatch(content[match.end():close]) is None:
                continue
            next_allowed = close + 1
            value = content[match.start():close + 1].decode("ascii", "replace")
            offset = base_offset + start_offset + match.start() * multiplier
            key = (value, offset)
            if key in seen:
                continue
            seen.add(key)
            found.append(finding("flag", "Possible CTF flag", value, offset, .98, value=value, source=source, encoding=encoding))
            if len(found) >= maximum:
                return found
    return found


def identify(data: bytes):
    for kind, signature, mime in SIGNATURES:
        if data.startswith(signature):
            return kind, mime
    if data.startswith(b"PK\x05\x06"):
        return "zip", "application/zip"
    if data.startswith(b"RIFF") and len(data) >= 12:
        kind = {b"WAVE": ("wav", "audio/wav"), b"AVI ": ("avi", "video/x-msvideo"), b"WEBP": ("webp", "image/webp")}.get(data[8:12])
        if kind:
            return kind
    if len(data) >= 12 and data[4:8] == b"ftyp":
        return "mp4", "video/mp4"
    if data.startswith(b"ID3") or data.startswith((b"\xff\xfb", b"\xff\xf3", b"\xff\xf2")):
        return "mp3", "audio/mpeg"
    if data[257:262] == b"ustar":
        return "tar", "application/x-tar"
    if data.startswith(b".snd"):
        return "au", "audio/basic"
    if data and b"\x00" not in data[:8192]:
        try:
            text = data[:8192].decode("utf-8")
            if sum(char.isprintable() or char.isspace() for char in text) / max(len(text), 1) > .95:
                return "text", "text/plain"
        except UnicodeError:
            pass
    return "unknown", "application/octet-stream"


class Analysis:
    def __init__(self, job_dir: Path, mode: str, limits: Limits):
        self.job = job_dir.resolve()
        self.original = self.job / "evidence" / "original.bin"
        self.root = self.job / "artifacts"
        self.root.mkdir(parents=True, exist_ok=True)
        self.mode, self.limits = mode, limits
        self.data = b""
        self.report = {"schema_version": "1.0", "job_id": self.job.name, "mode": mode, "file": {}, "status": "completed", "started_at": utc_now(), "completed_at": None, "analyzers": [], "findings": [], "artifacts": [], "recommendations": [], "errors": []}
        self.tools = []
        self.tool_by_name = {}
        self.flag_values = set()
        self.generated_bytes = 0
        self.file_end = None

    def artifact(self, name, data: bytes, media_type="text/plain", kind="analysis", max_bytes=None):
        if len(self.report["artifacts"]) >= self.limits.max_artifacts:
            raise ValueError("Artifact count limit reached")
        if max_bytes is not None:
            if len(data) > max_bytes:
                raise ValueError(f"Artifact {name} exceeds its byte limit")
        else:
            data = data[:MAX_OUTPUT]
        if self.generated_bytes + len(data) > self.limits.max_extracted_bytes:
            raise ValueError("Generated artifact byte quota reached")
        artifact_id = uuid.uuid4().hex
        suffix = Path(name).suffix
        target = self.root / f"{artifact_id}{suffix}"
        target.write_bytes(data)
        self.generated_bytes += len(data)
        artifact = {"id": artifact_id, "path": target.relative_to(self.root).as_posix(), "name": name, "size": len(data), "media_type": media_type, "kind": kind}
        self.report["artifacts"].append(artifact)
        return artifact

    def add_stage(self, result):
        result["findings"] = result["findings"][:1000]
        result["errors"] = result["errors"][:100]
        self.report["analyzers"].append(result)
        for item in result["findings"]:
            if len(self.report["findings"]) < 2000:
                self.report["findings"].append({**item, "analyzer": result["name"]})
        for artifact in result["artifacts"]:
            if not any(existing["id"] == artifact["id"] for existing in self.report["artifacts"]):
                self.report["artifacts"].append(artifact)

    def run_stage(self, name, progress, method):
        atomic_json(self.job / "progress.json", {"progress": progress, "stage": name})
        started = time.monotonic()
        try:
            result = method()
            result["duration_ms"] = round((time.monotonic() - started) * 1000)
        except Exception as exc:
            result = stage(name, errors=[f"{type(exc).__name__}: {str(exc)[:1000]}"], status="failed", duration_ms=round((time.monotonic() - started) * 1000))
        self.add_stage(result)
        return result

    def identification(self):
        info = json.loads((self.job / "upload.json").read_text(encoding="utf-8"))
        size = self.original.stat().st_size
        if size > self.limits.max_file_bytes:
            raise ValueError(f"Evidence exceeds file limit ({self.limits.max_file_bytes} bytes)")
        if self.original.is_symlink() or not self.original.is_file():
            raise ValueError("Evidence must be a regular file")
        self.data = self.original.read_bytes()
        sha256 = hashlib.sha256(self.data).hexdigest()
        kind, mime = identify(self.data)
        detected_by = "native signatures"
        errors = []
        try:
            import magic
            magic_mime = magic.from_buffer(self.data[:65536], mime=True)
            if magic_mime and magic_mime != "application/octet-stream":
                mime = magic_mime
                detected_by += ", libmagic"
        except ImportError:
            pass
        except Exception as exc:
            errors.append("libmagic: " + str(exc)[:300])
        self.report["file"] = {"filename": display_name(str(info.get("filename", "upload.bin"))), "size": size, "sha256": sha256, "mime": mime, "format": kind, "identified_by": detected_by}
        findings = [finding("identification", "File identified", f"{kind}; {mime}; {size} bytes", 0), finding("hash", "SHA-256", sha256)]
        if info.get("sha256") and info["sha256"] != sha256:
            findings.append(finding("integrity", "Evidence hash mismatch", "Stored upload SHA-256 does not match the original evidence", confidence=1))
        extension = Path(str(info.get("filename", ""))).suffix.lower()
        claimed = mimetypes.guess_type(str(info.get("filename", "")))[0]
        known_alias = (kind == "zip" and extension in {".docx", ".xlsx", ".pptx", ".jar", ".apk", ".odt", ".epub"})
        if claimed and claimed != mime and kind != "unknown" and not known_alias and not (claimed in {"image/jpg", "image/jpeg"} and kind == "jpeg"):
            findings.append(finding("extension_mismatch", "Filename and content type differ", f"Extension suggests {claimed}; content identifies as {mime}", 0, .9))
        if not size:
            findings.append(finding("validation", "Empty evidence file", "No bytes to analyze"))
        return stage("identification", findings, errors)

    def inventory(self):
        cache = os.environ.get("STEGOLAB_TOOL_REGISTRY")
        if cache and Path(cache).is_file():
            try:
                self.tools = json.loads(Path(cache).read_text(encoding="utf-8"))
            except (OSError, ValueError):
                self.tools = registry_snapshot()
        else:
            self.tools = registry_snapshot()
        self.tool_by_name = {tool["name"]: tool for tool in self.tools}
        self.report["tools"] = self.tools
        return stage("tool_registry", [finding("tool_inventory", "Optional tool availability", f"{sum(tool['available'] for tool in self.tools)} of {len(self.tools)} CLI tools available")], tools=self.tools)

    def metadata(self):
        findings, errors, values = [], [], {}
        kind = self.report["file"]["format"]
        if kind in RASTER:
            try:
                from PIL import Image
                Image.MAX_IMAGE_PIXELS = 32000000
                import warnings
                with warnings.catch_warnings():
                    warnings.simplefilter("error", Image.DecompressionBombWarning)
                    with Image.open(self.original) as image:
                        values = {"format": image.format, "width": image.width, "height": image.height, "mode": image.mode, "frames": getattr(image, "n_frames", 1), "info": {str(key): str(value)[:4096] for key, value in list(image.info.items())[:100]}}
                findings.append(finding("metadata", "Image metadata", json.dumps(values, ensure_ascii=True)[:16384]))
            except ImportError:
                errors.append("Pillow is unavailable; native headers and ExifTool remain available")
            except Exception as exc:
                errors.append("Image metadata: " + str(exc)[:500])
        if kind == "png" and len(self.data) >= 24:
            findings.append(finding("metadata", "PNG dimensions", f"{int.from_bytes(self.data[16:20], 'big')} × {int.from_bytes(self.data[20:24], 'big')}", 16))
        return stage("metadata", findings, errors, status="partial" if errors else "completed", data=values)

    def strings(self):
        records = []
        total = 0
        capped = False
        for encoding, regex in (("ascii", ASCII_RE), ("utf-16-le", UTF16_LE_RE), ("utf-16-be", UTF16_BE_RE)):
            for match in regex.finditer(self.data):
                value = match.group()[:4096].decode("ascii" if encoding == "ascii" else encoding, "replace")
                record = {"offset": match.start(), "encoding": encoding, "value": value, "truncated": len(match.group()) > 4096}
                total += len(value) + 100
                if len(records) >= 10000 or total > MAX_OUTPUT - 1024:
                    capped = True
                    break
                records.append(record)
            if capped:
                break
        serialized = json.dumps(records, ensure_ascii=True, separators=(",", ":")).encode()
        while len(serialized) > MAX_OUTPUT:
            records = records[:max(0, len(records) * 3 // 4)]
            serialized = json.dumps(records, ensure_ascii=True, separators=(",", ":")).encode()
            capped = True
        artifact = self.artifact("strings.json", serialized, "application/json")
        findings = [finding("strings", "Readable strings extracted", f"{len(records)} bounded ASCII and UTF-16 strings with byte offsets", count=len(records), artifact_id=artifact["id"])]
        if capped:
            findings.append(finding("limit", "String output truncated", "String count or output byte limit reached"))
        self.string_records = records
        return stage("strings", findings, artifacts=[artifact], status="partial" if capped else "completed", data={"strings": [{"offset": record["offset"], "text": record["value"], "encoding": record["encoding"]} for record in records[:500]]})

    def binary(self):
        sample = self.data[:1048576]
        entropy = -sum((count / len(sample)) * math.log2(count / len(sample)) for count in Counter(sample).values()) if sample else 0
        shown = self.data[:4096]
        lines = []
        for offset in range(0, len(shown), 16):
            chunk = shown[offset:offset + 16]
            lines.append(f"{offset:08x}  {' '.join(f'{byte:02x}' for byte in chunk):47}  |{''.join(chr(byte) if 32 <= byte < 127 else '.' for byte in chunk)}|")
        artifact = self.artifact("header-hexdump.txt", ("\n".join(lines) + "\n").encode())
        findings = [finding("entropy", "Byte entropy", f"{entropy:.4f} bits/byte over {len(sample)} bytes; high entropy can indicate compression or encryption", 0, .8, entropy=round(entropy, 5), sample_bytes=len(sample)), finding("hex", "Header hexadecimal dump", f"First {len(shown)} bytes", 0, artifact_id=artifact["id"])]
        return stage("binary", findings, artifacts=[artifact], data={"hex": "\n".join(lines), "preview": "\n".join(lines), "entropy": round(entropy, 5)})

    def signatures(self):
        findings = []
        for kind, signature, mime in SIGNATURES:
            start = 0
            matches = 0
            while matches < 30 and len(findings) < 200:
                offset = self.data.find(signature, start)
                if offset < 0:
                    break
                findings.append(finding("signature" if offset == 0 else "embedded_signature", f"{kind.upper()} signature", "Header signature" if offset == 0 else "Possible embedded file; signature alone is not proof of a complete file", offset, .99 if offset == 0 else .65, format=kind, mime=mime))
                start = offset + len(signature)
                matches += 1
        return stage("signatures", findings)

    def structure(self):
        kind = self.report["file"]["format"]
        findings, errors = [], []
        end = None
        data = self.data
        if kind == "png":
            cursor, count = 8, 0
            while cursor + 12 <= len(data) and count < 10000:
                length = int.from_bytes(data[cursor:cursor + 4], "big")
                chunk_type = data[cursor + 4:cursor + 8]
                if length > len(data) - cursor - 12:
                    errors.append(f"Truncated PNG chunk at byte {cursor}")
                    break
                content = data[cursor + 8:cursor + 8 + length]
                expected_crc = int.from_bytes(data[cursor + 8 + length:cursor + 12 + length], "big")
                if zlib.crc32(chunk_type + content) & 0xffffffff != expected_crc:
                    findings.append(finding("integrity", "PNG CRC mismatch", f"Chunk {chunk_type.decode('ascii', 'replace')}", cursor, 1))
                if chunk_type in {b"tEXt", b"iTXt", b"zTXt"}:
                    findings.append(finding("metadata", "PNG text chunk", content[:2048].decode("utf-8", "replace"), cursor + 8, .99, chunk=chunk_type.decode("ascii")))
                cursor += length + 12
                count += 1
                if chunk_type == b"IEND":
                    end = cursor
                    break
            if end is None:
                errors.append("PNG IEND chunk was not found within valid chunk boundaries")
        elif kind == "jpeg":
            # Marker lengths skip thumbnail data inside APP segments.
            cursor = 2
            while cursor + 1 < len(data):
                marker = data.find(b"\xff", cursor)
                if marker < 0 or marker + 1 >= len(data):
                    break
                code = data[marker + 1]
                if code == 0xd9:
                    end = marker + 2
                    break
                if code in {0, 0xff, 0xd8, 0x01} or 0xd0 <= code <= 0xd7:
                    cursor = marker + 2
                elif marker + 4 <= len(data):
                    segment_length = int.from_bytes(data[marker + 2:marker + 4], "big")
                    if segment_length < 2 or marker + 2 + segment_length > len(data):
                        errors.append(f"Invalid JPEG segment length at {marker}")
                        break
                    cursor = marker + 2 + segment_length
                else:
                    break
            if end is None:
                errors.append("JPEG end marker was not found")
        elif kind == "zip":
            eocd = data.rfind(b"PK\x05\x06", max(0, len(data) - 65557))
            if eocd >= 0 and eocd + 22 <= len(data):
                end = eocd + 22 + int.from_bytes(data[eocd + 20:eocd + 22], "little")
        elif kind in {"wav", "avi", "webp"} and len(data) >= 8:
            end = int.from_bytes(data[4:8], "little") + 8
        elif kind == "pdf":
            marker = data.rfind(b"%%EOF")
            if marker >= 0:
                end = marker + 5
                while end < len(data) and data[end] in b"\r\n\t ":
                    end += 1
        if end is not None:
            if end > len(data):
                errors.append("Declared format size exceeds evidence length")
            else:
                self.file_end = end
                findings.append(finding("structure", "Logical file end", f"Detected {kind} end at byte {end}", end, .95))
                if end < len(data):
                    findings.append(finding("appended_data", "Data follows logical file end", f"{len(data) - end} appended bytes", end, .99, size=len(data) - end))
        return stage("structure", findings, errors, status="partial" if errors else "completed")

    def flags(self):
        findings = flag_findings(self.data)
        for record in getattr(self, "string_records", []):
            if len(findings) >= 500:
                break
            for encoding, relative, decoded in decoded_candidates(record["value"]):
                token_offset = record["offset"] + relative * (2 if record["encoding"].startswith("utf-16") else 1)
                for item in flag_findings(decoded.encode("utf-8"), source="decoded string"):
                    item["decoded_offset"] = item["offset"]
                    item["offset"] = token_offset
                    item["offset_scope"] = "encoded token in original evidence"
                    item["encoding"] = encoding
                    item["detail"] = f"{encoding} decoded candidate: {item['value']}"
                    findings.append(item)
                    if len(findings) >= 500:
                        break
                if len(findings) >= 500:
                    break
        unique = []
        seen = set()
        for item in findings:
            identity = (item["value"], item["source"], item["offset"])
            if identity not in seen:
                unique.append(item)
                seen.add(identity)
        return stage("flags", unique[:300])

    def extraction(self):
        if self.mode != "deep":
            return stage("recursive_extraction", status="skipped", reason="Deep Scan enables bounded archive extraction")
        kind = self.report["file"]["format"]
        tool_slots = sum(1 for tool in self.tools if tool["available"] and tool["name"] not in {"strings", "xxd"} and ("*" in tool["formats"] or kind in tool["formats"]))
        # Reserve space for later diagnostic outputs, so a full archive quota
        # cannot crowd all file-type-specific analyzers out of the report.
        remaining_count = max(0, self.limits.max_artifacts - len(self.report["artifacts"]) - tool_slots)
        remaining_bytes = max(0, self.limits.max_extracted_bytes - self.generated_bytes - tool_slots * MAX_OUTPUT)
        from dataclasses import replace
        extractor = Extractor(self.root, replace(self.limits, max_artifacts=remaining_count, max_extracted_bytes=remaining_bytes))
        extractor.extract(self.original)
        # Carve only well-signalled appended ZIP/gzip/PDF/image candidates. Archive
        # extraction uses the complete original for appended ZIP central offsets.
        if self.file_end is not None and self.file_end < len(self.data):
            tail = self.data[self.file_end:]
            tail_kind, tail_mime = identify(tail)
            if tail_kind != "unknown" and tail and len(extractor.artifacts) < remaining_count and len(tail) <= remaining_bytes - extractor.bytes_written:
                import io
                try:
                    path, record = extractor.save_stream(io.BytesIO(tail), f"appended.{tail_kind if tail_kind != 'text' else 'txt'}", 1, "original")
                    record["offset"] = self.file_end
                    record["media_type"] = tail_mime
                    record["kind"] = "carved"
                    # ZIP appended to a carrier is already extracted above.
                    import zipfile
                    if not zipfile.is_zipfile(self.original):
                        extractor.extract(path, 1, record["id"])
                except Exception as exc:
                    extractor.errors.append("Appended carving: " + str(exc)[:300])
        for artifact in extractor.artifacts:
            source = self.root / artifact["path"]
            extracted_data = source.read_bytes()
            artifact["sha256"] = hashlib.sha256(extracted_data).hexdigest()
            kind, mime = identify(extracted_data)
            artifact["detected_format"] = kind
            artifact["media_type"] = mime
            if len(extractor.findings) < 800:
                extractor.findings.extend(flag_findings(extracted_data, source=artifact["id"], maximum=100))
            # Decode bounded textual candidates in extracted members as well.
            for match in itertools.islice(ASCII_RE.finditer(extracted_data), 1000):
                if len(extractor.findings) >= 900:
                    break
                for encoding, relative, decoded in decoded_candidates(match.group()[:4096].decode("ascii")):
                    for item in flag_findings(decoded.encode(), source=artifact["id"]):
                        item["decoded_offset"] = item["offset"]
                        item["offset"] = match.start() + relative
                        item["offset_scope"] = "encoded token in extracted artifact"
                        item["encoding"] = encoding
                        extractor.findings.append(item)
        self.generated_bytes += extractor.bytes_written
        return stage("recursive_extraction", extractor.findings, extractor.errors, extractor.artifacts, status="partial" if extractor.errors or any(item["type"] in {"rejected_member", "extraction_limit"} for item in extractor.findings) else "completed", bytes_extracted=extractor.bytes_written, depth_limit=self.limits.max_depth)

    def cli_tool(self, name):
        tool = self.tool_by_name[name]
        if not tool["available"]:
            return stage(name, errors=[f"Optional tool {name} is unavailable in this worker"], status="unavailable")
        if SPECS[name].get('manual'):
            return stage(name, status='skipped', reason='Explicit lab action only; never started automatically')
        kind = self.report["file"]["format"]
        if name in {"strings", "xxd"}:
            return stage(name, status="skipped", reason="Native offset-aware strings / hexadecimal analyzer provides bounded equivalent output")
        formats = tool["formats"]
        if "*" not in formats and kind not in formats:
            return stage(name, status="skipped", reason=f"Not applicable to detected {kind} format")
        if self.mode == "quick" and name not in {"file", "exiftool", "pngcheck"}:
            return stage(name, status="skipped", reason="Enabled in Deep Scan")
        executable = tool["executable"]
        file = str(self.original)
        arguments = {
            "file": ["--brief", "--mime-type", "--", file],
            "exiftool": ["-json", "-G1", "-n", file],
            "binwalk": [file],
            "pngcheck": ["-v", file],
            "imagemagick": (["identify"] if Path(executable).stem == "magick" else []) + ["-ping", "-format", "%m %w %h %z-bit\\n", file + "[0]"],
            "foremost": ["-w", "-i", file, "-o", str(self.root / "foremost-audit")],
            "tesseract": [file, "stdout", "-l", "eng", "--psm", "11"],
            "zbarimg": ["--quiet", "--raw", file],
            "ffprobe": ["-v", "error", "-protocol_whitelist", "file,pipe", "-show_format", "-show_streams", "-of", "json", file],
            "ffmpeg": ["-v", "error", "-nostdin", "-threads", "1", "-protocol_whitelist", "file,pipe", "-i", file, "-t", "10", "-f", "null", "-"],
            "pdfdetach": ["-list", file],
            "zsteg": ["-a", file],
            "steghide": ["info", file, "-p", ""],
        }[name]
        result = run_command([executable, *arguments], self.root)
        output = result["stdout"]
        audit_dir = self.root / "foremost-audit"
        if name == "foremost" and audit_dir.exists():
            audit = audit_dir / "audit.txt"
            if audit.is_file() and not audit.is_symlink():
                with audit.open("rb") as handle:
                    output += "\n" + handle.read(MAX_OUTPUT).decode("utf-8", "replace")
        errors = []
        if result["stderr"].strip():
            errors.append(result["stderr"][:8192])
        if result["status"] == "timeout":
            errors.append("Tool exceeded wall-clock timeout")
        if result.get("output_truncated"):
            errors.append("Tool output exceeded byte limit")
        status = result["status"]
        # zbar exit 4 explicitly means no symbols, which is a valid negative result.
        if name == "zbarimg" and result["returncode"] == 4:
            status = "completed"
        if status == "failed" and result["returncode"] is not None:
            errors.append(f"Tool exited with status {result['returncode']}")
        artifact = self.artifact(f"{name}.txt", (output + ("\nSTDERR:\n" + result["stderr"] if result["stderr"] else "")).encode())
        findings = [finding("tool_output", f"{name} output", output[:8192] or "No stdout findings", confidence=.8, artifact_id=artifact["id"])]
        parsed = None
        if name in {"exiftool", "ffprobe"} and output.strip():
            try:
                parsed = json.loads(output)
            except ValueError:
                errors.append("Tool did not return valid JSON")
                if status == "completed":
                    status = "partial"
        if name == "file" and status == "completed":
            findings.append(finding("identification", "libmagic MIME type", output.strip(), 0, .99))
            if self.report["file"]["format"] == "unknown" and output.strip():
                self.report["file"]["mime"] = output.strip()
        if name == "binwalk":
            for line in output.splitlines()[:500]:
                match = re.match(r"^\s*(\d+)\s+0x[0-9a-fA-F]+\s+(.+)", line)
                if match:
                    findings.append(finding("embedded_signature", "Binwalk signature", match[2][:1000], int(match[1]), .8))
        findings.extend(flag_findings(output.encode(), source=name))
        # foremost audit output remains generated data, never extracted evidence.
        if name == "foremost" and audit_dir.exists():
            for audit in list(audit_dir.iterdir())[:20]:
                if audit.is_file() and not audit.is_symlink():
                    audit.unlink(missing_ok=True)
            try:
                audit_dir.rmdir()
            except OSError:
                pass
        return stage(name, findings, errors, [artifact], status=status, returncode=result["returncode"], duration_ms=result["duration_ms"], data=parsed)

    def recommendations(self):
        kind = self.report["file"].get("format", "unknown")
        recommendations = ["Review candidate flags and byte offsets against the original evidence."]
        if self.mode == "quick":
            recommendations.append("Run Deep Scan for recursive archive extraction, OCR, barcode detection and file-type-specific tools.")
        if kind in {"png", "bmp"}:
            recommendations.append("Inspect least-significant-bit planes with zsteg; image presence alone does not prove hidden data.")
        if kind in {"jpeg", "bmp", "wav", "au"}:
            recommendations.append("If the challenge provides a password, inspect steghide payloads manually in an isolated environment; automatic password cracking is not performed.")
        if kind in MEDIA:
            recommendations.append("Inspect audio/video metadata and decoder diagnostics; a spectrogram can reveal visual audio clues.")
        if kind in {"zip", "tar", "gzip", "7z", "rar"}:
            recommendations.append("Review extracted members and rejected-member reasons. ZIP, TAR and gzip are extracted within shared quotas; encrypted, RAR and 7z archives are retained for manual inspection.")
        if kind == "pdf":
            recommendations.append("Review pdfdetach's embedded attachment inventory and PDF text strings.")
        self.report["recommendations"] = recommendations

    def run(self):
        identification = self.run_stage("identification", 2, self.identification)
        if identification["status"] == "failed":
            self.report["status"] = "failed"
            self.report["errors"].extend(identification["errors"])
        else:
            for name, progress, method in (("tool_registry", 8, self.inventory), ("metadata", 12, self.metadata), ("strings", 18, self.strings), ("binary", 25, self.binary), ("signatures", 30, self.signatures), ("structure", 36, self.structure), ("flags", 42, self.flags), ("recursive_extraction", 48, self.extraction)):
                self.run_stage(name, progress, method)
            names = list(SPECS)
            for i, name in enumerate(names):
                self.run_stage(name, 56 + round(i / len(names) * 40), lambda name=name: self.cli_tool(name))
            from ..labs.image import analyze_image
            from ..labs.audio import analyze_audio
            from ..labs.forensics import analyze_forensics
            from ..labs.flags import scan_report
            from ..labs.recommendations import recommend
            self.run_stage('image_lab', 96, lambda: analyze_image(self))
            self.run_stage('audio_lab', 97, lambda: analyze_audio(self))
            self.run_stage('file_forensics', 98, lambda: analyze_forensics(self))
            self.run_stage('central_flags', 99, lambda: scan_report(self))
            self.recommendations()
            self.report['recommended_operations'] = recommend(self.report)
        self.report["completed_at"] = utc_now()
        self.report["limits"] = {"max_file_bytes": self.limits.max_file_bytes, "max_generated_bytes": self.limits.max_extracted_bytes, "max_artifacts": self.limits.max_artifacts, "max_extraction_depth": self.limits.max_depth, "max_compression_ratio": self.limits.max_ratio, "max_report_bytes": 4 * 1024 * 1024}
        self.bound_report()
        atomic_json(self.job / "report.json", self.report)
        atomic_json(self.job / "progress.json", {"progress": 100, "stage": self.report["status"]})
        return self.report

    def bound_report(self):
        """Reserve disk for atomic writes and supervisor failure-report updates.

        Raw bounded tool/strings artifacts retain details when structured previews
        exceed the report budget. Never produce partial/invalid JSON by slicing.
        """
        maximum = 4 * 1024 * 1024
        def size():
            return len(json.dumps(self.report, ensure_ascii=True, indent=2).encode("utf-8"))
        if size() <= maximum:
            return
        self.report["report_truncated"] = True
        self.report["recommendations"].append("Structured report previews reached their byte limit; review bounded raw output artifacts for additional details.")
        for result in self.report["analyzers"]:
            if "data" in result and len(json.dumps(result["data"], ensure_ascii=True)) > 65536:
                result["data"] = {"truncated": True, "detail": "Preview omitted to preserve report byte limit; see analyzer artifacts"}
        if size() <= maximum:
            return
        for result in self.report["analyzers"]:
            if len(result["findings"]) > 200:
                result["findings"] = result["findings"][:200]
                result["findings_truncated"] = True
        self.report["findings"] = self.report["findings"][:1000]
        if size() > maximum:
            # Keep a useful complete envelope even for unusually verbose decoders.
            self.report["findings"] = self.report["findings"][:300]
            for result in self.report["analyzers"]:
                result["findings"] = result["findings"][:30]
                result["errors"] = [error[:512] for error in result["errors"][:5]]
                if "data" in result:
                    result["data"] = {"truncated": True, "detail": "See analyzer artifacts"}
            for item in self.report["findings"]:
                item["detail"] = item["detail"][:1024]
            for result in self.report["analyzers"]:
                for item in result["findings"]:
                    item["detail"] = item["detail"][:1024]
        if size() > maximum:
            # Last resort is still a valid, reviewable bounded report. This is
            # defensive against an unexpectedly verbose parser-added field.
            self.report["findings"] = self.report["findings"][:100]
            for result in self.report["analyzers"]:
                result["findings"] = result["findings"][:5]


def analyze_job(job_dir: Path | str, mode="quick", limits: Limits | None = None):
    if mode not in {"quick", "deep"}:
        raise ValueError("Mode must be quick or deep")
    return Analysis(Path(job_dir), mode, limits or Limits.from_environment()).run()
