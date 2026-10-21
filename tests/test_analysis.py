from __future__ import annotations

import hashlib
import base64
import json
from pathlib import Path

import pytest

from stegolab.analysis.engine import analyze_job, flag_findings
from stegolab.analysis.extraction import Limits


@pytest.fixture(autouse=True)
def no_external_tools(monkeypatch):
    # Exercise the real unavailable-tool path, with native analysis still active.
    monkeypatch.setenv("PATH", "")
    monkeypatch.delenv("STEGOLAB_TOOL_REGISTRY", raising=False)


def make_job(directory: Path, value: bytes, filename="challenge.bin") -> Path:
    evidence = directory / "evidence"
    evidence.mkdir(parents=True)
    (evidence / "original.bin").write_bytes(value)
    (directory / "upload.json").write_text(json.dumps({
        "filename": filename, "size": len(value), "sha256": hashlib.sha256(value).hexdigest(),
    }), encoding="utf-8")
    return directory


def flag_values(report):
    return {finding["value"] for finding in report["findings"] if finding["type"] == "flag"}


def test_quick_scan_identifies_content_hash_flags_offsets_and_appended_archive(tmp_path: Path, corpus):
    value = corpus["image.png"].read_bytes()
    job = make_job(tmp_path / "quick", value, "misleading.txt")
    report = analyze_job(job, "quick")
    assert report["status"] == "completed"
    assert report["file"]["format"] == "png"
    assert report["file"]["sha256"] == hashlib.sha256(value).hexdigest()
    assert "flag{png_text_chunk}" in flag_values(report)
    flag = next(finding for finding in report["findings"] if finding.get("value") == "flag{png_text_chunk}")
    assert flag["offset"] == value.index(b"flag{png_text_chunk}")
    assert any(finding["type"] == "extension_mismatch" for finding in report["findings"])
    appended = next(finding for finding in report["findings"] if finding["type"] == "appended_data")
    assert value[appended["offset"]:].startswith(b"PK\x03\x04")
    assert any(finding["type"] == "embedded_signature" and finding["format"] == "zip" for finding in report["findings"])
    assert not any(artifact["kind"] in {"extracted", "carved"} for artifact in report["artifacts"])
    assert json.loads((job / "report.json").read_text()) == report
    assert json.loads((job / "progress.json").read_text())["progress"] == 100
    assert (job / "evidence" / "original.bin").read_bytes() == value
    assert report["recommendations"]


def test_deep_scan_extracts_real_nested_archive_and_finds_hidden_flags(tmp_path: Path, corpus):
    value = corpus["image.png"].read_bytes()
    job = make_job(tmp_path / "deep", value, "challenge.png")
    report = analyze_job(job, "deep")
    assert report["status"] == "completed"
    assert {"flag{png_text_chunk}", "flag{appended_zip_flag}", "CTF{nested_zip_flag}"} <= flag_values(report)
    extracted = [artifact for artifact in report["artifacts"] if artifact["kind"] == "extracted"]
    assert {"clue.txt", "nested.zip", "answer.txt"} <= {artifact["name"] for artifact in extracted}
    for artifact in extracted:
        target = (job / "artifacts" / artifact["path"]).resolve()
        assert target.is_relative_to((job / "artifacts").resolve())
        assert hashlib.sha256(target.read_bytes()).hexdigest() == artifact["sha256"]
        assert target.stat().st_size == artifact["size"]
    assert any(artifact["kind"] == "carved" and value[artifact["offset"]:].startswith(b"PK") for artifact in report["artifacts"])
    assert (job / "evidence" / "original.bin").read_bytes() == value


def test_all_analyzers_have_consistent_envelopes_and_missing_tools_are_explicit(tmp_path: Path):
    job = make_job(tmp_path / "unavailable", b"flag{native_tools_work}")
    report = analyze_job(job, "deep")
    assert "flag{native_tools_work}" in flag_values(report)
    assert len(report["tools"]) >= 15
    unavailable = {result["name"] for result in report["analyzers"] if result["status"] == "unavailable"}
    assert {"exiftool", "binwalk", "zsteg", "steghide", "ffprobe"} <= unavailable
    for result in report["analyzers"]:
        assert {"name", "status", "findings", "errors", "artifacts", "duration_ms"} <= result.keys()
        assert isinstance(result["errors"], list)
        for finding in result["findings"]:
            assert {"type", "title", "detail", "offset", "confidence"} <= finding.keys()
            assert 0 <= finding["confidence"] <= 1
            assert finding["offset"] is None or finding["offset"] >= 0


def test_utf16_flag_reports_the_actual_byte_offset(tmp_path: Path, corpus):
    value = corpus["text.bin"].read_bytes()
    report = analyze_job(make_job(tmp_path / "unicode", value), "quick")
    wide = [finding for finding in report["findings"] if finding.get("value") == "CTF{wide_text_flag}"]
    assert wide
    assert {finding["offset"] for finding in wide} == {value.index("CTF{wide_text_flag}".encode("utf-16-le"))}
    assert "flag{plain_ascii_flag}" in flag_values(report)


def test_strings_json_remains_valid_when_output_is_capped(tmp_path: Path):
    value = b"abcd\0" * 15000
    job = make_job(tmp_path / "many-strings", value)
    report = analyze_job(job, "quick")
    artifact = next(artifact for artifact in report["artifacts"] if artifact["name"] == "strings.json")
    records = json.loads((job / "artifacts" / artifact["path"]).read_text())
    assert isinstance(records, list)
    assert 0 < len(records) <= 10000
    assert artifact["size"] <= 1048576


@pytest.mark.parametrize("name", ["truncated.png", "empty.bin"])
def test_malformed_and_empty_evidence_produce_reports_instead_of_crashing(tmp_path: Path, corpus, name):
    job = make_job(tmp_path / name, corpus[name].read_bytes(), name)
    report = analyze_job(job, "deep")
    assert report["status"] == "completed"
    assert (job / "report.json").is_file()
    if name.endswith(".png"):
        assert next(result for result in report["analyzers"] if result["name"] == "structure")["errors"]
    else:
        assert any(finding["type"] == "validation" for finding in report["findings"])


def test_evidence_over_limit_has_failed_report(tmp_path: Path):
    report = analyze_job(make_job(tmp_path / "oversize", b"0123456789"), "quick", Limits(max_file_bytes=4))
    assert report["status"] == "failed"
    assert report["errors"]
    assert report["artifacts"] == []


def test_hash_mismatch_is_reported_as_evidence_integrity_finding(tmp_path: Path):
    job = make_job(tmp_path / "integrity", b"flag{evidence}")
    (job / "evidence" / "original.bin").write_bytes(b"changed evidence")
    report = analyze_job(job, "quick")
    assert any(finding["type"] == "integrity" and "hash mismatch" in finding["title"].lower() for finding in report["findings"])


@pytest.mark.parametrize("value,expected", [
    (b"flag{}", []),
    (b"flag{" + b"x" * 256 + b"}", ["flag{" + "x" * 256 + "}"]),
    (b"flag{" + b"x" * 257 + b"}", []),
    (b"flag{broken\nline}", []),
    (b"flag{" * 10000, []),
    (b"mycontestctf{custom_prefix}", ["mycontestctf{custom_prefix}"]),
], ids=["empty-body", "max-body", "oversize-body", "newline-body", "incomplete-prefixes", "custom-prefix"])
def test_flag_candidate_boundaries_and_incomplete_data(value, expected):
    assert [finding["value"] for finding in flag_findings(value)] == expected


@pytest.mark.parametrize("encoding", ["utf-16-le", "utf-16-be"])
def test_wide_flag_offsets_are_bytes_in_both_byte_orders(encoding):
    prefix = b"An ASCII introduction\n"
    value = prefix + "Clue: CTF{wide_order}".encode(encoding)
    findings = flag_findings(value)
    match = [finding for finding in findings if finding["value"] == "CTF{wide_order}"]
    assert len(match) == 1
    assert match[0]["offset"] == len(prefix) + len("Clue: ".encode(encoding))
    assert match[0]["encoding"] == encoding


def test_encoded_flag_records_encoded_source_offset_and_decoded_offset(tmp_path: Path):
    token = base64.b64encode(b"Clue: flag{encoded_evidence}")
    value = b"Encoded clue: " + token + b"\n"
    report = analyze_job(make_job(tmp_path / "encoded", value), "quick")
    match = next(finding for finding in report["findings"] if finding.get("value") == "flag{encoded_evidence}")
    assert match["offset"] == value.index(token)
    assert match["decoded_offset"] == len(b"Clue: ")
    assert match["encoding"] == "base64"
