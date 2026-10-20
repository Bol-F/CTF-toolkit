from __future__ import annotations

import gzip
from pathlib import Path

import pytest

from stegolab.analysis.extraction import Extractor, Limits, safe_member_name
from tests.fixtures.corpus import zip_bytes


@pytest.mark.parametrize("name", [
    "../outside.txt", "dir/../../outside.txt", "/absolute.txt", "..\\outside.txt",
    "C:/outside.txt", "C:relative.txt", "\\\\server\\share\\payload", "dir/file:stream", "bad\x00name",
])
def test_archive_path_policy_rejects_cross_platform_escape(name):
    assert safe_member_name(name) is False


def test_zip_traversal_is_rejected_but_safe_member_is_retained(tmp_path: Path, corpus):
    extractor = Extractor(tmp_path / "artifacts", Limits())
    extractor.extract(corpus["traversal.zip"])
    assert [artifact["name"] for artifact in extractor.artifacts] == ["safe.txt"]
    rejected = [finding for finding in extractor.findings if finding["type"] == "rejected_member"]
    assert len(rejected) == 4
    assert all(finding["reason"] == "unsafe path" for finding in rejected)
    assert not (tmp_path / "escaped.txt").exists()
    for artifact in extractor.artifacts:
        target = (extractor.root / artifact["path"]).resolve()
        assert target.is_relative_to(extractor.root)
        assert target.read_bytes() == b"flag{safe_archive_entry}\n"
        assert not target.is_symlink()


def test_tar_links_never_create_filesystem_links(tmp_path: Path, corpus):
    extractor = Extractor(tmp_path / "artifacts", Limits())
    extractor.extract(corpus["links.tar"])
    assert [artifact["name"] for artifact in extractor.artifacts] == ["safe.txt"]
    rejected = [finding for finding in extractor.findings if finding["type"] == "rejected_member"]
    assert {finding["member"] for finding in rejected} == {"escape", "hardlink"}
    assert all("links" in finding["reason"] for finding in rejected)
    assert all(not path.is_symlink() for path in extractor.root.rglob("*"))


def test_high_compression_ratio_is_rejected_before_decompression(tmp_path: Path, corpus):
    extractor = Extractor(tmp_path / "artifacts", Limits(max_ratio=100))
    extractor.extract(corpus["bomb.zip"])
    assert extractor.artifacts == []
    assert extractor.bytes_written == 0
    assert any("compression ratio" in finding.get("reason", "") for finding in extractor.findings)
    assert list(extractor.output.iterdir()) == []


def test_total_byte_quota_and_count_quota_are_shared_across_members(tmp_path: Path):
    source = tmp_path / "members.zip"
    source.write_bytes(zip_bytes({"one.bin": bytes(range(32)), "two.bin": bytes(range(64))}))
    byte_limited = Extractor(tmp_path / "byte-artifacts", Limits(max_extracted_bytes=48))
    byte_limited.extract(source)
    assert len(byte_limited.artifacts) == 1
    assert sum(artifact["size"] for artifact in byte_limited.artifacts) == 32
    assert any("quota" in finding.get("reason", "") for finding in byte_limited.findings)
    count_limited = Extractor(tmp_path / "count-artifacts", Limits(max_artifacts=1))
    count_limited.extract(source)
    assert len(count_limited.artifacts) == 1
    assert any("count limit" in error for error in count_limited.errors)


def test_recursive_archive_stops_at_depth_limit(tmp_path: Path, corpus):
    extractor = Extractor(tmp_path / "artifacts", Limits(max_depth=2))
    extractor.extract(corpus["deep.zip"])
    assert len(extractor.artifacts) == 2
    assert max(artifact["depth"] for artifact in extractor.artifacts) == 2
    assert any(finding["type"] == "extraction_limit" for finding in extractor.findings)
    assert not any(b"flag{beyond_depth_limit}" in (extractor.root / artifact["path"]).read_bytes() for artifact in extractor.artifacts)


def test_gzip_streaming_limit_removes_partial_output(tmp_path: Path):
    source = tmp_path / "bomb.gz"
    source.write_bytes(gzip.compress(b"\0" * (2 * 1024 * 1024), mtime=0))
    extractor = Extractor(tmp_path / "artifacts", Limits(max_extracted_bytes=1024, max_ratio=1000))
    extractor.extract(source)
    assert extractor.artifacts == []
    assert list(extractor.output.iterdir()) == []
    assert any("limit" in finding.get("reason", "") for finding in extractor.findings)
