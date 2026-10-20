from __future__ import annotations

import sys
import time
from pathlib import Path

from stegolab.analysis.tools import registry_snapshot, run_command


def test_registry_reports_missing_optional_tools_without_failing(monkeypatch):
    monkeypatch.setenv("PATH", "")
    tools = registry_snapshot()
    names = {tool["name"] for tool in tools}
    assert {"exiftool", "binwalk", "steghide", "zsteg", "ffmpeg", "pdfdetach"} <= names
    assert all(tool["available"] is False for tool in tools)
    assert all(tool["version"] is None for tool in tools)
    for tool in tools:
        assert tool["formats"]
        assert tool["parameters"]
        assert tool["parser"]
        assert tool["error_handling"]
        assert tool["limits"]["shell"] is False
        assert 0 < tool["limits"]["timeout_seconds"] <= 60
        assert 0 < tool["limits"]["output_bytes"] <= 4194304


def test_tool_output_limit_applies_across_both_streams(tmp_path: Path):
    result = run_command(
        [sys.executable, "-c", "import sys; sys.stdout.write('a'*200000); sys.stdout.flush(); sys.stderr.write('b'*200000)"],
        tmp_path,
        timeout=5,
        max_output=2048,
    )
    assert result["status"] == "partial"
    assert result["output_truncated"] is True
    assert len(result["stdout"].encode()) + len(result["stderr"].encode()) <= 2048


def test_tool_timeout_terminates_the_process(tmp_path: Path):
    started = time.monotonic()
    result = run_command([sys.executable, "-c", "import time; time.sleep(30)"], tmp_path, timeout=0.2)
    assert result["status"] == "timeout"
    assert result["returncode"] is not None
    assert time.monotonic() - started < 8


def test_tool_runner_uses_literal_arguments_and_does_not_inherit_secrets(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("STEGOLAB_TEST_SECRET", "must-not-reach-a-tool")
    literal = "flag{literal_argument}; $(touch injected); & echo unexpected"
    code = "import os,sys; print(sys.argv[1]); print(os.environ.get('STEGOLAB_TEST_SECRET','absent'))"
    result = run_command([sys.executable, "-c", code, literal], tmp_path, timeout=5)
    assert result["status"] == "completed"
    assert result["stdout"].splitlines() == [literal, "absent"]
    assert not (tmp_path / "injected").exists()


def test_missing_program_is_a_structured_failure(tmp_path: Path):
    result = run_command([str(tmp_path / "nonexistent-tool")], tmp_path, timeout=1)
    assert result["status"] == "failed"
    assert result["returncode"] is None
    assert result["stderr"]
