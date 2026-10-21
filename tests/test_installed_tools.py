"""Exercise real installed adapters; missing host tools are explicitly skipped.

The Docker image supplies the tools and its ImageMagick policy. No CLI responses
are mocked, and fixtures are harmless images, PCM audio and a PDF text page.
"""
from __future__ import annotations

import hashlib
import json
import math
from pathlib import Path
import struct
import wave

import pytest
from PIL import Image, ImageDraw, PngImagePlugin

from stegolab.analysis.engine import analyze_job
from stegolab.analysis.tools import registry_snapshot, run_command


def minimal_pdf() -> bytes:
    stream = b"BT /F1 12 Tf 20 80 Td (flag{pdf_text_fixture}) Tj ET\n"
    objects = [
        b"<< /Type /Catalog /Pages 2 0 R >>",
        b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 240 120] /Resources << /Font << /F1 5 0 R >> >> /Contents 4 0 R >>",
        b"<< /Length " + str(len(stream)).encode() + b" >>\nstream\n" + stream + b"endstream",
        b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
    ]
    data = bytearray(b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n")
    offsets = [0]
    for index, value in enumerate(objects, 1):
        offsets.append(len(data))
        data.extend(f"{index} 0 obj\n".encode() + value + b"\nendobj\n")
    xref = len(data)
    data.extend(f"xref\n0 {len(offsets)}\n0000000000 65535 f \n".encode())
    for offset in offsets[1:]:
        data.extend(f"{offset:010d} 00000 n \n".encode())
    data.extend(f"trailer\n<< /Size {len(offsets)} /Root 1 0 R >>\nstartxref\n{xref}\n%%EOF\n".encode())
    return bytes(data)


def job_for(root: Path, source: Path):
    directory = root / source.stem
    (directory / "evidence").mkdir(parents=True)
    value = source.read_bytes()
    (directory / "evidence" / "original.bin").write_bytes(value)
    (directory / "upload.json").write_text(json.dumps({
        "filename": source.name, "size": len(value), "sha256": hashlib.sha256(value).hexdigest(),
    }), encoding="utf-8")
    return directory


@pytest.fixture(scope="module")
def installed_registry():
    return {tool["name"]: tool for tool in registry_snapshot()}


@pytest.fixture(scope="module")
def installed_reports(tmp_path_factory, installed_registry):
    root = tmp_path_factory.mktemp("installed-tool-analysis")
    registry_file = root / "tools.json"
    registry_file.write_text(json.dumps(list(installed_registry.values())), encoding="utf-8")

    png = root / "raster.png"
    image = Image.new("RGB", (256, 128), "white")
    ImageDraw.Draw(image).text((12, 40), "STEGOLAB CTF", fill="black", font_size=24)
    metadata = PngImagePlugin.PngInfo()
    metadata.add_text("Comment", "flag{tool_metadata}")
    image.save(png, pnginfo=metadata)

    audio = root / "audio.wav"
    samples = b"".join(struct.pack("<h", round(14000 * math.sin(2 * math.pi * 440 * n / 16000))) for n in range(16000))
    with wave.open(str(audio), "wb") as stream:
        stream.setnchannels(1)
        stream.setsampwidth(2)
        stream.setframerate(16000)
        stream.writeframes(samples)
    if installed_registry["steghide"]["available"]:
        secret = root / "embedded-secret.txt"
        secret.write_bytes(b"flag{steghide_actual_payload}\n")
        stego = root / "stego.wav"
        result = run_command([
            installed_registry["steghide"]["executable"], "embed", "-cf", str(audio),
            "-ef", str(secret), "-sf", str(stego), "-p", "", "-f", "-q",
        ], root, timeout=10)
        assert result["status"] == "completed", result
        assert stego.is_file()
        audio = stego

    pdf = root / "document.pdf"
    pdf.write_bytes(minimal_pdf())
    with pytest.MonkeyPatch.context() as patch:
        patch.setenv("STEGOLAB_TOOL_REGISTRY", str(registry_file))
        yield {
            "png": analyze_job(job_for(root / "jobs", png), "deep"),
            "wav": analyze_job(job_for(root / "jobs", audio), "deep"),
            "pdf": analyze_job(job_for(root / "jobs", pdf), "deep"),
        }


def tool_result(report, name):
    return next(result for result in reversed(report["analyzers"]) if result["name"] == name)


@pytest.mark.parametrize("tool,format", [
    ("file", "png"), ("exiftool", "png"), ("binwalk", "png"),
    ("pngcheck", "png"), ("imagemagick", "png"), ("foremost", "png"),
    ("tesseract", "png"), ("zbarimg", "png"), ("zsteg", "png"),
    ("ffprobe", "wav"), ("ffmpeg", "wav"), ("steghide", "wav"),
    ("pdfdetach", "pdf"),
])
def test_installed_adapter_completes_real_file_analysis(tool, format, installed_registry, installed_reports):
    if not installed_registry[tool]["available"]:
        pytest.skip(f"Optional host tool {tool} is unavailable; Docker supplies it")
    report = installed_reports[format]
    assert report["status"] == "completed"
    result = tool_result(report, tool)
    assert result["status"] == "completed", {"tool": tool, "result": result}
    assert result["returncode"] == (4 if tool == "zbarimg" else 0)
    assert result["artifacts"]
    if tool in {"exiftool", "ffprobe"}:
        assert result["data"]
    if tool == "pngcheck":
        assert not any("CRC mismatch" in finding["title"] for finding in report["findings"])
    if tool == "steghide":
        output = "\n".join(finding["detail"] for finding in result["findings"])
        assert "embedded-secret.txt" in output


def test_native_strings_and_hex_remain_available_with_cli_inventory(installed_registry, installed_reports):
    report = installed_reports["png"]
    assert next(result for result in report["analyzers"] if result["name"] == "strings")["status"] == "completed"
    assert {"strings.json", "header-hexdump.txt"} <= {artifact["name"] for artifact in report["artifacts"]}
    for tool in ("strings", "xxd"):
        assert tool_result(report, tool)["status"] == ("skipped" if installed_registry[tool]["available"] else "unavailable")


def test_imagemagick_policy_rejects_mvg_input(tmp_path: Path, installed_registry):
    tool = installed_registry["imagemagick"]
    if not tool["available"]:
        pytest.skip("Optional host ImageMagick is unavailable; Docker supplies it")
    mvg = tmp_path / "safe-but-disallowed.mvg"
    mvg.write_text("push graphic-context\nviewbox 0 0 10 10\nfill white\nrectangle 0,0 9,9\npop graphic-context\n", encoding="ascii")
    executable = tool["executable"]
    command = [executable, *(["identify"] if Path(executable).stem == "magick" else []), "-ping", f"mvg:{mvg}"]
    result = run_command(command, tmp_path, timeout=5)
    assert result["status"] == "failed", result
    assert "security policy" in result["stderr"].lower() or "not authorized" in result["stderr"].lower(), result
