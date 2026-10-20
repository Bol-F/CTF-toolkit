"""Build repeatable, harmless CTF evidence with Python's standard library.

The archive attacks are filenames, links and compressed zero bytes only. They
exercise extraction policy without executing any uploaded code.
"""

from __future__ import annotations

import io
import json
import struct
import tarfile
import zipfile
import zlib
from pathlib import Path


def png_chunk(kind: bytes, value: bytes) -> bytes:
    return struct.pack(">I", len(value)) + kind + value + struct.pack(">I", zlib.crc32(kind + value) & 0xFFFFFFFF)


def png_with_text(text: bytes = b"Comment\0flag{png_text_chunk}") -> bytes:
    """A valid one-pixel RGB PNG whose tEXt chunk contains a flag."""
    return (
        b"\x89PNG\r\n\x1a\n"
        + png_chunk(b"IHDR", struct.pack(">IIBBBBB", 1, 1, 8, 2, 0, 0, 0))
        + png_chunk(b"tEXt", text)
        + png_chunk(b"IDAT", zlib.compress(b"\0\xff\0\0"))
        + png_chunk(b"IEND", b"")
    )


def zip_bytes(files: dict[str, bytes], compression: int = zipfile.ZIP_DEFLATED) -> bytes:
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", compression=compression) as archive:
        for name, value in files.items():
            entry = zipfile.ZipInfo(name, date_time=(2020, 1, 1, 0, 0, 0))
            entry.compress_type = compression
            archive.writestr(entry, value)
    return output.getvalue()


def nested_image() -> bytes:
    nested = zip_bytes({"answer.txt": b"Nested archive answer: CTF{nested_zip_flag}\n"})
    appended = zip_bytes({"clue.txt": b"flag{appended_zip_flag}\n", "nested.zip": nested})
    return png_with_text() + appended


def traversal_zip() -> bytes:
    return zip_bytes({
        "../../escaped.txt": b"must never escape the artifact directory",
        "/absolute.txt": b"absolute paths must be rejected",
        "C:/windows-path.txt": b"drive paths must be rejected on Linux too",
        "..\\backslash.txt": b"backslash traversal must be rejected",
        "safe.txt": b"flag{safe_archive_entry}\n",
    })


def symlink_tar() -> bytes:
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w") as archive:
        symlink = tarfile.TarInfo("escape")
        symlink.type = tarfile.SYMTYPE
        symlink.linkname = "../../outside"
        archive.addfile(symlink)
        hardlink = tarfile.TarInfo("hardlink")
        hardlink.type = tarfile.LNKTYPE
        hardlink.linkname = "/etc/passwd"
        archive.addfile(hardlink)
        content = b"flag{safe_tar_entry}\n"
        regular = tarfile.TarInfo("safe.txt")
        regular.size = len(content)
        archive.addfile(regular, io.BytesIO(content))
    return output.getvalue()


def compression_bomb() -> bytes:
    # Only 4 MiB if a regression decompresses it, yet over 1000:1 compressed.
    return zip_bytes({"too-compressible.txt": b"\0" * (4 * 1024 * 1024)})


def text_flags() -> bytes:
    return b"Visible flag{plain_ascii_flag}\n" + "UTF16 CTF{wide_text_flag}".encode("utf-16-le")


def deep_archive(depth: int = 10) -> bytes:
    value = b"flag{beyond_depth_limit}\n"
    for level in range(depth):
        suffix = "txt" if level == 0 else "zip"
        value = zip_bytes({f"layer-{level}.{suffix}": value})
    return value


def build_corpus(directory: Path) -> dict[str, Path]:
    directory.mkdir(parents=True, exist_ok=True)
    corpus = {
        "image.png": nested_image(),
        "text.bin": text_flags(),
        "traversal.zip": traversal_zip(),
        "links.tar": symlink_tar(),
        "bomb.zip": compression_bomb(),
        "deep.zip": deep_archive(),
        "empty.bin": b"",
        "truncated.png": b"\x89PNG\r\n\x1a\n\0\0\xff\xffIHDR",
    }
    for name, value in corpus.items():
        (directory / name).write_bytes(value)
    return {name: directory / name for name in corpus}


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path)
    arguments = parser.parse_args()
    result = build_corpus(arguments.directory)
    print(json.dumps({name: str(path) for name, path in result.items()}, indent=2))
