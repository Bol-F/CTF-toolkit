"""Regenerate the small, public known-answer CTF examples (standard library only)."""
from __future__ import annotations

import base64
import hashlib
import io
import json
from pathlib import Path
import struct
import zipfile
import zlib


ROOT = Path(__file__).resolve().parent


def chunk(kind, content):
    return struct.pack('>I', len(content)) + kind + content + struct.pack('>I', zlib.crc32(kind + content) & 0xffffffff)


def png(pixels, metadata=None):
    content = b'\x89PNG\r\n\x1a\n' + chunk(b'IHDR', struct.pack('>IIBBBBB', 64, 64, 8, 2, 0, 0, 0))
    if metadata:
        content += chunk(b'tEXt', b'Comment\0' + metadata)
    raw = b''.join(b'\0' + pixels[row * 192:(row + 1) * 192] for row in range(64))
    return content + chunk(b'IDAT', zlib.compress(raw, 9)) + chunk(b'IEND', b'')


def archive(members):
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, 'w') as output:
        for name, data in members.items():
            entry = zipfile.ZipInfo(name, date_time=(2020, 1, 1, 0, 0, 0))
            entry.compress_type = zipfile.ZIP_DEFLATED
            output.writestr(entry, data)
    return stream.getvalue()


def main():
    pixels = bytearray([128, 156, 190] * (64 * 64))
    secret = b'flag{example_rgb_lsb}\0'
    for index, bit in enumerate(''.join(f'{byte:08b}' for byte in secret)):
        pixels[index] = (pixels[index] & 254) | int(bit)
    nested = archive({'answer.txt': b'CTF{example_nested_archive}\n'})
    samples = {
        'lsb.png': png(pixels),
        'metadata.png': png(bytes([40, 72, 106] * (64 * 64)), b'flag{example_metadata}'),
        'appended.png': png(bytes([40, 72, 106] * (64 * 64))) + archive({'clue.txt': b'flag{example_appended_zip}\n', 'nested.zip': nested}),
        'encoded.txt': base64.b64encode(base64.b32encode(b'picoCTF{example_two_stage_decode}')) + b'\n',
    }
    expected = {
        'lsb.png': {'flags': [secret[:-1].decode()], 'operation': 'RGB channels, bit 0, row order, MSB byte packing'},
        'metadata.png': {'flags': ['flag{example_metadata}'], 'operation': 'metadata/text chunk inspection'},
        'appended.png': {'flags': ['flag{example_appended_zip}', 'CTF{example_nested_archive}'], 'operation': 'Deep Scan: appended ZIP and nested ZIP extraction'},
        'encoded.txt': {'flags': ['picoCTF{example_two_stage_decode}'], 'recipe': ['base64_decode', 'base32_decode']},
    }
    for name, content in samples.items():
        (ROOT / name).write_bytes(content)
        expected[name]['sha256'] = hashlib.sha256(content).hexdigest()
    (ROOT / 'expected.json').write_text(json.dumps(expected, indent=2) + '\n', encoding='utf-8')
    print(f'Generated {len(samples)} benign examples in {ROOT}')


if __name__ == '__main__':
    main()
