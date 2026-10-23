# Public CTF examples

These small files are authored, benign known-answer challenges under the repository's MIT license. The visible flags are intentional test answers, not credentials. They contain no executable payloads and no private evidence. `expected.json` lists answers, operations and SHA-256 checksums.

| File | Investigation |
| --- | --- |
| `metadata.png` | Quick Scan; inspect its PNG Comment/text chunk for `flag{example_metadata}`. |
| `appended.png` | Deep Scan; inspect the appended ZIP, download `clue.txt`, and inspect the nested ZIP. Expected flags: `flag{example_appended_zip}` and `CTF{example_nested_archive}`. |
| `lsb.png` | Deep Scan or Image lab LSB extraction: RGB, bit 0, row order, MSB byte packing. Expected `flag{example_rgb_lsb}`. Channel/bit-plane visualization is also useful. |
| `encoded.txt` | Paste/upload into Crypto Lab, add Base64 decode then Base32 decode. Expected `picoCTF{example_two_stage_decode}`. |

Regenerate exactly these files with the standard library:

```sh
python examples/generate.py
```

For QR/OCR, GIF, stereo tones and a synthetic frequency-glyph audio example, install development dependencies and run `python -m tests.fixtures.advanced ./sample-evidence/advanced`. Those fixtures are generated locally; no challenge is downloaded.
