# StegoLab interactive labs

The existing FastAPI/SQLite queue and restricted worker are retained. Automatic scans now add image, audio, file-structure and central flag stages. Explicit operations create child jobs with copied original evidence, independent output directories, the same CPU/address-space/time/output limits and cancellation. A parent cannot be deleted while it has an active child. Existing evidence is never modified by a lab operation.

## Image semantics

Supported raster decoders are Pillow's PNG, BMP, JPEG, GIF, TIFF and WebP. RGB and alpha previews are generated separately as opaque PNGs: browser alpha premultiplication cannot erase RGB beneath transparent pixels. The preview is at most 1024×1024. Browser canvas channel/plane/invert/brightness/contrast/gamma and absolute differences operate on those sanitized preview bytes. They are immediate, local display operations. Full-resolution LSB extraction runs in the worker, never on a resized preview.

LSB options are explicit: channel order (e.g. RGB/BGR/A), ordered bit list (e.g. 0 or 0,1), rows or columns, reversed pixel traversal, frame index, skipped bits, and packed-byte order. Per pixel, channels are read in the given order; per channel, bits are emitted in the listed order. `msb` makes the first emitted bit the high bit of an output byte; `lsb` makes it the low bit. Output offsets refer to the packed bitstream and cannot be mapped directly onto compressed image-file offsets. Partial trailing bytes are omitted. JPEG pixel LSB extraction is possible but does not reverse JPEG-domain embedding algorithms.

Bounds: 32 million decoded pixels, 8 million pixels for native LSB operations, 1 MiB LSB output, 256 selectable source frames, 16 automatic GIF frames, and 16 million aggregate GIF frame pixels. GIF extraction preserves decoded frame timing/disposal metadata and hashes plus changed-pixel fractions. Metadata warnings are observations, not claims of hidden data.

## Byte and container inspection

`GET /api/jobs/{id}/bytes?offset=0&length=1024&artifact_id=...` reads at most 4 KiB from a completed source. The browser pages 512 bytes and shows hexadecimal and decimal locations. Structure/entropy clicks seek the same byte source. Arbitrary paths are never accepted. Extracted members can become new Deep Scan jobs via the archive explorer.

Up to 512 entropy windows cover the complete evidence. Embedded candidates remain signature candidates until format-specific checks pass. PNG validates chunk bounds/CRCs/IHDR/IEND through native parsing and Pillow. ZIP validates EOCD, central records and referenced local headers without decompressing all payloads. Gzip checks a complete stream/checksum within a 1 MiB validation budget. Image structure verification has explicit extent limitations. PDF magic/EOF alone never yields a confirmed embedded file. Up to eight validated regions (each ≤4 MiB) are carved per scan. This is structure validation, not authenticity or a promise that a payload is safe.

## Audio semantics

FFmpeg decodes up to 30 seconds to normalized 22,050 Hz stereo PCM. Native PCM WAV fallback supports mono/stereo 8/16/24/32-bit samples, with bounded resampling for display. Original codec/channel metadata remains in ffprobe results. Per-channel waveform min/max envelopes, a Hann-window STFT (1024 samples, hop 256), average frequency spectrum, RMS and peak frequency are calculated with NumPy. The linear frequency spectrogram spans −90 to 0 dB and supports hover coordinates, seeking, zoom and PNG export. Exported channel WAVs are inspection copies, not original evidence. SoX `stat` reads normalized PCM with the same tool limits.

## Recipe semantics

`POST /api/recipes` accepts UTF-8, hex or Base64 input and up to 20 ordered transformation steps. Input ≤64 KiB, each output ≤1 MiB and all intermediate bytes ≤4 MiB. Recipes execute as worker jobs; final bytes and intermediate representations are downloadable. Larger structured intermediates use a JSON artifact to keep the summary report bounded. Binary values retain Base64/hex representations even when invalid UTF-8. XOR consumes a hexadecimal key and preserves raw bytes. Unicode text reversal differs from byte reversal. Gzip/zlib decompression rejects incomplete/trailing/concatenated streams and enforces output bounds.

Operations: Base64/32/85, hex, binary, decimal/ASCII, URL, ROT13/47, Caesar, Atbash, Vigenere encryption/decryption, XOR, text/byte reversal, MD5/SHA-1/SHA-256/SHA-512, gzip/zlib decompression, UTF-8 validation and Unicode escaping/unescaping. ASCII encoding means decimal byte values, not lossy Unicode conversion.

## Flag evidence and recommendations

Raw patterns are exact format matches; decoded/OCR/LSB sources retain method/history and are contextual candidates. No mode asserts that a flag was accepted by a CTF server. Missing offsets are null rather than invented compressed-file locations. A supplied regex is limited to 256 characters and each matching call has a 50 ms timeout. Prefixes are escaped literals. Scanning is bounded to 64 MiB total source bytes, 500 matches, four heuristic decoding steps and bounded token/work budgets. Large/complex input may produce partial results. Original-byte patterns are scanned in overlapping windows; default native UTF-16 findings retain their byte offsets.

Recommendation objects contain operation, title, why and observed evidence. Rules cover lossless pixels, lossy JPEG-compatible tools, GIF frames, audio channels/spectrograms, PDF objects/attachments, ZIP validation/extraction and decoded text. They do not assign certainty that a secret exists.

## Explicit endpoints

- `POST /api/jobs/{id}/actions`: `image_prepare`, `image_lsb`, `audio_analyze`, `flag_scan`, `tool_extract`, `pdf_extract`, or `inspect`; optional artifact ID selects a reported child source.
- `POST /api/recipes`: ordered byte transformations; `GET /api/recipes/operations` advertises names and limits.
- `GET /api/jobs/{id}/preview/{artifact_id}`: only generated PNG/PCM artifacts explicitly marked as previews. Arbitrary extracted content always remains an opaque attachment.

Passwords are held only in a mode-0600 action file until completion/cancellation, omitted from public jobs/reports and redacted from diagnostics. Deleting or cancelling queued actions removes their stored parameters. The shared-worker UID/container boundary from the original deployment still applies.
