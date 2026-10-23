# StegoLab

A self-hosted CTF steganography and forensic investigation platform. Preserve uploaded evidence, inspect real analyzer results, explore image/audio clues, follow decoding chains, and export reproducible reports. No account, API key, CDN or cloud service is used at runtime.

## Run

Install Docker Engine with Compose v2 (or Docker Desktop):

```sh
git clone https://github.com/Bol-F/CTF-toolkit.git
cd CTF-toolkit
docker compose up -d --build
```

Open **http://localhost:8080** and wait for “Local worker online.” The first build downloads dependencies; scans then work offline. Allow approximately 2 GB of image space and 3 GB available RAM. Useful commands:

```sh
docker compose ps
docker compose logs --tail=100 web worker
docker compose down
```

The `stegolab-data` volume retains evidence/reports across restarts and `down`. Delete finished jobs in Jobs to release their files and reservations. Do not remove the volume if you need the evidence.

## Investigation workspace

The dark interface has an optional light theme and Beginner/Advanced controls. Dashboard summarizes the latest 100 investigations and their uploads/active scans, worker status and actual tool availability; those counters are not lifetime totals. File Analyzer combines an evidence tree, resizable workspace/inspector panels, findings, byte views, metadata, generated previews and extracted artifacts. Stego Studio and Audio Analyzer reuse those real image/audio operations. Flag Finder searches candidates across stored investigations and opens their evidence. Reports exports JSON and Markdown. PDF export is not provided.

Drag/drop or select multiple evidence files, choose Quick/Deep Scan, follow progress, cancel work, and return through persistent scan history. A completed job can contain unavailable or failed optional analyzers: review their statuses and evidence. Jobs persist until explicitly deleted; active child operations protect their source from deletion.

Keyboard shortcuts: `Ctrl/Cmd+O` opens the file picker, `Ctrl/Cmd+Shift+F` opens central Flag Finder, `Alt+Left/Right` switches evidence tabs, and `?` opens shortcut help. Focus a panel separator and use Left/Right to resize it. Recipe editing provides explicit Undo/Redo controls.

## Features

**Quick Scan:** SHA-256, actual format/MIME identification, filename/type mismatch checks, metadata, ASCII/UTF-16 strings with byte offsets, a 4 KiB header dump, sampled entropy, embedded signatures, logical-end/appended-data checks, fixed CTF flag patterns, bounded Base64/hex/URL/ROT13 candidates, and applicable file/ExifTool/pngcheck checks.

**Deep Scan:** adds bounded recursive ZIP/TAR/gzip extraction, recognized appended-payload carving, flag checks in members, OCR, barcodes, bit-plane checks and applicable binary/media/PDF tools. Possible signatures and flags are heuristic leads; confidence is not a calibrated probability.

The responsive browser workbench provides progress, cancellation, history, deletion, searchable findings/strings, metadata, hex, analyzer notices, artifact downloads, JSON export, tool status and encoding/hash/XOR utilities. XOR accepts a repeating hexadecimal key over UTF-8 input and returns hex. MD5/SHA-1 support forensic comparison, not password storage.

### Interactive analysis labs

- **Image lab:** immediate RGB/alpha channel and bit-plane 0–7 views, inversion, brightness/contrast/gamma, absolute difference, zoom and PNG export. Worker-native LSB extraction supports ordered RGBA channels, ordered bit planes, row/column traversal, reverse pixel direction, MSB/LSB byte packing, frame selection and bit skipping. PNG chunk/CRC inspection, appended data, GIF frame timing/difference/extraction and unusual metadata findings are included.
- **Forensics:** paged HEX/ASCII bytes with decimal/hex offsets, byte selection, clickable chunk/embedded-region maps, entropy plot, archive member explorer, and recursive inspection of extracted artifacts. A separate validation stage distinguishes complete embedded structures from magic-byte candidates.
- **Audio lab:** playback, waveform, per-channel PCM downloads, interactive/zoomable spectrogram, frequency spectrum and peaks, stereo separation, SoX statistics, FFmpeg metadata/encoding checks and spectrogram PNG export.
- **Crypto lab:** byte-preserving, reorderable recipes with intermediate results and final-byte download. Base64/32/85, hex, binary/decimal/ASCII, URL, ROT13/47, Caesar, Atbash, Vigenere, XOR, reverse text/bytes, hashes, gzip/zlib and UTF-8/Unicode escape operations are supported.
- **Flag Finder:** scans original evidence, metadata, decoded strings, extracted members, LSB output, OCR and QR contents. Configurable prefixes and a timeout-bounded custom regex are supported. Candidates retain source, offsets when known, method, transformation history and evidence. A confirmed **pattern match** does not guarantee a challenge answer.
- **Recommendations:** deterministic operations with specific evidence and an explanation of why the check may help. No hidden-message guarantees.

See [lab behavior and limits](docs/LABS.md). Native parsing and extraction stay in the network-disabled worker; the browser renders only generated PNG/PCM previews and visual transformations of those sanitized pixels. No raw uploaded image/audio is rendered inline.

## Tools

The Tools screen and `/api/tools` report actual worker versions, formats, fixed parameters, availability, limits, parser and error handling. Missing optional tools return `unavailable`, inapplicable/mode-excluded checks return `skipped`, and failures do not abort native analysis.

| Tool | Integration |
| --- | --- |
| ExifTool | JSON metadata |
| Binwalk | Signature/offset scanning; external automatic extraction disabled |
| strings | Installed; native bounded ASCII/UTF-16 scanner supplies offsets |
| xxd / Python | Native bounded hex inspection; xxd optional |
| file / libmagic | Content-based MIME identification |
| pngcheck | PNG integrity/chunk diagnostics |
| ImageMagick | Raster-only, first-frame `identify -ping` |
| foremost | Audit-only; native extraction controls generated files |
| Tesseract | English OCR |
| zbarimg | Barcode/QR text |
| ffprobe / ffmpeg | JSON metadata and up to ten seconds of decoder checks; file/pipe protocols only |
| pdfdetach | Attachment inventory |
| zsteg | PNG/BMP bit-plane checks |
| steghide | Capacity/metadata with empty password; no guessing |
| SoX | Audio statistics on normalized PCM previews |

Specialized tools are explicit tasks, never automatic password sweeps. The core includes zsteg and steghide; additional supported tools are installed in a separate optional worker variant:

```sh
docker compose -f docker-compose.yml -f docker-compose.tools.yml up -d --build
```

That variant adds StegSeek 0.6, StegoVeritas 1.11 (metadata-only), OutGuess 0.4, OpenStego 0.8.6 and StegSnow. StegDetect is deliberately unavailable: its archived source has no verified supported build here. Inventory entries include installation, license and compatibility information; an entry alone is not a claim that a program is installed. See [tool sources and compatibility](docs/TOOLS.md).

Steghide/OutGuess/OpenStego/StegSnow accept supplied passwords. StegSeek accepts only a user-supplied list of at most 1,000 candidates, one thread and a 20-second deadline, against the selected uploaded artifact. Passwords/wordlists are removed on completion or cancellation, and diagnostics redact them. Extracted output filenames are fixed or generated.

Docker installs these programs except optional xxd. Quick Scan runs applicable file, ExifTool and pngcheck checks; Deep Scan runs remaining applicable tools. Damaged input can still cause a tool to fail. Review per-analyzer statuses and bounded diagnostics. Updated Debian packages supply security patches; periodically rebuild for updates.

## Architecture

`web` is FastAPI plus a static browser app. It limits multipart requests, hashes and saves original evidence under generated job IDs, and queues work in SQLite WAL. It never launches analysis tools. `worker` has **networking disabled** and atomically claims jobs from the shared volume. One supervisor runs up to two subprocesses with independent process groups, sanitized environments, rlimits, deadlines and artifact directories. Cancellation/timeouts kill the whole process group. Interrupted jobs are failed on restart.

This avoids an external database, broker, frontend build step and cloud dependencies. One API process and one supervisor per volume are supported. Both containers run unprivileged, with read-only roots, dropped capabilities, PID/memory/CPU limits and no new privileges. The default HTTP binding is loopback. See [architecture/security details](docs/ARCHITECTURE.md).

```text
stegolab/app.py                  Uploads, API, reports, downloads, static UI
stegolab/store.py                SQLite queue, capacity and lifecycle
stegolab/worker.py               Supervisor, limits and cancellation
stegolab/analyze.py              Restricted analysis entry point
stegolab/analysis/engine.py      Structured analysis stages/reporting
stegolab/analysis/tools.py       Registry and bounded subprocess runner
stegolab/analysis/extraction.py  Streaming, quota-controlled extraction
stegolab/analysis/encoding.py    Bounded decoding candidates
stegolab/labs/                   Image, audio, forensics, flags, crypto and tool actions
stegolab/reporting.py            JSON/Markdown reporting and candidate normalization
stegolab/static/                 Local browser UI, labs and product shell
config/                         Policies, build helpers, live release smoke test
examples/                       Small public known-answer CTF files
.github/workflows/test.yml      Core CI and manually requested specialized tests
tests/                          Deterministic benign CTF fixtures/tests
```

Reports use `schema_version: "1.0"`. Every analyzer returns `name`, `status`, `findings`, `errors`, `artifacts`, and `duration_ms`, plus optional `data`. Findings include type, title, detail, nullable source-relative byte offset and numeric confidence (0–1). Reports aggregate analyzer attribution, timestamps, file identity, artifacts and recommendations. Extracted-member offsets are relative to that member. Decoded-candidate offsets identify source candidates, not exact decoded-character mappings. Artifact downloads resolve IDs through reports, never arbitrary paths.

## Configuration

Optionally copy `.env.example` to `.env` before starting.

| Variable | Default | Meaning |
| --- | --- | --- |
| `STEGOLAB_PORT` | 8080 | Local HTTP port |
| `STEGOLAB_MAX_FILE_MB` | 32 | Maximum evidence MiB |
| `STEGOLAB_MAX_STORAGE_MB` | 2048 | Retained-job reservation budget MiB |
| `STEGOLAB_CONCURRENCY` | 2 | Parallel jobs, maximum 4 |
| `STEGOLAB_QUICK_TIMEOUT` | 90 | Quick wall-clock/CPU budget seconds |
| `STEGOLAB_DEEP_TIMEOUT` | 300 | Deep wall-clock/CPU budget seconds |

Other defaults: 32 active jobs; 1,000 retained jobs; 64 MiB shared generated/extracted output; 32 MiB/member; depth 3; 100 artifacts; 100:1 compression ratio; 400 member inspections; 1 MiB combined stdout/stderr/tool; 20 seconds/tool; 768 MiB address space/job; two concurrent upload parsers. Each retained job reserves maximum upload size plus 80 MiB, so the storage budget can fill before queue/disk capacity. Physical free disk remains necessary. Higher concurrency may need larger Compose memory/CPU/PID limits.

## API and tests

See [release verification](docs/VERIFICATION.md) for executed checks, browser coverage and remaining release boundaries.

Offline API reference: `/docs`; machine-readable schema: `/openapi.json`.

```sh
curl -F 'file=@challenge.png' -F 'mode=deep' http://localhost:8080/api/jobs
curl http://localhost:8080/api/jobs/JOB_ID
curl http://localhost:8080/api/jobs/JOB_ID/report
curl -X POST http://localhost:8080/api/jobs/JOB_ID/cancel
```

List jobs with `GET /api/jobs?limit=100&offset=0`. Export Markdown with `GET /api/jobs/JOB_ID/report?format=markdown&download=1`; JSON remains the default. `GET /api/flags` provides paged cross-investigation candidates with search/classification filters. Delete terminal jobs with `DELETE /api/jobs/JOB_ID`. Download with `GET /api/jobs/JOB_ID/artifacts/ARTIFACT_ID`; reports support `?download=1`. `/api/health` includes worker heartbeat and limits. `POST /api/utilities` accepts JSON such as `{ "operation": "base64_decode", "text": "ZmxhZ3tsb2NhbH0=" }`.

Run the full Linux tests with deployment tools:

```sh
docker build --target test -t stegolab-tests .
docker run --rm --network none --cap-drop ALL --security-opt no-new-privileges --read-only --tmpfs /tmp:rw,noexec,nosuid,size=512m stegolab-tests
```

Tests generate a valid PNG with a text flag and appended/nested ZIP flags, ASCII/UTF-16/encoded text, malformed files, traversal ZIPs, TAR links, a small high-ratio archive and excessive nesting. They cover extraction quotas, missing tools, real subprocess time/output limits, API security/lifecycle, and Linux worker completion/cancellation/concurrency/deadlines/rlimits. CI checks all browser JavaScript with Node, validates both Compose configurations, runs the Docker test target, starts the real deployment and exercises a known-answer scan/extraction/recipe/export smoke test. Specialized-tool tests can be requested through the workflow's manual optional-tools input. The frontend is buildless: there is no bundler compilation step. Check syntax locally with `node --check` for each file in `stegolab/static/`, then verify browser interactions against the running app.

Host-side development (the restricted worker still requires Linux):

```sh
python -m venv .venv
# Activate .venv for your shell, then:
python -m pip install -r requirements-dev.txt
python -m pytest -q
python -m tests.fixtures.corpus ./sample-evidence
python -m tests.fixtures.advanced ./sample-evidence/advanced
```

Ready-to-upload benign challenges are committed in [`examples/`](examples/README.md), including metadata, RGB LSB, appended/nested ZIP and a two-stage encoding recipe. `examples/expected.json` contains public answers and hashes. Regenerate them with `python examples/generate.py`; no development dependencies are needed for those four examples. Run the live release smoke test with `python config/release-smoke.py` after Compose is healthy.

Upload generated `image.png` using Deep Scan. Host installations lacking CLI tools report them unavailable. Uploaded programs are never executed.

## Limitations

Local single-user use only: no authentication or tenant isolation. Keep loopback binding. Containers/resource limits reduce malformed-input risk but are not a malware-detonation sandbox. Jobs share one worker UID and data volume; directories are application isolation, not separate container filesystems. A compromised native decoder could access shared evidence. Never mount host directories or the Docker socket.

Extraction supports ZIP/TAR/gzip; encrypted ZIP, ZIP64, RAR and 7z are not automatically unpacked. Generic signature matches remain heuristic until container checks succeed; validation does not establish payload authenticity. PDF attachment inventory and explicit numbered attachment extraction are available. StegoVeritas is restricted to metadata, and StegDetect is unsupported. Image previews resize to 1024px, native LSB extraction is limited to 8 million pixels, GIF extraction to 16 frames/16 million aggregate pixels, and audio previews to 30 seconds. The audio lab is an inspection tool, without destructive editing or arbitrary plug-ins. Bounded decoding/previews can miss content beyond limits; review execution notices. Pipeline completion can include optional analyzer failures.

## Release and contribution

Application source and authored fixtures use the [MIT license](LICENSE); tools and container dependencies retain their own licenses. Read [third-party notices](THIRD_PARTY_NOTICES.md) before redistributing an image. Image builds retain Debian/Python/Ruby inventories and notices, plus pinned OpenStego/StegSeek source archives in the optional variant. The documented release publishes source; CI does not push binary images.

See [contributing](CONTRIBUTING.md), [security policy](SECURITY.md), [secure remote access](docs/REMOTE_ACCESS.md), and [GitHub publication/source-bundle instructions](docs/RELEASING.md). No GitHub publication is performed by the startup command.
