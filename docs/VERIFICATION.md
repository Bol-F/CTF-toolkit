# Release verification

Executed on 2026-10-21 with Docker Desktop Linux containers on a Windows host. These are observed results, not a claim that GitHub-hosted CI has run or that the repository has been published.

## Backend and container checks

| Check | Observed result |
| --- | --- |
| Core Docker test image build | Passed |
| Optional `tools-test` image build | Passed |
| Core tests | 117 passed; 6 optional-tool skips |
| Optional image tests | 123 passed; no skips |
| Windows host tests | 97 passed; 26 Linux/missing-tool skips |
| Default Compose build/startup | Web and worker healthy; loopback port 8080 |
| Optional Compose build/startup | Web and specialized worker healthy; five additional tools available with actual versions |
| Live release smoke | Known flags, nested extraction/download, JSON/Markdown exports, two-step recipe and malformed-ID error passed |
| JavaScript syntax / Python compilation | Passed; frontend is buildless, with no bundler compilation step |
| Compose configuration / Actionlint / whitespace | Passed |
| Gitleaks source scan | No leaks found in the reviewed release source snapshot |

The suites ran with networking disabled, dropped capabilities, no new privileges, a read-only root and a noexec/nosuid temporary filesystem. Final test runs additionally capped container memory at 2 GiB, CPU at two cores and PIDs at 128. Tests cover traversal, links, decompression ratios/quotas, malformed files, deadlines, cancellation, concurrency, worker resource limits, immutable originals, safe previews, export escaping, report indexing and source-relative offsets. A timing-sensitive recovery test was corrected to give the recovery scan an ordinary independent budget while keeping the first scan's one-second timeout assertion.

Real synthetic fixtures exercised PNG/BMP LSB extraction, appended/nested archives, metadata, OCR, QR, multistage encoding, GIF frames and stereo frequency peaks. Specialized round trips passed for steghide, StegSeek, OutGuess, OpenStego and StegSnow. StegoVeritas metadata-only execution passed. OpenStego extraction also passed through the actual worker at the default 768 MiB address-space limit after reducing Java memory reservations; that limit was not relaxed.

One upstream warning remains: Starlette deprecates its current httpx-based TestClient adapter. It did not fail these tests.

## Browser checks

Chrome was driven with Playwright because the Browser plugin and its browser skill were unavailable. The tested viewport sizes were 1536×1024 and 390×844; no Firefox or Safari claim is made. Tests used the real Docker API and worker. The final product pass used the built image's assets; an earlier developer pass intercepted only static files to validate edits before rebuilding, never scan responses.

Verified flows:

- Dashboard live history, worker/tool availability, multi-file upload and progress.
- Persistent dark/light theme, Beginner/Advanced mode and keyboard shortcut help.
- Evidence-tree navigation, panel resizing, HEX/ASCII bytes and structure-region jumps.
- Image channels, alpha, bits 0–7, brightness/contrast/gamma, LSB extraction and processed PNG export.
- Audio playback, stereo selection, spectrogram zoom/export and frequency-band/bin inspection.
- Central flag search/classification, copying, transformation/source details and navigation to evidence.
- Crypto byte upload, Undo/Redo, ordered recipes, intermediate output and final-byte download.
- JSON and Markdown report downloads, unavailable-tool search, empty-upload feedback and confirmed UI deletion.
- No relevant page/console errors or external requests in the exercised flows. Mobile document width stayed at 390 px.

## Visual review

A generated File Analyzer concept and the latest browser screenshots were inspected directly. The implementation follows a flat charcoal interface with mint accents, compact navigation, an evidence tree, editor and inspector. Review covered layout, typography, palette, icon consistency, spacing, responsive stacking and actual content density. The oversized upload section was collapsed after evidence selection; duplicate inspector flags were grouped by value and source count. A hidden recipe file input inheriting a mobile full-width rule caused overflow and was fixed and retested.

Intentional differences from the concept are the existing analysis tab names, real fixture pixels, actual analyzer statuses and real investigation counts. Concept-only findings and unsupported controls were not copied into the product.

Final pixel checks also caught browser range-input sanitization changing the initial gamma from 1 to 1.1. Gamma is now reset after configuring its range. Untouched original/processed pixels match exactly, with zero changed pixels and zero mean difference. All 32 RGBA/bit-plane selections were exercised. Light-theme colors were checked after their short transition settled.

## Publication boundaries

The application remains an unauthenticated, single-instance local CTF workbench. Jobs share a worker UID and data volume; a compromised native parser is not isolated from other jobs by a per-job container or VM. Image preview/LSB, audio duration, recursion, output and storage limits are deliberate; see [LABS.md](LABS.md) and [SECURITY.md](../SECURITY.md).

The history UI shows the newest 100 jobs; older records remain accessible through API pagination. PDF report export and StegDetect are unsupported. StegoVeritas is limited to metadata. Core hexadecimal inspection is native even when xxd is missing.

Installed package/license inventories and the three pinned optional-tool release/source archives were checked in built images. The large exact-Debian-source collector was not executed. Complete corresponding-source and dependency audits are still required before redistributing prebuilt images; see [RELEASING.md](RELEASING.md) and [THIRD_PARTY_NOTICES.md](../THIRD_PARTY_NOTICES.md). No commit, tag, push or public release was performed by this verification.
