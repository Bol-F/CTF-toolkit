# Architecture and security

The initial repository had only a README. FastAPI and static browser assets keep setup small, while separate Compose services isolate HTTP handling from untrusted parsing. Runtime state and processing stay local.

## Lifecycle and execution

Admission reserves queue/storage capacity in an immediate SQLite transaction. Upload bytes go to `jobs/<random-id>/evidence/original.bin`; SHA-256 and `upload.json` preserve provenance. Evidence is made read-only before queueing. Failed uploads clean partial files/reservations. User filenames are labels, never storage paths or shell text.

One supervisor holds an exclusive lock per volume. Atomic claims move jobs through uploading, queued, running and a terminal state. Queued cancellation is immediate; running cancellation is checked every 250 ms. Cancellation during upload survives enqueue. Startup fails interrupted uploads/scans. Terminal jobs remain until explicitly deleted.

Only a fixed Python module is started, using generated paths and validated modes. CLI templates use argv arrays with `shell=False`, bounded concurrent stdout/stderr draining and deadlines. Sanitized child environments omit credentials/proxies. Each job's process group is killed on cancellation, timeout, shutdown and completion. CPU/address-space/file-size/open-file rlimits complement Docker limits.

## Boundary and limitations

The worker has no networking, read-only root, unprivileged UID, dropped capabilities and no new privileges. The API publishes only loopback, validates Host headers and browser origins for mutation, caps raw request bytes including chunked transfers, and limits upload parsing concurrency. Artifact IDs resolve through reports with containment checks; opaque attachment responses prevent inline rendering. The UI uses `textContent` for evidence; CSP and frame/content-type headers protect it.

Jobs do not have separate kernel/filesystem boundaries. A decoder compromise under the shared UID could read other jobs or change evidence permissions. Read-only evidence protects against accidental changes, not that compromise. A multi-user service would need authentication and per-job containers/VMs, mounts and identities. This is a local CTF workbench, not a malware sandbox.

## Extension contract

Python entry: `stegolab.analysis.engine.analyze_job(job_dir, mode, limits=None)`. Worker CLI: `python -m stegolab.analyze JOB_DIR quick|deep`. Inputs: evidence and upload metadata. Outputs: atomic progress/report JSON and files below `artifacts/`.

Analyzer envelopes contain name, status, findings, errors, artifacts and elapsed milliseconds. Statuses: completed, partial, unavailable, skipped, failed, timeout. Identification failure stops later parsing; optional failures are isolated. Aggregate completion is distinct from optional execution notices. Findings carry source-relative offsets and heuristic confidence. Decoded-source offsets do not imply exact decoded-character positions.

Add a function/method returning the envelope and register it in the engine pipeline. CLI registry specs declare detected formats, version probes, fixed argv, limits and parsers. Add real positive/negative fixtures plus missing/failure/timeout/truncation tests. Never forward request-controlled switches to a tool.

## Extraction and storage

Archive paths are validated under POSIX/Windows conventions but used only as display labels. Members stream to generated artifact names; archive `extract`/`extractall` are never used. Reject traversal, absolute/drive/NUL paths, links, devices, sparse TAR members and encrypted ZIPs. Shared byte/member/depth/count/ratio/inspection quotas apply across recursion. Verify actual streamed bytes, not just declared sizes. Remove partial failures while counting their work against the processing budget.

The admission ledger reserves maximum upload size plus 80 MiB per retained job. This is not an OS volume quota: generation/extraction, report previews and transient output are separately bounded. Physical free disk is still necessary. Explicit retention avoids silently destroying evidence.
