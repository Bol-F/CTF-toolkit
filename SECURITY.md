# Security policy

## Intended deployment

StegoLab currently supports one trusted local user on the latest source revision. It has no authentication, authorization or tenant isolation. The default URL is `http://localhost:8080`; Compose binds to `127.0.0.1`. Keep that binding. For access from another trusted computer, use the SSH tunnel described in [remote access](docs/REMOTE_ACCESS.md). Public multi-user deployment is outside the current security model.

## Untrusted evidence

Uploaded programs and scripts are never executed. Analysis subprocesses run in a network-disabled nonroot worker with a read-only root, dropped capabilities, PID/CPU/memory limits, bounded outputs and deadlines. Archive extraction rejects unsafe paths/links and enforces cumulative depth, count, size and expansion-ratio limits. Browser previews use generated PNG/PCM data; original evidence remains an attachment. Tool output is untrusted text.

These controls reduce risk; they do not provide a separate VM or container for each job. Jobs share a UID and data volume. A compromised native decoder could access other evidence or alter permissions. Use only a dedicated local environment for CTF artifacts. Do not mount host secrets, arbitrary host directories or the Docker socket. Keep Docker and dependencies updated, and rebuild images after relevant security updates.

Supplied steganography passwords/wordlists are private job parameters and are removed after terminal completion/cancellation; output diagnostics redact supplied passwords. Successful extraction may itself reveal a challenge secret, so reports, artifacts and the Docker volume are sensitive. Deleting a job removes its application files, not backups or underlying storage blocks. Secure erasure is not provided.

## Reporting a vulnerability

Use the repository's **Security → Advisories → Report a vulnerability** private reporting facility when enabled. Maintainers should enable it before publication. If it is unavailable, open a minimal issue asking for a private reporting channel; omit exploit details and private artifacts until a channel is established. No monitored security email address or response SLA is claimed.

Include the affected revision/image ID, deployment settings, minimal benign reproduction, expected/actual behavior and logs with private evidence removed. High-priority areas include extraction traversal, resource-limit bypasses, arbitrary command execution, evidence access outside a selected job, and script injection through metadata/tool output. Avoid denial-of-service testing against anyone else's deployment.

## Maintenance

There is no published long-term support branch. Use the latest reviewed revision and inspect the actual tool inventory after rebuilding. See [architecture boundaries](docs/ARCHITECTURE.md), [lab limits](docs/LABS.md), and [third-party notices](THIRD_PARTY_NOTICES.md).
