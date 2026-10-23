# Contributing to StegoLab

StegoLab is a local CTF workbench. Changes should improve real analysis, preserve evidence, and make results explainable. Keep the FastAPI/SQLite worker architecture and buildless browser interface unless a change solves a demonstrated problem.

## Development

Use Python 3.12 or newer and Docker Compose v2. Create a virtual environment and install `requirements-dev.txt`. Run `python -m pytest -q` for native tests; tools and Linux worker tests can skip on unsupported hosts. Run the Docker test target for the deployment environment:

```sh
docker build --target test -t stegolab-tests .
docker run --rm --network none --cap-drop ALL --security-opt no-new-privileges --read-only --tmpfs /tmp:rw,noexec,nosuid,size=512m stegolab-tests
node --check stegolab/static/app.js
node --check stegolab/static/labs.js
docker compose config --quiet
```

There is no frontend compilation step or CDN. Serve the actual application with `docker compose up -d --build` and test at `http://localhost:8080`. Check keyboard access, a narrow viewport, both themes when changing presentation, and browser console errors. Use benign authored fixtures from `examples/` or `tests/fixtures/`; never submit private evidence or real credentials.

## Changes and pull requests

- Explain the concrete problem, resulting behavior, and checks actually executed. State skipped checks and why.
- For analyzer changes, add known-answer positive/negative fixtures and check structured errors, limits, unavailable tools and offsets. Avoid mocks when a small real fixture is feasible.
- Keep tool arguments fixed and passed as argv with no shell. Do not execute uploaded programs, enable external automatic extraction, or download dependencies during analysis.
- Preserve original evidence. Enforce shared extraction quotas, generated names, containment checks, parser timeouts and output caps.
- Render evidence through text-safe DOM operations. Keep dependencies local and respect the content security policy.
- Document every new external dependency's source, license, installation, supported formats and practical limits in `docs/TOOLS.md` and `THIRD_PARTY_NOTICES.md`.
- Keep fixes focused and do not reformat unrelated working modules. Add a migration when persistent storage changes.

By contributing authored material, you agree it may be distributed under the repository's MIT license. Include existing third-party notices and do not copy code/assets without compatible permission. Report security issues through [SECURITY.md](SECURITY.md).
