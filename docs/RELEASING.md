# Preparing and publishing a source release

The repository contains authored source and build recipes; release automation does not upload Docker images or user evidence. Publishing must be performed by a repository maintainer with the necessary GitHub access.

## Review and verify

1. Inspect `git status --short` and the staged diff. Exclude `.env`, private evidence, local databases, passwords, keys, generated reports and runtime volumes. The committed example flags are deliberately public test answers.
2. Run the checks in [CONTRIBUTING.md](../CONTRIBUTING.md), the core Docker test suite, and optional `tools-test` if that image is part of the release scope. Record commands, passed/skipped counts, platform and image IDs in release notes. Syntax checks are the frontend build check for this buildless application; also exercise the actual browser flow.
3. Start Compose, upload `examples/appended.png` in Deep Scan, verify known flags/extracted members, run the example decoding recipe, export reports, test cancellation/deletion and inspect notices for unavailable tools. Keep test evidence separate from real investigations.
4. Review [SECURITY.md](../SECURITY.md), dependencies, [THIRD_PARTY_NOTICES.md](../THIRD_PARTY_NOTICES.md) and current limits. Enable GitHub private vulnerability reporting and branch protections. A green CI run does not establish security or legal compliance.

## Publish the repository

Use an existing fork/remote or create a new GitHub repository through the GitHub UI. Replace the placeholder remote below with a repository you control. If `origin` already exists, inspect `git remote -v` and use that remote rather than adding it again.

```sh
git status --short
git diff --check
git add README.md LICENSE CONTRIBUTING.md SECURITY.md THIRD_PARTY_NOTICES.md Dockerfile docker-compose.yml docker-compose.tools.yml .dockerignore .gitignore .gitattributes .env.example requirements.txt requirements-dev.txt pytest.ini stegolab tests docs config examples .github
git diff --cached --stat
git diff --cached
git commit -m "Prepare StegoLab source release"
# Only when origin is not configured:
git remote add origin https://github.com/YOUR-ACCOUNT/StegoLab.git
git push -u origin HEAD
```

After CI passes, choose an unused semantic version, create an annotated tag, push it, and use GitHub's **Releases → Draft a new release**. Describe working features, actual verified tool versions, test results and limitations. GitHub provides source archives for tags. No token or secret needs to be stored in the repository.

```sh
git tag -a v0.1.0 -m "StegoLab source release"
git push origin v0.1.0
```

These commands are instructions, not a claim that this workspace has been committed or published.

## If you redistribute a prebuilt container

Local build instructions do not automatically satisfy obligations for distributing another party's binary. Preserve all notices, review dependencies including base-image packages/native Python wheels/Java libraries, and host complete corresponding sources and build scripts required by copyleft licenses with the exact image. The application MIT license does not cover third-party programs.

The images retain Debian source package versions and installed notices in `/usr/local/share/stegolab/`. Export exact Debian sources in a separate connected build, using the **same image ID** that will be distributed:

```sh
docker image inspect stegolab:local --format '{{.Id}}'
# Give that exact local image a stable audit tag; use stegolab:tools for the optional variant.
docker tag stegolab:local stegolab:source-audit
docker build -f config/Dockerfile.sources --build-arg IMAGE=stegolab:source-audit --target source-bundle --output type=local,dest=release-sources .
```

This helper downloads `.dsc` and corresponding source archives/patches for all installed Debian source versions, retaining checksums/notices. It intentionally fails if an exact version is no longer on configured mirrors; configure a matching official Debian snapshot and repeat. Do not replace it with a newer source version. The optional image also retains matching OpenStego and StegSeek source/release archives.

The collector does **not** certify a complete corresponding-source bundle for every component: audit Python native wheel embedded libraries, Ruby dependencies, the official Python base image build scripts and any Java embedded libraries separately. Preserve relevant build recipes and original source notices. Check the completed archive offline, publish it alongside the image with the same retention/access, and record image digest/source checksums. Do not publish a binary image until the audit is complete. Default CI deliberately publishes no images.
