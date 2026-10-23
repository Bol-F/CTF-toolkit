"""Release-only source collector, run in a disposable connected build container.

Download exact Debian source package versions from the image manifest. Fail
closed if a version has left configured mirrors: use a matching Debian snapshot
and rerun; do not silently substitute a newer source version.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import shutil
import subprocess


def main():
    output = Path('/release-sources')
    output.mkdir(exist_ok=True)
    for path in Path('/etc/apt/sources.list.d').glob('*.sources'):
        content = path.read_text()
        content = content.replace('Types: deb\n', 'Types: deb deb-src\n')
        path.write_text(content)
    subprocess.run(['apt-get', 'update'], check=True)
    manifest = json.loads(Path('/usr/local/share/stegolab/debian-packages.json').read_text())
    sources = sorted({(item['source_package'], item['source_version']) for item in manifest})
    for package, version in sources:
        if not package or not version:
            raise SystemExit('Missing exact source package identity')
        subprocess.run(['apt-get', 'source', '--download-only', '--only-source', f'{package}={version}'],
                       cwd=output, check=True)
    shutil.copytree('/usr/local/share/stegolab', output / 'notices', dirs_exist_ok=True)
    shutil.copytree('/usr/share/doc', output / 'debian-notices', dirs_exist_ok=True)
    shutil.copytree('/usr/share/common-licenses', output / 'common-licenses', dirs_exist_ok=True)
    upstream = Path('/usr/local/share/stegolab/upstream-sources')
    if upstream.is_dir():
        shutil.copytree(upstream, output / 'upstream-sources', dirs_exist_ok=True)
    checksums = []
    for path in sorted(output.rglob('*')):
        if path.is_file():
            with path.open('rb') as handle:
                digest = hashlib.file_digest(handle, 'sha256').hexdigest()
            checksums.append(f"{digest}  {path.relative_to(output).as_posix()}")
    (output / 'SHA256SUMS').write_text('\n'.join(checksums) + '\n')


if __name__ == '__main__':
    main()
