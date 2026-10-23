"""Build-only, offline inventory; preserve upstream license text alongside images.

This is an inventory, not an assertion that every redistribution obligation has
been discharged. See THIRD_PARTY_NOTICES.md and docs/RELEASING.md.
"""
from __future__ import annotations

import importlib.metadata
import json
from pathlib import Path
import shutil
import subprocess
import sys


ROOT = Path('/usr/local/share/stegolab')


def python_inventory(output: Path):
    result = []
    for distribution in importlib.metadata.distributions():
        name = distribution.metadata.get('Name', 'unknown')
        licenses = []
        for entry in distribution.files or ():
            if any(part.lower().startswith(('license', 'copying', 'notice', 'authors')) for part in entry.parts):
                source = Path(distribution.locate_file(entry))
                if source.is_file():
                    relative = Path(name) / Path(*entry.parts)
                    # Installed package metadata is trusted build input. Keep paths contained.
                    target = output / relative
                    if not target.resolve().is_relative_to(output.resolve()):
                        continue
                    target.parent.mkdir(parents=True, exist_ok=True)
                    shutil.copyfile(source, target)
                    licenses.append(str(relative))
        result.append({'name': name, 'version': distribution.version,
                       'license_expression': distribution.metadata.get('License-Expression'),
                       'license': distribution.metadata.get('License'),
                       'project_urls': distribution.metadata.get_all('Project-URL', []),
                       'notices': licenses})
    return sorted(result, key=lambda entry: entry['name'].lower())


def main():
    ROOT.mkdir(parents=True, exist_ok=True)
    if len(sys.argv) > 1 and sys.argv[1] == '--python-only':
        result = python_inventory(ROOT / 'python-notices-optional')
        (ROOT / 'python-packages-optional.json').write_text(json.dumps(result, indent=2), encoding='utf-8')
        return
    query = subprocess.check_output(['dpkg-query', '-W', '-f', '${binary:Package}\t${Version}\t${source:Package}\t${source:Version}\n'], text=True)
    packages = []
    for line in query.splitlines():
        package, version, source, source_version = line.split('\t')
        copyright_path = Path('/usr/share/doc') / package.split(':')[0] / 'copyright'
        packages.append({'package': package, 'version': version, 'source_package': source,
                         'source_version': source_version, 'copyright_file': str(copyright_path),
                         'copyright_present': copyright_path.is_file()})
    (ROOT / 'debian-packages.json').write_text(json.dumps(packages, indent=2), encoding='utf-8')
    (ROOT / 'python-packages.json').write_text(json.dumps(python_inventory(ROOT / 'python-notices'), indent=2), encoding='utf-8')
    ruby = subprocess.check_output(['gem', 'list', '--local'], text=True)
    (ROOT / 'ruby-packages.txt').write_text(ruby, encoding='utf-8')
    ruby_paths = subprocess.check_output(['gem', 'environment', 'gempath'], text=True)
    (ROOT / 'ruby-source-paths.txt').write_text(ruby_paths, encoding='utf-8')


if __name__ == '__main__':
    main()
