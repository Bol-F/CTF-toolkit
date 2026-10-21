"""Build-only downloads pinned to upstream release checksums; no runtime network."""
import hashlib
import io
from pathlib import Path
import tarfile
import urllib.request
import zipfile

SOURCES = {
    'openstego': ('https://github.com/syvaidya/openstego/releases/download/openstego-0.8.6/openstego-0.8.6.zip',
                 '402ba4190d329564996a1250b9096f0402452042469f517545c312527cedc41f'),
    'stegseek': ('https://github.com/RickdeJager/stegseek/archive/refs/tags/v0.6.tar.gz',
                '66cdd8e4e4b815d7fe368843e7df2f0416af0304df35e4f22db9f16c7ae6c771'),
}

for name,(url,digest) in SOURCES.items():
    content = urllib.request.urlopen(url,timeout=90).read()
    if hashlib.sha256(content).hexdigest()!=digest: raise SystemExit(f'{name} checksum mismatch')
    root = Path('/opt')/name
    root.mkdir(exist_ok=True)
    if name=='openstego':
        with zipfile.ZipFile(io.BytesIO(content)) as archive:
            for member in archive.infolist():
                target=(root/member.filename).resolve()
                if not target.is_relative_to(root): raise SystemExit('Unsafe release archive path')
                if member.is_dir(): target.mkdir(parents=True,exist_ok=True)
                else:
                    target.parent.mkdir(parents=True,exist_ok=True)
                    target.write_bytes(archive.read(member))
    else:
        with tarfile.open(fileobj=io.BytesIO(content),mode='r:gz') as archive:
            archive.extractall(root,filter='data')
