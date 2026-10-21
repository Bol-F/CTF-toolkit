"""Structure maps, entropy windows, and validated embedded container ranges."""
import gzip
import io
import math
import struct
import zipfile
import zlib
from collections import Counter

from PIL import Image


def entropy(data):
    return round(-sum((n/len(data))*math.log2(n/len(data)) for n in Counter(data).values()), 5) if data else 0.


def png_chunks(data, start=0):
    if data[start:start+8] != b'\x89PNG\r\n\x1a\n': return [], None
    cursor, chunks = start + 8, []
    while cursor + 12 <= len(data) and len(chunks) < 4096:
        size = int.from_bytes(data[cursor:cursor+4], 'big')
        if size > len(data) - cursor - 12: break
        kind = data[cursor+4:cursor+8]
        crc = int.from_bytes(data[cursor+8+size:cursor+12+size], 'big')
        valid = zlib.crc32(data[cursor+4:cursor+8+size]) & 0xffffffff == crc
        chunks.append({'name': kind.decode('ascii', 'replace'), 'offset': cursor, 'size': size+12,
                       'data_offset': cursor+8, 'data_size': size, 'crc_valid': valid,
                       'ancillary': bool(kind[0] & 32), 'classification': 'validated' if valid else 'invalid_crc'})
        cursor += size + 12
        if kind == b'IEND': return chunks, cursor
    return chunks, None


def validate_region(data, offset, kind):
    tail = data[offset:]
    try:
        if kind == 'png':
            chunks, end = png_chunks(data, offset)
            if end and chunks and chunks[0]['name'] == 'IHDR' and all(c['crc_valid'] for c in chunks):
                with Image.open(io.BytesIO(data[offset:end])) as image: image.verify()
                return end-offset, 'PNG chunk boundaries, CRCs and IEND validated'
        elif kind == 'zip':
            # Find a bounded EOCD and verify the local records referenced by the
            # central directory, without decompressing untrusted members.
            cursor = offset
            for _ in range(100):
                cursor = data.find(b'PK\x05\x06', cursor)
                if cursor < 0 or cursor+22 > len(data): break
                end = cursor+22+int.from_bytes(data[cursor+20:cursor+22], 'little')
                cursor += 4
                if end > len(data): continue
                with zipfile.ZipFile(io.BytesIO(data[offset:end])) as archive:
                    members = archive.infolist()
                    if len(members) > 1000: return None
                    if members and all(data[offset+m.header_offset:offset+m.header_offset+4] == b'PK\x03\x04' for m in members):
                        for member in members:
                            with archive.open(member) as handle: handle.read(0)
                        return end-offset, f'ZIP end record, central directory and {len(members)} local headers validated; payload CRCs not checked'
        elif kind in {'jpeg', 'gif', 'bmp', 'tiff', 'webp'}:
            with Image.open(io.BytesIO(tail)) as image:
                image.verify()
            if kind == 'jpeg':
                end = tail.rfind(b'\xff\xd9')
                if end >= 0: return end+2, 'Pillow structure verification and JPEG end marker validated'
            if kind == 'gif':
                end = tail.rfind(b';')
                if end >= 0: return end+1, 'Pillow GIF structure verified (end marker estimate)'
            return len(tail), 'Pillow verified image structure; exact extent is unknown'
        elif kind == 'gzip':
            decoder = zlib.decompressobj(31)
            output = decoder.decompress(tail, 1024*1024+1)
            if decoder.eof and len(output) <= 1024*1024:
                return len(tail)-len(decoder.unused_data), 'Gzip stream, trailer and checksum validated within 1 MiB limit'
        elif kind == 'pdf':
            # A PDF magic/EOF pair alone is deliberately not sufficient.
            return None
    except (OSError, ValueError, RuntimeError, NotImplementedError, EOFError, zipfile.BadZipFile, struct.error, zlib.error, Image.DecompressionBombError):
        pass
    return None


def analyze_forensics(analysis):
    from ..analysis.engine import stage, finding, SIGNATURES
    data = analysis.data
    regions, findings, artifacts = [], [], []
    chunks, end = png_chunks(data)
    regions.extend(chunks)
    if data.startswith(b'RIFF'):
        cursor=12
        while cursor+8<=len(data) and len(regions)<1000:
            length=int.from_bytes(data[cursor+4:cursor+8],'little')
            if length>len(data)-cursor-8:break
            regions.append({'name':data[cursor:cursor+4].decode('ascii','replace'),'offset':cursor,'size':length+8,
                            'classification':'riff_chunk','data_offset':cursor+8,'data_size':length})
            cursor+=8+length+(length%2)
    if analysis.report['file']['format']=='pdf':
        import re,itertools
        for match in itertools.islice(re.finditer(rb'\b\d+\s+\d+\s+obj\b',data),200):
            close=data.find(b'endobj',match.end())
            if close>=0:regions.append({'name':match.group().decode(),'offset':match.start(),'size':close+6-match.start(),'classification':'pdf_object_candidate'})
    if not regions:regions.append({'name':analysis.report['file']['format'].upper()+' header','offset':0,'size':min(64,len(data)),'classification':'header'})
    if end and end < len(data):
        regions.append({'name': 'Appended bytes', 'offset': end, 'size': len(data)-end, 'classification': 'appended'})
    block = max(256, (len(data)+511)//512)
    windows = [{'offset': offset, 'size': len(data[offset:offset+block]), 'entropy': entropy(data[offset:offset+block])}
               for offset in range(0, len(data), block)]
    candidates = []
    for kind, magic, mime in SIGNATURES:
        cursor = 1
        for _ in range(10):
            offset = data.find(magic, cursor)
            if offset < 0 or len(candidates) >= 80: break
            cursor = offset + len(magic)
            verified = validate_region(data, offset, kind)
            item = {'name': kind.upper(), 'format': kind, 'offset': offset,
                    'size': verified[0] if verified else len(magic),
                    'classification': 'confirmed_embedded_structure' if verified else 'signature_candidate',
                    'evidence': verified[1] if verified else 'Magic bytes only; complete embedded file was not validated'}
            candidates.append(item)
            findings.append(finding('embedded_file' if verified else 'embedded_signature',
                                    f'{"Validated embedded" if verified else "Candidate"} {kind.upper()}',
                                    item['evidence'], offset, .99 if verified else .5, **{k:v for k,v in item.items() if k not in {'offset','name','evidence'}}))
            if verified and analysis.mode == 'deep' and kind in {'png', 'jpeg', 'gif', 'gzip', 'zip'} and verified[0] <= 4*1024**2 and len(artifacts) < 8:
                record = analysis.artifact(f'embedded-{offset:x}.{kind}', data[offset:offset+verified[0]], mime, 'carved', max_bytes=4*1024**2)
                record.update(offset=offset, validation=item['evidence'])
                item['artifact_id'] = record['id']
                artifacts.append(record)
    archive_members = []
    try:
        if zipfile.is_zipfile(analysis.original):
            with zipfile.ZipFile(analysis.original) as archive:
                import itertools
                for member in itertools.islice(archive.infolist(), 400):
                    archive_members.append({'name': member.filename[:240], 'size': member.file_size,
                                            'compressed_size': member.compress_size, 'offset': member.header_offset,
                                            'encrypted': bool(member.flag_bits & 1), 'directory': member.is_dir()})
    except (OSError, ValueError, zipfile.BadZipFile): pass
    for artifact in analysis.report['artifacts']:
        if artifact.get('kind') == 'extracted':
            archive_members.append({'name': artifact['name'], 'size': artifact['size'], 'artifact_id': artifact['id'],
                                    'parent': artifact.get('parent'), 'depth': artifact.get('depth')})
    data = {'regions': regions[:4096], 'embedded': candidates, 'entropy': windows,
            'entropy_window_bytes': block, 'archive_members': archive_members[:500],
            'limits': {'signature_candidates': 80, 'entropy_windows': 512, 'carves': 8},
            'explanation': 'Confirmed embedded structure means container validation succeeded, not that content is trustworthy.'}
    return stage('file_forensics', findings, artifacts=artifacts, data=data)
