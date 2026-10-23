"""Central provenance-aware flag finder. Custom expressions have hard timeouts."""
import base64
import binascii
import codecs
import re
import urllib.parse

DEFAULT_PREFIXES = ['flag', 'CTF', 'picoCTF', 'HTB', 'THM', 'ictf', 'ductf', 'uiuctf', 'actf']


class FlagFinder:
    def __init__(self, prefixes=None, expression='', maximum=500):
        self.prefixes = prefixes if prefixes is not None else DEFAULT_PREFIXES
        if not 1 <= len(self.prefixes) <= 32 or any(not re.fullmatch(r'[A-Za-z0-9_-]{1,40}', x) for x in self.prefixes):
            raise ValueError('Use 1–32 flag prefixes containing letters, digits, underscore or dash')
        if len(expression) > 256: raise ValueError('Custom regex is limited to 256 characters')
        import regex
        self.pattern = regex.compile(expression if expression else '(?i)(?:' + '|'.join(re.escape(x) for x in self.prefixes) + r')\{[\x20-\x7e]{1,256}?\}')
        self.maximum, self.count, self.seen, self.errors = maximum, 0, set(), []
        self.bytes_scanned = 0

    def scan(self, data, source='original', method='raw bytes', history=None, offset_known=True, heuristic=False):
        if self.count >= self.maximum or self.bytes_scanned >= 64 * 1024**2: return []
        data = data[:min(4 * 1024**2, 64 * 1024**2 - self.bytes_scanned)]
        self.bytes_scanned += len(data)
        found = []
        try:
            # Latin-1 provides a one-character/one-byte offset mapping.
            for match in self.pattern.finditer(data.decode('latin1'), timeout=.05):
                if not match.group() or len(match.group()) > 512: continue
                key = (match.group(), source, method, match.start())
                if key in self.seen: continue
                self.seen.add(key)
                self.count += 1
                found.append({'type': 'flag', 'title': 'Flag format match', 'detail': match.group(),
                              'value': match.group(), 'source': source, 'source_file': source,
                              'offset': match.start() if offset_known else None, 'method': method,
                              'history': list(history or []), 'confidence': .8 if heuristic else 1.,
                              'classification': 'heuristic_candidate' if heuristic else 'confirmed_pattern_match',
                              'evidence': 'Exact configured pattern match; challenge acceptance is not verified' if not heuristic else 'Pattern match after a heuristic transformation; verify against challenge context'})
                if self.count >= self.maximum: break
        except TimeoutError:
            self.errors.append(f'Regex deadline reached for {source}; results may be incomplete')
        return found

    def scan_decoded(self, data, source='original', history=None):
        found, queue, seen = [], [(data[:262144], list(history or []))], set()
        budget = 0
        while queue and len(seen) < 40 and budget < 1024**2:
            value, steps = queue.pop(0)
            if value in seen: continue
            seen.add(value)
            budget += len(value)
            found.extend(self.scan(value, source, ' → '.join(steps) or 'raw bytes', steps,
                                   offset_known=not steps, heuristic=bool(steps)))
            if len(steps) >= 4: continue
            candidates = [(value, 0)] if len(value) <= 65536 else []
            candidates += [(m.group(), m.start()) for m in list(re.finditer(rb'[A-Za-z0-9+/=_%-]{8,4096}', value))[:60]]
            for token, _ in candidates[:60]:
                compact = b''.join(token.split())
                transforms = []
                try:
                    if len(compact) % 4 == 0: transforms.append(('Base64', base64.b64decode(compact, validate=True)))
                except (ValueError, binascii.Error): pass
                try:
                    if re.fullmatch(rb'[A-Z2-7=]{8,}', compact, re.I): transforms.append(('Base32', base64.b32decode(compact, casefold=True)))
                except (ValueError, binascii.Error): pass
                try:
                    if re.fullmatch(rb'[0-9a-fA-F]{8,}', compact) and len(compact) % 2 == 0: transforms.append(('Hex', bytes.fromhex(compact.decode())))
                except ValueError: pass
                if b'%' in token:
                    transforms.append(('URL', urllib.parse.unquote_to_bytes(token)))
                if not steps:
                    transforms.append(('ROT13', codecs.encode(token.decode('latin1'), 'rot_13').encode('latin1')))
                for name, decoded in transforms:
                    if decoded and decoded != value and len(decoded) <= 65536:
                        queue.append((decoded, steps + [name]))
                        if len(queue) >= 100: break
                if len(queue) >= 100: break
        return found


def scan_report(analysis, prefixes=None, expression=''):
    finder = FlagFinder(prefixes, expression)
    filename = analysis.report['file'].get('filename', 'original')
    findings = []
    block = 4 * 1024**2
    for offset in range(0,len(analysis.data),block-512):
        matches = finder.scan(analysis.data[offset:offset+block],filename)
        for match in matches: match['offset'] += offset
        findings.extend(matches)
    findings.extend(finder.scan_decoded(analysis.data,filename))
    # Preserve native wide-string positions and other established provenance.
    for prior in analysis.report.get('findings',[]):
        if prior.get('type')!='flag' or not prior.get('value'): continue
        matches = finder.scan(prior['value'].encode(),source=prior.get('source',filename),method=prior.get('encoding','native'))
        for match in matches:
            match['offset'] = prior.get('offset')
            match['history'] = [prior.get('encoding','native')]
        findings.extend(matches)
    for result in analysis.report['analyzers']:
        if result['name'] in {'flags', 'central_flags'}: continue
        for item in result.get('findings', [])[:100]:
            if item.get('type') == 'metadata' or result['name'] in {'exiftool', 'tesseract', 'zbarimg', 'zsteg'}:
                findings.extend(finder.scan_decoded(str(item.get('detail', '')).encode(),
                                source=analysis.report['file'].get('filename', 'original') + ':' + result['name'], history=[result['name']]))
    for artifact in analysis.report['artifacts'][:100]:
        path = analysis.root / artifact['path']
        if artifact.get('kind') in {'extracted', 'carved', 'lsb', 'tool_extracted', 'pdf_attachment'} or artifact.get('name') == 'strings.json':
            with path.open('rb') as handle: content = handle.read(4 * 1024**2)
            artifact_matches = finder.scan_decoded(content, artifact['name'], [artifact.get('method', artifact.get('kind', 'strings'))])
            for match in artifact_matches:
                match['artifact_id'] = artifact['id']
            findings.extend(artifact_matches)
    for match in findings:
        if analysis.report.get('job_id'):
            match['source_job_id'] = analysis.report['job_id']
    analysis.report['flag_candidates'] = findings[:500]
    summary_findings = [{**{k:v for k,v in item.items() if k not in {'type','value'}},
                         'type':'central_flag','candidate_value':item['value']} for item in findings[:500]]
    return {'name': 'central_flags', 'status': 'partial' if finder.errors else 'completed', 'findings': summary_findings,
            'errors': finder.errors, 'artifacts': [], 'duration_ms': 0,
            'data': {'prefixes': finder.prefixes, 'regex': expression, 'bytes_scanned': finder.bytes_scanned,
                     'limits': {'scan_bytes': 64 * 1024**2, 'decode_depth': 4, 'matches': 500},
                     'explanation': 'Confirmed means a format match, never a guarantee of the challenge answer.'}}
