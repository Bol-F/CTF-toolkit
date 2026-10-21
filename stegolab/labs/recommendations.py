"""Deterministic recommendations, each tied to observable evidence."""
def recommend(report):
    kind = report.get('file', {}).get('format', 'unknown')
    checks = []
    def add(operation, title, why, evidence):
        checks.append({'operation': operation, 'title': title, 'why': why, 'evidence': evidence,
                       'certainty': 'suggested_check', 'guarantees_hidden_data': False})
    if kind in {'png', 'bmp'}:
        add('image', 'Inspect channels, bit planes and LSB data', 'Lossless raster pixels preserve low-order bits that may carry CTF clues.', kind.upper())
    if kind == 'jpeg':
        add('image', 'Inspect metadata, appended bytes and JPEG-compatible tools', 'JPEG is lossy; steghide/OutGuess operate on compatible JPEG structures, while simple pixel LSB assumptions may fail.', 'JPEG header')
    if kind == 'gif':
        add('image', 'Compare animation frames and alpha', 'Clues may occupy individual frames or disposal/transparency states.', 'GIF frame container')
    if kind in {'wav','mp3','flac','ogg','au','mp4','matroska','webm','avi'}:
        add('audio', 'Inspect spectrogram and channel differences', 'Time-frequency plots and stereo separation can expose visual or asymmetric audio clues.', kind.upper())
    if kind == 'pdf':
        add('specialized', 'Inspect PDF attachments and objects', 'PDF containers support embedded attachments and metadata independent of visible pages.', 'PDF header')
    signatures = [x for x in report.get('findings', []) if x.get('format') == 'zip']
    if signatures:
        add('forensics', 'Validate ZIP regions and inspect controlled extraction', 'A ZIP signature was observed; directory/local-record validation separates a container from a coincidental byte match.', f'{len(signatures)} ZIP signature findings')
    if any(x.get('encoding') in {'base64','hex','url','rot13'} for x in report.get('findings', [])):
        add('crypto', 'Follow decoded text with a recipe', 'A bounded decoder found text matching a flag pattern; further transformations may explain its provenance.', 'Decoded candidate finding')
    if any('base64' in str(x.get('history', [])).lower() for x in report.get('flag_candidates', [])):
        add('crypto', 'Review Base64 transformation history', 'Base64-like source text decoded into a configured flag pattern.', 'Flag Finder decoding history')
    else:
        import base64,re
        strings=next((a.get('data',{}).get('strings',[]) for a in report.get('analyzers',[]) if a['name']=='strings' and a.get('data')),[])
        for record in strings[:100]:
            value=record.get('text','').strip()
            if len(value)>=12 and len(value)%4==0 and re.fullmatch(r'[A-Za-z0-9+/]+={0,2}',value):
                try:
                    decoded=base64.b64decode(value,validate=True).decode('utf-8')
                    if decoded and sum(c.isprintable() for c in decoded)/len(decoded)>.9:
                        add('crypto','Try Base64 decoding','A complete Base64-shaped token decodes into mostly printable UTF-8; inspect the result before choosing further steps.',f'String at offset {record.get("offset")}')
                        break
                except (ValueError,UnicodeError):pass
    if not checks: add('forensics', 'Inspect structure, entropy and readable strings', 'These observations can guide additional checks even when no specialized format was recognized.', kind)
    return checks
