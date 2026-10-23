"""Live, standard-library release smoke test; removes only jobs it creates."""
from __future__ import annotations

import json
from pathlib import Path
import sys
import time
import urllib.error
import urllib.request
import uuid


BASE = sys.argv[1].rstrip('/') if len(sys.argv) > 1 else 'http://localhost:8080'
CREATED = []


def request(path, body=None, method=None, content_type='application/json'):
    headers = {'Content-Type': content_type} if body is not None else {}
    return urllib.request.urlopen(urllib.request.Request(BASE + path, body, headers, method=method), timeout=15)


def json_request(path, value=None, method=None):
    body = json.dumps(value).encode() if value is not None else None
    with request(path, body, method) as response:
        content = response.read()
        return json.loads(content) if content else None


def wait_report(identifier):
    deadline = time.monotonic() + 330
    while time.monotonic() < deadline:
        job = json_request(f'/api/jobs/{identifier}')
        if job['status'] in ('completed', 'failed', 'cancelled', 'timeout'):
            if job['status'] != 'completed':
                raise AssertionError(f'Job {identifier} ended as {job["status"]}: {job}')
            return json_request(f'/api/jobs/{identifier}/report')
        time.sleep(.5)
    raise TimeoutError(f'Job {identifier} did not finish')


def main():
    health = json_request('/api/health')
    if not health.get('worker', {}).get('online', health.get('worker_online', False)):
        # Health shape may be versioned; a successful scan below is the final worker check.
        print('Health endpoint reached; verifying the worker with an actual scan.')
    sample = Path(__file__).resolve().parents[1] / 'examples' / 'appended.png'
    boundary = 'stegolab-' + uuid.uuid4().hex
    body = (f'--{boundary}\r\nContent-Disposition: form-data; name="mode"\r\n\r\ndeep\r\n'
            f'--{boundary}\r\nContent-Disposition: form-data; name="file"; filename="release-example.png"\r\n'
            f'Content-Type: image/png\r\n\r\n').encode() + sample.read_bytes() + f'\r\n--{boundary}--\r\n'.encode()
    with request('/api/jobs', body, 'POST', f'multipart/form-data; boundary={boundary}') as response:
        uploaded = json.load(response)
    CREATED.append(uploaded['id'])
    report = wait_report(uploaded['id'])
    serialized = json.dumps(report)
    for flag in ('flag{example_appended_zip}', 'CTF{example_nested_archive}'):
        assert flag in serialized, f'Missing known answer: {flag}'
    extracted = [item for item in report['artifacts'] if item.get('kind') == 'extracted']
    assert extracted, 'No archive members were extracted'
    with request(f'/api/jobs/{uploaded["id"]}/artifacts/{extracted[0]["id"]}') as response:
        assert response.read(), 'Extracted artifact download was empty'
    with request(f'/api/jobs/{uploaded["id"]}/report?download=1') as response:
        assert 'attachment' in response.headers.get('Content-Disposition', '')
        assert json.load(response)['schema_version']
    with request(f'/api/jobs/{uploaded["id"]}/report?format=markdown&download=1') as response:
        assert 'attachment' in response.headers.get('Content-Disposition', '')
        markdown = response.read().decode('utf-8')
        assert '# StegoLab investigation report' in markdown
        assert 'flag{example_appended_zip}' in markdown.replace('\\_', '_'), 'Markdown omitted the known flag'
    encoded = (sample.parent / 'encoded.txt').read_text().strip()
    recipe = json_request('/api/recipes', {'input': encoded, 'input_encoding': 'utf8',
        'steps': [{'operation': 'base64_decode'}, {'operation': 'base32_decode'}]}, 'POST')
    CREATED.append(recipe['id'])
    assert 'picoCTF{example_two_stage_decode}' in json.dumps(wait_report(recipe['id']))
    try:
        json_request('/api/jobs/invalid-id')
    except urllib.error.HTTPError as error:
        assert error.code in (400, 404, 422), error.code
    else:
        raise AssertionError('Malformed job ID unexpectedly succeeded')
    print('PASS: live scan, nested flags, extraction/download, JSON/Markdown export, two-step recipe, malformed-ID handling')


if __name__ == '__main__':
    try:
        main()
    finally:
        for identifier in reversed(CREATED):
            try:
                job = json_request(f'/api/jobs/{identifier}')
                if job['status'] not in ('completed', 'failed', 'cancelled', 'timeout'):
                    json_request(f'/api/jobs/{identifier}/cancel', {}, 'POST')
                    deadline = time.monotonic() + 10
                    while time.monotonic() < deadline and json_request(f'/api/jobs/{identifier}')['status'] in ('queued', 'running', 'uploading'):
                        time.sleep(.25)
                json_request(f'/api/jobs/{identifier}', method='DELETE')
            except Exception as error:
                print(f'Cleanup for smoke job {identifier}: {error}', file=sys.stderr)
