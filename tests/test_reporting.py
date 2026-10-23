from __future__ import annotations

import hashlib
import shutil
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from stegolab.app import create_app
from stegolab.config import Settings
from stegolab.reporting import flag_candidates, markdown_report
from stegolab.store import CapacityError, Store, atomic_json


def report(job_id='a' * 32):
    return {
        'job_id': job_id, 'mode': 'deep', 'status': 'completed',
        'file': {'filename': 'clue.png', 'sha256': hashlib.sha256(b'fixture').hexdigest(), 'size': 7, 'format': 'png'},
        'tools': [{'name': 'zsteg', 'version': '0.2.13', 'available': True, 'license': 'MIT'},
                  {'name': 'stegdetect', 'version': None, 'available': False}],
        'action': {'operation': 'image_lsb', 'parameters': {'channels': 'BGR', 'bits': [0], 'direction': 'column'}},
        'analyzers': [{'name': 'image_lsb', 'status': 'completed', 'duration_ms': 42, 'errors': []}],
        'flag_candidates': [
            {'value': 'flag{exact_match}', 'source_file': 'clue.png', 'offset': 32, 'classification': 'confirmed_pattern_match',
             'method': 'raw bytes', 'history': [], 'evidence': 'Exact pattern match'},
            {'value': 'CTF{derived_answer}', 'source_file': 'lsb-extracted.bin', 'offset': None, 'classification': 'heuristic_candidate',
             'method': 'Base64', 'history': ['configured image LSB', 'Base64'], 'evidence': 'Heuristic decoding'}],
        'findings': [{'type': 'signature', 'title': 'ZIP data', 'offset': 73, 'confidence': .99,
                      'analyzer': 'file_forensics', 'detail': '<script>alert(1)</script> | [click](https://invalid.example)'}],
        'artifacts': [{'id': 'artifact-1', 'name': 'lsb-extracted.bin', 'path': 'opaque.bin', 'kind': 'lsb', 'size': 17, 'offset': 73}],
        'recommendations': [{'title': 'Inspect bit planes', 'why': 'PNG supports lossless channel data'}], 'errors': [],
    }


def terminal(store, value=None, filename='clue.png'):
    job_id = store.reserve(filename, 'deep')
    root = store.settings.jobs_dir / job_id
    root.mkdir()
    if value is not None:
        atomic_json(root / 'report.json', {**value, 'job_id': job_id})
    store.finish(job_id, 'completed')
    return job_id


def test_markdown_contains_evidence_offsets_versions_and_inert_untrusted_text():
    data = report()
    text = markdown_report(data)
    assert data['file']['sha256'] in text
    for expected in ['32 (0x20)', '73 (0x49)', 'zsteg', '0.2.13', 'stegdetect', 'unavailable',
                     'flag{exact\\_match}', 'CTF{derived\\_answer}', 'lsb-extracted.bin', 'configured image LSB',
                     'BGR', 'column', 'Unknown', 'Artifact contents are separate downloads']:
        assert expected in text
    assert '<script>' not in text
    assert '&lt;script&gt;' in text
    assert '[click](https://invalid.example)' not in text
    assert '\\| \\[click\\]' in text
    assert 'not proof of challenge acceptance' in text


def test_candidates_normalize_legacy_without_promoting_confidence_or_inventing_offsets():
    data = {'file': {'filename': 'old.txt'}, 'analyzers': [{'name': 'strings', 'findings': [
        {'type': 'flag', 'value': 'flag{old}', 'confidence': .98, 'offset': 8},
        {'type': 'flag', 'value': 'flag{old}', 'confidence': .98, 'offset': 8}]}]}
    candidates = flag_candidates(data)
    assert len(candidates) == 1
    assert candidates[0]['classification'] == 'heuristic_candidate'
    assert candidates[0]['byte_offset'] == 8
    assert candidates[0]['transformation_history'] == []
    new = flag_candidates(report())
    assert new[1]['artifact_id'] == 'artifact-1'
    assert new[1]['byte_offset'] is None


def test_markdown_api_and_index_filters_pagination_and_persistence(tmp_path: Path):
    settings = Settings(data_dir=tmp_path / 'data')
    with TestClient(create_app(settings)) as client:
        store = client.app.state.store
        first = terminal(store, report(), 'first.png')
        second = terminal(store, report(), 'second.png')
        response = client.get(f'/api/jobs/{first}/report?format=markdown&download=true')
        assert response.status_code == 200
        assert response.headers['content-type'].startswith('text/markdown')
        assert response.headers['content-disposition'] == f'attachment; filename="stegolab-{first}.md"'
        assert first in response.text
        assert client.get(f'/api/jobs/{first}/report').json()['file'] == report()['file']
        assert client.get(f'/api/jobs/{first}/report?format=pdf').status_code == 422
        result = client.get('/api/flags?classification=heuristic_candidate&limit=1').json()
        assert result['total'] == 2 and result['limit'] == 1 and result['offset'] == 0
        candidate = result['candidates'][0]
        assert candidate['job_id'] == second and candidate['job_filename'] == 'second.png'
        assert candidate['byte_offset'] is None and candidate['artifact_id'] == 'artifact-1'
        assert candidate['transformation_history'] == ['configured image LSB', 'Base64']
        assert client.get('/api/flags?classification=heuristic_candidate&limit=1&offset=1').json()['candidates'][0]['job_id'] == first
        assert client.get('/api/flags?query=FIRST.png').json()['total'] == 2
        assert client.get('/api/flags?query=exact_match').json()['total'] == 2
        assert client.get('/api/flags?query=%25').json()['total'] == 0  # '%' is literal, not a LIKE wildcard.
        for suffix in ('classification=confirmed', 'limit=101', 'offset=-1', 'query=' + 'x' * 257):
            assert client.get('/api/flags?' + suffix).status_code == 422
        assert client.delete(f'/api/jobs/{first}').status_code == 204
        assert client.get('/api/flags').json()['total'] == 2
    with TestClient(create_app(settings)) as client:
        assert client.get('/api/flags').json()['candidates'][0]['job_id'] == second


def test_prior_report_index_migrates_and_missing_directory_can_be_deleted(tmp_path: Path):
    settings = Settings(data_dir=tmp_path / 'data')
    store = Store(settings)
    job_id = terminal(store, report())
    with store.connect() as db:
        db.execute('DELETE FROM flag_index')
        db.execute('DELETE FROM flag_index_jobs')
    with TestClient(create_app(settings)) as client:
        assert client.get('/api/flags').json()['total'] == 2
        shutil.rmtree(settings.jobs_dir / job_id)
        assert client.delete(f'/api/jobs/{job_id}').status_code == 204
        assert client.get('/api/flags').json()['total'] == 0


def test_safe_deletion_and_child_admission_are_serialized(tmp_path: Path):
    store = Store(Settings(data_dir=tmp_path / 'data'))
    parent = terminal(store)
    child = store.reserve('child', 'deep', parent_id=parent)
    with pytest.raises(ValueError, match='active lab action'):
        store.delete_finished(parent)
    assert store.get(parent) is not None
    store.finish(child, 'cancelled')
    store.delete_finished(parent)
    with pytest.raises(CapacityError, match='no longer available'):
        store.reserve('late child', 'deep', parent_id=parent)
    assert store.get(child)['status'] == 'cancelled'


def test_flag_api_preserves_no_report_and_running_job_semantics(tmp_path: Path):
    with TestClient(create_app(Settings(data_dir=tmp_path / 'data'))) as client:
        store = client.app.state.store
        absent = terminal(store)
        queued = store.reserve('queued', 'quick')
        assert client.get(f'/api/jobs/{absent}/report?format=markdown').status_code == 404
        assert client.get(f'/api/jobs/{queued}/report?format=markdown').status_code == 409
        assert client.get('/api/flags').json()['total'] == 0


def test_rescan_candidates_link_to_parent_artifact_evidence(tmp_path: Path):
    from types import SimpleNamespace
    from stegolab.labs.flags import scan_report
    artifacts = tmp_path / 'artifacts'
    artifacts.mkdir()
    (artifacts / 'opaque.bin').write_bytes(b'CTF{artifact_evidence}')
    source_job = 'b' * 32
    report = {'job_id': source_job, 'file': {'filename': 'clue.png'}, 'analyzers': [], 'findings': [],
              'artifacts': [{'id': 'exact-artifact', 'path': 'opaque.bin', 'name': 'nested-clue.txt', 'kind': 'extracted'}]}
    scan_report(SimpleNamespace(report=report, root=artifacts, data=b'not a flag'))
    candidate = report['flag_candidates'][0]
    assert candidate['value'] == 'CTF{artifact_evidence}'
    assert candidate['artifact_id'] == 'exact-artifact'
    assert candidate['source_job_id'] == source_job


def test_artifact_scoped_flag_action_does_not_scan_unrelated_parent_evidence(tmp_path: Path, monkeypatch):
    import json
    from stegolab.analysis.engine import Analysis, stage
    from stegolab.labs.actions import run_action
    monkeypatch.setattr(Analysis, 'inventory', lambda self: stage('tool_registry'))
    settings = Settings(data_dir=tmp_path / 'data')
    with TestClient(create_app(settings)) as client:
        uploaded = client.post('/api/jobs', files={'file': ('parent.png', b'flag{original_parent}')}).json()
        job_id = uploaded['id']
        root = settings.jobs_dir / job_id
        artifacts = root / 'artifacts'
        artifacts.mkdir()
        selected_bytes = b'prefix flag{selected_artifact}'
        (artifacts / 'selected.bin').write_bytes(selected_bytes)
        (artifacts / 'unrelated.bin').write_bytes(b'flag{unrelated_sibling}')
        parent = report(job_id)
        parent['file']['filename'] = 'parent.png'
        parent['flag_candidates'] = [{'value': 'flag{original_parent}', 'offset': 0, 'source_file': 'parent.png'}]
        parent['artifacts'] = [
            {'id': 'selected', 'name': 'nested-clue.txt', 'path': 'selected.bin', 'kind': 'extracted'},
            {'id': 'unrelated', 'name': 'other-clue.txt', 'path': 'unrelated.bin', 'kind': 'extracted'}]
        atomic_json(root / 'report.json', parent)
        client.app.state.store.finish(job_id, 'completed')
        response = client.post(f'/api/jobs/{job_id}/actions', json={'operation': 'flag_scan', 'artifact_id': 'selected'})
        assert response.status_code == 202, response.text
        child = response.json()
        child_root = settings.jobs_dir / child['id']
        options = json.loads((child_root / 'action.json').read_text())
        assert options['source_artifact_id'] == 'selected'
        output = run_action(child_root, options)
        client.app.state.store.finish(child['id'], 'completed')
        candidates = output['flag_candidates']
        assert candidates and {item['value'] for item in candidates} == {'flag{selected_artifact}'}
        assert all(item['source_file'] == 'nested-clue.txt' for item in candidates)
        assert all(item['source_job_id'] == job_id and item['artifact_id'] == 'selected' for item in candidates)
        assert next(item for item in candidates if item['method'] == 'raw bytes')['offset'] == 7
        indexed = client.get('/api/flags?query=selected_artifact').json()['candidates']
        assert indexed[0]['byte_offset'] == 7
        assert indexed[0]['source_job_id'] == job_id and indexed[0]['artifact_id'] == 'selected'
        # Docker is the runtime; permit cleanup of read-only evidence on Windows.
        for path in settings.jobs_dir.rglob('original.bin'):
            path.chmod(0o600)
