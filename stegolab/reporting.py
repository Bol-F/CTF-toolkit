"""Portable evidence summaries; reports remain data, never rendered HTML."""
from __future__ import annotations

import json


def flag_candidates(report):
    """Normalize current and older reports without upgrading heuristic evidence."""
    candidates = list(report.get('flag_candidates') or [])
    if not candidates:
        for stage in report.get('analyzers', []):
            for item in stage.get('findings', []):
                if item.get('type') == 'flag' and item.get('value'):
                    candidates.append({**item, 'method': item.get('method', stage.get('name', 'native'))})
    seen, result = set(), []
    for item in candidates[:2000]:
        if not isinstance(item, dict) or not isinstance(item.get('value'), str):
            continue
        candidate = dict(item)
        candidate['source_file'] = item.get('source_file', item.get('source', report.get('file', {}).get('filename', 'original')))
        candidate['byte_offset'] = item.get('byte_offset', item.get('offset'))
        candidate['transformation_history'] = item.get('transformation_history', item.get('history', []))
        matches = [artifact for artifact in report.get('artifacts', []) if artifact.get('name') == candidate['source_file']]
        if len(matches) == 1 and matches[0].get('id'):
            candidate.setdefault('artifact_id', matches[0]['id'])
        candidate.setdefault('classification', 'heuristic_candidate')
        candidate.setdefault('evidence', 'Legacy candidate; inspect the source evidence and challenge context')
        key = json.dumps([candidate['value'], candidate['source_file'], candidate['byte_offset'], candidate.get('method'), candidate['transformation_history']], ensure_ascii=True)
        if key in seen:
            continue
        seen.add(key)
        result.append(candidate)
    return result


def _cell(value):
    """Escape report content as inert Markdown table text, including HTML."""
    if isinstance(value, (dict, list)):
        value = json.dumps(value, ensure_ascii=False)
    text = '' if value is None else str(value)
    # Escape backslash first. HTML is encoded so uploaded metadata cannot inject tags.
    return (text.replace('\\', '\\\\').replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;')
            .replace('|', '\\|').replace('`', '\\`').replace('[', '\\[').replace(']', '\\]')
            .replace('*', '\\*').replace('_', '\\_').replace('\r', ' ').replace('\n', ' / '))


def _offset(value):
    return f'{value} ({hex(value)})' if isinstance(value, int) and not isinstance(value, bool) and value >= 0 else 'Unknown'


def markdown_report(report, job=None):
    """Generate a deterministic reviewable report from the stored analysis only."""
    job = job or {}
    file = report.get('file', {})
    rows = ['# StegoLab investigation report', '',
            'Flag candidates are evidence of a pattern match, not proof of challenge acceptance.', '',
            '## Investigation', '', '| Field | Value |', '| --- | --- |']
    facts = [('Job ID', report.get('job_id', job.get('id'))), ('Filename', file.get('filename', job.get('filename'))),
             ('Status', job.get('status', report.get('status'))), ('Scan mode', report.get('mode', job.get('mode'))),
             ('Created at', job.get('created_at')), ('Started at', report.get('started_at')),
             ('Completed at', report.get('completed_at')), ('Parent investigation', job.get('parent_id')),
             ('File size (bytes)', file.get('size', job.get('size'))), ('Detected format', file.get('format')),
             ('Media type', file.get('mime')), ('SHA-256', file.get('sha256', job.get('sha256')))]
    rows += [f'| {_cell(label)} | {_cell(value)} |' for label, value in facts if value is not None]
    rows += ['', '## Operations performed', '', '| Operation | Status | Duration (ms) | Errors |', '| --- | --- | --- | --- |']
    for stage in report.get('analyzers', []):
        rows.append('| ' + ' | '.join(_cell(value) for value in (stage.get('name'), stage.get('status'), stage.get('duration_ms'), stage.get('errors', []))) + ' |')
    action = report.get('action')
    if action:
        rows += ['', 'Explicit action: ' + _cell(action.get('operation')), '', 'Public action parameters: ' + _cell(action.get('parameters', {}))]
    for stage in report.get('analyzers', []):
        if stage.get('name') == 'crypto_lab':
            rows += ['', 'Recipe steps: ' + _cell([step.get('operation') for step in stage.get('data', {}).get('steps', [])])]
    rows += ['', '## Tool inventory', '', '| Tool | Version | Availability | License |', '| --- | --- | --- | --- |']
    tools = report.get('tools', [])
    for tool in tools:
        rows.append('| ' + ' | '.join(_cell(value) for value in (tool.get('name'), tool.get('version'), 'available' if tool.get('available') else 'unavailable', tool.get('license'))) + ' |')
    if not tools:
        rows += ['| No inventory recorded | Unknown | Not recorded | |']
    rows += ['', '## Flag candidates', '', '| Value | Source | Byte offset | Method | Classification | Evidence | Transformation history |', '| --- | --- | --- | --- | --- | --- | --- |']
    for candidate in flag_candidates(report):
        rows.append('| ' + ' | '.join(_cell(value) for value in (candidate['value'], candidate['source_file'], _offset(candidate['byte_offset']), candidate.get('method'), candidate['classification'], candidate['evidence'], candidate['transformation_history'])) + ' |')
    rows += ['', '## Findings and offsets', '', '| Analyzer | Finding | Byte offset | Confidence | Evidence |', '| --- | --- | --- | --- | --- |']
    for item in report.get('findings', []):
        rows.append('| ' + ' | '.join(_cell(value) for value in (item.get('analyzer'), item.get('title', item.get('type')), _offset(item.get('offset')), item.get('confidence'), item.get('detail'))) + ' |')
    rows += ['', '## Extracted files and generated artifacts', '', '| Name | Kind | Bytes | SHA-256 | Artifact ID | Source offset |', '| --- | --- | --- | --- | --- | --- |']
    for item in report.get('artifacts', []):
        rows.append('| ' + ' | '.join(_cell(value) for value in (item.get('name'), item.get('kind'), item.get('size'), item.get('sha256', 'Not recorded'), item.get('id'), _offset(item.get('offset')))) + ' |')
    rows += ['', 'Artifact contents are separate downloads; this report does not bundle uploaded files.', '', '## Recommended follow-up', '']
    for item in report.get('recommended_operations') or report.get('recommendations', []):
        detail = f"{item.get('title', item.get('operation', 'Operation'))}: {item.get('why', '')}" if isinstance(item, dict) else item
        rows.append('- ' + _cell(detail))
    rows += ['', '## Report errors', '']
    rows += ['- ' + _cell(error) for error in report.get('errors', [])] or ['None recorded.']
    return '\n'.join(rows) + '\n'
