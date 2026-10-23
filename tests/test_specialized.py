"""Real known-password round trips; absent optional tools are explicit skips."""
import json
from pathlib import Path
import shutil

import numpy as np
from PIL import Image
import pytest

from stegolab.analysis.tools import run_command
from stegolab.labs.actions import run_action
from tests.test_analysis import make_job

SECRET=b'flag{specialized_roundtrip}\n'
PASSWORD='ctf-user-supplied-key-3921'


@pytest.mark.parametrize('tool',['steghide','stegseek','outguess','openstego','stegsnow'])
def test_real_specialized_payload_roundtrip_with_supplied_password(tool,tmp_path):
    if not shutil.which(tool):pytest.skip(f'{tool} requires its installed worker variant')
    raw=np.random.default_rng(42).integers(0,256,(256,256,3),dtype=np.uint8)
    cover=tmp_path/'cover.png';Image.fromarray(raw).save(cover)
    secret=tmp_path/'secret.txt';secret.write_bytes(SECRET)
    if tool in {'steghide','stegseek'}:
        if not shutil.which('steghide'):pytest.skip('steghide fixture encoder unavailable')
        cover=tmp_path/'cover.bmp';Image.fromarray(raw).save(cover)
        stego=tmp_path/'stego.bmp'
        command=['steghide','embed','-cf',str(cover),'-ef',str(secret),'-sf',str(stego),'-p',PASSWORD,'-f','-q']
    elif tool=='outguess':
        cover=tmp_path/'cover.jpg';Image.fromarray(raw).save(cover,quality=90)
        stego=tmp_path/'stego.jpg'
        command=['outguess','-k',PASSWORD,'-d',str(secret),str(cover),str(stego)]
    elif tool=='openstego':
        stego=tmp_path/'stego.png'
        command=['openstego','embed','-a','RandomLSB','-mf',str(secret),'-cf',str(cover),'-sf',str(stego),'-p',PASSWORD]
    else:
        cover=tmp_path/'cover.txt';cover.write_text('A benign CTF whitespace carrier.\n'*50)
        stego=tmp_path/'stego.txt'
        command=['stegsnow','-C','-p',PASSWORD,'-m',SECRET.decode().strip(),str(cover),str(stego)]
    result=run_command(command,tmp_path,timeout=15)
    assert result['status']=='completed' and stego.exists(),result
    root=make_job(tmp_path/'job',stego.read_bytes(),stego.name)
    options={'operation':'tool_extract','tool':tool,'password':PASSWORD}
    if tool=='stegseek':options.update(password='',passwords=['wrong-guess',PASSWORD])
    report=run_action(root,options)
    result=report['analyzers'][-1]
    assert result['status']=='completed',result
    payloads=[a for a in report['artifacts'] if a['kind']=='tool_extracted']
    assert payloads
    contents=[(root/'artifacts'/a['path']).read_bytes() for a in payloads]
    assert any(SECRET.strip() in content for content in contents)
    diagnostics=[(root/'artifacts'/a['path']).read_text() for a in report['artifacts'] if a['kind']=='tool_output']
    assert all(PASSWORD not in text for text in diagnostics)
    assert PASSWORD not in json.dumps(report)
    assert not (root/'supplied-wordlist.txt').exists()


def test_stegoveritas_metadata_only_adapter(tmp_path):
    if not shutil.which('stegoveritas'):pytest.skip('StegoVeritas is optional')
    from PIL import PngImagePlugin
    import io
    metadata=PngImagePlugin.PngInfo();metadata.add_text('Comment','flag{veritas_metadata}')
    output=io.BytesIO();Image.new('RGB',(40,30),'white').save(output,'PNG',pnginfo=metadata)
    root=make_job(tmp_path/'metadata-job',output.getvalue(),'metadata.png')
    report=run_action(root,{'operation':'tool_extract','tool':'stegoveritas'})
    assert report['analyzers'][-1]['status']=='completed',report


def test_legacy_detector_is_unavailable_even_if_on_path(tmp_path):
    root=make_job(tmp_path/'legacy',b'\xff\xd8\xff\xd9','sample.jpg')
    report=run_action(root,{'operation':'tool_extract','tool':'stegdetect'})
    assert report['analyzers'][-1]['status']=='unavailable'
    assert not any(a['kind']=='tool_extracted' for a in report['artifacts'])


def test_openstego_real_worker_address_limit_and_parameter_cleanup(tmp_path):
    """The Java adapter must function inside the actual 768 MiB worker limit."""
    import os
    import sys
    if sys.platform != 'linux' or not shutil.which('openstego'):
        pytest.skip('OpenStego restricted-worker integration requires the optional Linux image')
    from fastapi.testclient import TestClient
    from stegolab.app import create_app
    from stegolab.config import Settings
    from tests.test_worker import worker, wait_for, terminal
    raw=np.random.default_rng(12).integers(0,256,(256,256,3),dtype=np.uint8)
    cover=tmp_path/'cover.png';Image.fromarray(raw).save(cover)
    secret=tmp_path/'secret.txt';secret.write_bytes(SECRET)
    stego=tmp_path/'stego.png'
    result=run_command(['openstego','embed','-a','RandomLSB','-mf',str(secret),'-cf',str(cover),'-sf',str(stego),'-p',PASSWORD],tmp_path,timeout=15)
    assert result['status']=='completed' and stego.exists(),result
    settings=Settings(data_dir=tmp_path/'data',concurrency=1,memory_mb=768,deep_timeout=35)
    with TestClient(create_app(settings)) as client:
        parent=client.post('/api/jobs',files={'file':('stego.png',stego.read_bytes())}).json()
        client.app.state.store.finish(parent['id'],'completed')
        with worker(settings,tool_path=os.environ.get('PATH','')) as (_,store):
            response=client.post(f'/api/jobs/{parent["id"]}/actions',json={'operation':'tool_extract','tool':'openstego','password':PASSWORD})
            assert response.status_code==202,response.text
            child=response.json()
            job=wait_for(lambda:terminal(store,child['id']),seconds=40,description='OpenStego inside restricted worker')
            report=client.get(f'/api/jobs/{child["id"]}/report').json()
            diagnostics=[(settings.jobs_dir/child['id']/'artifacts'/a['path']).read_text(errors='replace')
                         for a in report.get('artifacts',[]) if a['kind']=='tool_output']
            assert job['status']=='completed',{'errors':report.get('errors'),'diagnostics':diagnostics}
            assert report['analyzers'][-1]['status']=='completed',report
            artifacts=[a for a in report['artifacts'] if a['kind']=='tool_extracted']
            assert artifacts
            assert SECRET in client.get(f'/api/jobs/{child["id"]}/artifacts/{artifacts[0]["id"]}').content
            assert not (settings.jobs_dir/child['id']/'action.json').exists()
