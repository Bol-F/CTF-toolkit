import base64
import gzip
import hashlib
import json
from pathlib import Path
import shutil
import zlib

import numpy as np
from PIL import Image
import pytest
from fastapi.testclient import TestClient

from stegolab.app import create_app
from stegolab.config import Settings
from stegolab.analysis.engine import analyze_job, Analysis
from stegolab.analysis.extraction import Limits
from stegolab.labs.actions import run_action
from stegolab.labs.crypto import apply, run_recipe
from stegolab.labs.flags import FlagFinder
from stegolab.labs.forensics import validate_region, png_chunks
from stegolab.labs.image import extract_lsb
from tests.fixtures.advanced import make_advanced
from tests.test_analysis import make_job


@pytest.fixture
def samples(tmp_path): return make_advanced(tmp_path/'advanced')


@pytest.fixture
def no_tools(monkeypatch):
    monkeypatch.setenv('PATH','');monkeypatch.delenv('STEGOLAB_TOOL_REGISTRY',raising=False)


@pytest.mark.parametrize('name',['lsb.png','lsb.bmp'])
def test_native_lsb_known_answer_for_lossless_formats(samples,name):
    result,info=extract_lsb(samples[name])
    assert result.startswith(b'flag{native_lsb_known_answer}\0')
    assert info['source_dimensions']==[64,64]


def test_lsb_channel_direction_bit_order_and_bit_selection(tmp_path):
    pixels=np.zeros((2,4,4),np.uint8);pixels[:,:,3]=255
    # Red bit0 in row order spells ASCII A (01000001).
    for i,bit in enumerate([0,1,0,0,0,0,0,1]): pixels[i//4,i%4,0]=bit
    target=tmp_path/'bits.png';Image.fromarray(pixels,'RGBA').save(target)
    assert extract_lsb(target,channels='R',max_bytes=1)[0]==b'A'
    assert extract_lsb(target,channels='R',max_bytes=1,bit_order='lsb')[0]==b'\x82'
    assert extract_lsb(target,channels='R',max_bytes=1,reverse=True)[0]==b'\x82'
    assert extract_lsb(target,channels='R',max_bytes=1,direction='column')[0]==b'\x21'
    assert extract_lsb(target,channels='R',bits=[1],max_bytes=1)[0]==b'\0'
    with pytest.raises(ValueError):extract_lsb(target,channels='R;sh')
    with pytest.raises(ValueError):extract_lsb(target,bits=[8])


def test_image_channels_alpha_gif_frames_and_metadata(samples,tmp_path,no_tools):
    report=analyze_job(make_job(tmp_path/'meta',samples['metadata.png'].read_bytes()),'deep')
    result=next(a for a in report['analyzers'] if a['name']=='image_lab')
    assert result['status']=='completed'
    assert result['data']['channels']['A']['min']==127
    assert any(f['type']=='unusual_metadata' for f in result['findings'])
    assert any(f['value']=='flag{unusual_metadata_answer}' for f in report['flag_candidates'])
    report=analyze_job(make_job(tmp_path/'gif',samples['frames.gif'].read_bytes()),'quick')
    frames=next(a for a in report['analyzers'] if a['name']=='image_lab')['data']['frames']
    assert len(frames)==3
    assert [f['duration_ms'] for f in frames]==[80,160,240]
    assert frames[1]['changed_pixel_fraction']==1


def test_automatic_lsb_flags_reach_central_finder(samples,tmp_path,no_tools):
    report=analyze_job(make_job(tmp_path/'image',samples['lsb.png'].read_bytes()),'deep')
    assert any(a['kind']=='lsb' for a in report['artifacts'])
    assert any(f['value']=='flag{native_lsb_known_answer}' and 'LSB' in str(f['history']) for f in report['flag_candidates'])


def test_structure_validation_rejects_coincidental_magic(samples):
    content=samples['appended.png'].read_bytes()
    chunks,end=png_chunks(content)
    assert all(c['crc_valid'] for c in chunks)
    assert validate_region(content,end,'zip')
    assert validate_region(b'noisePK\x03\x04not a zip',5,'zip') is None
    assert validate_region(b'noise%PDF-1.4 fake %%EOF',5,'pdf') is None


@pytest.mark.parametrize('encode,decode',[
    ('base64_encode','base64_decode'),('base32_encode','base32_decode'),('base85_encode','base85_decode'),
    ('hex_encode','hex_decode'),('binary_encode','binary_decode'),('decimal_encode','decimal_decode'),
    ('ascii_encode','ascii_decode'),('url_encode','url_decode'),('unicode_escape','unicode_unescape')])
def test_recipe_reversible_encodings(encode,decode):
    value='CTF{Unicode_é_🙂}'.encode()
    assert apply(apply(value,encode),decode)==value


def test_crypto_chain_and_byte_output_provenance(samples):
    result=run_recipe({'input':samples['encoded.txt'].read_text(),'steps':[{'operation':'base64_decode'},{'operation':'base32_decode'}]})
    assert result['output']['text']=='picoCTF{two_stage_decode}'
    assert len(result['steps'])==2
    assert result['flags'][0]['history']==['base64_decode','base32_decode']
    binary=run_recipe({'input':'00ff4142','input_encoding':'hex','steps':[{'operation':'xor','key':'ff'},{'operation':'reverse_bytes'}]})
    assert binary['output']['hex']=='bdbe00ff'


def test_classic_ciphers_unicode_and_compressed_limits():
    assert apply(b'Attack at dawn!','vigenere_encrypt','LEMON')==b'Lxfopv ef rnhr!'
    assert apply(b'Lxfopv ef rnhr!','vigenere_decrypt','LEMON')==b'Attack at dawn!'
    assert apply(b'Abc XYZ','atbash')==b'Zyx CBA'
    assert apply(b'flag{abc}','caesar',shift=13)==b'synt{nop}'
    assert apply(apply(b'hello!','rot47'),'rot47')==b'hello!'
    assert apply('🙂é'.encode(),'reverse_text')=='é🙂'.encode()
    assert apply(gzip.compress(b'flag{gzip}'),'gzip_decompress')==b'flag{gzip}'
    assert apply(zlib.compress(b'flag{zlib}'),'zlib_decompress')==b'flag{zlib}'
    with pytest.raises(ValueError):apply(zlib.compress(b'x'*(1024*1024+1)),'zlib_decompress')
    with pytest.raises(ValueError):run_recipe({'input':'xx','steps':[{'operation':'hex_encode'}]*20})


def test_flagfinder_custom_prefix_regex_timeout_and_multistage(samples):
    found=FlagFinder().scan_decoded(samples['encoded.txt'].read_bytes())
    assert any(f['value']=='picoCTF{two_stage_decode}' and f['history']==['Base64','Base32'] for f in found)
    exact=FlagFinder(['CUSTOM']).scan(b'xxCUSTOM{one}xx')
    assert exact[0]['offset']==2 and exact[0]['classification']=='confirmed_pattern_match'
    regex=FlagFinder(expression=r'KEY-[0-9]{4}').scan(b'xxKEY-1234')
    assert regex[0]['value']=='KEY-1234'
    finder=FlagFinder(expression=r'(a+)+$')
    assert finder.scan(b'a'*50000+b'!')==[]
    assert finder.errors


def test_audio_waveform_spectrum_and_stereo_channels(samples,tmp_path):
    report=analyze_job(make_job(tmp_path/'audio',samples['stereo.wav'].read_bytes()),'deep')
    data=next(a for a in report['analyzers'] if a['name']=='audio_lab')['data']
    assert data['channels']==2
    assert abs(data['channel_data'][0]['peak_frequency_hz']-440)<25
    assert abs(data['channel_data'][1]['peak_frequency_hz']-880)<25
    assert all(c['waveform'] for c in data['channel_data'])
    assert len([a for a in report['artifacts'] if a['kind']=='spectrogram'])==2


def test_lab_api_bytes_previews_recipes_actions_and_secret_cancel(samples,tmp_path):
    settings=Settings(data_dir=tmp_path/'data')
    with TestClient(create_app(settings)) as client:
        job=client.post('/api/jobs',files={'file':('lsb.png',samples['lsb.png'].read_bytes())}).json()
        store=client.app.state.store
        report=analyze_job(settings.jobs_dir/job['id'],'quick');store.finish(job['id'],'completed')
        info=client.get(f'/api/jobs/{job["id"]}/bytes?offset=1&length=8').json()
        assert info['bytes']==list(samples['lsb.png'].read_bytes()[1:9]) and info['offset_hex']=='0x1'
        assert client.get(f'/api/jobs/{job["id"]}/bytes?length=999999').status_code==422
        preview=next(a for a in report['artifacts'] if a.get('preview'))
        response=client.get(f'/api/jobs/{job["id"]}/preview/{preview["id"]}')
        assert response.headers['content-type']=='image/png'
        text_artifact=next(a for a in report['artifacts'] if a['name']=='strings.json')
        assert client.get(f'/api/jobs/{job["id"]}/preview/{text_artifact["id"]}').status_code==415
        action=client.post(f'/api/jobs/{job["id"]}/actions',json={'operation':'tool_extract','password':'do-not-report-this'}).json()
        assert action['parent_id']==job['id']
        assert client.delete(f'/api/jobs/{job["id"]}').status_code==409
        action_file=settings.jobs_dir/action['id']/'action.json'
        assert action_file.is_file()
        client.post(f'/api/jobs/{action["id"]}/cancel')
        assert not action_file.exists()
        recipe=client.post('/api/recipes',json={'input':'ZmxhZ3tyZWNpcGV9','steps':[{'operation':'base64_decode'}]}).json()
        root=settings.jobs_dir/recipe['id']
        result=run_action(root,json.loads((root/'action.json').read_text()))
        assert next(a for a in result['analyzers'] if a['name']=='crypto_lab')['data']['output']['text']=='flag{recipe}'


def test_real_qr_contents_reach_flagfinder(samples,tmp_path):
    if not shutil.which('zbarimg'):pytest.skip('zbarimg is installed in Docker')
    report=analyze_job(make_job(tmp_path/'qr',samples['qr.png'].read_bytes()),'deep')
    assert any(f['value']=='CTF{qr_only_known_answer}' and 'zbarimg' in str(f['history']) for f in report['flag_candidates'])


def test_real_ocr_contents_reach_flagfinder(samples,tmp_path):
    if not shutil.which('tesseract'):pytest.skip('Tesseract is installed in Docker')
    report=analyze_job(make_job(tmp_path/'ocr',samples['ocr.png'].read_bytes()),'deep')
    assert any(f['value']=='CTF{OCR_KNOWN_ANSWER}' and 'tesseract' in str(f['history']) for f in report['flag_candidates'])


def test_pdf_attachment_extraction_ignores_embedded_traversal_name(tmp_path):
    if not shutil.which('pdfdetach'):pytest.skip('pdfdetach is installed in Docker')
    payload=b'flag{pdf_attachment_bytes}\n'
    objects=[b'<< /Type /Catalog /Pages 2 0 R /Names << /EmbeddedFiles << /Names [(clue.txt) 4 0 R] >> >> >>',
             b'<< /Type /Pages /Kids [3 0 R] /Count 1 >>',
             b'<< /Type /Page /Parent 2 0 R /MediaBox [0 0 100 100] >>',
             b'<< /Type /Filespec /F (../../escape.txt) /EF << /F 5 0 R >> >>',
             f'<< /Type /EmbeddedFile /Length {len(payload)} >>\nstream\n'.encode()+payload+b'endstream']
    content=bytearray(b'%PDF-1.4\n');offsets=[0]
    for number,obj in enumerate(objects,1):
        offsets.append(len(content));content.extend(f'{number} 0 obj\n'.encode()+obj+b'\nendobj\n')
    xref=len(content)
    content.extend(f'xref\n0 {len(offsets)}\n0000000000 65535 f \n'.encode())
    for offset in offsets[1:]:content.extend(f'{offset:010} 00000 n \n'.encode())
    content.extend(f'trailer\n<< /Size {len(offsets)} /Root 1 0 R >>\nstartxref\n{xref}\n%%EOF\n'.encode())
    root=make_job(tmp_path/'pdf',bytes(content),'attachment.pdf')
    report=run_action(root,{'operation':'pdf_extract','attachment':1})
    assert report['analyzers'][-1]['status']=='completed',report
    artifact=next(a for a in report['artifacts'] if a['kind']=='pdf_attachment')
    assert (root/'artifacts'/artifact['path']).read_bytes()==payload
    assert not (tmp_path/'escape.txt').exists()


def test_recommendations_explain_base64_without_claiming_a_flag(tmp_path,no_tools):
    import base64
    content=base64.b64encode(b'A printable clue with no flag pattern inside.')
    report=analyze_job(make_job(tmp_path/'encoded',content,'encoded.txt'),'quick')
    suggestions=[r for r in report['recommended_operations'] if r['operation']=='crypto']
    assert suggestions and 'printable' in suggestions[0]['why'].lower()
    assert suggestions[0]['guarantees_hidden_data'] is False
