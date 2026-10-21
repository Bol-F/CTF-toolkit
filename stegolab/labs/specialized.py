"""Explicit stego adapters. Legacy/unavailable programs are reported honestly."""
import re
import shutil


def spec(executable, formats, license, source, installation, parameters, blocked=None):
    return {'executables':[executable], 'version_args':['--help'], 'formats':formats, 'license':license,
            'source':source, 'installation':installation, 'parameters':[parameters], 'parser':'bounded diagnostics and payload',
            'manual':True, 'blocked':blocked}


SPECS = {
    'sox':spec('sox',['wav','mp3','flac','ogg'],'GPL-2.0-or-later / libSoX LGPL-2.1-or-later','https://sox.sourceforge.net/','Debian package','stat on normalized PCM'),
    'stegseek':spec('stegseek',['jpeg','bmp','wav','au'],'GPL-2.0','https://github.com/RickdeJager/stegseek','Optional image: pinned v0.6 build','--crack fixed-input supplied-wordlist fixed-output -t 1 -s -n'),
    'stegoveritas':spec('stegoveritas',['png','jpeg','bmp','gif','tiff','webp'],'MIT (package metadata)','https://github.com/bannsec/stegoVeritas','Optional image: 1.11 in isolated venv','-meta only; external carving and extraction disabled'),
    'outguess':spec('outguess',['jpeg','ppm','pnm'],'BSD-4-Clause/BSD-3-Clause; IJG JPEG license; additional source licenses in Debian copyright','https://github.com/resurrecting-open-source-projects/outguess','Debian trixie 1:0.4-2 in optional image','-k supplied-password -r fixed-input fixed-output'),
    'openstego':spec('openstego',['png','bmp'],'GPL-2.0','https://github.com/syvaidya/openstego','Optional image: SHA256-pinned official 0.8.6 Java distribution','extract RandomLSB with supplied password'),
    'stegsnow':spec('stegsnow',['text'],'Apache-2.0; Debian packaging BSD-3-Clause','https://www.darkside.com.au/snow/','Debian trixie 20130616-8 in optional image','-C -p supplied-password fixed-input fixed-output'),
    'stegdetect':spec('stegdetect',['jpeg'],'BSD-style + bundled JPEG license','https://github.com/abeluck/stegdetect','Unsupported legacy source; no verified modern build','disabled',
                      'Archived/unmaintained detector; deliberately excluded and never executed'),
}
SPECS['sox']['version_args'] = ['--version']
SPECS['stegseek']['version_args'] = ['--version']
SPECS['outguess']['version_args'] = ['-h']
SPECS['stegsnow']['version_args'] = ['-V']
SPECS['openstego']['version_args'] = ['--version']


def execute(analysis, options):
    from ..analysis.engine import stage, identify
    from ..analysis.tools import SPECS as ALL_SPECS, run_command
    from .flags import FlagFinder
    name = options.get('tool','steghide')
    if name not in {'steghide','zsteg',*SPECS} or name == 'sox': raise ValueError('Unknown extraction adapter')
    entry = ALL_SPECS[name]
    if entry.get('blocked'): return stage(name,status='unavailable',errors=[entry['blocked']])
    executable = shutil.which(entry['executables'][0])
    if not executable: return stage(name,status='unavailable',errors=[f'{name} is not installed in this worker'])
    if analysis.report['file']['format'] not in entry['formats']: raise ValueError(f'{name} is incompatible with this detected format')
    password, candidates = options.get('password',''), options.get('passwords',[])
    if len(password.encode()) > 256 or len(candidates) > 1000 or any(len(p.encode()) > 256 or '\n' in p or '\x00' in p for p in candidates):
        raise ValueError('At most 1,000 supplied candidates of 256 bytes are permitted')
    out = analysis.root/'specialized'; out.mkdir()
    output, source = out/'payload.bin', str(analysis.original)
    if name=='outguess':
        # OutGuess selects a handler by extension. The extension is derived from
        # the detected format, never from the upload's display filename.
        source_copy = out / ('input.jpg' if analysis.report['file']['format']=='jpeg' else 'input.ppm')
        shutil.copyfile(analysis.original,source_copy)
        source = str(source_copy)
    if name == 'steghide': args = ['extract','-sf',source,'-xf',str(output),'-p',password,'-f']
    elif name == 'outguess': args = ['-k',password,'-r',source,str(output)]
    elif name == 'stegsnow': args = ['-C','-p',password,source,str(output)]
    elif name == 'openstego': args = ['extract','-a','RandomLSB','-sf',source,'-xd',str(out),'-xf','payload.bin','-p',password]
    elif name == 'stegseek':
        if not candidates: raise ValueError('StegSeek requires a supplied candidate list; no bundled dictionary/seed sweep is used')
        wordlist = analysis.job/'supplied-wordlist.txt'
        wordlist.write_text('\n'.join(candidates)+'\n',encoding='utf-8'); wordlist.chmod(0o600)
        args = ['--crack',source,str(wordlist),str(output),'-t','1','-s','-n','-f']
    elif name == 'stegoveritas': args = ['-meta','-out',str(out),source]
    else: args = ['-a',source]
    try:
        result = run_command([executable,*args],analysis.root,timeout=20,max_output=1048576)
        text = result['stdout']+'\n'+result['stderr']
        for secret in sorted((s for s in [password,*candidates] if s),key=len,reverse=True): text = text.replace(secret,'[redacted]')
        text = re.sub(r'(?im)^.*(?:found passphrase|passphrase:|password:).*$', '[password diagnostic redacted]',text)
        artifacts = [analysis.artifact(f'{name}-diagnostics.txt',text.encode(),kind='tool_output')]
        for target in list(out.iterdir())[:10]:
            if target.name.startswith('input.'):continue
            if target.is_file() and not target.is_symlink() and target.stat().st_size <= 1048576:
                data = target.read_bytes(); fmt,mime = identify(data)
                record = analysis.artifact(target.name,data,mime,'tool_extracted')
                record.update(method=name,detected_format=fmt,partial=result['status']!='completed'); artifacts.append(record)
        finder, findings = FlagFinder(), []
        for record in artifacts: findings.extend(finder.scan_decoded((analysis.root/record['path']).read_bytes(),record['name'],[name]))
        if name not in {'zsteg','stegoveritas'} and not any(a['kind']=='tool_extracted' for a in artifacts) and result['status']=='completed':
            result['status']='failed'
        return stage(name,findings,[] if result['status']=='completed' else [f'{name} failed or produced no payload; review redacted diagnostics'],artifacts,status=result['status'],
                     data={'returncode':result['returncode'],'passwords_persisted':False,'limits':{'seconds':20,'threads':1,'candidates':1000,'output_bytes':1048576}})
    finally:
        (analysis.job/'supplied-wordlist.txt').unlink(missing_ok=True)
        shutil.rmtree(out,ignore_errors=True)
