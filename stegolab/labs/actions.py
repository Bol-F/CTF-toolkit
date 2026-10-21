"""Lab tasks share the existing resource-limited worker lifecycle."""
import base64
import json
import shutil
from pathlib import Path
from types import SimpleNamespace

from ..analysis.engine import Analysis, stage, atomic_json, utc_now
from ..analysis.extraction import Limits


def run_action(job_dir, options):
    analysis = Analysis(Path(job_dir),'deep',Limits.from_environment())
    if options['operation'] == 'inspect': return analysis.run()
    analysis.run_stage('identification',5,analysis.identification)
    if not analysis.report['file']: raise ValueError('Could not identify evidence')
    operation = options['operation']
    def action():
        if operation == 'image_prepare':
            from .image import analyze_image
            return analyze_image(analysis)
        if operation == 'image_lsb':
            from .image import extract_lsb
            from .flags import FlagFinder
            fields = {'channels','bits','bit_order','direction','reverse','frame','max_bytes','skip_bits'}
            content, info = extract_lsb(analysis.original,**{k:v for k,v in options.items() if k in fields})
            record = analysis.artifact('lsb-extracted.bin',content,kind='lsb')
            record.update(extraction=info,method='Configured image LSB')
            found = FlagFinder().scan_decoded(content,record['name'],['configured image LSB'])
            return stage('image_lsb',found,artifacts=[record],data={**info,'text_preview':content[:8192].decode('utf-8','replace'),'hex_preview':content[:4096].hex()})
        if operation == 'audio_analyze':
            from .audio import analyze_audio
            return analyze_audio(analysis)
        if operation == 'flag_scan':
            from .flags import scan_report
            proxy = analysis
            context = options.get('parent_job')
            if context:
                if len(context)!=32 or not all(c in '0123456789abcdef' for c in context): raise ValueError('Invalid parent job')
                parent = analysis.job.parent/context
                report = json.loads((parent/'report.json').read_text())
                root = (parent/'artifacts').resolve()
                report['artifacts'] = [a for a in report.get('artifacts',[]) if (root/a['path']).resolve().is_relative_to(root) and not (root/a['path']).is_symlink()]
                proxy = SimpleNamespace(report=report,data=analysis.data,root=root)
            result = scan_report(proxy,options.get('prefixes'),options.get('expression',''))
            analysis.report['flag_candidates'] = proxy.report.get('flag_candidates',[])
            return result
        if operation == 'tool_extract':
            from .specialized import execute
            return execute(analysis,options)
        if operation == 'crypto':
            from .crypto import run_recipe
            payload = {**options['recipe'],'input':base64.b64encode(analysis.data).decode(),'input_encoding':'base64'}
            result = run_recipe(payload)
            content = base64.b64decode(result['output']['base64'])
            record = analysis.artifact('recipe-output.bin',content,kind='decoded',max_bytes=1048576)
            serialized=json.dumps(result,ensure_ascii=True).encode()
            if len(serialized)>1024*1024:
                details=analysis.artifact('recipe-intermediates.json',serialized,'application/json','recipe',max_bytes=16*1024**2)
                return stage('crypto_lab',result['flags'],artifacts=[record,details],data={'details_artifact_id':details['id'],'detail_bytes':len(serialized),
                             'explanation':'Intermediate bytes retained as a bounded JSON artifact to keep the report small'})
            return stage('crypto_lab',result['flags'],artifacts=[record],data=result)
        if operation == 'pdf_extract':
            from ..analysis.tools import run_command
            from .flags import FlagFinder
            executable = shutil.which('pdfdetach')
            if not executable: return stage('pdf_extract',status='unavailable',errors=['pdfdetach is unavailable'])
            if analysis.report['file']['format']!='pdf': raise ValueError('PDF attachment extraction requires a PDF')
            number = int(options.get('attachment',1))
            if not 1<=number<=100: raise ValueError('Select attachment 1–100')
            target = analysis.root/'attachment.bin'
            result = run_command([executable,'-save',str(number),'-o',str(target),str(analysis.original)],analysis.root)
            if result['status']!='completed':
                target.unlink(missing_ok=True)
                return stage('pdf_extract',status=result['status'],errors=[result['stderr'][:2000]])
            content = target.read_bytes(); target.unlink()
            record = analysis.artifact(f'pdf-attachment-{number}.bin',content,kind='pdf_attachment')
            return stage('pdf_extract',FlagFinder().scan_decoded(content,record['name'],['pdfdetach']),artifacts=[record])
        raise ValueError('Unsupported lab action')
    result = analysis.run_stage(operation,30,action)
    if result['status']=='failed':
        analysis.report.update(status='failed',errors=result['errors'])
    analysis.report.update(action={'operation':operation,'parent_job':options.get('parent_job'),'parameters_redacted':True},completed_at=utc_now())
    analysis.bound_report()
    atomic_json(analysis.job/'report.json',analysis.report)
    atomic_json(analysis.job/'progress.json',{'progress':100,'stage':analysis.report['status']})
    return analysis.report
