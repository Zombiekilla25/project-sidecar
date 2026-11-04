from __future__ import annotations
from pathlib import Path
import json
from .timing import TimingRecord

def load_phk1_canary(path):
    """Parse a future fifth-canary result. No file is opened implicitly."""
    try: obj=json.loads(Path(path).read_text())
    except (OSError,json.JSONDecodeError) as e: raise ValueError(f'cannot read canary result: {e}') from e
    if not isinstance(obj,dict) or obj.get('schema')!='sidecar-phk1-canary-result-v1':raise ValueError('wrong PHK1 canary result schema')
    for key in ('job_fingerprint','result_identity','status'):
        if not isinstance(obj.get(key),str) or not obj[key]:raise ValueError(f'missing required result identity: {key}')
    timings=obj.get('timings_us')
    if not isinstance(timings,dict):raise ValueError('timings_us object required')
    wrapped={'schema':'sidecar-fk-timing-v1','source':obj.get('source','PHK1 canary result'),'measured':True,'identity':{'job_fingerprint':obj['job_fingerprint'],'result_identity':obj['result_identity']},'timings_us':{**timings,'batch_size':obj.get('item_count')}}
    record=TimingRecord.from_dict(wrapped,'fk')
    return {'status':obj['status'],'identity':record.identity,'timings_us':record.values,'measured':True}
