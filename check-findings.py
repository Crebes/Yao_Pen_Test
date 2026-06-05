import json, glob, os, re

base = '/mnt/c/Data/ClaudeProjects/PenTest/yao-pentest'
hosts = ['app.stg.yao.legal', 'backoffice.staging.yao.legal', 'app.yao.legal',
         'backoffice.yao.legal', 'uk.yao.legal', 'aus.yao.legal', 'demo.yao.legal']

for host in hosts:
    safe = re.sub(r'[^a-zA-Z0-9_.-]', '_', host)
    dirs = sorted(glob.glob(f'{base}/pentest_{safe}_*'), key=os.path.getmtime, reverse=True)
    for sd in dirs:
        sj = f'{sd}/summary.json'
        if os.path.exists(sj):
            s = json.load(open(sj))
            b = s.get('findings_by_severity', {})
            name = os.path.basename(sd)
            c = b.get('CRITICAL',0); h = b.get('HIGH',0); m = b.get('MEDIUM',0); l = b.get('LOW',0)
            print(f'{name}  C={c} H={h} M={m} L={l}')
            break
    else:
        print(f'{host}: no summary.json found')
