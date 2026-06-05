import json, glob, os

base = '/mnt/c/Data/ClaudeProjects/PenTest/yao-pentest'

dirs = sorted(glob.glob(f'{base}/batch_*'), key=os.path.getmtime, reverse=True)
bd = dirs[0] if dirs else None
print('Batch dir:', bd)
print('Complete: ', os.path.exists(f'{bd}/batch_complete') if bd else False)
print()

cp = {}
if bd and os.path.exists(f'{bd}/checkpoint.json'):
    data = json.load(open(f'{bd}/checkpoint.json'))
    cp = data.get('completed', {})
    if isinstance(cp, list):
        cp = {u: {'status': 'complete'} for u in cp}

print(f'Checkpoint: {len(cp)} completed')
for url, info in cp.items():
    st = info.get('status','?') if isinstance(info, dict) else str(info)
    print(f'  {st:15} {url}')

print()
targets = json.load(open(f'{base}/targets.json'))['targets']
print(f'targets.json: {len(targets)} targets')
for t in targets:
    in_cp = t['url'] in cp
    print(f'  {"DONE" if in_cp else "MISSING":8} {t["url"]}')
