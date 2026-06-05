import json, glob, os, re, sys
sys.path.insert(0, '/mnt/c/Data/ClaudeProjects/PenTest/yao-pentest')

base = '/mnt/c/Data/ClaudeProjects/PenTest/yao-pentest'

# Find active batch
dirs = sorted(glob.glob(f'{base}/batch_*'), key=os.path.getmtime, reverse=True)
bd = dirs[0]
print(f'Active batch: {bd}')
print(f'Has batch_complete: {os.path.exists(bd+"/batch_complete")}')

# Load checkpoint
cp_raw = json.load(open(f'{bd}/checkpoint.json'))
cp = cp_raw.get('completed', {})
if isinstance(cp, list):
    cp = {u: {'status':'complete'} for u in cp}
print(f'Checkpoint entries: {len(cp)}')

# For each target, find its scan dir
targets = json.load(open(f'{base}/targets.json'))['targets']
ts_epoch = os.path.getmtime(bd)
print(f'Batch mtime epoch: {ts_epoch}')
print()

for t in targets:
    url  = t['url']
    host = url.replace('https://','').replace('http://','')
    safe = re.sub(r'[^a-zA-Z0-9_.-]', '_', host)
    scan_dirs = sorted(glob.glob(f'{base}/pentest_{safe}_*'), key=os.path.getmtime)
    in_cp = url in cp

    print(f'{"[CP]" if in_cp else "    "} {host}')
    for sd in scan_dirs:
        sd_mt = os.path.getmtime(sd)
        has_summary = os.path.exists(f'{sd}/summary.json')
        diff = sd_mt - ts_epoch
        print(f'       dir: {os.path.basename(sd)}  mtime_diff={diff:+.0f}s  summary={has_summary}')

    # Simulate the window check
    matched = None
    for sd in scan_dirs:
        sd_mt = os.path.getmtime(sd)
        batch_end = ts_epoch + 86400
        if in_cp and sd_mt <= batch_end:
            matched = sd
        elif not in_cp and sd_mt >= ts_epoch - 60 and sd_mt <= ts_epoch + 43200:
            matched = sd
    print(f'       matched: {os.path.basename(matched) if matched else "NONE"}')
    print()
