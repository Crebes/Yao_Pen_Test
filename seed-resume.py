"""
Create a new resumable batch dir pre-seeded with completed targets from
the most recent complete batch. Only the 4 targets that failed will run.
"""
import json, os, glob, datetime

base = '/mnt/c/Data/ClaudeProjects/PenTest/yao-pentest'

# Find the complete batch
complete_batches = [d for d in sorted(glob.glob(f'{base}/batch_*'), key=os.path.getmtime, reverse=True)
                    if os.path.exists(f'{d}/batch_complete')]
if not complete_batches:
    print('No complete batch found.'); exit(1)

old_batch = complete_batches[0]
print(f'Source batch: {old_batch}')

# Load its checkpoint
old_cp = json.load(open(f'{old_batch}/checkpoint.json'))
completed = old_cp.get('completed', {})
if isinstance(completed, list):
    completed = {u: {'status': 'complete'} for u in completed}
print(f'Already completed: {len(completed)} targets')
for url, info in completed.items():
    st = info.get('status','?') if isinstance(info,dict) else str(info)
    print(f'  {st:15} {url}')

# Create new batch dir (no batch_complete — so resume logic finds it)
ts = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
new_batch = f'{base}/batch_{ts}'
os.makedirs(new_batch)

# Write checkpoint with the already-done targets
json.dump({'completed': completed}, open(f'{new_batch}/checkpoint.json', 'w'), indent=2)
open(f'{new_batch}/batch.log', 'w').write(
    f'[{datetime.datetime.now().strftime("%H:%M:%S")}] Resuming from seeded checkpoint — {len(completed)} targets pre-populated\n'
)

print(f'\nNew resumable batch: {new_batch}')
print('Run batch-run.sh — it will skip completed targets and run only the missing ones.')
