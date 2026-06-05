import os, glob, shutil

base = '/mnt/c/Data/ClaudeProjects/PenTest/yao-pentest'
for d in sorted(glob.glob(f'{base}/batch_*')):
    complete = os.path.join(d, 'batch_complete')
    if os.path.exists(complete):
        print(f'KEEPING  (complete): {os.path.basename(d)}')
    else:
        print(f'REMOVING (incomplete): {os.path.basename(d)}')
        shutil.rmtree(d, ignore_errors=True)
print('Done.')
