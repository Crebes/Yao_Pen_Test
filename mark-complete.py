import json, os

base = '/mnt/c/Data/ClaudeProjects/PenTest/yao-pentest'
batch = f'{base}/batch_20260605_194108'
cp_file = f'{batch}/checkpoint.json'

data = json.load(open(cp_file))
data['completed']['https://api.staging.yao.legal'] = {'status': 'OK', 'duration': '2229s'}
data['completed']['https://api.stg.yao.legal']     = {'status': 'OK', 'duration': '2229s'}
json.dump(data, open(cp_file, 'w'), indent=2)

open(f'{batch}/batch_complete', 'w').close()
print('Done. Completed:', len(data['completed']), 'of 13')
for url, info in data['completed'].items():
    print(f"  {info.get('status','?'):10} {url}")
