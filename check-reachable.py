import glob, os, re

base = '/mnt/c/Data/ClaudeProjects/PenTest/yao-pentest'
dirs = sorted(glob.glob(f'{base}/pentest_*_202606*'))

for d in dirs:
    nmap = f'{d}/nmap.txt'
    host = re.sub(r'pentest_', '', os.path.basename(d))
    host = re.sub(r'_20260\d+_\d+$', '', host)
    if os.path.exists(nmap):
        txt = open(nmap).read()
        if 'Failed to resolve' in txt or '0 hosts up' in txt:
            print(f'UNREACHABLE  {host}')
        else:
            print(f'OK           {host}')
    else:
        print(f'NO NMAP      {host}')
