import json, os, re

base = '/mnt/c/Data/ClaudeProjects/PenTest/yao-pentest'
for d in ['pentest_api.yao.legal_20260605_190819', 'pentest_api.yao.legal_20260605_194119']:
    path = f'{base}/{d}'
    s = json.load(open(f'{path}/summary.json'))
    b = s['findings_by_severity']
    print(f'{d}')
    print(f'  Findings: C={b.get("CRITICAL",0)} H={b.get("HIGH",0)} M={b.get("MEDIUM",0)} L={b.get("LOW",0)}')
    nmap = f'{path}/nmap.txt'
    if os.path.exists(nmap):
        txt = open(nmap).read()
        has503_title = bool(re.search(r'http-title.*503|503.*Service Temporarily', txt, re.IGNORECASE))
        has503_any   = '503' in txt
        print(f'  503 in http-title: {has503_title}')
        print(f'  503 anywhere in nmap: {has503_any}')
        # show matching lines
        for line in txt.splitlines():
            if '503' in line:
                print(f'    -> {line.strip()[:100]}')
