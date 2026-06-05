"""
Regenerate all report.html files from existing summary.json data
using the current pentest_wizard.py (which labels everything FULL SCAN).
"""
import sys, json, os, glob, datetime, re
sys.path.insert(0, '/mnt/c/Data/ClaudeProjects/PenTest/yao-pentest')
import pentest_wizard as pw

base = '/mnt/c/Data/ClaudeProjects/PenTest/yao-pentest'
scan_dirs = sorted(glob.glob(f'{base}/pentest_*_202606*'))

updated = 0
skipped = 0
for scan_dir in scan_dirs:
    sj = f'{scan_dir}/summary.json'
    if not os.path.exists(sj):
        skipped += 1
        continue
    try:
        s = json.load(open(sj))
        pw.FINDINGS  = s.get('findings', [])
        pw.TOOL_LOG  = s.get('tool_log', [])
        ts = s.get('timestamp', datetime.datetime.now().isoformat())
        start = datetime.datetime.fromisoformat(ts) - datetime.timedelta(seconds=int(s.get('duration_s', 1500)))
        pw.generate_html_report(
            scan_dir,
            s.get('target_host', ''),
            s.get('target_url', ''),
            s.get('modules_run', []),
            s.get('tools_missing', []),
            start,
            'staging'
        )
        updated += 1
        print(f'  Updated: {os.path.basename(scan_dir)}')
    except Exception as e:
        print(f'  SKIP {os.path.basename(scan_dir)}: {e}')
        skipped += 1

print(f'\nDone. Updated {updated}, skipped {skipped}.')
