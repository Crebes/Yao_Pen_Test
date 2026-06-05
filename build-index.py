import json, os, glob, sys, datetime

base    = '/mnt/c/Data/ClaudeProjects/PenTest/yao-pentest'
targets = json.load(open(f'{base}/targets.json'))['targets']

results = []
for t in targets:
    host = t['url'].replace('https://','').replace('http://','')
    # Wizard uses re.sub(r"[^a-zA-Z0-9_.-]", "_", host) — dots are preserved
    dirs = sorted(glob.glob(f'{base}/pentest_{host}_202606*'))
    scan_dir = dirs[-1] if dirs else None

    counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0, 'INFO': 0}
    unreachable = False
    if scan_dir and os.path.exists(f'{scan_dir}/nmap.txt'):
        nmap_txt = open(f'{scan_dir}/nmap.txt').read()
        if 'Failed to resolve' in nmap_txt or '0 hosts up' in nmap_txt:
            unreachable = True
    if scan_dir and os.path.exists(f'{scan_dir}/summary.json'):
        s = json.load(open(f'{scan_dir}/summary.json'))
        counts = s.get('findings_by_severity', counts)

    results.append({
        'url': t['url'], 'mode': t['mode'], 'notes': t.get('notes',''),
        'scan_dir': scan_dir, 'host': host, 'unreachable': unreachable,
        'critical': counts['CRITICAL'], 'high': counts['HIGH'],
        'medium': counts['MEDIUM'], 'low': counts['LOW'], 'info': counts['INFO'],
    })
    print(f"  {t['url']}: C={counts['CRITICAL']} H={counts['HIGH']} M={counts['MEDIUM']} L={counts['LOW']}  -> {scan_dir.split('/')[-1] if scan_dir else 'NOT FOUND'}")

# ── Build combined index HTML ──────────────────────────────
batch_dir = f'{base}/batch_20260604_223607'
os.makedirs(batch_dir, exist_ok=True)

SEV_COLOR = {'CRITICAL':'#c0392b','HIGH':'#e67e22','MEDIUM':'#d4a017','LOW':'#27ae60','INFO':'#2980b9'}

def grade(r):
    if r['critical'] >= 2:  return ('F', '#c0392b')
    if r['critical'] == 1:  return ('D', '#e74c3c')
    if r['high'] >= 3:      return ('C', '#e67e22')
    if r['high'] >= 1:      return ('B', '#f39c12')
    if r['medium'] >= 1:    return ('B+','#2ecc71')
    return ('A', '#27ae60')

rows = ''
for r in results:
    mc = '#b45309' if r['mode'] == 'staging' else '#1a7a4a'
    ml = 'STAGING' if r['mode'] == 'staging' else 'PRODUCTION'

    report_path = f"{r['scan_dir']}/report.html" if r['scan_dir'] else ''
    rel_report  = os.path.relpath(report_path, batch_dir).replace('\\','/') if report_path and os.path.exists(report_path) else ''
    report_link = f"<a href='{rel_report}' style='color:#2980b9;font-weight:600;'>Open Report &#x2197;</a>" if rel_report else "<span style='color:#aaa;'>—</span>"

    if r['unreachable']:
        grade_cell = "<span style='background:#555;color:#fff;padding:2px 10px;border-radius:10px;font-size:0.75em;font-weight:700;'>UNREACHABLE</span>"
        ch = hh = mh = lh = "<span style='color:#aaa;'>—</span>"
        row_style = "background:#f8f8f8;"
        action = "<span style='color:#e67e22;font-weight:600;font-size:0.82em;'>&#x26A0; Verify URL / check DNS</span>"
    else:
        g, gc = grade(r)
        grade_cell = f"<span style='background:{gc};color:#fff;width:30px;height:30px;display:inline-flex;align-items:center;justify-content:center;border-radius:50%;font-weight:800;font-size:0.9em;'>{g}</span>"
        ch = f"<span style='color:#c0392b;font-weight:800;'>{r['critical']}</span>" if r['critical'] else '0'
        hh = f"<span style='color:#e67e22;font-weight:700;'>{r['high']}</span>"     if r['high']     else '0'
        mh = f"<span style='color:#d4a017;font-weight:700;'>{r['medium']}</span>"   if r['medium']   else '0'
        lh = str(r['low'])
        row_style = ""
        action = report_link

    rows += f"""<tr style='{row_style}'>
      <td style='font-weight:600;font-size:0.88em;'>{r['url']}</td>
      <td><span style='background:{mc};color:#fff;padding:2px 8px;border-radius:10px;font-size:0.72em;font-weight:700;'>{ml}</span></td>
      <td style='text-align:center;'>{grade_cell}</td>
      <td style='text-align:center;'>{ch}</td>
      <td style='text-align:center;'>{hh}</td>
      <td style='text-align:center;'>{mh}</td>
      <td style='text-align:center;color:#888;'>{lh}</td>
      <td style='font-size:0.82em;color:#555;'>{r['notes'].split('—')[0].strip()}</td>
      <td style='font-size:0.85em;'>{action}</td>
    </tr>"""

tc = sum(r['critical'] for r in results)
th = sum(r['high']     for r in results)
tm = sum(r['medium']   for r in results)
tl = sum(r['low']      for r in results)
ts = datetime.datetime.now().strftime('%d %B %Y, %H:%M')

html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>Yao Security Assessment — All Targets</title>
<style>
  *{{box-sizing:border-box;margin:0;padding:0}}
  body{{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Arial,sans-serif;background:#f4f6f9;color:#2c3e50;font-size:15px}}
  .header{{background:linear-gradient(135deg,#0f1923 0%,#1a2a3a 60%,#0f3460 100%);color:#fff;padding:36px 48px}}
  .header h1{{font-size:1.8em;font-weight:700}}
  .header .sub{{color:#a8c6e8;margin-top:4px;font-size:0.92em}}
  .meta{{margin-top:16px;display:flex;gap:28px;flex-wrap:wrap}}
  .meta div{{font-size:0.82em;color:#c8ddf0}}.meta strong{{color:#fff;display:block;font-size:1.05em}}
  .container{{max-width:1200px;margin:0 auto;padding:28px 20px}}
  .card{{background:#fff;border-radius:10px;box-shadow:0 2px 8px rgba(0,0,0,.07);padding:24px 28px;margin-bottom:22px}}
  .card h2{{font-size:1.1em;font-weight:700;color:#1a1a2e;border-bottom:2px solid #e8ecf0;padding-bottom:10px;margin-bottom:18px}}
  .totals{{display:flex;gap:32px;flex-wrap:wrap}}
  .tot{{text-align:center}}.tot .n{{font-size:2.2em;font-weight:800}}.tot .l{{font-size:0.72em;font-weight:700;text-transform:uppercase}}
  table{{width:100%;border-collapse:collapse}}
  th{{background:#f0f3f7;text-align:left;padding:9px 12px;font-size:0.76em;text-transform:uppercase;letter-spacing:.5px;color:#666}}
  td{{padding:10px 12px;border-bottom:1px solid #f0f3f7;vertical-align:middle}}
  tr:last-child td{{border-bottom:none}}
  .scale{{display:flex;gap:10px;flex-wrap:wrap;margin-top:6px}}
  .scale span{{padding:2px 10px;border-radius:8px;font-size:0.78em;font-weight:700;color:#fff}}
  .footer{{text-align:center;color:#aaa;font-size:0.78em;padding:20px}}
</style>
</head>
<body>
<div class="header">
  <h1>&#x1F6E1; Security Assessment — All Targets</h1>
  <div class="sub">Yao Pentest Wizard &nbsp;·&nbsp; Batch scan results</div>
  <div class="meta">
    <div><strong>{len(results)}</strong>Targets scanned</div>
    <div><strong>{sum(1 for r in results if r['mode']=='staging')} staging / {sum(1 for r in results if r['mode']=='production')} production</strong>Scan modes</div>
    <div><strong>{ts}</strong>Report generated</div>
  </div>
</div>
<div class="container">

  <div class="card">
    <h2>&#x1F4CA; Combined Findings Across All Targets</h2>
    <div class="totals">
      <div class="tot"><div class="n" style="color:#c0392b;">{tc}</div><div class="l" style="color:#c0392b;">Critical</div></div>
      <div class="tot"><div class="n" style="color:#e67e22;">{th}</div><div class="l" style="color:#e67e22;">High</div></div>
      <div class="tot"><div class="n" style="color:#d4a017;">{tm}</div><div class="l" style="color:#d4a017;">Medium</div></div>
      <div class="tot"><div class="n" style="color:#27ae60;">{tl}</div><div class="l" style="color:#27ae60;">Low</div></div>
    </div>
    <div style="margin-top:18px;font-size:0.82em;color:#666;">
      <strong>Grade scale:</strong>
      <div class="scale">
        <span style="background:#27ae60;">A — No HIGH/CRITICAL</span>
        <span style="background:#2ecc71;">B+ — Low severity only</span>
        <span style="background:#f39c12;">B — 1–2 HIGH</span>
        <span style="background:#e67e22;">C — 3+ HIGH</span>
        <span style="background:#e74c3c;">D — 1 CRITICAL</span>
        <span style="background:#c0392b;">F — 2+ CRITICAL</span>
      </div>
    </div>
  </div>

  <div class="card">
    <h2>&#x1F50D; Results by Target</h2>
    <table>
      <thead><tr>
        <th>Target URL</th><th>Mode</th><th style="text-align:center;">Grade</th>
        <th style="text-align:center;">CRIT</th><th style="text-align:center;">HIGH</th>
        <th style="text-align:center;">MED</th><th style="text-align:center;">LOW</th>
        <th>Notes</th><th>Full Report</th>
      </tr></thead>
      <tbody>{rows}</tbody>
    </table>
  </div>

  <div class="card" style="border-left:4px solid #e67e22;">
    <h2>&#x26A0;&#xFE0F; Disclaimer</h2>
    <p style="color:#555;line-height:1.7;font-size:0.9em;">
      Automated scan — findings require manual verification before remediation.
      Production targets were scanned read-only (no Hydra brute-force).
      This does not constitute a professional penetration test.
    </p>
  </div>

</div>
<div class="footer">Yao Pentest Wizard &nbsp;·&nbsp; {ts} &nbsp;·&nbsp; Authorised use only</div>
</body></html>"""

index_path = f'{batch_dir}/index.html'
open(index_path, 'w').write(html)
print(f'\nIndex report: {index_path}')
print(f'Windows path: {index_path.replace("/mnt/c/","C:\\\\").replace("/",chr(92))}')
