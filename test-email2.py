import json, urllib.request, urllib.error, base64, sys

sys.path.insert(0, '/mnt/c/Data/ClaudeProjects/PenTest/yao-pentest')
sys.argv = [sys.argv[0]]  # clear args for dashboard import

config = json.load(open('/mnt/c/Data/ClaudeProjects/PenTest/yao-pentest/email-config.json'))
api_key = config['sendgrid_api_key']
from_email = config['from']

# Generate the actual report
import dashboard as db
import glob, os, re
dirs = sorted(glob.glob('/mnt/c/Data/ClaudeProjects/PenTest/yao-pentest/batch_*'),
              key=lambda d: re.search(r'batch_(\d+_\d+)', d).group(1) if re.search(r'batch_(\d+_\d+)', d) else '', reverse=True)
batch_dir = next((d for d in dirs if os.path.exists(f'{d}/batch_complete')), None)
print('Using batch:', batch_dir)

html = db.generate_export_report(batch_dir)
print(f'Report size: {len(html)} chars, base64: {len(base64.b64encode(html.encode()))} bytes')

# Send with attachment
payload = {
    'personalizations': [{'to': [{'email': from_email}]}],
    'from': {'email': from_email},
    'subject': 'Yao Pentest Report — Test with Attachment',
    'content': [{'type': 'text/plain', 'value': 'Test with attachment attached.'}],
    'attachments': [{
        'content': base64.b64encode(html.encode('utf-8')).decode(),
        'type': 'text/html',
        'filename': 'pentest-report.html',
        'disposition': 'attachment',
    }],
}

data = json.dumps(payload).encode()
print(f'Payload size: {len(data)} bytes')

req = urllib.request.Request('https://api.sendgrid.com/v3/mail/send',
    data=data,
    headers={'Authorization': 'Bearer ' + api_key, 'Content-Type': 'application/json'},
    method='POST')
try:
    resp = urllib.request.urlopen(req, timeout=60)
    print('SUCCESS:', resp.status, '— check your inbox!')
except urllib.error.HTTPError as e:
    print('ERROR', e.code, ':', e.reason)
    print(e.read().decode())
