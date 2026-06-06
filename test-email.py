import json, urllib.request, urllib.error

config = json.load(open('/mnt/c/Data/ClaudeProjects/PenTest/yao-pentest/email-config.json'))
api_key = config['sendgrid_api_key']
from_email = config['from']

payload = {
    'personalizations': [{'to': [{'email': from_email}]}],
    'from': {'email': from_email},
    'subject': 'Yao Pentest — Test Email',
    'content': [{'type': 'text/plain', 'value': 'Test email from Yao Pentest Wizard. If you received this, email is configured correctly!'}],
}

data = json.dumps(payload).encode()
req = urllib.request.Request(
    'https://api.sendgrid.com/v3/mail/send',
    data=data,
    headers={
        'Authorization': 'Bearer ' + api_key,
        'Content-Type': 'application/json'
    },
    method='POST'
)
try:
    resp = urllib.request.urlopen(req, timeout=30)
    print('SUCCESS — email sent! Status:', resp.status)
except urllib.error.HTTPError as e:
    body = e.read().decode()
    print('ERROR', e.code, ':', e.reason)
    print(body)
