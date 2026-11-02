import base64
import json
import unittest
from urllib.parse import quote
from tracefence import audit, render_html

SECRET='DEMO-ONLY-credential/7f2a+9c='
def src(): return dict(kind='source', id='vault-read',tool='read_config',secrets=[dict(label='test-token',value=SECRET)])
def sink(payload, destination='https://collector.example/submit'): return dict(kind='sink',id='send-1',tool='http_post',destination=destination,payload=payload)
def run(events): return audit(enumerate(events,1))

class FlowTests(unittest.TestCase):
    def test_plain(self): self.assertEqual(run([src(),sink({'body':SECRET})])['finding_count'],1)
    def test_base64(self): self.assertEqual(run([src(),sink(base64.b64encode(SECRET.encode()).decode())])['finding_count'],1)
    def test_url(self): self.assertEqual(run([src(),sink(quote(SECRET,safe=''))])['finding_count'],1)
    def test_hex(self): self.assertEqual(run([src(),sink(SECRET.encode().hex())])['finding_count'],1)
    def test_destination(self): self.assertEqual(run([src(),sink({},'https://example.test/'+quote(SECRET,safe=''))])['finding_count'],1)
    def test_temporal_order(self): self.assertEqual(run([sink(SECRET),src()])['finding_count'],0)
    def test_clean(self): self.assertEqual(run([src(),sink({'body':'ordinary summary'})])['finding_count'],0)
    def test_nested(self): self.assertEqual(run([src(),sink({'a':[{'b':SECRET}]})])['finding_count'],1)
    def test_key(self): self.assertEqual(run([src(),sink({SECRET:'x'})])['finding_count'],1)
    def test_redacted_metadata(self):
        a=src(); a['id']=SECRET
        report=run([a,sink({SECRET:SECRET})]); self.assertNotIn(SECRET,json.dumps(report)); self.assertNotIn(SECRET,render_html(report))
    def test_html_escape(self):
        report=run([src(),sink({'<script>alert(1)</script>':SECRET})]); self.assertNotIn('<script>',render_html(report))
    def test_duplicate_id(self):
        with self.assertRaises(ValueError):run([src(),src()])
    def test_short_secret(self):
        a=src();a['secrets'][0]['value']='short'
        with self.assertRaises(ValueError):run([a])
    def test_unpadded(self): self.assertEqual(run([src(),sink(base64.urlsafe_b64encode(SECRET.encode()).decode().rstrip('='))])['finding_count'],1)

if __name__=='__main__': unittest.main()
