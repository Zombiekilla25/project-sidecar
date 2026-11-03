import unittest
from sidecar_miner.prl_job import decode_prl_notify
HEADER=bytes(range(76)).hex()
def msg(**updates):
    p={'job_id':'4d64167a_2097152','header':HEADER,'height':98095,'target':f'{(0xffff<<240):064x}','cert_version':2}; p.update(updates)
    return {'id':None,'method':'mining.notify','params':p}
class PrlJobDecoderTests(unittest.TestCase):
    def test_authoritative_notify_fields_and_normalized_fingerprint(self):
        a=decode_prl_notify(msg(),1,4.0); b=decode_prl_notify({'params':dict(reversed(list(msg()['params'].items()))),'method':'mining.notify','id':None},2,8.0)
        self.assertEqual(a.fingerprint,b.fingerprint); self.assertEqual(a.generation,1); self.assertEqual(len(a.header),76)
    def test_arrival_clean_and_difficulty_do_not_change_job_identity(self):
        self.assertEqual(decode_prl_notify(msg(clean=True),1).fingerprint,decode_prl_notify(msg(),2).fingerprint)
    def test_wrong_method_type_or_response_id_rejected(self):
        for m in ({'id':None,'method':'mining.submit','params':{}},{'id':2,'method':'mining.notify','params':msg()['params']},[],None):
            with self.subTest(m=m),self.assertRaises(ValueError): decode_prl_notify(m,1)
    def test_missing_fields_rejected(self):
        for field in ('job_id','header','target','height','cert_version'):
            p=msg()['params'].copy(); del p[field]
            with self.subTest(field=field),self.assertRaises(ValueError): decode_prl_notify({'id':None,'method':'mining.notify','params':p},1)
    def test_invalid_id_hex_lengths_ranges_and_clean_rejected(self):
        bad=[{'job_id':''},{'job_id':'bad id'},{'header':'00'},{'header':'zz'*76},{'target':'0'}, {'target':'g'*64},{'height':-1},{'height':1<<64},{'cert_version':4},{'clean':'true'}]
        for fields in bad:
            with self.subTest(fields=fields),self.assertRaises(ValueError): decode_prl_notify(msg(**fields),1)
    def test_target_hex_case_is_canonical(self):
        self.assertEqual(decode_prl_notify(msg(target=f'{(0xffff<<240):064X}'),1).fingerprint,decode_prl_notify(msg(),2).fingerprint)
