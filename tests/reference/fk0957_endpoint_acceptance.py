#!/usr/bin/env python3
"""Independent offline signed-request attacks for the FK0957 remote endpoint."""
from __future__ import annotations
import base64, hashlib, json, os, re, subprocess, tempfile
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest import mock


def run(candidate: Path) -> dict:
    import sys
    sys.path.insert(0,str(candidate/'tools/phk2_host'))
    import phk2_fk0957_remote_topology_endpoint as ep
    import phk2_fk0957_topology_transport as tr
    import test_phk2_fk0957_topology_transport as transport_fixtures
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    release=Ed25519PrivateKey.generate(); handoff_key=Ed25519PrivateKey.generate()
    issuers={'release':release.public_key().public_bytes(serialization.Encoding.Raw,serialization.PublicFormat.Raw),
             'handoff':handoff_key.public_key().public_bytes(serialization.Encoding.Raw,serialization.PublicFormat.Raw)}
    # Use the candidate's descriptor fixture constructor for valid signed
    # descriptor bytes; authorization, handoff, manifest, and attacks below
    # are independently constructed by this reference harness.
    fixture=transport_fixtures.TopologyTransportTests(); fixture.setUp()
    now=datetime.now(timezone.utc).replace(microsecond=0); operation='1'*32; auth_id='2'*64
    descriptor=fixture.raw; dsha=fixture.digest; permit=fixture.permit(); nonce=permit.nonce
    head='a'*40  # fixture.setUp pins clean Git state to this synthetic head
    prof=ep._profile_hash(); sources={p:hashlib.sha256((candidate/p).read_bytes()).hexdigest()
                                      for p in ep.RELEASE_SOURCE_PATHS}
    manifest={'schema':'fk0957-runtime-source-manifest-v1','version':1,'production_head':head,
      'worktree_clean':True,'source_hashes':sources,'native_runtime_hashes':{p.name:p.sha256 for p in tr.LIBRARY_PINS},
      'transaction_profile_sha256':prof,'issued_at':now.isoformat()}
    msha=hashlib.sha256(ep.canonical(manifest)).hexdigest()
    hand={'schema':'fk0957-maintenance-handoff-v1','version':1,'handoff_id':'4'*64,'operation_id':operation,
      'authorization_id':auth_id,'permit_sha256':dsha,'target':dict(ep.EXPECTED_TARGET),
      'bridge_executable_sha256':'5'*64,'bridge_config_sha256':'6'*64,
      'expected_clients':['client-a'],'expected_lanes':['lane-a'],'bridge_release_state':'RELEASED',
      'usbfs_ownership':'EXCLUSIVE','production_head':head,'manifest_sha256':msha,
      'transaction_profile_sha256':prof,'issued_at':now.isoformat(),'expires_at':(now+timedelta(seconds=90)).isoformat()}
    def signed(p,key,issuer):
      raw=ep.canonical(p); return {'payload':p,'payload_sha256':hashlib.sha256(raw).hexdigest(),
        'signature_algorithm':'Ed25519','signature_hex':key.sign(raw).hex(),'issuer':issuer}
    handenv=signed(hand,handoff_key,'FK0957_MAINTENANCE_AUTHORITY')
    handsha=hashlib.sha256(ep.canonical(hand)).hexdigest()
    auth={'schema':'fk0957-release-authorization-v1','version':1,'authorization_id':auth_id,
      'operation_id':operation,'permit_sha256':dsha,'handoff_sha256':handsha,
      'target':dict(ep.EXPECTED_TARGET),'production_head':head,'manifest_sha256':msha,
      'transaction_profile_sha256':prof,'issued_at':now.isoformat(),
      'expires_at':(now+timedelta(seconds=90)).isoformat(),'nonce':nonce}
    request={'schema':ep.SCHEMA,'version':1,'operation_id':operation,
      'descriptor_evidence_b64':base64.b64encode(descriptor).decode(),
      'descriptor_evidence_sha256':dsha,'handoff':handenv,
      'release_authorization':signed(auth,release,'FK0957_RELEASE_AUTHORITY'),
      'runtime_manifest':signed(manifest,release,'FK0957_RELEASE_AUTHORITY')}
    def validate(r):
      return ep._validate_request(ep.canonical(r),issuers,now=now)
    def resign_handoff_case(label, field, value, also_auth=False):
      h=json.loads(json.dumps(hand)); h[field]=value
      he=signed(h,handoff_key,'FK0957_MAINTENANCE_AUTHORITY')
      hh=hashlib.sha256(ep.canonical(h)).hexdigest(); a=dict(auth,handoff_sha256=hh)
      if also_auth: a['target']=dict(value)
      r=dict(request,handoff=he,release_authorization=signed(a,release,'FK0957_RELEASE_AUTHORITY'))
      try: validate(r); outcomes[label]='ACCEPTED_SIGNED_ASSERTION'
      except ep.Refusal as e: outcomes[label]=e.code
    def resign_manifest_case(label, changed_manifest):
      mh=hashlib.sha256(ep.canonical(changed_manifest)).hexdigest()
      h=dict(hand,manifest_sha256=mh)
      he=signed(h,handoff_key,'FK0957_MAINTENANCE_AUTHORITY')
      hh=hashlib.sha256(ep.canonical(h)).hexdigest()
      a=dict(auth,manifest_sha256=mh,handoff_sha256=hh)
      r=dict(request,handoff=he,release_authorization=signed(a,release,'FK0957_RELEASE_AUTHORITY'),
             runtime_manifest=signed(changed_manifest,release,'FK0957_RELEASE_AUTHORITY'))
      try: validate(r); outcomes[label]='ACCEPTED_SIGNED_ASSERTION'
      except ep.Refusal as e: outcomes[label]=e.code
    outcomes={}
    try: validate(request); outcomes['baseline']='ACCEPT'
    except ep.Refusal as e: outcomes['baseline']=e.code
    for label, changed_request in (
        ('missing_handoff', {k:v for k,v in request.items() if k != 'handoff'}),
        ('unsigned_handoff', dict(request, handoff=dict(handenv, signature_hex='0'*128))),
    ):
      try: validate(changed_request); outcomes[label]='ACCEPT'
      except ep.Refusal as e: outcomes[label]=e.code
    # Real policy refusal cases.
    for label, mutate in [
      ('operation_mismatch',lambda r:r.update(operation_id='9'*32)),
      ('descriptor_digest_mismatch',lambda r:r.update(descriptor_evidence_sha256='0'*64)),
    ]:
      r=json.loads(json.dumps(request)); mutate(r)
      try: validate(r); outcomes[label]='ACCEPT'
      except ep.Refusal as e: outcomes[label]=e.code
    # Re-sign handoff and release auth with the trusted fixture keys. This models
    # a maintenance issuer attesting a different bridge/client/lane identity.
    resign_handoff_case('unknown_usbfs_owner','usbfs_ownership','UNKNOWN')
    resign_handoff_case('competing_usbfs_owner','usbfs_ownership','COMPETING')
    resign_handoff_case('bridge_still_active','bridge_release_state','ACTIVE')
    for target_field, wrong_value in [('card_id','FK0958'),('adapter_serial','wrong-adapter'),
      ('usb_descriptor_serial','wrong-usb'),('vid','ffff'),('pid','ffff'),('interface','B')]:
      h=json.loads(json.dumps(hand)); h['target'][target_field]=wrong_value
      he=signed(h,handoff_key,'FK0957_MAINTENANCE_AUTHORITY'); hh=hashlib.sha256(ep.canonical(h)).hexdigest()
      a=dict(auth,handoff_sha256=hh,target=dict(h['target']))
      r=dict(request,handoff=he,release_authorization=signed(a,release,'FK0957_RELEASE_AUTHORITY'))
      try: validate(r); outcomes['wrong_target:'+target_field]='ACCEPTED_SIGNED_ASSERTION'
      except ep.Refusal as e: outcomes['wrong_target:'+target_field]=e.code
    stale=json.loads(json.dumps(hand)); stale['expires_at']=(now-timedelta(seconds=1)).isoformat()
    stale_env=signed(stale,handoff_key,'FK0957_MAINTENANCE_AUTHORITY')
    stale_auth=dict(auth,handoff_sha256=hashlib.sha256(ep.canonical(stale)).hexdigest())
    stale_request=dict(request,handoff=stale_env,release_authorization=signed(stale_auth,release,'FK0957_RELEASE_AUTHORITY'))
    try: validate(stale_request); outcomes['stale_handoff']='ACCEPT'
    except ep.Refusal as e: outcomes['stale_handoff']=e.code
    resign_handoff_case('wrong_bridge_hash','bridge_executable_sha256','a'*64)
    resign_handoff_case('wrong_clients','expected_clients',['unexpected-client'])
    resign_handoff_case('wrong_lanes','expected_lanes',['unexpected-lane'])
    for source_path in sorted(sources):
      changed=json.loads(json.dumps(manifest)); changed['source_hashes'][source_path]='0'*64
      resign_manifest_case('tampered_source:'+Path(source_path).name,changed)
    changed=json.loads(json.dumps(manifest)); changed['production_head']='f'*40
    resign_manifest_case('wrong_production_head',changed)
    changed=json.loads(json.dumps(manifest)); changed['native_runtime_hashes']['libc']='0'*64
    resign_manifest_case('native_runtime_pin_tampered',changed)
    # Main executable default trust pins are deliberately empty, so no physical call occurs.
    called=[]
    with mock.patch.object(ep,'_load_trust_config',side_effect=ep.Refusal('ISSUER_PINS_NOT_PROVISIONED')), \
         mock.patch.object(tr,'run_fk0957_topology_discovery',side_effect=lambda *_:called.append('OPEN')):
      try: ep.execute_request(ep.canonical(request))
      except ep.Refusal as e: outcomes['unprovisioned_endpoint']=e.code
    outcomes['production_trust_configured']=bool(ep.TRUST_CONFIG_SHA256)
    outcomes['physical_transport_calls_before_pin_provisioning']=len(called)
    # Execute the actual endpoint request flow twice with only the FTDI edge
    # replaced by a fake result. The durable authorization ledger must stop
    # the second invocation before the fake physical boundary.
    fake_result=SimpleNamespace(
      card_id='FK0957',adapter_serial='153300000957A',usb_descriptor_serial='153300000957',
      physical_interface='A',descriptor_evidence_sha256=dsha,permit_nonce=nonce,
      transport_source_sha256='8'*64,worktree_clean=True,
      runtime_library_provenance=tuple((p.name,str(p.path),p.sha256,p.build_id,p.soname,(),(),str(p.path)) for p in tr.LIBRARY_PINS),
      scan_a_transaction_sha256='9'*64,scan_a_tck_count=591,scan_a_raw_tdo=b'a',
      scan_b_transaction_sha256='a'*64,scan_b_tck_count=586,scan_b_raw_tdo=b'b',total_tck_count=1177,
      matched_device_count=1,opened_device_count=1,second_device_opened=False,
      write_count=0,reset_count=0,program_count=0)
    parsed=SimpleNamespace(aggregate_dr_length=33,taps_tdo_to_tdi=(),raw_tdo_scan_a_bits='0',raw_tdo_scan_b_bits='1')
    with tempfile.TemporaryDirectory(prefix='fk0957-execute-once-') as td:
      ledger=Path(td)/'ledger'; ledger.mkdir(mode=0o700); ledger.chmod(0o700)
      with mock.patch.object(ep,'TRUST_CONFIG_SHA256','a'*64), \
           mock.patch.object(ep,'_load_trust_config',return_value=issuers), \
           mock.patch.object(ep,'CONSUMED_AUTHORIZATION_DIR',ledger), \
           mock.patch.object(tr,'issue_fk0957_topology_permit',return_value=permit), \
           mock.patch.object(tr,'run_fk0957_topology_discovery',return_value=fake_result) as physical, \
           mock.patch.object(tr,'validate_transport_observation',return_value=parsed):
        first_status='REFUSED'; second_status='REFUSED'
        try:
          first_raw=ep.execute_request(ep.canonical(request)); first_status=json.loads(first_raw)['status']
        except ep.Refusal as e: first_status=e.code
        try: ep.execute_request(ep.canonical(request))
        except (ep.Refusal, tr.Refusal) as e: second_status=getattr(e, 'code', type(e).__name__)
        outcomes['endpoint_full_request_replay']={'first':first_status,'second':second_status,
            'physical_transport_calls':physical.call_count}
    # O_EXCL durable ledger replay, using an isolated temp directory.
    with tempfile.TemporaryDirectory(prefix='fk0957-endpoint-ledger-') as td:
      ledger=Path(td)/'ledger'; ledger.mkdir(mode=0o700); ledger.chmod(0o700)
      with mock.patch.object(ep,'CONSUMED_AUTHORIZATION_DIR',ledger):
        replay=[]
        for _ in range(2):
          try: ep._consume_authorization(auth_id,ep.canonical(request['release_authorization'])); replay.append('CONSUMED')
          except ep.Refusal as e: replay.append(e.code)
      outcomes['authorization_replay']=replay
    # Endpoint's checks accept signed client/lane/bridge values without a local
    # expected-value policy; physical ownership is an issuer assertion only.
    source=Path(ep.__file__).read_text()
    outcomes['ownership_is_live_observation']=any(x in source for x in ('/proc/*/fd','/sys/bus/usb','fuser','lsof'))
    outcomes['expected_bridge_pin_present']='EXPECTED_BRIDGE' in source
    outcomes['expected_clients_pin_present']='EXPECTED_CLIENTS' in source
    outcomes['expected_lanes_pin_present']='EXPECTED_LANES' in source
    outcomes['endpoint_has_signing_key']=any(x in source for x in ('PRIVATE_KEY_PATH','LOCAL_SIGNING_KEY_PATH','Ed25519PrivateKey'))
    outcomes['source_files_manifest_bound']=sorted(sources)
    outcomes['head_is_pinned_to_immutable_expected_commit']='EXPECTED_PRODUCTION_HEAD' in source
    malformed=0; escaped=[]
    replacements=(None,True,0,[],{},'x')
    for key in ep.REQUEST_FIELDS:
      for replacement in replacements:
        row=json.loads(json.dumps(request)); row[key]=replacement
        try: ep._validate_request(ep.canonical(row),issuers,now=now)
        except ep.Refusal: malformed+=1
        except BaseException as exc: escaped.append(type(exc).__name__)
    outcomes['malformed_top_level_type_campaign']={'generated':len(ep.REQUEST_FIELDS)*len(replacements),
        'refused':malformed,'escaped_exception_classes':escaped}
    outcomes['rgb_remote_result_consumer_present']=(candidate/'tools/phk2_host/phk2_fk0957_topology_rgb_orchestrator.py').is_file()
    fixture.doCleanups()
    return outcomes

if __name__=='__main__':
  import argparse
  p=argparse.ArgumentParser(); p.add_argument('candidate'); p.add_argument('--output',required=True); a=p.parse_args()
  result=run(Path(a.candidate).resolve()); Path(a.output).write_text(json.dumps(result,sort_keys=True,indent=2)+'\n'); print(json.dumps(result,sort_keys=True))
