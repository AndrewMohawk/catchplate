#!/usr/bin/env python3
"""Bounded sandbox-only in-memory audit retry diagnostic; no payload output.

Host-side operator tool. Captures at most 1 MiB / 8 seconds in the named
sandbox gate's network namespace, only its traffic to the named app:3000.
Headers never leave the capture helper. Database comparison is read-only.
After printing counts, keeps the captured batch in memory awaiting an explicit
operator command; EOF/anything but 'recover-missing' ends without writes.
"""
from __future__ import annotations
import json
import subprocess
import sys

APP = "catchplate-sandbox-catchplate-1"
GATE = "catchplate-sandbox-decision-gate-rs-1"
IMAGE = "sha256:ec14a558a42e483a834860521e399b461a2df880fcba495e7127b0d8d2a51e01"

CAPTURE = r'''
import json, socket, struct, sys, time
source, destination = map(socket.inet_aton, sys.argv[1:3])
s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
s.bind(("eth0", 0)); s.settimeout(.25)
streams = {}; total = 0; deadline = time.monotonic()+8
while time.monotonic() < deadline and total <= 1048576:
 try: packet = s.recv(65535)
 except socket.timeout: continue
 if len(packet)<54 or packet[12:14]!=b'\x08\x00': continue
 ip=packet[14:]; ihl=(ip[0]&15)*4
 if ip[9]!=6 or ip[12:16]!=source or ip[16:20]!=destination: continue
 tcp=ip[ihl:]; sport,dport,seq=struct.unpack('!HHI',tcp[:8])
 if dport!=3000: continue
 thl=(tcp[12]>>4)*4; data=tcp[thl:]
 if not data: continue
 total+=len(data)
 parts=streams.setdefault(sport,{})
 parts[seq]=data
 ordered=sorted(parts.items()); assembled=bytearray(); start=ordered[0][0]
 for position,chunk in ordered:
  offset=position-start
  if offset>len(assembled): break
  overlap=len(assembled)-offset
  if overlap<len(chunk): assembled.extend(chunk[overlap:])
 marker=b'POST /api/data-plane/audit HTTP/1.1\r\n'
 begin=assembled.find(marker)
 if begin<0: continue
 end=assembled.find(b'\r\n\r\n',begin)
 if end<0: continue
 headers=bytes(assembled[begin:end]).split(b'\r\n')
 lengths=[int(h.split(b':',1)[1].strip()) for h in headers[1:] if h.lower().startswith(b'content-length:')]
 if len(lengths)!=1 or not 0<lengths[0]<=1048576: raise SystemExit(2)
 if len(assembled)<end+4+lengths[0]: continue
 body=bytes(assembled[end+4:end+4+lengths[0]])
 parsed=json.loads(body)
 if set(parsed)!={'events'} or not 1<=len(parsed['events'])<=200: raise SystemExit(3)
 print(json.dumps(parsed),flush=True)
 raise SystemExit(0)
raise SystemExit(4)
'''

COMPARE = r'''
import json, os, sqlite3, sys
from pathlib import Path
from catchplate import db
assert os.environ.get('CATCHPLATE_DEVELOPMENT_SANDBOX')=='1'
assert os.environ.get('CATCHPLATE_RELEASE_CHANNEL')=='dev'
assert json.loads(Path('/data/.catchplate-development-sandbox.json').read_text())=={'schema':'catchplate.developmentSandbox/v1','syntheticOnly':True}
batch=json.load(sys.stdin); instance=os.environ['CATCHPLATE_DATA_PLANE_INSTANCE_ID']
connection=sqlite3.connect('file:/data/catchplate.sqlite3?mode=ro',uri=True)
connection.row_factory=sqlite3.Row
present=0; different=0; missing=[]
for index,item in enumerate(batch['events']):
 rowid=db._data_plane_audit_row_id(instance,item['eventId'])
 row=connection.execute('SELECT * FROM audit_events WHERE id=?',(rowid,)).fetchone()
 if row is None: missing.append(index); continue
 present+=1
 canonical=db.dumps(db._audit_event_for_storage(item['eventType'],item['event']))
 if not db._audit_batch_row_matches(row,event_type=item['eventType'],actor_type='data-plane',actor_id=instance,event_json=canonical): different+=1
print(json.dumps({'total':len(batch['events']),'present':present,'missing':len(missing),'allExistingExact':different==0,'conflicting':different,'missingIndices':missing}))
'''

RECOVER = r'''
import http.client,json,os,sys
from pathlib import Path
from cryptography.hazmat.primitives import serialization
from scripts.test_credential_lease_delivery import AppResponse,b64e,canonical_json_bytes,sha256_prefixed,verify_response_signature
from catchplate.policy_bundle import policy_hash
from catchplate.demo_seed_policy import require_demo_semantics
payload=json.load(sys.stdin)
assert os.environ.get('CATCHPLATE_DEVELOPMENT_SANDBOX')=='1'
assert os.environ.get('CATCHPLATE_RELEASE_CHANNEL')=='dev'
assert len(payload['events'])==14
assert json.loads(Path('/data/.catchplate-development-sandbox.json').read_text())=={'schema':'catchplate.developmentSandbox/v1','syntheticOnly':True}
policy=json.loads(Path('/data/policy-bundle.json').read_text()); require_demo_semantics(policy)
digest=policy_hash(policy)
def request(method,path,body=None,headers=None):
 c=http.client.HTTPConnection('127.0.0.1',3000,timeout=8)
 try:
  c.request(method,path,body=body,headers=headers or {})
  r=c.getresponse(); h=r.getheaders(); raw=r.read(1048577)
  assert len(raw)<=1048576
  return AppResponse(r.status,{k.lower():v for k,v in h},tuple((k.lower().encode(),v.encode()) for k,v in h),raw)
 finally:c.close()
nonce=b64e(os.urandom(32)); target='/attestation?nonce='+nonce
response=request('GET',target,headers={'X-Catchplate-Response-Nonce':nonce})
assert response.status_code==200
attestation=response.json()
key=serialization.load_pem_public_key(attestation['response_signing_public_key_pem'].encode())
keyid=sha256_prefixed(key.public_bytes(serialization.Encoding.DER,serialization.PublicFormat.SubjectPublicKeyInfo))
assert keyid==attestation['response_signing_key_id']
verify_response_signature(response,public_key=key,key_id=keyid,method='GET',target=target,response_nonce=nonce,policy_hash=digest)
token=Path('/run/secrets/catchplate/audit.token').read_text().strip()
accepted=0
for event in payload['events']:
 nonce=b64e(os.urandom(32)); body=canonical_json_bytes({'events':[event]})
 response=request('POST','/api/data-plane/audit',body,{'Content-Type':'application/json','X-Catchplate-Data-Plane-Token':token,'X-Catchplate-Response-Nonce':nonce})
 verify_response_signature(response,public_key=key,key_id=keyid,method='POST',target='/api/data-plane/audit',response_nonce=nonce,policy_hash=digest)
 result=response.json()
 assert response.status_code==200 and result['ok'] is True and result['accepted']==1
 assert result['apiVersion']=='catchplate.dataPlaneAuditAck/v1'
 assert result['batchDigest']==sha256_prefixed(body)
 assert result['instanceId']==os.environ['CATCHPLATE_DATA_PLANE_INSTANCE_ID']
 accepted+=1
 print(json.dumps({'singletonAccepted':accepted,'signedAckVerified':True}),flush=True)
admin=Path('/run/secrets/catchplate/admin.token').read_text().strip()
response=request('GET','/api/audit/verify',headers={'X-Catchplate-Admin-Token':admin})
verification=response.json()
assert response.status_code==200 and verification['ok'] is True and verification['complete'] is True
print(json.dumps({'accepted':accepted,'auditChainOk':True,'auditChainComplete':True,'auditChainCount':verification['count']}),flush=True)
'''


def run(command, *, data=None, timeout=15):
    result = subprocess.run(command, input=data, capture_output=True, timeout=timeout)
    if result.returncode != 0:
        stage = "capture" if "run" in command else "compare" if "exec" in command else "inspect"
        label = "permission" if b"PermissionError" in result.stderr else "runtime"
        print(json.dumps({'failedStage':stage,'exitCode':result.returncode,'errorLabel':label}),flush=True)
        raise RuntimeError("bounded-helper-failed")
    return result.stdout


def main():
    addresses = []
    for name in (GATE, APP):
        raw = run(["docker", "inspect", "--format", "{{range .NetworkSettings.Networks}}{{.IPAddress}} {{end}}", name])
        values = raw.decode().split()
        if len(values) != 1:
            raise RuntimeError("unexpected-network-scope")
        addresses.append(values[0])
    batch_bytes = run([
        "docker", "run", "--rm", "--pull", "never", "--read-only", "--log-driver", "none",
        "--network", "container:" + GATE, "--user", "0:0", "--cap-drop", "ALL", "--cap-add", "NET_RAW",
        "--security-opt", "no-new-privileges:true", "--cpus", "0.5", "--memory", "128m",
        "--pids-limit", "16", "--entrypoint", "python", IMAGE, "-B", "-c", CAPTURE,
        *addresses,
    ], timeout=12)
    batch = json.loads(batch_bytes)
    result = json.loads(run(["docker", "exec", "-i", APP, "python", "-B", "-c", COMPARE], data=batch_bytes))
    print(json.dumps({key: value for key, value in result.items() if key != "missingIndices"}), flush=True)
    # Retain only in this process; never write a replay artifact or raw body.
    print('awaiting_operator_command', flush=True)
    command = sys.stdin.readline().strip()
    if command != 'recover-missing':
        return
    if not (result['total']==15 and result['present']==1 and result['missing']==14
            and result['allExistingExact'] and result['conflicting']==0):
        raise RuntimeError('recovery-precondition-changed')
    missing={'events':[batch['events'][index] for index in result['missingIndices']]}
    # This command is entered only after reviewing counts and explicit approval.
    receipt=run(['docker','exec','-i',APP,'python','-B','-c',RECOVER],
                data=json.dumps(missing).encode(),timeout=110)
    # RECOVER has a fixed flags/counts-only output contract; stderr is suppressed.
    for line in receipt.decode().splitlines():
        record=json.loads(line)
        if not set(record)<={'singletonAccepted','signedAckVerified','accepted','auditChainOk','auditChainComplete','auditChainCount'}:
            raise RuntimeError('unexpected-receipt')
        print(json.dumps(record),flush=True)
    after=json.loads(run(['docker','exec','-i',APP,'python','-B','-c',COMPARE],data=batch_bytes))
    print(json.dumps({key:value for key,value in after.items() if key!='missingIndices'}),flush=True)


if __name__ == '__main__':
    try:
        main()
    except Exception as exc:
        print(json.dumps({'ok':False,'errorType':type(exc).__name__}), flush=True)
        raise SystemExit(1) from None
