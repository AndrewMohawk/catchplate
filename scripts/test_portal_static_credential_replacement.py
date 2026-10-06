#!/usr/bin/env python3
"""Focused synthetic/source controls; no app import, server, real MFA or browser.

Actual portal helpers execute in Node against inert DOM, response, clock and
WebAuthn fixtures. These controls do not establish backend or Rust rotation.
"""
from __future__ import annotations

import ast
from pathlib import Path
import re
import shutil
import subprocess
import unittest


ROOT = Path(__file__).resolve().parents[1]
APP = (ROOT / "serverware/app.py").read_text()
FRAGMENT = (ROOT / "serverware/portal_static_credential_replacement.py").read_text()


def literal(source: str, name: str) -> str:
    for node in ast.parse(source).body:
        if isinstance(node, ast.Assign) and any(
            isinstance(target, ast.Name) and target.id == name for target in node.targets
        ) and isinstance(node.value, ast.Constant):
            value = ast.literal_eval(node.value)
            assert isinstance(value, str)
            return value
    raise AssertionError(f"missing literal {name}")


UI = literal(APP, "UI_HTML")
SCRIPT = literal(FRAGMENT, "STATIC_CREDENTIAL_REPLACEMENT_SCRIPT")
ROTATION_PAGE_SCRIPT = literal((ROOT / "serverware/portal_static_credential_rotation.py").read_text(),
    "STATIC_CREDENTIAL_ROTATION_PAGE_SCRIPT")


def helper(name: str, *, kind: str = "function") -> str:
    # Source-owned top-level indentation; no evaluation or registry import.
    start = re.search(rf"(?m)^    (?:async )?{kind} {name}\b", UI)
    if start is None:
        raise AssertionError(f"missing portal helper {name}")
    end = re.search(r"(?m)^    }$", UI[start.start():])
    if end is None:
        raise AssertionError(f"missing helper terminator {name}")
    return UI[start.start():start.start() + end.end()] + "\n"


HELPERS = helper("ApiError", kind="class") + "".join(helper(name) for name in (
    "adminToken", "adminHeaders", "hasOperatorAuth", "requireAdminToken",
    "setStatus", "runUiAction", "controlStateKey", "captureControlState", "restoreControlState",
    "b64ToBytes", "bytesToB64", "credentialToJson", "prepareRequestOptions",
    "ensureCsrfToken", "api", "setupCredentialMutationGuard", "persistPendingMutation", "restorePendingMutation",
    "renderPendingMutation", "controlPlaneAssertion", "mutationOptions", "runControlPlaneMutation",
    "continuePendingMutation", "finishMutation",
))

FIXTURE = r"""
const assert = require('node:assert/strict');
const nodes = new Map(), events = {}, storage = new Map(), writes = [];
function element(id='') {
  return {id, value:'', textContent:'', checked:false, tagName:'INPUT', open:false, handlers:{},
    addEventListener(k,v){this.handlers[k]=v;}, focus(){}, setAttribute(){},
    showModal(){this.open=true;}, close(){this.open=false;},
    replaceChildren(...children){this.children=children;}, contains(){return true;}};
}
function $(id){if(!nodes.has(id))nodes.set(id,element(id));return nodes.get(id);}
const document={querySelectorAll(){return [...nodes.values()];}, createElement(){return element();}};
const window={PublicKeyCredential:function(){}, addEventListener(k,v){events[k]=v;}};
const sessionStorage={setItem(k,v){writes.push([k,v]);storage.set(k,v);},
  getItem(k){return storage.get(k)||null;},removeItem(k){storage.delete(k);}};
const localStorage={setItem(){throw new Error('unexpected local persistence');}};
const id='static /\u03bb', secret='  synthetic-secret\n\u03bb\t ';
const digest='sha256:'+'a'.repeat(64), approvalId='00000000-0000-4000-8000-000000000001';
const state={currentUserId:'user:requester',currentUserRoles:['credential_owner'],
  authStatus:{authenticated:true,userId:'user:requester',roles:['credential_owner'],
    authMethod:'oidc-session',sessionState:'active'},
  credentials:[{id,name:'Static fixture',kind:'bearer',metadata:{},lifecycle_status:'active'}],
  controlPlaneApprovals:[]};
let pendingMutation=null, csrfToken=null, oidcSessionStatusUnknown=false, protectedStaticCredentials=false,
  protectedStaticRotation=false;
const pendingMutationKey='synthetic-pending';
$('admin-token').value='synthetic-operator';
const calls=[], queue=[]; let refreshes=0, refreshHook=async()=>{};
async function refresh(){refreshes++;await refreshHook();renderAuthStatus();}
function renderAuthStatus(){credentialReplacementAuthChanged();renderCredentialReplacement();}
function esc(value){return String(value).replaceAll('&','&amp;').replaceAll('"','&quot;').replaceAll('<','&lt;');}
async function fetch(path, options={}) {
  assert.equal(Object.hasOwn(options,'credentialReplacement'),false);
  calls.push({path,options,body:options.body?JSON.parse(options.body):null});
  assert.ok(queue.length,'unexpected synthetic request');
  const next=queue.shift(); return typeof next==='function'?await next(path,options):next;
}
function response(status,detail){return {status,ok:status>=200&&status<300,
  headers:{get(){return null;}},async text(){return JSON.stringify(detail);},async json(){return detail;}};}
function challenge(status,extra={}){return response(status,{detail:{
  error:status===412?'control_plane_webauthn_required':'control_plane_approval_required',
  action:'credential.update',resourceId:id,payloadDigest:digest,
  ...(status===428?{approvalId,expiresAt:new Date(Date.now()+60000).toISOString()}:{}),...extra}});}
function options(){return response(200,{publicKey:{challenge:'AQ',allowCredentials:[{id:'Ag',type:'public-key'}]}});}
function assertion(){return {id:'synthetic-passkey',rawId:new Uint8Array([2]),type:'public-key',
  response:{clientDataJSON:new Uint8Array([1]),authenticatorData:new Uint8Array([3]),signature:new Uint8Array([4])}};}
let hardware=0, hardwareHook=async()=>assertion();
const navigator={credentials:{async get(value){hardware++;assert.ok(value.publicKey.challenge instanceof Uint8Array);
  return hardwareHook(value);}}};
function gate(){let resolve;const promise=new Promise(r=>resolve=r);return {promise,resolve};}
async function until(predicate){for(let i=0;i<100&&!predicate();i++)await Promise.resolve();assert.ok(predicate(),'fixture boundary not reached');}
function open(){openCredentialReplacement(id);$('credential-replacement-secret').value=secret;return credentialReplacement;}
function approval(status='approved'){return {id:approvalId,status,action:'credential.update',resource_id:id,
  payload_digest:digest,requester_id:'user:requester',required_approver_roles:['credential_owner']};}
function changed(){ $('admin-token').value='different-synthetic-operator';credentialReplacementAuthChanged(); }
function cleared(owner,held=[...owner.mutations]) {
  assert.equal(credentialReplacement,null);assert.equal(pendingMutation,null);assert.equal(owner.original,null);
  assert.equal(owner.pending,null);assert.equal(owner.mutations.size,0);assert.equal(owner.controller.signal.aborted,true);
  for(const value of held){assert.equal(Object.hasOwn(value.body,'secret'),false);assert.equal(Object.hasOwn(value.body,'mfa'),false);}
  assert.equal($('credential-replacement-secret').value,'');assert.equal($('credential-replacement-dialog').open,false);
  assert.equal(JSON.stringify(writes).includes(secret),false);assert.equal(storage.size,0);
}
"""


class StaticCredentialReplacementControls(unittest.TestCase):
    def javascript(self, source: str) -> None:
        node = shutil.which("node")
        self.assertIsNotNone(node, "Node is required; synthetic controls must not silently skip")
        result = subprocess.run(
            [node, "--max-old-space-size=128", "-"],
            input=FIXTURE + HELPERS + SCRIPT + "\n(async()=>{\n" + source
            + "\n})().catch(error=>{console.error(error);process.exitCode=1;});\n",
            text=True, capture_output=True, timeout=10, check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_protected_rotation_inventory_navigation_and_one_shot_prefill(self) -> None:
        prefill = ROTATION_PAGE_SCRIPT.split("rotationPagePrefill();", 1)[0]
        self.javascript(r"""
const selectedId='00000000-0000-4000-8000-000000000007';
const selected={...state.credentials[0],id:selectedId};
protectedStaticCredentials=true;protectedStaticRotation=true;
assert.equal(credentialReplacementButton(selected),
  `<a href="/credentials/static/rotation#credential=${selectedId}">Review secret rotation</a> `);
for(const patch of [{id:'x\"<'},{id:selectedId+'?secret=x'},{kind:'oauth2'},
    {metadata:{oauth:true}},{lifecycle_status:'retired'},{lifecycle_status:undefined}]){
  assert.equal(credentialReplacementButton({...selected,...patch}),'');
}
protectedStaticCredentials=false;
assert.equal(credentialReplacementEligible(selected),false);
assert.throws(open);assert.equal(calls.length,0);assert.equal(hardware,0);
protectedStaticRotation=false;
assert.match(credentialReplacementButton(state.credentials[0]),/data-credential-replacement/);
let clearedHashes=[];
window.location={hash:''};
window.history={replaceState(state,title,path){
  assert.equal(state,null);assert.equal(title,'');assert.equal(path,'/credentials/static/rotation');
  assert.equal($('rotation-credential-id').value,'');
  clearedHashes.push(window.location.hash);window.location.hash='';
}};
document.getElementById=$;
""" + prefill + r"""
rotationPagePrefill();assert.equal(clearedHashes.length,0);
window.location.hash='#credential='+selectedId;rotationPagePrefill();
assert.equal($('rotation-credential-id').value,selectedId);
assert.equal(window.location.hash,'');assert.match($('rotation-status').textContent,/No predecessor read/);
assert.equal(rotationFlow,null);assert.equal(rotationPrerequisitesObserved,false);
for(const fragment of ['#credential=bad','#credential='+selectedId+'&action=rotate',
    '#credential=%30'+selectedId.slice(1),'#secret=private','#credential='+'a'.repeat(200)]){
  $('rotation-credential-id').value='';window.location.hash=fragment;rotationPagePrefill();
  assert.equal(window.location.hash,'');assert.equal($('rotation-credential-id').value,'');
  assert.match($('rotation-status').textContent,/manually/);
}
assert.equal(calls.length,0);assert.equal(hardware,0);assert.equal(writes.length,0);
assert.equal(credentialReplacement,null);assert.equal(rotationFlow,null);
assert.equal(rotationPrerequisitesObserved,false);
""")

    def test_protected_mode_refuses_legacy_replacement_before_side_effects(self) -> None:
        function = next(node for node in ast.parse(APP).body
            if isinstance(node, ast.FunctionDef) and node.name == "update_credential")
        guard = function.body[0]
        self.assertIsInstance(guard, ast.If)
        self.assertEqual(ast.unparse(guard.test), "_protected_static_credentials()")
        self.assertIsInstance(guard.body[0], ast.Raise)
        class Refused(Exception):
            pass
        calls = []
        def refusal(**kwargs):
            calls.append(kwargs)
            return Refused()
        code = compile(ast.Module(body=[guard], type_ignores=[]), "protected-update-guard", "exec")
        for protected in (False, True):
            context = {"_protected_static_credentials": lambda: protected, "HTTPException": refusal}
            if protected:
                with self.assertRaises(Refused):
                    exec(code, context)
            else:
                exec(code, context)
        self.assertEqual([call["status_code"] for call in calls], [409])
        self.javascript(r"""
protectedStaticCredentials=true;
assert.match(credentialReplacementButton(state.credentials[0]),/no plaintext editor/);
assert.throws(open);assert.equal(credentialReplacement,null);assert.equal(calls.length,0);
protectedStaticCredentials=false;const owner=open();
protectedStaticCredentials=true;credentialReplacementAuthChanged();cleared(owner);
assert.equal(calls.length,0);assert.equal(hardware,0);
""")

    def test_01_source_closure_and_secret_snapshot_exclusion(self) -> None:
        dialog_style = re.search(r"(?m)^    dialog \{[^\n]+\}", UI).group(0)
        self.assertIn("color: var(--text); background: var(--panel);", dialog_style)
        for suffix in ("HTML", "SCRIPT"):
            name = f"STATIC_CREDENTIAL_REPLACEMENT_{suffix}"
            self.assertEqual(UI.count(f"__SERVERWARE_{name}__"), 1)
            self.assertIn(f'("__SERVERWARE_{name}__", {name})', APP)
        self.assertIn("from serverware.portal_static_credential_replacement import (", APP)
        self.assertEqual(UI.count("    initCredentialReplacement();"), 1)
        self.assertIn("credentialReplacementButton(item)", helper("credentialActions"))
        for name in ("markOIDCSessionStatusUnknown", "signInWithOIDC", "signOutOperator"):
            self.assertIn("discardCredentialReplacement(", helper(name))
        self.assertIn("discardCredentialReplacement(", helper("fetchAuthStatus"))
        self.assertIn("discardCredentialReplacement(", helper("api"))
        self.assertRegex(UI, r"(?s)\$\('admin-token'\)\.addEventListener\('input'.{0,250}discardCredentialReplacement")
        self.javascript(r"""
const owner=open();assert.equal($('credential-replacement-secret').value,secret);
assert.equal(JSON.stringify(captureControlState()).includes(secret),false);
$('credential-replacement-secret').value='';
restoreControlState({'id:credential-replacement-secret':{value:secret,checked:false}});
assert.equal($('credential-replacement-secret').value,'');
assert.equal(credentialReplacementButton({...state.credentials[0],id:'x"<'}).includes('x&quot;&lt;'),true);
discardCredentialReplacement();cleared(owner);
""")

    def test_02_exact_static_put_and_input_boundaries(self) -> None:
        self.javascript(r"""
for(const patch of [{kind:'oauth2'},{metadata:{oauth:true}},{lifecycle_status:'retired'}]){
  const original=state.credentials[0];state.credentials[0]={...original,...patch};
  assert.equal(credentialReplacementButton(state.credentials[0]),'');assert.throws(open);
  state.credentials[0]=original;
}
for(const value of ['', '\ud800', '\udc00', '\u00e9'.repeat(524289)]){
  const owner=open();$('credential-replacement-secret').value=value;
  assert.equal((await submitCredentialReplacement()).blocked,true);cleared(owner);
}
assert.equal(calls.length,0);
const owner=open();queue.push(response(200,{id,secret_generation:2}));
const result=await submitCredentialReplacement();assert.equal(result.uiHandled,true);
assert.equal(calls.length,1);assert.equal(calls[0].path,'/api/credentials/'+encodeURIComponent(id));
assert.equal(calls[0].options.method,'PUT');assert.deepEqual(calls[0].body,{secret});
assert.equal(calls[0].options.credentials,'same-origin');assert.equal(refreshes,1);cleared(owner);
assert.match($('operator-status').textContent,/accepted; credential list refreshed/);
assert.doesNotMatch($('operator-status').textContent,/Rust|rotated|lease|verified/i);
""")

    def test_03_real_client_mfa_approval_continuation_and_duplicates(self) -> None:
        self.javascript(r"""
const owner=open();queue.push(challenge(412),options(),challenge(428));
const first=submitCredentialReplacement();assert.equal((await submitCredentialReplacement()).blocked,true);
assert.equal((await first).pending,true);assert.equal(hardware,1);assert.equal(calls.length,3);
assert.equal(pendingMutation.persist,false);assert.equal(pendingMutation.body.secret,secret);
assert.deepEqual(pendingMutation.body.mfa,{approvalId});assert.equal(storage.size,0);assert.equal(writes.length,0);
assert.deepEqual(calls[1].body,{action:'credential.update',resourceId:id,payloadDigest:digest,approvalId:null});
assert.equal(calls[2].body.mfa.assertion.response.signature,'BA');
state.controlPlaneApprovals=[approval('pending')];assert.equal((await continuePendingMutation()).pending,true);
assert.equal(calls.length,3);
state.controlPlaneApprovals=[approval()];queue.push(challenge(412,{approvalId}),options(),response(200,{id}));
const held=[...owner.mutations], last=continuePendingMutation();
assert.equal((await continuePendingMutation()).blocked,true);assert.equal((await last).uiHandled,true);
assert.equal(calls.length,6);assert.equal(hardware,2);assert.equal(calls[5].body.secret,secret);
assert.equal(calls[5].body.mfa.approvalId,approvalId);assert.equal(calls[4].body.approvalId,approvalId);
assert.deepEqual(Object.keys(calls[5].body).sort(),['mfa','secret']);cleared(owner,held);
""")

    def test_04_cancel_storage_refusal_and_unrelated_mutations(self) -> None:
        self.javascript(r"""
initCredentialReplacement();
for(const cancel of [()=>discardCredentialReplacement(),
  ()=>$('credential-replacement-dialog').handlers.cancel({preventDefault(){}}),()=>events.pagehide()]){
  const owner=open();queue.push(challenge(428));await submitCredentialReplacement();
  const held=[...owner.mutations];cancel();cleared(owner,held);
}
storage.set(pendingMutationKey,JSON.stringify({kind:credentialReplacementKind,persist:true,body:{secret}}));
restorePendingMutation();assert.equal(pendingMutation,null);assert.equal(storage.size,0);
for(const reply of [response(403,{detail:secret}),()=>Promise.reject(new Error(secret)),
  challenge(428,{payloadDigest:'not-a-digest'}),challenge(428,{resourceId:'another'})]){
  const owner=open(), before=calls.length;queue.push(reply);
  assert.equal((await submitCredentialReplacement()).blocked,true);cleared(owner);
  assert.equal(calls.length,before+1);assert.equal($('operator-status').textContent.includes(secret),false);
}
queue.push(challenge(412),options(),challenge(412));const owner=open();
assert.equal((await submitCredentialReplacement()).blocked,true);assert.equal(hardware,1);cleared(owner);
queue.length=0;queue.push(response(200,{ok:true}));
const plain=await runControlPlaneMutation({kind:'ordinary',path:'/synthetic',body:{safe:true}});
assert.equal(plain.result.ok,true);assert.equal(plain.pending,false);
""")

    def test_05_auth_change_at_each_async_secret_boundary(self) -> None:
        # Each subcase gets fresh script globals; responses ignore abort on
        # purpose, proving post-await checks rather than trusting the double.
        for boundary in ("csrf-fetch", "csrf-json", "put-fetch", "put-text", "options", "hardware"):
            with self.subTest(boundary=boundary):
                self.javascript("const boundary=" + repr(boundary) + ";\n" + r"""
const wait=gate();let reached=false;
const blocked=()=>{reached=true;return wait.promise;};
if(boundary.startsWith('csrf')){
  $('admin-token').value='';queue.push(boundary==='csrf-fetch'?blocked:
    {...response(200,{token:'synthetic-csrf'}),json:blocked});
}else if(boundary==='put-fetch')queue.push(blocked);
else if(boundary==='put-text')queue.push({...response(200,{id}),text:blocked});
else {queue.push(challenge(412),boundary==='options'?blocked:options());
  if(boundary==='hardware')hardwareHook=blocked;}
const owner=open(), running=submitCredentialReplacement();await until(()=>reached);
const held=[...owner.mutations];changed();cleared(owner,held);
// A later editor must not be touched by the earlier promise's catch/finally.
const fresh=open();const message=$('credential-replacement-status').textContent;
wait.resolve(boundary==='csrf-json'?{token:'stale-csrf'}:boundary==='put-text'?JSON.stringify({id}):
  boundary==='hardware'?assertion():boundary==='options'?options():response(200,{id,token:'stale-csrf'}));
assert.equal((await running).blocked,true);assert.equal(credentialReplacement,fresh);
assert.equal($('credential-replacement-secret').value,secret);
assert.equal($('credential-replacement-status').textContent,message);
assert.equal(csrfToken,null);assert.equal(pendingMutation,null);
assert.equal(calls.filter(call=>call.options.method==='PUT').length,boundary.startsWith('csrf')?0:1);
discardCredentialReplacement();
""")

    def test_06_refresh_races_and_original_approval_refusals(self) -> None:
        for boundary in ("pending-refresh", "continue-refresh", "success-refresh"):
            with self.subTest(boundary=boundary):
                self.javascript("const boundary=" + repr(boundary) + ";\n" + r"""
const owner=open(), wait=gate();let reached=false,running;
if(boundary==='continue-refresh'){
  queue.push(challenge(428));await submitCredentialReplacement();state.controlPlaneApprovals=[approval()];
  refreshHook=()=>{reached=true;return wait.promise;};running=continuePendingMutation();
}else{
  refreshHook=()=>{reached=true;return wait.promise;};
  queue.push(boundary==='pending-refresh'?challenge(428):response(200,{id}));running=submitCredentialReplacement();
}
await until(()=>reached);const count=calls.length,held=[...owner.mutations];changed();cleared(owner,held);
const fresh=open();wait.resolve();assert.equal((await running).blocked,true);
assert.equal(credentialReplacement,fresh);assert.equal(pendingMutation,null);assert.equal(calls.length,count);
assert.doesNotMatch($('operator-status').textContent,/accepted; credential list refreshed/);
discardCredentialReplacement();
""")
        self.javascript(r"""
const originalNow=Date.now;
for(const change of [()=>{state.controlPlaneApprovals=[approval('denied')];},
  ()=>{state.controlPlaneApprovals=[{...approval(),payload_digest:'sha256:'+'b'.repeat(64)}];},
  ()=>{state.controlPlaneApprovals=[{...approval(),requester_id:'different'}];},
  ()=>{Date.now=()=>originalNow()+120000;}]){
  const owner=open();queue.push(challenge(428));await submitCredentialReplacement();
  const count=calls.length;change();
  // render is the real application's normal invalidation hook; no renewal.
  renderAuthStatus();if(credentialReplacement)await continuePendingMutation();
  cleared(owner);assert.equal(calls.length,count);Date.now=originalNow;state.controlPlaneApprovals=[];
}
""")


if __name__ == "__main__":
    unittest.main(verbosity=2)
