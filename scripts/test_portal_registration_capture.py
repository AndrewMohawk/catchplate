#!/usr/bin/env python3
"""One source/synthetic control; no live cookie, hardware or custody evidence."""
from __future__ import annotations

import ast
import base64
import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess
from types import SimpleNamespace
import unittest
from unittest.mock import Mock


ROOT = Path(__file__).resolve().parents[1]
APP = (ROOT / "serverware/app.py").read_text()
FRAGMENT = (ROOT / "serverware/portal_registration_capture.py").read_text()


def literal(source, name):
    return next(node.value.value for node in ast.parse(source).body
        if isinstance(node, ast.Assign) and isinstance(node.value, ast.Constant)
        and any(isinstance(target, ast.Name) and target.id == name for target in node.targets))


def javascript(source, name):
    start = re.search(rf"(?m)^    (?:async )?function {name}\b", source)
    if start is None:
        raise AssertionError("missing source function")
    end = re.search(r"(?m)^    }$", source[start.start():])
    if end is None:
        raise AssertionError("missing source terminator")
    return source[start.start():start.start() + end.end()] + "\n"


class RegistrationCaptureControl(unittest.TestCase):
    def test_registration_options_offer_security_key_without_changing_authority_or_freshness(self):
        tree = ast.parse((ROOT / "serverware/webauthn.py").read_text())
        function = next(node for node in tree.body if isinstance(node, ast.FunctionDef)
                        and node.name == "registration_options")
        canonical = lambda value: json.dumps(value, sort_keys=True, separators=(",", ":"))
        prefixed = lambda value: "sha256:" + hashlib.sha256(value).hexdigest()
        create = Mock()
        namespace = {
            "Any": object,
            "os": SimpleNamespace(urandom=lambda length: b"\x01" * length),
            "db": SimpleNamespace(create_webauthn_challenge=create),
            "b64u": lambda value: base64.urlsafe_b64encode(value).rstrip(b"=").decode(),
            "_sha256": lambda value: hashlib.sha256(value).digest(),
            "_sha256_prefixed": prefixed, "canonical_json": canonical,
            "WEBAUTHN_RP_NAME": "Synthetic options control",
            "WEBAUTHN_RP_ID": "registration.invalid", "ES256_ALG": -7,
        }
        exec(compile(ast.Module(body=[function], type_ignores=[]), "webauthn.py", "exec"), namespace)
        authorization = {"mode": "oidc-session-first-enrollment", "payload_digest": "sha256:" + "a" * 64}
        value = namespace["registration_options"]("synthetic-user", "synthetic-key", authorization=authorization)
        public_key = value["publicKey"]
        self.assertEqual(set(public_key), {"rp", "user", "challenge", "pubKeyCredParams",
                                         "timeout", "attestation", "hints", "authenticatorSelection"})
        self.assertEqual(public_key["hints"], ["security-key"])
        self.assertEqual(public_key["attestation"], "direct")
        self.assertEqual(public_key["authenticatorSelection"], {
            "residentKey": "discouraged", "userVerification": "preferred",
            "authenticatorAttachment": "cross-platform"})
        self.assertEqual(public_key["pubKeyCredParams"], [{"type": "public-key", "alg": -7}])
        self.assertEqual(public_key["timeout"], 300000)
        create.assert_called_once()
        stored = create.call_args.kwargs
        self.assertEqual(stored["ttl_seconds"], 300)
        self.assertEqual(stored["challenge_type"], "registration")
        self.assertEqual(stored["challenge"], public_key["challenge"])
        self.assertEqual(stored["user_id"], "synthetic-user")
        self.assertIs(stored["payload"]["authorization"], authorization)
        self.assertEqual(stored["payload"]["label"], "synthetic-key")
        self.assertEqual(stored["scope_key"], prefixed(canonical({
            "authorization": authorization, "label": "synthetic-key", "user_id": "synthetic-user"
        }).encode()))
        self.assertEqual(value["serverware"], {"authorizationMode": authorization["mode"],
                                              "payloadDigest": authorization["payload_digest"]})

    def test_explicit_cookie_capture_retains_only_real_202_locator_and_refuses_stale_work(self):
        ui = literal(APP, "UI_HTML")
        script = literal(FRAGMENT, "REGISTRATION_CAPTURE_SCRIPT")
        html = literal(FRAGMENT, "REGISTRATION_CAPTURE_HTML")
        self.assertIn("from serverware.portal_registration_capture import REGISTRATION_CAPTURE_HTML, REGISTRATION_CAPTURE_SCRIPT", APP)
        for name in ("HTML", "SCRIPT"):
            marker = "__SERVERWARE_REGISTRATION_CAPTURE_" + name + "__"
            self.assertEqual(ui.count(marker), 1)
            self.assertIn(f'("{marker}", REGISTRATION_CAPTURE_{name})', APP)
        self.assertIn("initRegistrationCapture();", ui)
        self.assertIn('onclick="openProtectedRegistrationCapture()"', ui)
        self.assertIn("renderRegistrationCapture();", javascript(ui, "renderAuthStatus"))
        for name in ("markOIDCSessionStatusUnknown", "fetchAuthStatus", "signInWithOIDC", "signOutOperator"):
            self.assertIn("registrationCaptureInvalidate(", javascript(ui, name))
        self.assertIn("registrationCaptureInvalidate('Entered operator credentials changed.');", ui)
        self.assertIn("window.addEventListener('pagehide'", script)
        self.assertNotIn("localStorage", script)
        self.assertNotIn("sessionStorage", script)
        self.assertNotIn("/register/verify", script)
        self.assertNotIn("execute-retained", script)
        self.assertNotIn("/activation", script)
        self.assertNotIn("innerHTML", script)
        self.assertIn("each step is separate", html.lower())
        legacy = javascript(ui, "enrollFirstOIDCSessionPasskey")
        self.assertIn("'/api/auth/session/webauthn/register/verify'", legacy)
        self.assertIn("sessionActivationMode !== 'legacy'", javascript(ui, "verifyOIDCSessionPasskey"))
        tree = ast.parse(APP)
        route = next(node for node in tree.body if isinstance(node, ast.FunctionDef)
                     and node.name == "operator_session_webauthn_register_prepare_execution")
        route_source = ast.unparse(route)
        for guard in ("_require_registration_execution_session_csrf", "_pending_oidc_session_for_request",
                      "_registration_execution_owner", "_require_registration_execution_bootstrap_branch",
                      "_oidc_registration_originals", "_registration_execution_prepared_response"):
            self.assertIn(guard, route_source)
        response = next(node for node in tree.body if isinstance(node, ast.FunctionDef)
                        and node.name == "_registration_execution_prepared_response")
        self.assertIn("JSONResponse(status_code=202", ast.unparse(response))
        self.assertIn("'executionStarted': False", ast.unparse(response))
        node = shutil.which("node")
        self.assertIsNotNone(node, "Node is required; this control must not skip")
        program = r"""
const assert=require('node:assert/strict'),vm=require('node:vm');
const source=SCRIPT,helpers=HELPERS;
const digest='sha256:'+'a'.repeat(64),old='sha256:'+'b'.repeat(64);
function fixture(){
  const f={events:[],posts:[],bootstrap:'synthetic-bootstrap-only-01234567890123456789',
    hook:null,clock:10,timers:new Map(),nextTimer:0,
    preparation:{schema:'serverware.webAuthnRegistrationExecutionPreparation/v1',
      status:'retained-execution-grant',purpose:'authorize-registration-evidence-execution',
      localDigest:digest,registrationCompleted:false,executionStarted:false},prepareStatus:202};
  const elements=new Map();
  function $(id){if(!elements.has(id))elements.set(id,{value:'',textContent:'',open:false,
    disabled:false,hidden:false,events:{},addEventListener(name,fn){this.events[name]=fn;},
    focus(){},scrollIntoView(){f.events.push('navigation');}});return elements.get(id);}
  async function checkpoint(name){f.events.push(name);if(f.hook)await f.hook(name);}
  const ctx={console,AbortController,TextEncoder,Uint8Array,Buffer,$,
    state:{authStatus:{authenticated:false,sessionActivationMode:'protected',sessionState:'pending_webauthn',webauthnRequired:true}},
    oidcSessionStatusUnknown:false,oidcSessionActivationBusy:false,sessionActivationBusy:false,
    registrationHandoffBusy:false,sessionActivationEpoch:0,registrationHandoffEpoch:0,
    performance:{now:()=>f.clock},
    setTimeout(fn){const id=++f.nextTimer;f.timers.set(id,fn);return id;},clearTimeout(id){f.timers.delete(id);},
    window:{PublicKeyCredential:function(){},addEventListener(name,fn){f[name]=fn;}},
    navigator:{credentials:{async create(value){f.hardware=value;await checkpoint('hardware');
      return {id:'synthetic-key',rawId:new Uint8Array([1]),type:'public-key',
        response:{clientDataJSON:new Uint8Array([2]),attestationObject:new Uint8Array([3])}};}}},
    b64ToBytes:value=>new Uint8Array(Buffer.from(value,'base64url')),
    bytesToB64:value=>Buffer.from(value).toString('base64url'),
    async requestWebAuthnBootstrapToken(){await checkpoint('bootstrap');return f.bootstrap;},
    async fetch(path,options){
      assert.equal(options.credentials,'same-origin');assert.equal(options.cache,'no-store');
      assert.ok(options.signal instanceof AbortSignal);
      const phase=path==='/api/csrf'?'csrf':path.endsWith('/options')?'options':path.endsWith('/prepare-execution')?'prepare':null;
      assert.ok(phase,'no alternate/legacy/execute/activation route');
      if(phase!=='csrf'){
        assert.equal(options.method,'POST');
        assert.deepEqual(Object.keys(options.headers).sort(),['Content-Type','X-Serverware-CSRF-Token']);
        assert.equal(options.headers['X-Serverware-CSRF-Token'],'synthetic-csrf');
        f.posts.push({phase,body:JSON.parse(options.body)});
      }
      await checkpoint('fetch:'+phase);
      const status=phase==='prepare'?f.prepareStatus:200;
      return {ok:status>=200&&status<300,status,async json(){await checkpoint('json:'+phase);
        if(phase==='csrf')return {token:'synthetic-csrf'};
        if(phase==='prepare')return structuredClone(f.preparation);
        return {publicKey:{challenge:'YQ',user:{id:'Yg'},timeout:300000},
          serverware:{authorizationMode:'oidc-session-first-enrollment'}};}};
    }};
  vm.createContext(ctx);
  vm.runInContext(`
    function sessionActivationAuthScope(){return JSON.stringify(state.authStatus);}
    function renderAuthStatus(){renderRegistrationCapture();}
    function registrationHandoffDigest(value){return typeof value==='string'&&/^sha256:[0-9a-f]{64}$/.test(value);}
    function clearRegistrationHandoffPrompt(){registrationHandoffEpoch++;}
    function renderRegistrationHandoff(){}
    ${helpers}\n${source}\n
    globalThis.controls={action:registrationCaptureAction,open:openProtectedRegistrationCapture,
      invalidate:registrationCaptureInvalidate,render:renderRegistrationCapture,init:initRegistrationCapture,
      owner:()=>registrationCapture,attempted:()=>registrationCaptureOptionsAttempted};`,ctx);
  f.ctx=ctx;f.api=ctx.controls;f.$=$;f.api.init();
  $('registration-handoff-locator').value=old;
  $('registration-handoff-finalization-locator').value='unchanged-finalization';
  return f;
}
async function captured(f){await f.api.action('options');assert.equal(f.api.owner().phase,'options-held');
  assert.equal(f.events.filter(v=>v==='hardware').length,0);
  await f.api.action('hardware');assert.equal(f.api.owner().phase,'captured');}
(async()=>{
  // Navigation/render and unselected modes cannot create options or hardware.
  for(const mode of ['legacy','unavailable',undefined]){
    const f=fixture();f.ctx.state.authStatus.sessionActivationMode=mode;f.api.render();f.api.open();
    await f.api.action('options');assert.equal(f.posts.length,0);assert.equal(f.api.attempted(),false);
  }
  // Exact actual route/response shape; three separate clicks and no next action.
  const good=fixture();good.api.open();assert.equal(good.posts.length,0);
  await captured(good);assert.deepEqual(good.posts.map(v=>v.phase),['options']);
  await good.api.action('prepare');assert.deepEqual(good.posts.map(v=>v.phase),['options','prepare']);
  assert.equal(good.events.filter(v=>v==='hardware').length,1);
  assert.equal(good.events.filter(v=>v==='bootstrap').length,2);
  assert.equal(good.posts[1].body.purpose,'authorize-registration-evidence-execution');
  assert.deepEqual(Object.keys(good.posts[1].body).sort(),['bootstrapToken','label','purpose','response']);
  assert.equal(good.posts[1].body.response.response.attestationObject,'Aw');
  assert.equal(good.$('registration-handoff-locator').value,digest);
  assert.equal(good.$('registration-handoff-mode').value,'pending');
  assert.equal(good.$('registration-handoff-finalization-locator').value,'unchanged-finalization');
  assert.equal(good.api.owner(),null);assert.equal(good.timers.size,0);
  assert.match(good.$('registration-capture-status').textContent,/NOT completed.*NOT started.*NOT activated/);
  await good.api.action('prepare');await good.api.action('options');assert.equal(good.posts.length,2);
  // Status, grammar and booleans are checked before accepting any locator.
  const failures=[f=>f.prepareStatus=200,f=>f.prepareStatus=503,
    f=>f.preparation.localDigest='invented',f=>f.preparation.executionStarted=true,
    f=>f.preparation.registrationCompleted=true,f=>f.preparation.extra='unexpected',
    f=>f.preparation.status='prepared',f=>f.preparation.purpose='wrong-purpose'];
  for(const alter of failures){const f=fixture();await captured(f);alter(f);await f.api.action('prepare');
    assert.equal(f.$('registration-handoff-locator').value,old);assert.equal(f.api.owner(),null);
    await f.api.action('prepare');assert.equal(f.posts.length,2);}
  // Stale continuations after every asynchronous boundary cannot restore state.
  for(const phase of ['options','hardware','prepare']){
    const points=phase==='hardware'?['hardware']:['bootstrap','fetch:csrf','json:csrf','fetch:'+phase,'json:'+phase];
    for(const point of points){const f=fixture();if(phase!=='options')await f.api.action('options');
      if(phase==='prepare')await f.api.action('hardware');
      f.hook=name=>{if(name===point){f.hook=null;f.ctx.state.authStatus.sessionActivationMode='unavailable';
        f.api.invalidate('Synthetic authentication change.');}};
      await f.api.action(phase);assert.equal(f.api.owner(),null);
      assert.equal(f.$('registration-handoff-locator').value,old);
      assert.equal(f.$('registration-handoff-finalization-locator').value,'unchanged-finalization');
      const count=f.posts.length;await f.api.action('prepare');assert.equal(f.posts.length,count);
    }
  }
  // Consume before uncertain sends; duplicate click/discard never opens a retry.
  const concurrent=fixture();let resume,entered;
  const entry=new Promise(resolve=>entered=resolve);
  concurrent.hook=async name=>{if(name==='fetch:options'){entered();await new Promise(resolve=>resume=resolve);}};
  const original=concurrent.api.action('options');await entry;
  assert.equal(concurrent.api.attempted(),true);await concurrent.api.action('options');
  concurrent.api.invalidate('Discard while sending.');resume();await original;
  assert.equal(concurrent.posts.length,1);assert.equal(concurrent.api.owner(),null);
  concurrent.hook=null;await concurrent.api.action('options');assert.equal(concurrent.posts.length,1);
  for(const point of ['fetch:prepare','json:prepare']){const f=fixture();await captured(f);
    f.hook=name=>{if(name===point)throw new Error('Synthetic transport failure');};
    await f.api.action('prepare');assert.equal(f.api.owner(),null);
    assert.equal(f.$('registration-handoff-locator').value,old);}
  // Original local bound, pagehide and cancellation discard only local evidence.
  const expired=fixture();await captured(expired);const timer=[...expired.timers.values()][0];
  expired.clock+=300001;timer();assert.equal(expired.api.owner(),null);
  await expired.api.action('prepare');assert.equal(expired.posts.length,1);
  const hidden=fixture();await captured(hidden);hidden.pagehide();assert.equal(hidden.api.owner(),null);
  const cancel=fixture();cancel.bootstrap=null;await cancel.api.action('options');
  assert.equal(cancel.posts.length,0);assert.equal(cancel.api.attempted(),false);
})().catch(error=>{console.error(error);process.exitCode=1;});
""".replace("SCRIPT", json.dumps(script), 1).replace("HELPERS", json.dumps(
            javascript(ui, "credentialToJson") + javascript(ui, "prepareCreationOptions")), 1)
        result = subprocess.run([node, "--max-old-space-size=128", "-"], input=program,
                                text=True, capture_output=True, timeout=15, check=False)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_owned_bootstrap_prompt_cancellation_settles_without_touching_other_workflow(self):
        ui = literal(APP, "UI_HTML")
        script = literal(FRAGMENT, "REGISTRATION_CAPTURE_SCRIPT")
        self.assertIn("let webauthnBootstrapPrompt = null;", ui)
        self.assertIn("requestWebAuthnBootstrapToken(owner.controller.signal)", script)
        helper = javascript(ui, "requestWebAuthnBootstrapToken")
        self.assertIn("signal?.removeEventListener('abort', cancel)", helper)
        node = shutil.which("node")
        self.assertIsNotNone(node, "Node is required; this control must not skip")
        program = r"""
const assert=require('node:assert/strict'),vm=require('node:vm');
const helper=HELPER,source=SCRIPT;
function fixture(){
  const elements=new Map(),f={requests:0};
  class Element extends EventTarget {
    constructor(){super();this.value='';this.textContent='';this.open=false;}
    showModal(){assert.equal(this.open,false);this.open=true;}
    close(){this.open=false;}focus(){}scrollIntoView(){}
  }
  function $(id){if(!elements.has(id))elements.set(id,new Element());return elements.get(id);}
  const ctx={$,console,AbortController,TextEncoder,performance:{now:()=>10},clearTimeout(){},setTimeout(){return 1;},
    state:{authStatus:{authenticated:false,sessionActivationMode:'protected',sessionState:'pending_webauthn',webauthnRequired:true}},
    oidcSessionStatusUnknown:false,oidcSessionActivationBusy:false,sessionActivationBusy:false,
    registrationHandoffBusy:false,sessionActivationEpoch:0,registrationHandoffEpoch:0,
    window:{addEventListener(name,fn){f[name]=fn;}},
    async fetch(){f.requests++;throw new Error('No request is permitted in this prompt-only fixture');}};
  vm.createContext(ctx);
  vm.runInContext(`
    let webauthnBootstrapPrompt=null;
    function sessionActivationAuthScope(){return JSON.stringify(state.authStatus);}
    function renderAuthStatus(){renderRegistrationCapture();}
    ${helper}\n${source}\n
    globalThis.controls={action:registrationCaptureAction,invalidate:registrationCaptureInvalidate,
      init:initRegistrationCapture,request:requestWebAuthnBootstrapToken,
      owner:()=>registrationCapture,busy:()=>registrationCaptureBusy,
      attempted:()=>registrationCaptureOptionsAttempted,
      prepareFixture(){
        // Synthetic preceding browser state only, not a server success DTO.
        registrationCapture=registrationCaptureOwner();registrationCapture.phase='captured';
        registrationCapture.attestation={synthetic:true};registrationCaptureOptionsAttempted=true;
      }};`,ctx);
  f.ctx=ctx;f.$=$;f.api=ctx.controls;f.api.init();return f;
}
(async()=>{
  for(const phase of ['options','prepare'])for(const reason of ['auth','discard','pagehide']){
    const f=fixture();if(phase==='prepare')f.api.prepareFixture();
    const pending=f.api.action(phase);
    assert.equal(f.$('webauthn-bootstrap-dialog').open,true);assert.equal(f.api.busy(),true);
    const owner=f.api.owner();f.$('webauthn-bootstrap-token').value='synthetic-entered-bootstrap';
    if(reason==='auth'){
      f.ctx.state.authStatus.sessionActivationMode='unavailable';f.api.invalidate('Authentication changed.');
    }else if(reason==='discard')f.$('registration-capture-discard').dispatchEvent(new Event('click'));
    else f.pagehide();
    await pending;
    assert.equal(owner.controller.signal.aborted,true);assert.equal(owner.attestation,null);
    assert.equal(f.$('webauthn-bootstrap-dialog').open,false);
    assert.equal(f.$('webauthn-bootstrap-token').value,'');
    assert.equal(f.api.owner(),null);assert.equal(f.api.busy(),false);
    assert.equal(f.ctx.oidcSessionActivationBusy,false);assert.equal(f.requests,0);
    assert.equal(f.api.attempted(),phase==='prepare');
    // Cancelled invocation removed its abort/cancel/submit callbacks. It cannot
    // clear a subsequent prompt, even when its old signal is aborted again.
    const later=f.api.request();f.$('webauthn-bootstrap-token').value='different-workflow';
    owner.controller.abort();assert.equal(f.$('webauthn-bootstrap-dialog').open,true);
    assert.equal(f.$('webauthn-bootstrap-token').value,'different-workflow');
    f.$('webauthn-bootstrap-form').dispatchEvent(new Event('submit',{cancelable:true}));
    assert.equal(await later,'different-workflow');
  }
  // An existing foreign prompt is never adopted by the capture or its signal.
  const foreign=fixture();const other=foreign.api.request();
  foreign.$('webauthn-bootstrap-token').value='foreign-secret';
  await foreign.api.action('options');foreign.api.invalidate('Discard capture.');
  assert.equal(foreign.$('webauthn-bootstrap-dialog').open,true);
  assert.equal(foreign.$('webauthn-bootstrap-token').value,'foreign-secret');
  const signal=new AbortController();assert.equal(await foreign.api.request(signal.signal),null);
  signal.abort();assert.equal(foreign.$('webauthn-bootstrap-token').value,'foreign-secret');
  foreign.$('webauthn-bootstrap-cancel').dispatchEvent(new Event('click',{cancelable:true}));
  assert.equal(await other,null);assert.equal(foreign.$('webauthn-bootstrap-token').value,'');
  const pre=fixture(),aborted=new AbortController();aborted.abort();
  assert.equal(await pre.api.request(aborted.signal),null);
  assert.equal(pre.$('webauthn-bootstrap-dialog').open,false);assert.equal(pre.requests,0);
})().catch(error=>{console.error(error);process.exitCode=1;});
""".replace("HELPER", json.dumps(helper), 1).replace("SCRIPT", json.dumps(script), 1)
        result = subprocess.run([node, "--max-old-space-size=128", "-"], input=program,
                                text=True, capture_output=True, timeout=10, check=False)
        self.assertEqual(result.returncode, 0, result.stderr)


if __name__ == "__main__":
    unittest.main(verbosity=2)
