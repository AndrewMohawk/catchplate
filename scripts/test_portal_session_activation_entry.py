#!/usr/bin/env python3
"""One source/synthetic entry control, not cold-owner or hardware evidence."""
from __future__ import annotations

import ast
import builtins
from pathlib import Path
import re
import shutil
import subprocess
from types import SimpleNamespace
import unittest


ROOT = Path(__file__).resolve().parents[1]
APP = (ROOT / "serverware/app.py").read_text()
FRAGMENT = (ROOT / "serverware/portal_session_activation.py").read_text()


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


class SessionEntryControl(unittest.TestCase):
    def test_actual_mode_projection_and_navigation_never_chains_or_falls_back(self):
        # Cold-owner observations are fixture inputs to this pure projection
        # test, never reusable success objects admitted by production.
        class Owner:
            activation_execution_enabled = True
        class EnrollmentError(RuntimeError):
            pass
        class CustodyStartupError(RuntimeError):
            pass
        class CustodyClientError(RuntimeError):
            pass
        enrollment = SimpleNamespace(_EnrollmentOwner=Owner, EnrollmentStartupError=EnrollmentError,
                                     require_started=lambda: None)
        modules = {
            "serverware": SimpleNamespace(control_plane_enrollment_startup=enrollment),
            "serverware.control_plane_custody_startup": SimpleNamespace(CustodyStartupError=CustodyStartupError),
            "serverware.control_plane_custody_client": SimpleNamespace(CustodyClientError=CustodyClientError),
        }
        def fixture_import(name, *args, **kwargs):
            return modules[name]
        namespace = {"__builtins__": {**vars(builtins), "__import__": fixture_import}}
        tree = ast.parse(APP)
        projected = next(node for node in tree.body if isinstance(node, ast.FunctionDef)
                         and node.name == "_operator_session_activation_mode")
        exec(compile(ast.Module(body=[projected], type_ignores=[]), "app.py", "exec"), namespace)
        mode = namespace["_operator_session_activation_mode"]
        self.assertEqual(mode(), "legacy")
        enrollment.require_started = lambda: Owner()
        self.assertEqual(mode(), "protected")
        Owner.activation_execution_enabled = False
        self.assertEqual(mode(), "unavailable")
        enrollment.require_started = lambda: object()
        self.assertEqual(mode(), "unavailable")
        for error in (EnrollmentError, CustodyStartupError, CustodyClientError, OSError):
            def failed(error=error):
                raise error("synthetic source failure")
            enrollment.require_started = failed
            self.assertEqual(mode(), "unavailable")
            enrollment.require_started = lambda: Owner()
            Owner.activation_execution_enabled = property(lambda self, error=error: failed(error))
            self.assertEqual(mode(), "unavailable")
        status = next(node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == "operator_auth_status")
        self.assertIn("'sessionActivationMode': _operator_session_activation_mode()", ast.unparse(status))
        ui = literal(APP, "UI_HTML")
        script = literal(FRAGMENT, "SESSION_ACTIVATION_SCRIPT")
        self.assertIn("!['legacy', 'protected', 'unavailable'].includes(status.sessionActivationMode)",
                      javascript(ui, "fetchAuthStatus"))
        self.assertIn("state.authStatus?.sessionActivationMode", javascript(script, "sessionActivationAuthScope"))
        self.assertIn("Open protected session workflow", javascript(ui, "renderAuthStatus"))
        node = shutil.which("node")
        self.assertIsNotNone(node, "Node is required; this control must not skip")
        program = r"""
const assert=require('node:assert/strict'), elements=new Map(), calls=[];
let scrolls=0, prompts=0, invalidations=0, refreshes=0;
function $(id){if(!elements.has(id))elements.set(id,{value:'',textContent:'',
  focus(){},setAttribute(){},scrollIntoView(){scrolls++;}});return elements.get(id);}
let state={authStatus:{sessionActivationMode:'protected',sessionState:'pending_webauthn',webauthnRequired:true}};
let sessionActivationBusy=false,oidcSessionActivationBusy=false,oidcSessionStatusUnknown=false,csrfToken=null;
const window={PublicKeyCredential:function(){}}, navigator={credentials:{async get(){prompts++;return {};}}};
const sessionActivationAttempts=new Set(['retained:activate']);
function setStatus(message){$('status').textContent=message;}
function sessionActivationInvalidate(){invalidations++;}
function renderAuthStatus(){}
function prepareRequestOptions(value){return value;}
function credentialToJson(value){return value;}
async function refresh(){refreshes++;}
async function fetchAuthStatus(){return {authenticated:true,sessionState:'active',authMethod:'oidc-session'};}
function oidcSessionActivationIsActive(value){return value.authenticated===true&&value.sessionState==='active'&&value.authMethod==='oidc-session';}
async function sessionApi(path){calls.push(path);return path.endsWith('/options')?{publicKey:{}}:{ok:true,authenticated:true};}
class ApiError extends Error{}
""" + javascript(script, "sessionActivationMessage") + javascript(script, "openProtectedOIDCSessionWorkflow") + javascript(ui, "verifyOIDCSessionPasskey") + r"""
(async()=>{
  $('session-activation-locator').value='existing-retained-id';$('session-activation-action').value='recover';
  $('registration-handoff-finalization-locator').value='different-retained-id';
  assert.equal((await verifyOIDCSessionPasskey()).uiHandled,true);
  assert.equal(scrolls,1);assert.equal(calls.length,0);assert.equal(prompts,0);assert.equal(invalidations,0);
  assert.equal($('session-activation-locator').value,'existing-retained-id');
  assert.equal($('session-activation-action').value,'recover');assert.equal(sessionActivationAttempts.size,1);
  assert.match($('status').textContent,/not readiness or activation/);
  for(const mode of ['unavailable',undefined,'unexpected']){
    state.authStatus.sessionActivationMode=mode;
    assert.equal((await verifyOIDCSessionPasskey()).blocked,true);
    assert.equal(calls.length,0);assert.equal(prompts,0);assert.equal(invalidations,0);
  }
  state.authStatus.sessionActivationMode='protected';sessionActivationBusy=true;
  const prior=scrolls;assert.equal((await verifyOIDCSessionPasskey()).blocked,true);assert.equal(scrolls,prior);
  sessionActivationBusy=false;oidcSessionStatusUnknown=true;
  assert.equal((await verifyOIDCSessionPasskey()).blocked,true);assert.equal(calls.length,0);
  oidcSessionStatusUnknown=false;state.authStatus.sessionActivationMode='legacy';
  assert.equal((await verifyOIDCSessionPasskey()).authenticated,true);
  assert.deepEqual(calls,['/api/auth/session/webauthn/options','/api/auth/session/webauthn/verify']);
  assert.equal(prompts,1);assert.equal(refreshes,1);assert.equal(invalidations,1);
  assert.equal(sessionActivationAttempts.size,1);
})().catch(error=>{console.error(error);process.exitCode=1;});
"""
        result = subprocess.run([node, "--max-old-space-size=128", "-"], input=program,
                                text=True, capture_output=True, timeout=10, check=False)
        self.assertEqual(result.returncode, 0, result.stderr)


if __name__ == "__main__":
    unittest.main(verbosity=2)
