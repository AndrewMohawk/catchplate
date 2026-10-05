#!/usr/bin/env python3
"""Four offline preview controls: real compiler, extracted app, inert JS IO.

No app boot, database connection, provider, browser, or native acceptance.
The JS handoff is a transport fixture, not authority verification.
"""
from __future__ import annotations

import ast
import base64
import copy
import hmac
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
from types import SimpleNamespace
from typing import Any, Literal
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
os.environ["SERVERWARE_RELEASE_CHANNEL"] = "test"
os.environ["SERVERWARE_DATA_DIR"] = "/tmp/unused-policy-preview"

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi import HTTPException
from pydantic import BaseModel, ConfigDict, Field, ValidationError
from serverware import policy_bundle as policy

SOURCE = (ROOT / "serverware/app.py").read_text()
TREE = ast.parse(SOURCE)
NODES = {node.name: node for node in TREE.body if isinstance(node, (ast.FunctionDef, ast.ClassDef))}
UI = next(ast.literal_eval(node.value) for node in TREE.body if isinstance(node, ast.Assign)
    and any(isinstance(target, ast.Name) and target.id == "UI_HTML" for target in node.targets))


def forbidden(*args, **kwargs):
    raise AssertionError("preview attempted signing, writing, or unexpected IO")


def javascript(name):
    start = re.search(r"(?m)^    (?:async )?(?:function|class) " + re.escape(name) + r"\b", UI)
    assert start is not None, name
    end = re.search(r"(?m)^    }$", UI[start.start():])
    assert end is not None, name
    return UI[start.start():start.start() + end.end()] + "\n"


def extracted():
    names = ("PolicyDryRunCase", "PolicyCandidateRequest", "PolicyPreviewRequest",
        "_policy_ids", "_policy_diff", "_run_policy_dry_runs", "_policy_preview_report",
        "_normalized_credential_provider", "_credential_metadata_scopes",
        "_credential_metadata_binding_alias", "_assert_credential_policy_binding",
        "_assert_credential_injection_binding", "_assert_route_credential_binding",
        "_assert_policy_candidate_credential_bindings")
    namespace = dict(Any=Any, Literal=Literal, BaseModel=BaseModel, ConfigDict=ConfigDict, Field=Field,
        HTTPException=HTTPException, hmac=hmac, PolicyBundleError=policy.PolicyBundleError,
        compile_policy_bundle=policy.compile_policy_bundle, sign_policy_bundle=forbidden,
        POLICY_PUBLISH_DRY_RUN_REQUIRED=True,
        _canonical_json=lambda value: json.dumps(value, sort_keys=True, separators=(",", ":")))
    module = ast.Module(body=[ast.ImportFrom(module="__future__", names=[ast.alias(name="annotations")], level=0)]
        + [NODES[name] for name in names], type_ignores=[])
    exec(compile(ast.fix_missing_locations(module), "<actual-preview-functions>", "exec"), namespace)
    for name in ("PolicyDryRunCase", "PolicyCandidateRequest", "PolicyPreviewRequest"):
        namespace[name].model_rebuild(_types_namespace=namespace)
    return namespace


class PolicyPreviewControls(unittest.TestCase):
    def setUp(self):
        self.ns = extracted()
        self.bundle = policy.demo_policy_bundle("synthetic-static")
        # Exercise static replacement only; unrelated OAuth demo credentials
        # are not present in this deliberately synthetic database view.
        self.bundle["credentials"] = [item for item in self.bundle["credentials"]
            if item["id"] == "synthetic-static"]
        self.bundle["routes"] = [item for item in self.bundle["routes"]
            if item["id"] == "demo.echo"]
        self.current = policy.compile_policy_bundle(self.bundle, validate_schema=True,
            enforce_signed_policy_constraints=True)
        self.bundle["metadata"]["sequence"] += 1
        self.credential = dict(id="synthetic-static", kind="bearer", metadata={
            "provider_id": "demo", "provider_subject": "demo-service-account",
            "secret_class": "bearerToken"})
        self.ns.update(get_policy_snapshot=lambda: self.current,
            db=SimpleNamespace(get_credential=lambda identifier: self.credential
                if identifier == "synthetic-static" else None))
        self.cases = [dict(principalId="agent:demo", host="demo-upstream", port=8443,
            method="GET", path="/echo", expectedRouteId="demo.echo", expect="allow"),
            dict(principalId="agent:demo", host="denied.invalid", method="GET", path="/echo", expect="deny")]

    def report(self, bundle=None):
        payload = self.ns["PolicyPreviewRequest"](bundle=bundle or self.bundle, dryRun=self.cases)
        with patch.object(policy, "_load_policy_private_key", forbidden), \
                patch.object(policy, "_load_policy_signing_trust", forbidden), \
                patch.object(policy, "ensure_data_dirs", forbidden):
            return self.ns["_policy_preview_report"](bundle=payload.bundle, dry_run=payload.dry_run)

    def test_01_unsigned_real_compiler_and_exact_route(self):
        before = copy.deepcopy(self.bundle)
        report = self.report()
        self.assertEqual(self.bundle, before)
        self.assertEqual(report["apiVersion"], "serverware.policyPreview/v1")
        self.assertTrue(report["previewOnly"] and report["dryRun"]["passed"])
        for name in ("signatureVerified", "activated", "publicationReady"):
            self.assertIs(report[name], False)
        self.assertFalse({"signedBundle", "signature", "signingKeyId"} & set(report))
        self.assertFalse({"signature", "signingKeyId", "policyHash"} & set(report["candidate"]))
        endpoint = ast.get_source_segment(SOURCE, NODES["policy_preview"])
        self.assertIn('require_role("policy_author", "policy_publisher")', endpoint)
        self.assertIn('_policy_preview_report(bundle=payload.bundle, dry_run=payload.dry_run)', endpoint)
        self.assertEqual(ast.literal_eval(NODES["policy_preview"].decorator_list[0].args[0]), "/api/policy/preview")
        self.assertIn("sign_policy_bundle(bundle)", ast.get_source_segment(SOURCE, NODES["_policy_candidate_report"]))

    def test_02_closed_model_signed_draft_and_credential_refusals(self):
        for name in ("signature", "signingKeyId"):
            bundle = copy.deepcopy(self.bundle)
            bundle["metadata"][name] = None
            with self.assertRaises(HTTPException) as caught:
                self.report(bundle)
            self.assertEqual(caught.exception.status_code, 400)
        self.credential["metadata"]["provider_subject"] = "different-synthetic-subject"
        with self.assertRaises(HTTPException) as caught:
            self.report()
        self.assertEqual(caught.exception.status_code, 409)
        with self.assertRaises(ValidationError):
            self.ns["PolicyPreviewRequest"](bundle=self.bundle, dryRun=self.cases, publicationReady=True)
        with self.assertRaises(ValidationError):
            self.ns["PolicyPreviewRequest"](bundle=self.bundle, dryRun=[self.cases[0]] * 257)

    def test_03_explicit_signed_semantic_constraints(self):
        bundle = policy.demo_policy_bundle("synthetic-static")
        route = next(item for item in bundle["routes"] if item["adapter"]["type"] == "npm.registry")
        route["constraints"] = [item for item in route["constraints"] if item["type"] != "responseBinding"]
        policy.compile_policy_bundle(bundle, validate_schema=True)  # Existing unsigned domain unchanged.
        with self.assertRaises(HTTPException) as caught:
            self.report(bundle)
        self.assertIn("signed npm.publish requires a responseBinding", caught.exception.detail)

    def test_04_exact_ui_handoff_and_prefetch_guards(self):
        node = shutil.which("node")
        self.assertIsNotNone(node)
        signed = copy.deepcopy(self.bundle)
        key = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))  # Public deterministic test key only.
        signed["metadata"]["signingKeyId"] = policy._public_key_id(key.public_key())
        signature = key.sign(policy.policy_signature_bytes(signed))
        signed["metadata"]["signature"] = "ed25519:" + base64.urlsafe_b64encode(signature).decode().rstrip("=")
        key.public_key().verify(signature, policy.policy_signature_bytes(signed))
        fixture = dict(bundle=self.bundle, signed=signed, report=self.report(), cases=self.cases,
            base=self.current.hash)
        helpers = "".join(javascript(name) for name in ("ApiError", "adminToken", "adminHeaders",
            "hasOperatorAuth", "requireAdminToken", "ensureCsrfToken", "api", "canonicalJson",
            "policyAuthorityPackage", "invalidatePolicyCandidate", "policyAuthoringScope",
            "previewPolicyCandidate", "signedPolicyCandidate", "renderPolicyCandidate", "stagePolicyCanary"))
        result = subprocess.run([node, "--max-old-space-size=128", "-"],
            input="const fixture=" + json.dumps(fixture) + ";\n" + JS_FIXTURE + helpers + JS_CHECKS,
            text=True, capture_output=True, timeout=15, check=False)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), "PREVIEW_UI_CONTROLS_PASS")


JS_FIXTURE = r"""
const assert=require('node:assert/strict'), clone=value=>JSON.parse(JSON.stringify(value));
const nodes=new Map();
function $(id){if(!nodes.has(id))nodes.set(id,{value:'',textContent:'',disabled:false,focus(){}});return nodes.get(id);}
let state, csrfToken=null, oidcSessionStatusUnknown=false, policyPreviewGeneration=0;
let calls=[], csrfHook=null, requestId=0;
const pkg={apiVersion:'serverware.policyAuthorityPortalPackage/v1',handoff:Object.fromEntries(
 ['candidateId','artifactEnvelopeDigest','canaryId','assignmentEnvelopeDigest','loadReceiptEnvelopeDigest',
  'instanceId','bootId','runtimeAttestationHandoffDigest','predecessorPolicyHash'].map(name=>[name,'synthetic-'+name]))};
function reset(){nodes.clear();calls=[];csrfToken=null;csrfHook=null;oidcSessionStatusUnknown=false;
 state={currentUserId:'synthetic:operator',currentUserRoles:['policy_author'],
 authStatus:{authenticated:true,userId:'synthetic:operator',roles:['policy_author'],authMethod:'oidc-session',sessionState:'active'},
 activePolicy:{policy_hash:fixture.base},policyCandidate:null,setupSession:null};}
function buildPolicyCandidate(){return {bundle:clone(fixture.bundle),dryRun:fixture.cases,basePolicyHash:fixture.base};}
function credentialReplacementApiGuard(value){assert.equal(value,undefined);return null;}
function authorityRequestId(){return 'synthetic-request-'+(++requestId);}
function setStatus(){throw new Error('unexpected status/auth failure');}
function discardCredentialReplacement(){throw new Error('unexpected auth refusal');}
function renderAuthStatus(){throw new Error('unexpected auth render');}
async function refresh(){}
function response(payload){return {status:200,ok:true,headers:{get(){return null;}},
 async json(){return payload;},async text(){return JSON.stringify(payload);}};}
async function fetch(path,options={}){
 assert.equal(Object.hasOwn(options,'checkContext'),false);calls.push({path,options});
 if(path==='/api/csrf'){if(csrfHook)await csrfHook();return response({token:'synthetic-csrf'});}
 if(path==='/api/policy/preview'){assert.deepEqual(JSON.parse(options.body).bundle,fixture.bundle);return response(fixture.report);}
 if(path==='/api/policy')return response({policy_hash:fixture.base});
 if(path==='/api/policy/authority/candidates/package')return response({portalPackage:pkg,packageDigest:'synthetic-package'});
 if(path==='/api/policy/authority/candidates/handoff')return response({fixtureOnly:true});
 throw new Error('unexpected fixture route '+path);
}
function supply(){ $('policy-signed-bundle').value=JSON.stringify(fixture.signed);
 $('policy-authority-package').value=JSON.stringify(pkg);renderPolicyCandidate(); }
"""

JS_CHECKS = r"""
(async()=>{
 reset();await previewPolicyCandidate();assert.equal($('policy-stage-button').disabled,true);
 assert.match($('policy-candidate-summary').textContent,/Unsigned preview/);
 let count=calls.length;await assert.rejects(stagePolicyCanary,/independently signed/);assert.equal(calls.length,count);
 supply();assert.equal($('policy-stage-button').disabled,false);await stagePolicyCanary();
 const sent=calls.filter(call=>call.path.endsWith('/handoff'));assert.equal(sent.length,1);
 const body=JSON.parse(sent[0].options.body);assert.deepEqual(body.candidatePolicyBundle,fixture.signed);
 assert.equal(body.candidatePolicyBundle.metadata.signature,fixture.signed.metadata.signature);
 assert.equal(body.candidatePolicyBundle.metadata.signingKeyId,fixture.signed.metadata.signingKeyId);
 reset();await previewPolicyCandidate();supply();let changed=clone(fixture.signed);changed.metadata.sequence++;
 $('policy-signed-bundle').value=JSON.stringify(changed);count=calls.length;
 await assert.rejects(stagePolicyCanary,/differs from the previewed draft/);assert.equal(calls.length,count);
 for(const change of [()=>{$('admin-token').value='changed-synthetic';},()=>invalidatePolicyCandidate()]){
   reset();csrfHook=change;await assert.rejects(previewPolicyCandidate,/inputs or authentication changed/);
   assert.deepEqual(calls.map(call=>call.path),['/api/csrf']);
 }
 for(const change of [()=>{$('admin-token').value='changed-synthetic';},()=>{$('policy-signed-bundle').value+=' ';}]){
   reset();await previewPolicyCandidate();supply();csrfToken=null;calls=[];csrfHook=change;
   await assert.rejects(stagePolicyCanary,/changed/);
   assert.deepEqual(calls.map(call=>call.path),['/api/policy','/api/csrf']);
 }
 console.log('PREVIEW_UI_CONTROLS_PASS');
})().catch(error=>{console.error(error);process.exitCode=1;});
"""


if __name__ == "__main__":
    unittest.main(verbosity=2)
