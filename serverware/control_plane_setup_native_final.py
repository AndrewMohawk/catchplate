"""Actual one-shot final Setup HTTP consumer and historical recovery."""
import os
import threading
import time
from fastapi import Request
from fastapi.responses import JSONResponse
from serverware import auth,db,webauthn,authority_contract
from serverware import authority_setup_native_final as p
from serverware import authority_setup_native_final_policy as policy
from serverware import control_plane_setup_policy as setup
from serverware import control_plane_setup_native_hardware as hardware
from serverware import control_plane_policy_canary_startup as cold
from serverware.control_plane_approval_verification import _request_pin

PREFIX="/api/setup/native-final"
PATHS=frozenset(PREFIX+"/"+phase for phase in ("options","prepare","complete","settle","lookup"))
MAX_HTTP,MAX_RESPONSE=32768,4*1024*1024
COMMON={"apiVersion":"serverware.setupNativeFinalResponse/v1","okForAction":False,"automaticRetryAllowed":False,
    "measuredHost":False,"proxyReady":False,"resultScope":p.SCOPE,"hostAssociationTrust":"trusted-host-local"}


def error(status=409,*,unknown=False):
    return JSONResponse({**COMMON,"status":"final-outcome-unknown" if unknown else "refused"},status_code=status,
        headers={"Cache-Control":"no-store","Pragma":"no-cache","X-Content-Type-Options":"nosniff"})


def _identity(request):
    p.require(type(request) is Request and request.method=="POST" and request.url.path in PATHS and not request.url.query
        and request.headers.get("content-type")=="application/json" and not request.headers.getlist("authorization")
        and not request.headers.getlist("x-serverware-admin-token") and len(request.headers.getlist("cookie"))==1
        and request.headers.getlist("origin")==[webauthn.WEBAUTHN_ORIGIN] and webauthn.WEBAUTHN_ORIGIN not in ("","null"))
    names=[part.strip().split("=",1)[0] for part in request.headers["cookie"].split(";")]
    p.require(len(names)==len(set(names)) and not request.cookies.get("serverware_admin"))
    identity=auth.oidc_identity_from_session_token(request.cookies.get(auth.OIDC_SESSION_COOKIE_NAME))
    p.require(type(identity) is auth.AdminIdentity and identity.user_id.startswith("oidc:"))
    auth.validate_csrf_request(request);return identity


def _row(sid):
    with db.connect() as connection:
        p.require(isinstance(connection,db.PostgresMetadataConnection))
        row=connection.execute("WITH chosen AS (SELECT row_to_json(source)::text AS original FROM setup_native_final_attempts AS source WHERE session_id = ?) "
            "SELECT CASE WHEN octet_length(original) <= ? THEN original ELSE NULL END AS original FROM chosen",(sid,p.MAX_ROW_BYTES)).fetchone()
    if row is None:return None
    p.require(type(row["original"]) is str)
    result=p.enrollment.setup.document(row["original"].encode("utf-8"),p.MAX_ROW_BYTES,exact=False);p.row_original(result);return result


class _Owner:
    def __init__(self,request,sid,phase):
        self.request,self.scope,self.pin=request,request.scope,_request_pin(request)
        self.pid,self.thread=os.getpid(),threading.get_ident();self.identity=_identity(request)
        self.cold,self.selected,_=cold.native_setup_final_owner()
        self.custody,self.binding,self.configuration=self.cold.custody,self.cold.binding,self.cold.configuration_digest
        self.policy=self.selected["credentialPolicy"];self.credential=None;self.dispatched=False
        self.started_mono,self.started_epoch=time.monotonic_ns(),time.time_ns()
        self.last_mono,self.last_epoch=self.started_mono,self.started_epoch
        self.deadline,self.expires=self.started_mono+30_000_000_000,self.started_epoch+30_000_000_000
        self.session=setup._session(sid);self.session_original=p.enrollment.setup.row_original(self.session)
        self.continuation=setup._continuation(sid);p.require(self.continuation is not None)
        self.continuation_original=p.enrollment.candidate.row_original(self.continuation).decode("ascii")
        retained=p.original(self.continuation["request_original"],p.enrollment.candidate.MAX_ARGUMENT_BYTES)
        self.rotated=set(retained["request"])==p.enrollment.candidate.ROTATED_STATIC_REQUEST_FIELDS
        self.static=self.rotated or set(retained["request"])==p.enrollment.candidate.STATIC_REQUEST_FIELDS
        self.hardware=hardware._row(sid);p.require(self.hardware is not None)
        self.hardware_original=p.hardware.row_original(self.hardware).decode("ascii")
        self.phase=phase;self.check()
        if phase!="lookup":
            if self.static: p.enrollment.candidate.require_static_session(self.session,rotated=self.rotated)
            else: p.require(self.session["revision"]==3)
            p.require(self.session["phase"]=="credential_activated" and self.session["status"]=="active" and self.session["terminal_at"] is None
                and self.continuation["setup_original"].encode("ascii")==self.session_original
                and self.continuation["configuration_digest"]==self.configuration)
            self.clip(min(p.hardware.prepared(self.hardware["attempt_original"])["expiresAtEpochNs"],p.enrollment.setup.epoch(self.session["expires_at"])))

    def clip(self,expires):
        self.expires=min(self.expires,expires);self.deadline=min(self.deadline,self.started_mono+self.expires-self.started_epoch);self.check()

    def check(self):
        mono,epoch=time.monotonic_ns(),time.time_ns()
        p.require((os.getpid(),threading.get_ident())==(self.pid,self.thread) and self.last_mono<=mono<self.deadline
            and self.last_epoch<=epoch<self.expires and self.request.scope is self.scope and _request_pin(self.request)==self.pin
            and _identity(self.request)==self.identity)
        actual,selected,_=cold.native_setup_final_owner();p.require(actual is self.cold and selected==self.selected
            and setup.startup.require_started() is self.custody and setup.custody_client._snapshot(self.custody) is self.binding
            and p.enrollment.setup.row_original(setup._session(self.session["id"]))==self.session_original
            and p.enrollment.candidate.row_original(setup._continuation(self.session["id"])).decode("ascii")==self.continuation_original
            and p.hardware.row_original(hardware._row(self.session["id"])).decode("ascii")==self.hardware_original)
        actor=self.identity.user_id;owner=self.session["owner_id"]
        if self.phase=="prepare":p.require(actor==owner and {"credential_owner","policy_author"}<=self.identity.roles)
        elif self.phase in ("complete","settle"):p.require(actor!=owner and "attestation_reviewer" in self.identity.roles)
        else:p.require(actor==owner or "attestation_reviewer" in self.identity.roles)
        if self.credential is not None:
            current=db.get_webauthn_credential_by_record_id(self.credential["id"])
            p.require(type(current) is dict and current.get("revoked_at") is None and all(current[name]==self.credential[name]
                for name in ("id","credential_id","user_id","public_key_cose")))
            admitted=webauthn._allowed_authenticator(current,setup.activation._authenticator_policy(self.policy))
            p.require(admitted["currently_trusted"] is True and admitted["effective_authenticator_class"] in {"hardware","yubikey"})
        self.last_mono,self.last_epoch=mono,epoch

    def values(self,operation,row=None,receipt=None):
        values={"actor_id":self.identity.user_id,"control_plane_configuration_digest":self.configuration,
            "credential_policy":self.policy,"maximum_final_nanos":self.selected["maximumChallengeNanos"],"hardware_original":self.hardware_original,
            "challenge_original":None if row is None else row["challenge_original"],"receipt_original":receipt}
        if operation==p.SETTLE and self.static: values["continuation_original"]=self.continuation_original
        return p.arguments(operation,values)

    def assertion(self,value):return setup._Owner.assertion(self,value)


def _options(owner,operation,values):
    descriptors=webauthn._credential_descriptors_for_policy(owner.identity.user_id,setup.activation._authenticator_policy(owner.policy))
    p.require(type(descriptors) is list and 1<=len(descriptors)<=64)
    owner.credential=db.get_webauthn_credential(descriptors[0]["id"])
    p.require(type(owner.credential) is dict and owner.credential["user_id"]==owner.identity.user_id);owner.check()
    challenge=db.issue_policy_authority_webauthn_challenge(operation=operation,input_value=values,user_id=owner.identity.user_id,
        credential_id=owner.credential["credential_id"],deadline_ns=owner.deadline)
    payload=challenge["payload"];p.require(challenge["used_at"] is None and challenge["challenge_type"]=="policy_authority"
        and challenge["user_id"]==owner.identity.user_id and payload["credentialId"]==owner.credential["credential_id"]
        and payload["rpId"]==owner.policy["rpId"] and payload["origin"] in owner.policy["origins"])
    owner.check()
    return {"publicKey":{"challenge":challenge["challenge"],"rpId":payload["rpId"],"allowCredentials":[{"type":"public-key","id":owner.credential["credential_id"]}],
        "timeout":30000,"userVerification":"required"},"serverware":{"schema":p.OPTIONS,"operation":operation,"operationId":payload["operationId"],
        "challengeId":challenge["id"],"credentialRecordId":owner.credential["id"],"payloadDigest":p.sha256(p.canonical(values))}}


def _call(owner,operation,values,assertion_value=None):
    evidence=None
    if operation in p.ASSERTION_OPERATIONS:evidence=owner.assertion({setup.MFA_FIELD:setup.profile.OPTIONS_SCHEMA,"assertion":assertion_value})
    policy.verify_original(operation,values,configuration_payload=owner.cold.payload,root_key=owner.cold.root,now_epoch_ns=owner.last_epoch)
    owner.check();p.require(not owner.dispatched);owner.dispatched=True
    result=setup.custody_client.ControlPlaneCustodyClient._request_authority(owner.custody,operation=operation,input_value={
        "schema":"serverware.policyAuthorityControlledWriterInput/v1","handler":authority_contract.operation_spec(operation)["handler"],
        "operationManifestDigest":authority_contract.OPERATION_MANIFEST_DIGEST,"arguments":{**values,**({"authn_evidence":evidence} if evidence is not None else {})}},deadline_ns=owner.deadline)
    p.require(type(result) is dict and set(result)=={"ok","operation","requestDigest","auditEventDigest","idempotentReplay","finalOriginal"}
        and result["ok"] is True and result["operation"]==operation and result["idempotentReplay"] is False
        and result["requestDigest"]==p.request_digest(operation,values))
    p.digest(result["auditEventDigest"]);row=_row(owner.session["id"])
    p.require(row is not None and p.row_original(row).decode("ascii")==result["finalOriginal"]
        and row[{p.PREPARE:"prepare_request_digest",p.COMPLETE:"complete_request_digest",p.SETTLE:"settle_request_digest"}[operation]]==result["requestDigest"])
    if operation==p.SETTLE:
        observed=setup._session(owner.session["id"]);expected={**owner.session,"revision":owner.session["revision"]+1,"phase":"native_scoped_complete","status":"complete",
            "updated_at":row["settled_at"],"terminal_at":row["settled_at"]}
        p.require(observed==expected);owner.session=observed;owner.session_original=p.enrollment.setup.row_original(observed)
    owner.check();return row


def _bundle(owner,row):
    if row is None:return None
    values={"actor_id":row["owner_id"],"control_plane_configuration_digest":row["configuration_digest"],"credential_policy":owner.policy,
        "maximum_final_nanos":owner.selected["maximumChallengeNanos"],"hardware_original":row["hardware_original"],"challenge_original":row["challenge_original"]}
    return {"challengeOriginal":row["challenge_original"],"issuerRequestOriginal":p.canonical(values).decode("ascii"),"receiptOriginal":row["receipt_original"]}


def _completion_audited(row):
    # Read-only operator observation. The kernel independently proves the same
    # current row before settlement; this boolean is never submitted as authority.
    if row is None or row["revision"]==0:return False
    with db.connect() as connection:
        value=connection.execute("SELECT status,event_type,event_digest,CASE WHEN octet_length(event_json)<=8192 THEN event_json ELSE NULL END AS event_json, "
            "audited_at,audit_event_hash,last_error,claim_id,claimed_at "
            "FROM metadata_audit_outbox WHERE id = ?",(row["complete_audit_id"],)).fetchone()
    if value is None or value["status"]!="audited":return False
    from serverware import authority_transition_core as core,authority_transition_quota as q
    p.require(row["complete_audit_id"]==q._audit_identity(p.COMPLETE,row["complete_request_digest"])
        and value["event_type"]==p.COMPLETE and value["audited_at"] is not None and value["audit_event_hash"] is not None
        and all(value[name] is None for name in ("last_error","claim_id","claimed_at")))
    event=p.original(value["event_json"],8192)
    p.require(event["sessionId"]==row["session_id"] and event["requestDigest"]==row["complete_request_digest"]
        and event["challengeSha256"]==row["challenge_sha256"]
        and value["event_digest"]==core.framed_digest("serverware.metadataAuditOutboxEvent/v1",value["event_json"].encode("ascii")))
    p.digest(value["audit_event_hash"])
    p.require(p.enrollment.setup.epoch(value["audited_at"])<=time.time_ns());return True


def on_request(request,raw):
    owner=None
    try:
        p.require(request.url.path in PATHS and type(raw) is bytes and 0<len(raw)<=MAX_HTTP and request.headers.get("content-length")==str(len(raw)))
        v=p.enrollment.setup.document(raw,MAX_HTTP,exact=False);phase=request.url.path.rsplit("/",1)[-1]
        selected=v.get("phase") if phase=="options" else phase
        p.require(selected in ("prepare","complete","settle","lookup") and (phase!="options" or selected in ("prepare","complete")))
        fields={"apiVersion","sessionId"}|({"phase"} if phase=="options" else set())|({"receiptOriginal"} if selected=="complete" else set())|({"assertion"} if phase in ("prepare","complete") else set())
        p.require(set(v)==fields and v["apiVersion"]==p.HTTP);p.enrollment.setup.identifier(v["sessionId"])
        owner=_Owner(request,v["sessionId"],selected);row=_row(v["sessionId"])
        if selected=="lookup":
            owner.check();p.require(_row(v["sessionId"])==row)
            response={**COMMON,"status":"observation","final":p.public(row),"bundle":_bundle(owner,row),
                "completionAuditIncluded":_completion_audited(row),
                "setupPhase":owner.session["phase"],"scopedNativeSetupComplete":row is not None and row["revision"]==2
                    and owner.session["phase"]=="native_scoped_complete" and owner.session["status"]=="complete"}
        else:
            operation={"prepare":p.PREPARE,"complete":p.COMPLETE,"settle":p.SETTLE}[selected]
            p.require(row is None if selected=="prepare" else row is not None and row["revision"]==(0 if selected=="complete" else 1))
            if row is not None:owner.clip(p.challenge(row["challenge_original"])["expiresAtEpochNs"])
            receipt=v.get("receiptOriginal") if selected=="complete" else row["receipt_original"] if row is not None else None
            values=owner.values(operation,row,receipt)
            if selected=="settle":p.require(_completion_audited(row),"completion audit is not included; no settlement dispatched")
            if phase=="options":
                policy.verify_original(operation,values,configuration_payload=owner.cold.payload,root_key=owner.cold.root,now_epoch_ns=owner.last_epoch)
                response={**COMMON,"status":"fresh-assertion-required","options":_options(owner,operation,values)}
            else:
                row=_call(owner,operation,values,v.get("assertion"))
                response={**COMMON,"status":{"prepare":"independent-final-authorization-required","complete":"native-completion-pending-audit","settle":"scoped-native-setup-complete"}[selected],
                    "final":p.public(row),"bundle":_bundle(owner,row),"setupPhase":owner.session["phase"],"scopedNativeSetupComplete":selected=="settle"}
                response["completionAuditIncluded"]=_completion_audited(row)
        owner.check();p.require(len(p.canonical(response))<=MAX_RESPONSE)
        return JSONResponse(response,status_code=201 if phase=="prepare" else 200,headers={"Cache-Control":"no-store","Pragma":"no-cache","X-Content-Type-Options":"nosniff"})
    except Exception:return error(unknown=owner is not None and owner.dispatched)
