"""One controlled reservation, one fixed native contact, independent completion."""
import urllib.error
import urllib.request
from fastapi.responses import JSONResponse
from catchplate import authority_setup_native_hardware as p
from catchplate import authority_setup_native_hardware_policy as policy
from catchplate import control_plane_setup_native_runtime as prior
from catchplate import control_plane_setup_native_ca as installed
from catchplate import control_plane_policy_canary_startup as cold
from catchplate import authority_contract, db, http_client, webauthn

PREFIX="/api/setup/native-hardware"
PATHS=frozenset(PREFIX+"/"+phase for phase in ("options","prepare","complete","lookup"))
NATIVE_PATH="/v1/native-setup-hardware"
MAX_HTTP,MAX_RESPONSE=131072,4*1024*1024
COMMON={"apiVersion":"catchplate.setupNativeHardwareResponse/v1","okForAction":False,"automaticRetryAllowed":False,
    "measuredHost":False,"enrollmentComplete":False,"proxyReady":False,"hostAssociationTrust":"trusted-host-local"}


def error(status=409,*,unknown=False):
    return JSONResponse({**COMMON,"status":"hardware-outcome-unknown" if unknown else "refused"},
        status_code=status if status in (400,401,403,409,412,413,415,428,503) else 503,
        headers={"Cache-Control":"no-store","Pragma":"no-cache","X-Content-Type-Options":"nosniff"})


def _row(sid):
    with db.connect() as connection:
        p.require(isinstance(connection,db.PostgresMetadataConnection))
        row=connection.execute("WITH chosen AS (SELECT row_to_json(source)::text AS original FROM setup_native_hardware_attempts AS source WHERE session_id = ?) "
            "SELECT CASE WHEN octet_length(original) <= ? THEN original ELSE NULL END AS original FROM chosen",(sid,p.MAX_ROW_BYTES)).fetchone()
    if row is None: return None
    p.require(type(row["original"]) is str)
    value=p.enrollment.setup.document(row["original"].encode("utf-8"),p.MAX_ROW_BYTES,exact=False); p.row_original(value); return value


def _bundle(row,evidence=None):
    if row is None: return None
    actual=evidence if evidence is not None else row["evidence_original"]
    request=None if actual is None else p.canonical({**p.original(row["inputs_original"],p.MAX_ARGUMENT_BYTES),
        "attempt_original":row["attempt_original"],"evidence_original":actual}).decode("ascii")
    return {"inputsOriginal":row["inputs_original"],"attemptOriginal":row["attempt_original"],"evidenceOriginal":actual,"verifierRequestOriginal":request}


class _Owner(prior._Owner):
    def __init__(self,request):
        self.hardware_cold=None; self.native_contact=False; self.held_inputs=None
        super().__init__(request)

    def bind(self,sid):
        super().bind(sid)
        self.hardware_cold,self.hardware_policy,now=cold.native_setup_hardware_owner()
        p.require(self.hardware_cold is self.runtime_cold and self.hardware_policy["credentialPolicy"]==self.policy)
        enrolled=installed.issued._enrollment(sid); ca=installed._row(sid); runtime=prior._row(sid)
        p.require(enrolled is not None and ca is not None and runtime is not None)
        self.held_inputs=p.inputs({"actor_id":self.identity.user_id,"control_plane_configuration_digest":self.configuration,
            "credential_policy":self.policy,"maximum_attempt_nanos":self.hardware_policy["maximumAttemptNanos"],
            "association_original":self.association_original,"scope_original":p.canonical(self.runtime_scope).decode("ascii"),
            "enrollment_original":p.enrollment.row_original(enrolled).decode("ascii"),"installation_original":p.ca.row_original(ca).decode("ascii"),
            "runtime_original":p.runtime.row_original(runtime).decode("ascii")})
        self.clip(min(p.runtime.prepared(runtime["attempt_original"])["expiresAtEpochNs"],p.enrollment.intent(enrolled["intent_original"])["expiresAtEpochNs"]))
        policy.verify_inputs(self.held_inputs,self.hardware_cold.payload,self.hardware_cold.root,now); self.check()

    def check(self):
        super().check()
        if self.hardware_cold is not None:
            owner,selected,_=cold.native_setup_hardware_owner(); p.require(owner is self.hardware_cold and selected==self.hardware_policy)
        if self.held_inputs is not None:
            sid=self.session["id"]
            p.require(p.enrollment.row_original(installed.issued._enrollment(sid)).decode("ascii")==self.held_inputs["enrollment_original"]
                and p.ca.row_original(installed._row(sid)).decode("ascii")==self.held_inputs["installation_original"]
                and p.runtime.row_original(prior._row(sid)).decode("ascii")==self.held_inputs["runtime_original"])
        super().check()

    def values(self,operation,row=None,submitted=None):
        value={**self.held_inputs,**{name:None for name in p.FIELDS-p.INPUT_FIELDS}}
        if row is not None:
            p.require(row["inputs_original"]==p.canonical(self.held_inputs).decode("ascii"))
            value.update(attempt_original=row["attempt_original"],evidence_original=submitted["evidenceOriginal"],
                hardware_receipt_original=submitted["hardwareReceiptOriginal"],proxy_receipt_original=submitted["proxyReceiptOriginal"])
        return p.arguments(operation,value)


def _options(owner,values):
    descriptors=webauthn._credential_descriptors_for_policy(owner.identity.user_id,prior.prior.setup.activation._authenticator_policy(owner.policy))
    p.require(type(descriptors) is list and 1<=len(descriptors)<=64)
    owner.credential=db.get_webauthn_credential(descriptors[0]["id"])
    p.require(type(owner.credential) is dict and owner.credential["user_id"]==owner.identity.user_id); owner.check()
    challenge=db.issue_policy_authority_webauthn_challenge(operation=p.PREPARE,input_value=values,user_id=owner.identity.user_id,
        credential_id=owner.credential["credential_id"],deadline_ns=owner.deadline)
    payload=challenge["payload"]
    p.require(challenge["used_at"] is None and challenge["challenge_type"]=="policy_authority" and challenge["user_id"]==owner.identity.user_id
        and payload["credentialId"]==owner.credential["credential_id"] and payload["rpId"]==owner.policy["rpId"] and payload["origin"] in owner.policy["origins"])
    owner.check()
    return {"publicKey":{"challenge":challenge["challenge"],"rpId":payload["rpId"],"allowCredentials":[{"type":"public-key","id":owner.credential["credential_id"]}],
        "timeout":30000,"userVerification":"required"},"catchplate":{"schema":p.OPTIONS,"operation":p.PREPARE,"operationId":payload["operationId"],
        "challengeId":challenge["id"],"credentialRecordId":owner.credential["id"],"payloadDigest":p.sha256(p.canonical(values))}}


def _call(owner,operation,values,assertion):
    evidence=None
    if operation==p.PREPARE:
        evidence=owner.assertion({prior.prior.setup.MFA_FIELD:prior.prior.setup.profile.OPTIONS_SCHEMA,"assertion":assertion})
    owner.check(); p.require(not owner.dispatched); owner.dispatched=True
    result=prior.prior.setup.custody_client.ControlPlaneCustodyClient._request_authority(owner.custody,operation=operation,
        input_value={"schema":"catchplate.policyAuthorityControlledWriterInput/v1","handler":authority_contract.operation_spec(operation)["handler"],
            "operationManifestDigest":authority_contract.OPERATION_MANIFEST_DIGEST,"arguments":{**values,**({"authn_evidence":evidence} if evidence is not None else {})}},deadline_ns=owner.deadline)
    owner.check()
    p.require(type(result) is dict and set(result)=={"ok","operation","requestDigest","auditEventDigest","idempotentReplay","hardwareOriginal"}
        and result["ok"] is True and result["operation"]==operation and result["idempotentReplay"] is False
        and result["requestDigest"]==p.request_digest(operation,values))
    p.digest(result["auditEventDigest"]); row=_row(owner.session["id"])
    p.require(row is not None and p.row_original(row).decode("ascii")==result["hardwareOriginal"]
        and row["prepare_request_digest" if operation==p.PREPARE else "complete_request_digest"]==result["requestDigest"])
    owner.check(); return row


def _native(owner,row):
    from catchplate import app
    owner.check(); p.require(owner.dispatched and not owner.native_contact and row["phase"]=="hardware_outcome_unknown")
    original=row["attempt_original"].encode("ascii"); p.require(len(original)<=8192)
    url,token=app._policy_shadow_generation_url(NATIVE_PATH),app.DATA_PLANE_MANAGEMENT_TOKEN
    p.require(type(token) is str and 0<len(token.encode("utf-8"))<=4096)
    request=urllib.request.Request(url,data=original,method="POST",headers={"Accept":"application/json","Accept-Encoding":"identity",
        "Content-Type":"application/json","X-Catchplate-Data-Plane-Token":token})
    owner.native_contact=True  # Persistent reservation already committed. Never retry this contact.
    try:
        response=http_client.request_bytes(request,timeout=30,max_bytes=65536,deadline=http_client.HttpDeadline(owner.deadline/1_000_000_000),
            require_https=False,expected_statuses=(200,),expected_content_types=("application/json",))
    except urllib.error.HTTPError as error:
        error.close(); raise ValueError("native hardware contact unknown") from None
    owner.check(); p.require(app._policy_shadow_generation_url(NATIVE_PATH)==url and app.DATA_PLANE_MANAGEMENT_TOKEN==token)
    text=response.body.decode("ascii"); p.evidence(text)
    policy.verify_quote({**owner.held_inputs,"attempt_original":row["attempt_original"],"evidence_original":text},
        owner.hardware_cold.payload,owner.hardware_cold.root,owner.last_epoch)
    owner.check(); p.require(_row(owner.session["id"])==row); return text


def on_request(request,raw):
    owner=None
    try:
        p.require(request.url.path in PATHS and type(raw) is bytes and 0<len(raw)<=MAX_HTTP and request.headers.get("content-length")==str(len(raw)))
        value=p.enrollment.setup.document(raw,MAX_HTTP,exact=False); phase=request.url.path.rsplit("/",1)[-1]
        fields={"apiVersion","sessionId"}|({"assertion"} if phase=="prepare" else
            {"evidenceOriginal","hardwareReceiptOriginal","proxyReceiptOriginal"} if phase=="complete" else set())
        p.require(set(value)==fields and value["apiVersion"]==p.HTTP); p.enrollment.setup.identifier(value["sessionId"])
        owner=_Owner(request)
        if phase=="lookup":
            owner.session=prior.prior.setup._session(value["sessionId"]); owner.session_original=p.enrollment.setup.row_original(owner.session)
            p.require(owner.session["owner_id"]==owner.identity.user_id)
            row=_row(owner.session["id"]); p.require(row is None or row["owner_id"]==owner.identity.user_id)
            owner.check(); p.require(_row(owner.session["id"])==row)
            response={**COMMON,"status":"observation","hardware":p.public(row),"bundle":_bundle(row),"resultOriginal":None if row is None else row["result_original"]}
        else:
            owner.bind(value["sessionId"]); row=_row(owner.session["id"])
            if phase in {"options","prepare"}:
                p.require(row is None,"original attempt already exists; no recontact")
                values=owner.values(p.PREPARE)
                if phase=="options": response={**COMMON,"status":"fresh-assertion-required","options":_options(owner,values)}
                else:
                    row=_call(owner,p.PREPARE,values,value["assertion"])
                    evidence=_native(owner,row)
                    response={**COMMON,"status":"independent-verification-required","hardware":p.public(row),"bundle":_bundle(row,evidence)}
            else:
                p.require(row is not None and row["phase"]=="hardware_outcome_unknown"); owner.clip(p.prepared(row["attempt_original"])["expiresAtEpochNs"])
                row=_call(owner,p.COMPLETE,owner.values(p.COMPLETE,row,value),None)
                response={**COMMON,"status":"hardware-proxy-verified","hardware":p.public(row),"resultOriginal":row["result_original"]}
        owner.check(); p.require(len(p.canonical(response))<=MAX_RESPONSE)
        return JSONResponse(response,status_code=201 if phase=="prepare" else 200,
            headers={"Cache-Control":"no-store","Pragma":"no-cache","X-Content-Type-Options":"nosniff"})
    except Exception:
        return error(unknown=owner is not None and owner.dispatched)
