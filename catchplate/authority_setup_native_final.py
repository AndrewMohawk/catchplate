"""Closed scoped native Setup completion, distinct from measured-host Setup."""
from collections.abc import Mapping
from catchplate import authority_setup_native_hardware as hardware

canonical,require,digest,sha256,original=hardware.canonical,hardware.require,hardware.digest,hardware.sha256,hardware.original
enrollment=hardware.enrollment
PREPARE,COMPLETE,SETTLE=("setup.native-final."+phase for phase in ("prepare","complete","settle"))
OPERATIONS=frozenset({PREPARE,COMPLETE,SETTLE})
ASSERTION_OPERATIONS=frozenset({PREPARE,COMPLETE})
TABLE="setup_native_final_attempts"
HTTP,OPTIONS="catchplate.setupNativeFinalRequest/v1","catchplate.setupNativeFinalOptions/v1"
CHALLENGE="catchplate.setupNativeFinalChallenge/v1"
RECEIPT="catchplate.setupNativeFinalReceipt/v1"
DOMAIN=b"catchplate/setup-native-final-authority/v1\0"
SCOPE="enclave-hardware-and-proxy-only"
MAX_ARGUMENT_BYTES=MAX_ROW_BYTES=4*1024*1024
FIELDS=frozenset({"actor_id","control_plane_configuration_digest","credential_policy","maximum_final_nanos","hardware_original","challenge_original","receipt_original"})
STATIC_SETTLE_FIELDS=FIELDS|{"continuation_original"}
CHALLENGE_FIELDS=frozenset({"apiVersion","challengeId","sessionId","ownerId","hardwareSha256","policyHash","configurationSha256",
    "nonce","issuedAtEpochNs","expiresAtEpochNs","resultScope","hostAssociationTrust"})
RECEIPT_FIELDS=frozenset({"apiVersion","purpose","resultScope","hostAssociationTrust","challengeSha256","hardwareSha256","sessionId",
    "nonceSha256","policyHash","configurationSha256","authorityKeyId","authorityProvider","issuedAtEpochNs","expiresAtEpochNs",
    "measuredHost","proxyReady"})
ROW_FIELDS=frozenset({"session_id","revision","phase","owner_id","reviewer_id","reviewer_credential_id","review_trust_original","hardware_original","challenge_original","challenge_sha256",
    "receipt_original","prepare_request_digest","prepare_audit_id","complete_request_digest","complete_audit_id","settle_request_digest","configuration_digest","created_at","completed_at","settled_at"})


def source(text):
    row=original(text,hardware.MAX_ROW_BYTES)
    require(hardware.row_original(row).decode("ascii")==text and row["phase"]=="hardware_proxy_verified")
    values=original(row["inputs_original"],hardware.MAX_ARGUMENT_BYTES)
    values.update({name:row[name] for name in hardware.FIELDS-hardware.INPUT_FIELDS})
    return row,hardware.arguments(hardware.COMPLETE,values)


def challenge(text):
    c=original(text,8192); require(set(c)==CHALLENGE_FIELDS and c["apiVersion"]==CHALLENGE
        and c["resultScope"]==SCOPE and c["hostAssociationTrust"]=="trusted-host-local")
    for name in ("challengeId","sessionId"): enrollment.setup.identifier(c[name])
    enrollment.setup.text(c["ownerId"],1024); require(c["ownerId"].startswith("oidc:"))
    for name in ("hardwareSha256","policyHash","configurationSha256"): digest(c[name])
    require(len(enrollment.original(c["nonce"],32))==32)
    window(c); return c


def window(c):
    require(type(c["issuedAtEpochNs"]) is int and type(c["expiresAtEpochNs"]) is int
        and 0<c["issuedAtEpochNs"]<c["expiresAtEpochNs"]<=2**63-1
        and c["expiresAtEpochNs"]-c["issuedAtEpochNs"]<=300_000_000_000)


def receipt(text):
    r=original(text,16384); require(set(r)=={"payload","signature"})
    v=r["payload"]; require(type(v) is dict and set(v)==RECEIPT_FIELDS and v["apiVersion"]==RECEIPT
        and v["purpose"]=="native-setup-final-authorization" and v["resultScope"]==SCOPE
        and v["hostAssociationTrust"]=="trusted-host-local" and v["measuredHost"] is False and v["proxyReady"] is False)
    for name in ("challengeSha256","hardwareSha256","nonceSha256","policyHash","configurationSha256","authorityKeyId"): digest(v[name])
    enrollment.setup.identifier(v["sessionId"]); enrollment.setup.text(v["authorityProvider"],128); window(v)
    require(type(r["signature"]) is str and r["signature"].startswith("ed25519:") and len(enrollment.original(r["signature"][8:],64))==64)
    return r


def arguments(operation,value,*,typed=False):
    require(isinstance(value,Mapping))
    fields=STATIC_SETTLE_FIELDS if "continuation_original" in value else FIELDS
    require(operation in OPERATIONS and isinstance(value,Mapping) and fields<=set(value)<=fields|({"businessIntent","authn_evidence"} if typed else set())
        and (not typed or "businessIntent" in value))
    require(fields==FIELDS or operation==SETTLE)
    v={name:value[name] for name in fields}; enrollment.setup.text(v["actor_id"],1024); require(v["actor_id"].startswith("oidc:"))
    row,prior=source(v["hardware_original"]); digest(v["control_plane_configuration_digest"])
    require(type(v["maximum_final_nanos"]) is int and 1_000_000_000<=v["maximum_final_nanos"]<=300_000_000_000)
    require(v["credential_policy"]==prior["credential_policy"] and v["control_plane_configuration_digest"]==row["configuration_digest"])
    if fields==STATIC_SETTLE_FIELDS: static_continuation(v)
    if operation==PREPARE: require(v["challenge_original"] is None and v["receipt_original"] is None and v["actor_id"]==row["owner_id"])
    else:
        c=challenge(v["challenge_original"]); receipt(v["receipt_original"])
        require(c["hardwareSha256"]==sha256(v["hardware_original"].encode("ascii")) and c["sessionId"]==row["session_id"]
            and c["ownerId"]==row["owner_id"] and c["configurationSha256"]==row["configuration_digest"])
    require(len(canonical(v))<=MAX_ARGUMENT_BYTES)
    # Size admission precedes reservation: include the literal nested issuer
    # request plus bounded challenge/receipt and public response overhead.
    draft={**v,"challenge_original":""};draft.pop("receipt_original")
    require(len(canonical({"issuerRequestOriginal":canonical(draft).decode("ascii")}))+524288<=MAX_ARGUMENT_BYTES)
    return v


def static_continuation(values):
    """Literal branch selection, bound to the already retained native chain."""
    if "continuation_original" not in values: return None
    text=values["continuation_original"]
    retained=original(text,enrollment.candidate.MAX_ROW_BYTES)
    require(enrollment.candidate.row_original(retained).decode("ascii")==text)
    request=original(retained["request_original"],enrollment.candidate.MAX_ARGUMENT_BYTES)
    rotated=set(request["request"])==enrollment.candidate.ROTATED_STATIC_REQUEST_FIELDS
    require(rotated or set(request["request"])==enrollment.candidate.STATIC_REQUEST_FIELDS)
    old,prior=source(values["hardware_original"])
    enrolled=original(prior["enrollment_original"],enrollment.MAX_ROW_BYTES)
    intent=enrollment.intent(enrolled["intent_original"])
    require(retained["session_id"]==old["session_id"]==intent["sessionId"]
        and retained["owner_id"]==old["owner_id"]==intent["ownerId"]
        and retained["configuration_digest"]==values["control_plane_configuration_digest"]
        and sha256(text.encode("ascii"))==intent["continuationSha256"]
        and sha256(retained["setup_original"].encode("ascii"))==intent["setupSha256"]
        and retained["credential_id"]==intent["credentialId"]
        and retained["credential_version"]==intent["credentialVersion"])
    require((enrollment.rotated_continuation(intent)==retained and intent["continuationOriginal"]==text)
        if rotated else intent["apiVersion"]==enrollment.SCHEMA and intent["credentialVersion"]==1)
    return retained


def row_original(row):
    require(type(row) is dict and set(row)==ROW_FIELDS and type(row["revision"]) is int)
    old,_=source(row["hardware_original"]); c=challenge(row["challenge_original"])
    require(row["session_id"]==old["session_id"]==c["sessionId"] and row["owner_id"]==old["owner_id"]==c["ownerId"]
        and row["configuration_digest"]==old["configuration_digest"]==c["configurationSha256"]
        and c["hardwareSha256"]==sha256(row["hardware_original"].encode("ascii"))
        and row["challenge_sha256"]==sha256(row["challenge_original"].encode("ascii")))
    digest(row["prepare_request_digest"]); enrollment.setup.epoch(row["created_at"])
    enrollment.setup.identifier(row["prepare_audit_id"])
    require(row["revision"] in (0,1,2) and row["phase"]==("final_outcome_unknown","native_completion_pending_audit","native_scoped_complete")[row["revision"]])
    completed=("reviewer_id","reviewer_credential_id","review_trust_original","receipt_original","complete_request_digest","complete_audit_id","completed_at")
    if row["revision"]==0: require(all(row[name] is None for name in completed))
    else:
        require(row["reviewer_id"]!=row["owner_id"]); enrollment.setup.text(row["reviewer_id"],1024)
        enrollment.setup.identifier(row["reviewer_credential_id"]); enrollment.setup.identifier(row["complete_audit_id"])
        trust=original(row["review_trust_original"],4096)
        require(set(trust)=={"trustHighWaterDigest","metadataPublicationSequence","credentialPolicyDigest"})
        digest(trust["trustHighWaterDigest"]);digest(trust["credentialPolicyDigest"])
        require(type(trust["metadataPublicationSequence"]) is int and 0<trust["metadataPublicationSequence"]<=2**63-1)
        receipt(row["receipt_original"]); digest(row["complete_request_digest"]); enrollment.setup.epoch(row["completed_at"])
    if row["revision"]<2: require(row["settle_request_digest"] is None and row["settled_at"] is None)
    else: digest(row["settle_request_digest"]); enrollment.setup.epoch(row["settled_at"])
    raw=canonical(row); require(len(raw)<=MAX_ROW_BYTES); return raw


def public(row):
    if row is None:return None
    row_original(row)
    return {name:row[name] for name in ("revision","phase","owner_id","reviewer_id","challenge_sha256","prepare_request_digest","complete_request_digest","settle_request_digest")}


def request_digest(operation,value):
    from catchplate import authority_contract as c,authority_request_commitment as r
    v=arguments(operation,value,typed="businessIntent" in value)
    typed={**v,"businessIntent":c.synthesize_business_intent(operation,v)}
    return r.framed_digest("catchplate.policyAuthorityV9Request/v1",canonical({"schema":"catchplate.policyAuthorityV9Authorization/v1",
        "operation":operation,"handler":c.operation_spec(operation)["handler"],"operationManifestDigest":c.OPERATION_MANIFEST_DIGEST,
        "arguments":r._authorization_arguments(typed)}))
