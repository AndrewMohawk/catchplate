"""Independent final authority verifies the original chain, never a success DTO."""
from catchplate import authority_setup_native_final as p
from catchplate import authority_setup_native_hardware_policy as hardware

FIELD,SCHEMA="setupNativeFinalPolicy","catchplate.setupNativeFinalAuthorityPolicy/v1"


def validate_policy(value,*,payload,root_key=None):
    enabled=any(set(role.get("enabledOperations",()))&p.OPERATIONS for role in payload["roles"].values())
    if value is None: p.require(not enabled); return None
    hp=hardware.validate_policy(payload.get(hardware.FIELD),payload=payload,root_key=root_key)
    p.require(hp is not None and type(value) is dict and set(value)=={"schema","credentialPolicy","maximumChallengeNanos"}
        and value["schema"]==SCHEMA and value["credentialPolicy"]==hp["credentialPolicy"]
        and type(value["maximumChallengeNanos"]) is int and 1_000_000_000<=value["maximumChallengeNanos"]<=hp["maximumAttemptNanos"])
    return value


def verify_source(values,payload,root_key,now):
    selected=validate_policy(payload.get(FIELD),payload=payload,root_key=root_key)
    row,source=p.source(values["hardware_original"])
    p.require(selected is not None and values["credential_policy"]==selected["credentialPolicy"]
        and values["maximum_final_nanos"]==selected["maximumChallengeNanos"]
        and values["control_plane_configuration_digest"]==row["configuration_digest"])
    if p.static_continuation(values) is not None:
        static_event_limit(values,payload,root_key)
    attempt=hardware.verify_original(p.hardware.COMPLETE,source,configuration_payload=payload,root_key=root_key,now_epoch_ns=now)
    return selected,row,source,attempt


def static_event_limit(values,payload,root_key):
    from catchplate import authority_setup_bind_credential as binding
    from catchplate.authority_policy_canary_policy import full_configuration_digest
    p.require(p.static_continuation(values) is not None)
    selected=binding.validate_policy(payload.get(binding.FIELD),payload=payload,root_key=root_key)
    p.require(selected is not None and selected["credentialPolicy"]==values["credential_policy"]
        and values["control_plane_configuration_digest"]==full_configuration_digest(payload),
        "Static native final settlement lacks its independently selected event capacity")
    return selected["maximumEvents"]


def computed_receipt(values,payload,root_key,now):
    selected,row,source,attempt=verify_source(values,payload,root_key,now)
    c=p.challenge(values["challenge_original"])
    issued_after=max(p.hardware.receipt(row[field],role)["payload"]["issuedAtEpochNs"]
        for field,role in (("hardware_receipt_original",p.hardware.ROLES[0]),("proxy_receipt_original",p.hardware.ROLES[1])))
    expires=min(attempt["expiresAtEpochNs"],*(p.hardware.receipt(row[field],role)["payload"]["expiresAtEpochNs"]
        for field,role in (("hardware_receipt_original",p.hardware.ROLES[0]),("proxy_receipt_original",p.hardware.ROLES[1]))))
    p.require(c["hardwareSha256"]==p.sha256(values["hardware_original"].encode("ascii")) and c["sessionId"]==row["session_id"]
        and c["ownerId"]==row["owner_id"] and c["configurationSha256"]==row["configuration_digest"]
        and c["policyHash"]==attempt["policyHash"] and max(attempt["issuedAtEpochNs"],issued_after)<=c["issuedAtEpochNs"]<=now<c["expiresAtEpochNs"]<=expires
        and c["expiresAtEpochNs"]-c["issuedAtEpochNs"]<=selected["maximumChallengeNanos"])
    signer=payload[hardware.FIELD]["finalAuthority"]
    return {"apiVersion":p.RECEIPT,"purpose":"native-setup-final-authorization","resultScope":p.SCOPE,"hostAssociationTrust":"trusted-host-local",
        "challengeSha256":p.sha256(values["challenge_original"].encode("ascii")),"hardwareSha256":c["hardwareSha256"],"sessionId":c["sessionId"],
        "nonceSha256":p.sha256(p.enrollment.original(c["nonce"],32)),"policyHash":c["policyHash"],"configurationSha256":c["configurationSha256"],
        "authorityKeyId":p.hardware.ca.key_id(hardware.authority(signer)),"authorityProvider":signer["provider"],
        "issuedAtEpochNs":now,"expiresAtEpochNs":c["expiresAtEpochNs"],"measuredHost":False,"proxyReady":False}


def verify_original(operation,arguments,*,configuration_payload,root_key,now_epoch_ns):
    v=p.arguments(operation,arguments,typed="businessIntent" in arguments)
    if operation==p.PREPARE:return verify_source(v,configuration_payload,root_key,now_epoch_ns)
    expected=computed_receipt(v,configuration_payload,root_key,now_epoch_ns)
    receipt=p.receipt(v["receipt_original"]); actual=receipt["payload"]
    p.require(p.challenge(v["challenge_original"])["issuedAtEpochNs"]<=actual["issuedAtEpochNs"]<=now_epoch_ns<actual["expiresAtEpochNs"])
    expected["issuedAtEpochNs"]=actual["issuedAtEpochNs"]; p.require(p.canonical(expected)==p.canonical(actual))
    hardware.authority(configuration_payload[hardware.FIELD]["finalAuthority"]).verify(
        p.enrollment.original(receipt["signature"][8:],64),p.DOMAIN+p.canonical(actual))
    return actual
