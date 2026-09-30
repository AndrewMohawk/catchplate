"""Real independent receipt producer: computed originals only, no sign-success API."""
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from serverware import authority_setup_native_hardware as p
from serverware import authority_setup_native_hardware_policy as policy
from serverware import authority_request_commitment as commitment, authority_contract as contract
from serverware import native_setup_independent_originals as originals


def _produce(owner):
    p.require(type(owner) is originals.Originals)
    now=owner.check(); c=owner.configuration
    root=p.ca._public(c["authorityRootPublicKeyPem"])
    raw=c["authorityConfigurationOriginal"].encode("ascii")
    p.require(p.sha256(raw)==c["authorityConfigurationSha256"])
    envelope=p.original(c["authorityConfigurationOriginal"],4*1024*1024)
    schema="serverware.signedPolicyAuthorityServiceConfiguration/v6"
    p.require(set(envelope)=={"schema","payload","signature"} and envelope["schema"]==schema)
    payload=envelope["payload"]
    p.require(type(payload) is dict and payload.get("schema")=="serverware.policyAuthorityServiceConfiguration/v6"
        and payload.get("sourceRevision")==contract.SOURCE_REVISION
        and type(payload.get("runtimeUid")) is int and type(payload.get("runtimeGid")) is int
        and owner.uid!=payload["runtimeUid"] and owner.gid!=payload["runtimeGid"]
        and policy.runtime_policy.configuration.full_configuration_digest(payload)==c["controlPlaneConfigurationDigest"]
        ==owner.values["control_plane_configuration_digest"])
    root.verify(p.enrollment.original(envelope["signature"],64),commitment.framed_digest(schema,p.canonical(payload)).encode("ascii"))
    selected=policy.validate_policy(payload.get(policy.FIELD),payload=payload,root_key=root)
    p.require(selected is not None and all(p.OPERATIONS<=set(payload["roles"][role].get("enabledOperations",())) for role in ("verifier","planner")))
    result=policy.computed_receipt(owner.values,payload,root,now,owner.role)
    owner.result_expires=result["expiresAtEpochNs"]
    signer=selected["hardwareVerifier" if owner.role==p.ROLES[0] else "proxyVerifier"]
    seed=owner._take_seed()
    try:
        key=Ed25519PrivateKey.from_private_bytes(seed)
        p.require(key.public_key().public_bytes(serialization.Encoding.Raw,serialization.PublicFormat.Raw)
            ==policy.authority(signer).public_bytes(serialization.Encoding.Raw,serialization.PublicFormat.Raw))
        p.require(now<=owner.check()<result["expiresAtEpochNs"])
        signature=key.sign(p.RECEIPT_DOMAIN+owner.role.encode("ascii")+b"\0"+p.canonical(result))
        value={"payload":result,"signature":"ed25519:"+p.enrollment.encoded(signature)}
        raw=p.canonical(value); p.receipt(raw.decode("ascii"),owner.role)
        p.require(len(raw)<=16384 and now<=owner.check()<result["expiresAtEpochNs"])
        return raw
    finally: seed[:]=bytes(len(seed))


def hardware():
    with originals.hardware_originals() as owner: owner._publish(_produce(owner))


def proxy():
    with originals.proxy_originals() as owner: owner._publish(_produce(owner))
