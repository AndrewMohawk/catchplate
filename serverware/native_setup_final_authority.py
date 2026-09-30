"""One fixed independently pinned final authorization, never caller-signed bytes."""
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from serverware import authority_setup_native_final as p
from serverware import authority_setup_native_final_policy as policy
from serverware import authority_contract as contract,authority_request_commitment as commitment
from serverware import native_setup_independent_originals as originals


def _produce(owner):
    p.require(type(owner) is originals.Originals and owner.role=="final-authority")
    now=owner.check(); c=owner.configuration; root=p.hardware.ca._public(c["authorityRootPublicKeyPem"])
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
        and policy.hardware.runtime_policy.configuration.full_configuration_digest(payload)==c["controlPlaneConfigurationDigest"]
        ==owner.values["control_plane_configuration_digest"])
    root.verify(p.enrollment.original(envelope["signature"],64),commitment.framed_digest(schema,p.canonical(payload)).encode("ascii"))
    p.require(policy.validate_policy(payload.get(policy.FIELD),payload=payload,root_key=root) is not None
        and all(p.OPERATIONS<=set(payload["roles"][role].get("enabledOperations",())) for role in ("verifier","planner")))
    original,_=p.source(owner.values["hardware_original"])
    p.require(owner.values["actor_id"]==original["owner_id"])
    result=policy.computed_receipt(owner.values,payload,root,now)
    owner.result_expires=result["expiresAtEpochNs"]
    selected=payload[policy.hardware.FIELD]["finalAuthority"]
    seed=owner._take_seed()
    try:
        key=Ed25519PrivateKey.from_private_bytes(seed)
        p.require(key.public_key().public_bytes(serialization.Encoding.Raw,serialization.PublicFormat.Raw)
            ==policy.hardware.authority(selected).public_bytes(serialization.Encoding.Raw,serialization.PublicFormat.Raw))
        p.require(now<=owner.check()<result["expiresAtEpochNs"])
        signature=key.sign(p.DOMAIN+p.canonical(result))
        raw=p.canonical({"payload":result,"signature":"ed25519:"+p.enrollment.encoded(signature)})
        p.receipt(raw.decode("ascii"));p.require(now<=owner.check()<result["expiresAtEpochNs"])
        return raw
    finally:seed[:]=bytes(len(seed))


def run():
    with originals.final_originals() as owner:owner._publish(_produce(owner))
