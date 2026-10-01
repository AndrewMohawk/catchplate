"""Source-fixed adopted endpoint issuer dispatch, never an approval source.

The packaged caller retains the complete input and runtime before selecting a
private key. Every input version below is exact; old commissioning commands do
not acquire adopted authority. No services, resources or histories are created.
"""
from __future__ import annotations

from serverware import native_pilot_adopted_delivery as delivery
from serverware import native_pilot_adopted_service_authority as service
from serverware import native_pilot_closure_authority as closure
from serverware import native_pilot_encrypted_authority as encrypted
from serverware import native_pilot_key_authority as keys
from serverware import native_pilot_verifier_authority as verifier

p = keys.p
MAX_INPUT = 32 * 1024 * 1024
OPERATIONS = ("delivery", "role-keys", "admission", "closure", "encrypted-delivery", "request-commitment", "verifier", "grant", "launch")


def prepare_input(role, operation, raw, *, boot, now_boottime_ns, now_unix_ns):
    p.require(role in keys.profile.ADOPTED_ROLES and operation in OPERATIONS)
    clocks = dict(boot=boot, now_boottime_ns=now_boottime_ns, now_unix_ns=now_unix_ns)
    value = p.document(raw, MAX_INPUT)
    if operation == "delivery":
        p.require(value["apiVersion"] == delivery.API and value["role"] == role)
        result = delivery.prepare_input(raw, **clocks)
        expiry = result["core_observation"]["expiresAtUnixNanos"] if role == "retrieval" else None
        return {"deadline": p.ns(result["window"]["startupDeadlineBoottimeNs"]), "epochLimit": expiry}
    if operation in ("role-keys", "admission"):
        p.require(value["apiVersion"] == keys.profile.ADOPTED_API)
        result = keys.profile.prepare_input(operation, role, raw, **clocks)
        return {"deadline": p.ns(result["window"]["startupDeadlineBoottimeNs"]),
            "epochLimit": result["payload"]["expiresAtUnixNanos"]}
    if operation == "closure":
        p.require(value["apiVersion"] == "serverware.nativePilotClosureAuthorityInput/v3"
            and value["guestRole"] == role)
        return closure.prepare_input(raw, **clocks)
    if operation in ("encrypted-delivery", "request-commitment"):
        p.require(value["apiVersion"] == encrypted.ADOPTED_API)
        return encrypted.prepare_input("delivery" if operation == "encrypted-delivery" else operation, role, raw, **clocks)
    if operation == "verifier":
        p.require(value["apiVersion"] == verifier.ADOPTED_API)
        return verifier.prepare_input(role, raw, **clocks)
    if operation == "grant":
        p.require(role in ("publicationReconciliation", "retrieval", "persistence")
            and value["apiVersion"] == service.INPUT_API)
        return service.prepare_input("publication" if role == "publicationReconciliation" else role, raw, **clocks)
    from serverware import native_pilot_adopted_launch_profile as launch
    return launch.prepare_input(role, raw, **clocks)


def execute(role, operation, raw, *, signing_key=None):
    """Called only after the packaged caller's complete prepare_input check."""
    p.require(role in keys.profile.ADOPTED_ROLES and operation in OPERATIONS)
    if operation == "launch":
        p.require(signing_key is None)
        from serverware import native_pilot_adopted_launch_profile as launch
        return launch.assemble(role, input_original=raw)[0]
    p.require(signing_key is not None)
    if operation == "delivery":
        return delivery.sign(raw, signing_key)
    if operation in ("role-keys", "admission"):
        return keys.sign(operation, role, raw, signing_key)[0]
    if operation == "closure":
        return closure.sign(input_original=raw, signing_key=signing_key)[0]
    if operation in ("encrypted-delivery", "request-commitment"):
        return encrypted.sign("delivery" if operation == "encrypted-delivery" else operation, role, raw, signing_key)[0]
    if operation == "verifier":
        return verifier.sign(role, raw, signing_key)[0]
    p.require(operation == "grant" and role in ("publicationReconciliation", "retrieval", "persistence"))
    return service.sign("publication" if role == "publicationReconciliation" else role,
        input_original=raw, signing_key=signing_key)
