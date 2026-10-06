"""Three purpose-fixed operations using independently supplied existing keys.

No key loading/generation, owner reconstruction, installation, clock renewal or
runtime claim occurs here. C9/installation are original-sample anchored, not
currentness evidence. Service authorization uses genuine signer epoch time.
"""
import time

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from serverware import native_activation_receiver_profile as profile
from serverware import native_activation_receiver_installation as installation

p = profile.p
MAX_INPUT = profile.MAX_INPUT
OPERATIONS = ("delivery", "service", "installation")


def prepare_input(operation, raw, *, now_unix_ns=None):
    """Public preflight only; it neither approves input nor admits native state."""
    p.require(operation in OPERATIONS)
    if operation == "delivery":
        return profile.prepare_delivery(raw)
    now = time.time_ns() if now_unix_ns is None else now_unix_ns
    p.integer(now)
    if operation == "service":
        return profile.prepare_service(raw, now_unix_ns=now)
    return installation.prepare(raw, now_unix_ns=now)


def sign(operation, raw, signing_key, *, check=None):
    """Return one complete existing signed original (installation: completion/v2).

    The caller must independently approve/pin all input bytes and fence an
    uncertain invocation; this function has no retry, durable ownership or
    private-key acquisition interface. A delayed C9 is not silently renewed.
    """
    p.require(operation in OPERATIONS and isinstance(signing_key, Ed25519PrivateKey)
        and (check is None or callable(check)))
    first_epoch = time.time_ns()
    context = prepare_input(operation, raw, now_unix_ns=first_epoch)
    expected = context["signer"].public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    actual = signing_key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    p.require(actual == expected)

    def live():
        if check is not None:
            check()
        if operation != "delivery":
            now = time.time_ns()
            p.require(now >= first_epoch)
            profile.service_live(context if operation == "service" else context["service"], now)

    live()
    if operation == "delivery":
        result = profile.delivery.sign_activation_delivery_sample_anchored(
            **context["arguments"], signing_key=signing_key)
        live(); profile.verify_delivery(context, result)
    else:
        domain = profile.SERVICE_DOMAIN if operation == "service" else installation.DOMAIN
        message = p.preimage(domain, context["payload"])
        live()  # Validation must not consume the original epoch interval unnoticed.
        signature = signing_key.sign(message)
        live(); context["signer"].verify(signature, message)
        if operation == "service":
            result = p.canonical({"payload": context["payload"], "signature": p.encoded(signature)})
            p.require(len(result) <= profile.delivery.MAX_DELIVERY)
            profile.verify_service(context, result)
        else:
            result = installation.completion(context["payload"], p.encoded(signature))
    live()
    return result
