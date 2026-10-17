"""Bounded unsigned release expectations, never a proof or release grant.

Only encrypted delivery bytes, original dates and digest hints cross this seam.
The private committed/proof verifier must independently authenticate every
binding. A forged hint can fail that verification, never authorize opening.
"""
from __future__ import annotations

from catchplate import authority_oidc_session_activation_delivery_recovery_packet as packets
from catchplate import authority_transition_oidc_session_activation_delivery as consume


registration, delivery = consume.registration, consume.delivery
authorization, capture = packets.authorization, packets.vector.capture
SCHEMA = "catchplate.oidcSessionActivationReleaseHints/v1"
MAX_DESCRIPTOR_BYTES = 1024
LIMITS = (71, MAX_DESCRIPTOR_BYTES)
MAX_NODES, MAX_DEPTH = 16, 2
_FIELDS = frozenset({"schema", "effectsDigest", "deliveryEnvelopeBase64Url", "createdAt", "expiresAt"})


class ReleaseHintsError(ValueError):
    pass


def _decode_on_work(originals, *, work):
    """Return ordinary expected data; no signature, replay or currentness."""
    ledger = capture._SharedLedger(work)
    if (type(originals) is not tuple or len(originals) != 2
            or any(type(raw) is not bytes or not 2 <= len(raw) <= maximum
                for raw, maximum in zip(originals, LIMITS))):
        raise ReleaseHintsError("release hints require their exact bounded raw2")
    packet_raw, descriptor_raw = originals
    work.charge(input_bytes=sum(map(len, originals)))
    try:
        packet_digest = packet_raw.decode("ascii")
    except UnicodeError as exc:
        raise ReleaseHintsError("release packet hint is not ASCII") from exc
    registration._digest(packet_digest)
    value = authorization.wire._decode_object(descriptor_raw, work=work,
        maximum_bytes=MAX_DESCRIPTOR_BYTES, maximum_nodes=MAX_NODES, maximum_depth=MAX_DEPTH)
    registration._closed(value, _FIELDS, "release hint descriptor")
    authorization.shape._literal(value["schema"], SCHEMA)
    registration._digest(value["effectsDigest"])
    envelope = registration._encoded_original(value["deliveryEnvelopeBase64Url"],
        delivery.ENVELOPE_BYTES, work, minimum=delivery.ENVELOPE_BYTES)
    delivery._envelope(envelope, work)
    times = []
    for field in ("createdAt", "expiresAt"):
        registration._text(value[field], "release hint " + field, 64, work)
        parsed = registration._utc(value[field], "release hint " + field, work)
        if parsed.isoformat() != value[field]:
            raise ReleaseHintsError("release hint time is not the original canonical UTC form")
        times.append(registration._now(parsed))
    if not 0 < times[1] - times[0] <= delivery.MAX_DELIVERY_LIFETIME_NS:
        raise ReleaseHintsError("release hint delivery interval exceeds its source bound")
    authorization.capability._canonical(descriptor_raw, value, ledger,
        MAX_DESCRIPTOR_BYTES, MAX_NODES)
    return packet_digest, value["effectsDigest"], envelope, value["createdAt"], value["expiresAt"]


def _from_packet_on_work(*, packet_payload, packet_digest, work):
    """Project hints from owned packet data, without a second private replay."""
    registration._digest(packet_digest)
    registration._closed(packet_payload, packets.producer.packet.PACKET_FIELDS, "release hint packet")
    authorization.shape._literal(packet_payload["operation"], consume.OPERATION)
    rows = packet_payload["selectedRows"]
    if type(rows) is not list or len(rows) != consume.MAX_SELECTED_ROWS:
        raise ReleaseHintsError("release hint packet has a different selected inventory")
    selected = []
    work.prepare_scan(rows)
    for item in rows:
        registration._closed(item, consume.capacity._SELECTED_FIELDS, "release hint selected row")
        if item["table"] == "oidc_session_activation_deliveries":
            if item["present"] is not True:
                raise ReleaseHintsError("release hint delivery row is absent")
            selected.append(item)
    if len(selected) != 1:
        raise ReleaseHintsError("release hint packet does not select exactly one delivery")
    row = selected[0]["row"]
    registration._closed(row, consume._DELIVERY_FIELDS, "release hint delivery row")
    registration._same(selected[0]["key"], {"id": row["id"]}, work, "release hint selected delivery key")
    consume._ciphertext_on_work(row, work)
    # Detach the small descriptor before effect hashing; neither the ciphertext
    # nor these timestamps is promoted into authenticated public state.
    descriptor = capture._JSONCapture(capture._SharedLedger(work),
        maximum_bytes=MAX_DESCRIPTOR_BYTES).visit({"schema": SCHEMA,
            "effectsDigest": "sha256:" + "0" * 64,
            "deliveryEnvelopeBase64Url": row["encrypted_active_token"][len(delivery.STORED_PREFIX):],
            "createdAt": row["created_at"], "expiresAt": row["expires_at"]})
    descriptor["effectsDigest"] = packets.neutral._effects_digest_on_work(
        selected_rows=rows, mutations=packet_payload["mutations"], result=packet_payload["result"],
        work_units=packet_payload["workUnits"], work=work)
    raw = authorization.capability._wire(descriptor, capture._SharedLedger(work),
        MAX_DESCRIPTOR_BYTES, MAX_NODES)
    work.prepare_utf8(packet_digest)
    originals = (packet_digest.encode("ascii"), raw)
    _decode_on_work(originals, work=work)
    return originals
