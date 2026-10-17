"""Expired planning v7 originals, never fresh process or execution authority.

The caller supplies independently authenticated R1 and the exact original policy
interval. Fresh completion authority is separate; original times are evidence,
not a replacement clock or permission to reopen an old planning service.
"""
from __future__ import annotations

from cryptography.exceptions import InvalidSignature

from catchplate import oidc_session_activation_history_custody_bootstrap as history


def _verify_on_work(*, custody_bytes, root_public_key, expected_policy_interval,
        work, live_window, transport_deadline_ns, _continuity=None):
    try:
        if (type(expected_policy_interval) is not tuple or len(expected_policy_interval) != 2
                or any(type(value) is not int or value <= 0 for value in expected_policy_interval)
                or expected_policy_interval[0] >= expected_policy_interval[1]):
            history._fail("historical bridge requires an independently pinned original policy interval")
        original = history.authorization._original(custody_bytes, history.MAX_BYTES,
            "historical bridged planning custody")
        root = root_public_key
        history.authorization._public(root)
        window = history.clock._validate(live_window)
        history.shape._integer(transport_deadline_ns, minimum=1)
        bound = min(window[4], transport_deadline_ns)
        current = history.planner_bootstrap._processing(window, bound, work, _continuity=_continuity)
        current()
        envelope = history._decode(original, work)
        history.shape._object(envelope, history._ENVELOPE_FIELDS, "historical bridged planning custody")
        history.shape._literal(envelope["schema"], history.BRIDGE_CONSUME_SCHEMA)
        history.shape._base64url(envelope["signatureBase64Url"], signature=True)
        payload = envelope["payload"]
        history._payload_for_purpose(payload, purpose=history.BRIDGE_CONSUME_CONSUMER_ROLE)
        history._canonical(original, envelope, work)
        unsigned = history._wire(payload, work)
        current()
        history.capability._signature(root, envelope["signatureBase64Url"], history.BRIDGE_CONSUME_SCHEMA,
            unsigned, history.capture._SharedLedger(work))
        current()
        if payload["issuedAtEpochNs"] > current():
            history._fail("historical bridged planning custody is future-issued")
        planner, policy = history._admit_bridge_planner(payload, root, window, bound, work, current,
            purpose=history.BRIDGE_CONSUME_CONSUMER_ROLE,
            _historical_policy_interval=expected_policy_interval, _continuity=_continuity)
        request = history._admit_consume_request(payload, work, current)
        opening = history.clock._sample_on_work(work)
        if _continuity is not None:
            current((opening[1], opening[2]))
        else:
            current()
        result = history._HistoricalPlanningMaterial(original, planner,
            history.BRIDGE_CONSUME_CONSUMER_ROLE, history.CONSUME_PROCESS_MODE,
            history.CONSUME_SERVICE_UID, history.CONSUME_SERVICE_GID,
            payload["receiverIdentity"], payload["bundleKeyDigest"], payload["deliveryKeyDigest"],
            (payload["issuedAtEpochNs"], payload["expiresAtEpochNs"]), opening, request,
            policy.historical_root_public_key, policy, root, expected_policy_interval)
        history._canonical(original, envelope, work)
        policy.live()
        current()
        return result
    except (AttributeError, KeyError, TypeError, ValueError, OverflowError, RecursionError, InvalidSignature) as exc:
        if isinstance(exc, history.OidcSessionActivationHistoryCustodyBootstrapError):
            raise
        raise history.OidcSessionActivationHistoryCustodyBootstrapError(
            "historical bridged planning custody admission failed") from exc
