"""Cold native-review authority policy and separately delivered root enrollment.

The surrounding measured configuration owns this policy's provenance. The
enrollment is a separate root-signed original because embedding its final
generation digest in that same configuration would create a digest cycle.
This module creates no keys, descriptors, connections or authority services.
Returned material is immutable owned data, never a substitute for cold launch
admission, authenticated current reads or receipt commit/completion.
"""
from __future__ import annotations

from dataclasses import dataclass
import json

from serverware import authority_contract as authority
from serverware import authority_current_root_authorization as authorization
from serverware import authority_native_jit_review_open_custody as opening
from serverware import authority_revocation_configuration as configuration
from serverware import oidc_session_activation_planner_bootstrap as activation
from serverware.authority_query_read_work import QueryReadValidationLimits, _ValidationWork


FIELD = "nativeJitReviewAuthorityPolicy"
SCHEMA = "serverware.nativeJitReviewAuthorityPolicy/v1"
MAX_POLICY_BYTES = 512 * 1024
_FIELDS = frozenset({"schema", "sourceContractDigest", "authenticationPolicy",
    "trustPolicy", "stateEndpoint"})
ERROR = "Native JIT review authority policy is invalid"
shape = configuration.capability.shape


class NativeJitReviewServicePolicyError(ValueError):
    pass


@dataclass(frozen=True, slots=True, repr=False, eq=False)
class _PolicyMaterial:
    # Properties return fresh JSON for owners whose existing closed capture
    # requires dict/list values. No caller can mutate this held policy data.
    _authentication_original: bytes
    _trust_original: bytes
    enrollment_original: bytes
    state_configuration: tuple

    @property
    def authentication_policy(self):
        return json.loads(self._authentication_original)

    @property
    def trust_policy(self):
        return json.loads(self._trust_original)


def _validated_policy_on_work(value, *, payload, root_key, work):
    ledger = configuration.capability.capture._SharedLedger(work)
    authorization._public(root_key)
    # Own the entire configured policy/role/audience graph before any key or
    # trust-library callback; only configuration permits finite timeouts.
    owned = configuration._ConfigurationCapture(ledger,
        maximum_bytes=authority.MAX_REQUEST_BYTES).visit({"policy": value, "payload": payload})
    policy, configured = owned["policy"], owned["payload"]
    shape._object(policy, _FIELDS, "native review authority policy")
    shape._literal(policy["schema"], SCHEMA)
    shape._literal(policy["sourceContractDigest"], authority.OPERATION_MANIFEST_DIGEST)
    if type(configured) is not dict or FIELD not in configured or opening.FIELD not in configured:
        raise NativeJitReviewServicePolicyError(ERROR)
    shape._literal(configured.get("schema"), configuration.CONFIG_SCHEMA)
    configuration.capability.plan._same(policy, configured[FIELD], work,
        "native review authority policy differs from its signed configuration field")
    shape._object(policy["authenticationPolicy"], activation._AUTHN_FIELDS,
        "native review authentication policy")
    shape._object(policy["trustPolicy"], activation._TRUST_FIELDS,
        "native review trust policy")
    configuration.capability._wire(policy, ledger, MAX_POLICY_BYTES)
    endpoint = activation._state_endpoint(policy["stateEndpoint"])
    webauthn = configured["webauthn"]
    shape._object(webauthn, activation.evidence_policy._WEBAUTHN_FIELDS,
        "native review configured WebAuthn policy")
    # The native opening policy remains independently purpose-closed. Its
    # existing validator also keeps authorizer/ACK keys separate from the
    # configuration root and generic configured role keys.
    work.prepare_normalization(configured[opening.FIELD])
    selected = configuration.production._callback(work,
        lambda: opening.validate_policy(configured[opening.FIELD],
            payload=configured, root_key=root_key))
    if selected is None:
        raise NativeJitReviewServicePolicyError(ERROR)
    configuration.capability.plan._same(selected["portalOrigin"], webauthn["origin"], work,
        "native review portal differs from the configured WebAuthn origin")
    activation._policies({"rpId": webauthn["rpId"], "origin": webauthn["origin"],
        "authenticationPolicy": policy["authenticationPolicy"],
        "trustPolicy": policy["trustPolicy"]}, configured, work)
    return policy, endpoint


def admit_on_work(value, *, configuration_payload, configuration_root_key,
                  enrollment_original, expected_generation_digest, work):
    """Join policy to genuine separate enrollment on the caller's held meter.

    The caller supplies the actual admitted launch generation; None is never
    a startup fallback. This authenticates enrollment, not a current head.
    """
    try:
        shape._digest(expected_generation_digest)
        original = authorization._original(enrollment_original,
            authorization.MAX_ENROLLMENT_BYTES, "native review root enrollment")
        policy, endpoint = _validated_policy_on_work(value,
            payload=configuration_payload, root_key=configuration_root_key, work=work)
        enrolled = authorization._admit_enrollment_on_work(enrollment_bytes=original,
            root_public_key=configuration_root_key, work=work)
        configuration.capability.plan._same(enrolled.payload["generationDigest"],
            expected_generation_digest, work, "native review enrollment differs from actual launch")
        ledger = configuration.capability.capture._SharedLedger(work)
        authn = configuration.capability._wire(policy["authenticationPolicy"], ledger, MAX_POLICY_BYTES)
        trust = configuration.capability._wire(policy["trustPolicy"], ledger, MAX_POLICY_BYTES)
        return _PolicyMaterial(authn, trust, original, endpoint)
    except (KeyError, TypeError, ValueError, AttributeError, OverflowError, RecursionError):
        raise NativeJitReviewServicePolicyError(ERROR) from None


def validate_policy(value, *, payload, root_key):
    """Configuration-loader grammar; separate enrollment is not embedded here."""
    try:
        if value is None:
            if type(payload) is dict and FIELD not in payload:
                return None
            raise NativeJitReviewServicePolicyError(ERROR)
        work = _ValidationWork(QueryReadValidationLimits())
        policy, _ = _validated_policy_on_work(value, payload=payload, root_key=root_key, work=work)
        return policy
    except (KeyError, TypeError, ValueError, AttributeError, OverflowError, RecursionError):
        raise NativeJitReviewServicePolicyError(ERROR) from None
